"""Local signed policy updates and ordinary admission/dispatch; no external effects."""
import copy
from dataclasses import replace
from datetime import timedelta
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

import snapshot as s
import authority_store as store_module
from authority_store import AuthorityStore
from managed_verifier import ManagedAuthorityVerifier
from fixture_support_updates import grant_json, sign_snapshots
from fixture_support import sign_fixture
import test_caller_authority as caller_fixtures

b = s.b


def reopened_source(directory, anchor, selection, node, node_sha, now):
    verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=selection,
        node=node, node_sha256=node_sha)
    return AuthorityStore(directory, verifier=verifier, expected_anchor=anchor, clock=lambda: now)


def lease_child(directory, anchor, selection, node, node_sha, now, ready, release, results):
    try:
        source = reopened_source(directory, anchor, selection, node, node_sha, now)
        with source.lease():
            ready.set()
            if not release.wait(10):
                raise RuntimeError("fixture release timeout")
            results.put(len(source.authority_policy().grants))
    except Exception as exc:
        results.put(getattr(exc, "cause", type(exc).__name__))


class AuthorityUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        caller_fixtures.CallerAuthorityTests.setUpClass()

    def setUp(self):
        self.f = caller_fixtures.CallerAuthorityTests(); self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.now = self.f.now
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "authority"
        self.claims = {"iss": "urn:example:policy-authority", "aud": "urn:example:verifier",
            "scope": "merchant-purchase", "epoch": "epoch-1", "revision": 1,
            "iat": self.f.f.second - 2, "nbf": self.f.f.second - 2, "exp": self.f.f.second + 80,
            "runtime_grants": [grant_json(self.f.f.grant)], "delegation_grants": [grant_json(self.f.grant)]}
        self.calls = []

    def setup_source(self, variants=None, *, headers=None, max_age=30):
        claims = variants if variants is not None else [self.claims]
        tokens, key = sign_snapshots(self.f.f.node, claims, headers=headers)
        self.tokens = tokens
        self.selection = s.AuthoritySelection(self.claims["iss"], self.claims["aud"], self.claims["scope"],
            self.claims["epoch"], "authority-key", key, 1, max_age)
        verifier = s.SnapshotVerifier(expected_profile=s.PROFILE, selection=self.selection,
            node=self.f.f.node, node_sha256=self.f.f.node_sha)
        self.source = AuthorityStore.create(self.directory, verifier=verifier, clock=lambda: self.now)
        self.managed = self.configure(self.source)
        return tokens

    def configure(self, source, *, state=None, execute=None):
        return ManagedAuthorityVerifier(source=source, verifier_id=self.f.f.verifier.verifier_id,
            policy=self.f.f.policy, state_store=self.f.store if state is None else state,
            execute=execute if execute is not None else lambda *args: self.calls.append(args), max_runtime_token_age_seconds=60,
            max_caller_token_age_seconds=40)

    def reopen(self):
        source = AuthorityStore(self.directory, verifier=self.source.verifier, expected_anchor=self.source.anchor,
                                clock=lambda: self.now)
        state = b.durable_state_module().DurableStateStore(self.f.store.directory, expected_anchor=self.f.store.anchor)
        return source, self.configure(source, state=state)

    def admit(self, **options):
        return self.managed.admit(b.encode(self.f.f.request), original=b.encode(self.f.f.original),
            evidence_artifacts={"urn:example:jwt": self.f.f.raw}, caller_proof=self.f.proof, **options)

    def test_signed_intake_and_recording_callback(self):
        raw, = self.setup_source()
        result = self.source.accept(raw)
        self.assertEqual(result["revision"], 1)
        bound = self.admit()
        out = self.managed.dispatch(bound, caller_proof=self.f.proof)
        self.assertEqual(self.calls, [(bound.effective, out.checkpoint)])
        self.assertEqual(b.decode(bound.receipt)["expires_at"], b.core.iso(self.now + timedelta(seconds=28)))

    def test_empty_state_and_unguarded_getters_fail(self):
        self.setup_source()
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_NOT_AVAILABLE"):
            self.admit()
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_LEASE_REQUIRED"):
            self.source.authority_policy()

    def test_revocation_and_old_version_rejection_survive_restart(self):
        revoked = copy.deepcopy(self.claims); revoked["revision"] = 2
        revoked["delegation_grants"][0]["revoked"] = True
        raw, deny = self.setup_source([self.claims, revoked])
        self.source.accept(raw); bound = self.admit(); self.source.accept(deny)
        source, managed = self.reopen()
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_ROLLBACK"):
            source.accept(raw)
        with self.assertRaisesRegex(b.Invalid, "CALLER_AUTHORIZATION_FAILED"):
            managed.dispatch(managed.restore_admission(self.f.f.request["request_id"]), caller_proof=self.f.proof)
        self.assertEqual(self.calls, [])

    def test_runtime_revocation_prevents_dispatch(self):
        revoked = copy.deepcopy(self.claims); revoked["revision"] = 2
        revoked["runtime_grants"][0]["revoked"] = True
        raw, deny = self.setup_source([self.claims, revoked])
        self.source.accept(raw); bound = self.admit(); self.source.accept(deny)
        with self.assertRaisesRegex(b.Invalid, "RUNTIME_EVIDENCE_VERIFICATION_FAILED"):
            self.managed.dispatch(bound, caller_proof=self.f.proof)
        self.assertEqual(self.calls, [])

    def test_actor_key_rotation_rejects_old_proof_and_accepts_new_proof(self):
        new_proof, key = sign_fixture(self.f.f.node, b.encode(self.f.header), b.encode(self.f.claims))
        rotated = copy.deepcopy(self.claims); rotated["revision"] = 2
        rotated["delegation_grants"] = [grant_json(replace(self.f.grant, public_key_spki=key))]
        first, second = self.setup_source([self.claims, rotated])
        self.source.accept(first); bound = self.admit(); self.source.accept(second)
        with self.assertRaisesRegex(b.Invalid, "CALLER_AUTHORIZATION_FAILED"):
            self.managed.dispatch(bound, caller_proof=self.f.proof)
        self.assertEqual(self.calls, [])
        self.managed.dispatch(bound, caller_proof=new_proof)
        self.assertEqual(len(self.calls), 1)

    def test_runtime_key_rotation_rejects_previously_signed_evidence(self):
        _, key = sign_fixture(self.f.f.node, b.encode(self.f.header), b.encode(self.f.claims))
        rotated = copy.deepcopy(self.claims); rotated["revision"] = 2
        rotated["runtime_grants"] = [grant_json(replace(self.f.f.grant, public_key_spki=key))]
        first, second = self.setup_source([self.claims, rotated])
        self.source.accept(first); bound = self.admit(); self.source.accept(second)
        with self.assertRaisesRegex(b.Invalid, "RUNTIME_EVIDENCE_VERIFICATION_FAILED"):
            self.managed.dispatch(bound, caller_proof=self.f.proof)
        self.assertEqual(self.calls, [])

    def test_newer_full_policy_can_restore_permission_without_extending_receipt(self):
        revoked = copy.deepcopy(self.claims); revoked["revision"] = 2
        revoked["delegation_grants"] = []
        active = copy.deepcopy(self.claims); active.update(revision=3, iat=self.f.f.second + 10)
        raw, deny, allow = self.setup_source([self.claims, revoked, active])
        self.source.accept(raw); bound = self.admit(); self.source.accept(deny)
        self.now += timedelta(seconds=10); self.source.accept(allow)
        output = self.managed.dispatch(bound, caller_proof=self.f.proof)
        self.assertEqual(b.decode(output.checkpoint)["usable_until"], b.decode(bound.receipt)["expires_at"])

    def test_equivalent_resigning_is_idempotent(self):
        first, second = self.setup_source([self.claims, self.claims])
        self.assertNotEqual(first, second)
        self.assertEqual(self.source.accept(first), self.source.accept(second))
        self.admit()

    def test_conflicting_current_revision_blocks_until_higher_revision(self):
        other = copy.deepcopy(self.claims); other["delegation_grants"] = []
        newer = {**self.claims, "revision": 2}
        first, conflict, recovery = self.setup_source([self.claims, other, newer])
        self.source.accept(first)
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REVISION_CONFLICT"):
            self.source.accept(conflict)
        source, managed = self.reopen()
        self.assertTrue(source.status()["conflict"])
        with self.assertRaises(s.AuthorityError):
            source.accept(first)
        with self.assertRaises(s.AuthorityError):
            managed.restore_admission(self.f.f.request["request_id"])
        source.accept(recovery)
        self.assertFalse(source.status()["conflict"])
        self.admit()

    def test_higher_revision_cannot_move_issuance_time_backwards(self):
        older = {**self.claims, "revision": 2, "iat": self.claims["iat"] - 1}
        first, other = self.setup_source([self.claims, older]); self.source.accept(first)
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_ISSUANCE_ROLLBACK"):
            self.source.accept(other)
        self.assertEqual(self.source.status()["revision"], 1)

    def test_expired_saved_state_can_receive_a_new_snapshot(self):
        short = {**self.claims, "exp": self.f.f.second + 1}
        fresh = {**self.claims, "revision": 2, "iat": self.f.f.second + 2, "nbf": self.f.f.second + 2}
        raw, other = self.setup_source([short, fresh]); self.source.accept(raw)
        self.now += timedelta(seconds=2)
        with self.assertRaises(s.AuthorityError):
            self.admit()
        self.source.accept(other)
        self.admit()

    def test_stale_saved_state_can_receive_new_revision(self):
        fresh = {**self.claims, "revision": 2, "iat": self.f.f.second + 10}
        first, second = self.setup_source([self.claims, fresh], max_age=10)
        self.source.accept(first); self.now += timedelta(seconds=10)
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_STALE"):
            self.admit()
        self.source.accept(second); self.admit()

    def test_expiry_observation_persists_even_when_permission_is_rejected(self):
        short = {**self.claims, "exp": self.f.f.second + 1}
        raw, = self.setup_source([short]); self.source.accept(raw)
        with self.source.lease():
            self.now += timedelta(seconds=1)
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_OUTSIDE_WINDOW"):
                self.source.authority_policy()
        self.now -= timedelta(microseconds=1)
        source, _ = self.reopen()
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_CLOCK_ROLLBACK"):
            with source.lease(): pass

    def test_refresh_failure_blocks_until_valid_refresh(self):
        raw, = self.setup_source(); self.source.accept(raw); bound = self.admit()
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"):
            self.source.refresh(lambda: (_ for _ in ()).throw(ValueError("private transport data")))
        self.assertTrue(self.source.status()["unavailable"])
        with self.assertRaises(s.AuthorityError):
            self.managed.dispatch(bound, caller_proof=self.f.proof)
        self.source.refresh(lambda: raw)
        self.managed.dispatch(bound, caller_proof=self.f.proof)

    def test_invalid_unsolicited_snapshot_does_not_block_current_state(self):
        raw, = self.setup_source(); self.source.accept(raw)
        with self.assertRaises(s.AuthorityError):
            self.source.accept(b"invalid")
        self.assertFalse(self.source.status()["unavailable"])
        self.admit()

    def test_signed_wrong_selection_fields_are_rejected(self):
        variants = [self.claims]
        for field in ("iss", "aud", "scope", "epoch"):
            variants.append({**self.claims, field: "wrong"})
        tokens = self.setup_source(variants); self.source.accept(tokens[0])
        for raw in tokens[1:]:
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_CONTEXT_MISMATCH"):
                self.source.accept(raw)
        self.assertEqual(self.source.status()["revision"], 1)

    def test_bad_header_signature_and_claim_shapes(self):
        headers = [{"alg": "ES256", "typ": typ, "kid": "authority-key"} for typ in (s.TOKEN_TYPE, s.c.TOKEN_TYPE)]
        good, wrong_type = self.setup_source([self.claims, self.claims], headers=headers)
        self.source.accept(good)
        for raw in (wrong_type, good[:-20] + b"A" * 20, good + b"\n", b"x" * 65537):
            with self.assertRaises(s.AuthorityError):
                self.source.accept(raw)

    def test_wrong_authority_key_is_rejected(self):
        raw, = self.setup_source()
        other, _ = sign_snapshots(self.f.f.node, [self.claims])
        with self.assertRaises(s.AuthorityError):
            self.source.accept(other[0])
        self.source.accept(raw)

    def test_revision_bool_zero_and_unknown_claim_rejected(self):
        variants = [self.claims, {**self.claims, "revision": True}, {**self.claims, "revision": 0},
                    {**self.claims, "unknown": 1}]
        tokens = self.setup_source(variants)
        for raw in tokens[1:]:
            with self.assertRaises(s.AuthorityError):
                self.source.accept(raw)

    def test_freshness_and_expiry_boundaries(self):
        raw, = self.setup_source(max_age=10); self.source.accept(raw)
        self.now += timedelta(seconds=8)
        with self.source.lease():
            self.source.authority_policy()
        self.now += timedelta(microseconds=1)
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_STALE"):
            with self.source.lease():
                pass

    def test_clock_high_from_getter_persists_across_restart(self):
        raw, = self.setup_source(); self.source.accept(raw)
        with self.source.lease():
            self.now += timedelta(seconds=10)
            self.source.authority_policy()
        self.now -= timedelta(seconds=1)
        source, _ = self.reopen()
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_CLOCK_ROLLBACK"):
            with source.lease():
                pass

    def test_lease_preserves_body_io_error_and_releases_lock(self):
        raw, = self.setup_source(); self.source.accept(raw)
        original = FileNotFoundError("fixture consumer I/O")
        with self.assertRaises(FileNotFoundError) as observed:
            with self.source.lease():
                raise original
        self.assertIs(observed.exception, original)
        self.assertEqual(self.source.accept(raw)["revision"], 1)
        self.assertEqual(self.calls, [])

    def test_unreadable_identity_is_typed_at_each_authority_entry(self):
        raw, = self.setup_source(); self.source.accept(raw)
        def lease():
            with self.source.lease():
                self.fail("unreadable identity must not enter lease")
        for entry in (lease, lambda: self.source.accept(raw), self.source.status, self.admit):
            with self.subTest(entry=entry), patch.object(s.jwt, "file_sha", side_effect=PermissionError("fixture source")):
                with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_IMPLEMENTATION_CHANGED"):
                    entry()
        with patch.object(s.jwt, "file_sha", side_effect=FileNotFoundError("fixture source")):
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REFRESH_FAILED"):
                self.source.refresh(lambda: raw)
        self.assertEqual(self.source.accept(raw)["revision"], 1)
        self.assertEqual(self.calls, [])

    def test_gate_io_error_is_store_unavailable_and_releases_lock(self):
        raw, = self.setup_source(); self.source.accept(raw)
        with patch.object(store_module.os, "open", side_effect=PermissionError("fixture store open")):
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_STORE_UNAVAILABLE"):
                with self.source.lease():
                    self.fail("unavailable store must not enter lease")
        self.assertEqual(self.source.accept(raw)["revision"], 1)

    def test_device_identity_mismatch_preserves_original_store(self):
        raw, = self.setup_source(); self.source.accept(raw)
        self.admit()
        for field in ("directory_device", "db_device", "lock_device"):
            with self.subTest(field=field):
                changed = b.decode(self.source.anchor)
                changed[field] += 1
                with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_STORE_REPLACED"):
                    AuthorityStore(self.directory, verifier=self.source.verifier,
                        expected_anchor=b.encode(changed), clock=lambda: self.now)
        source, managed = self.reopen()
        self.assertEqual(source.status()["revision"], 1)
        restored = managed.restore_admission(self.f.f.request["request_id"])
        managed.dispatch(restored, caller_proof=self.f.proof)
        self.assertEqual(len(self.calls), 1)

    def test_lease_blocks_reentrant_updates_and_other_threads(self):
        raw, = self.setup_source(); self.source.accept(raw)
        outcomes = []
        with self.source.lease():
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_REENTRANT"):
                self.source.accept(raw)
            def update():
                try:
                    self.source.accept(raw)
                except s.AuthorityError as exc:
                    outcomes.append(exc.cause)
            worker = threading.Thread(target=update); worker.start(); worker.join(3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(outcomes, ["AUTHORITY_BUSY"])

    def test_callback_holds_lease_until_return_and_update_must_retry(self):
        revoked = copy.deepcopy(self.claims); revoked["revision"] = 2
        revoked["delegation_grants"] = []
        first, second = self.setup_source([self.claims, revoked]); self.source.accept(first)
        entered, release = threading.Event(), threading.Event()
        results = []
        def record(*args):
            self.calls.append(args); entered.set()
            if not release.wait(10): raise RuntimeError("fixture callback timeout")
        self.managed = self.configure(self.source, execute=record)
        bound = self.admit()
        def dispatch():
            try: results.append(self.managed.dispatch(bound, caller_proof=self.f.proof))
            except Exception as exc: results.append(exc)
        worker = threading.Thread(target=dispatch); worker.start()
        try:
            self.assertTrue(entered.wait(10))
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_BUSY"):
                self.source.accept(second)
        finally:
            release.set(); worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(results), 1)
        self.assertFalse(isinstance(results[0], Exception), results)
        self.assertEqual(len(self.calls), 1)
        self.source.accept(second)
        # Use an independent empty replay store so the revoked permission,
        # rather than replay consumption, is the reason this admission fails.
        state = b.durable_state_module().DurableStateStore.create(Path(self.tmp.name) / "second-state",
            scope="second callback fixture", verifier_id=self.f.f.verifier.verifier_id)
        self.managed = self.configure(self.source, state=state)
        with self.assertRaisesRegex(b.Invalid, "CALLER_AUTHORIZATION_FAILED"):
            self.admit()
        self.assertEqual(len(self.calls), 1)

    def test_other_process_lease_excludes_successful_update(self):
        raw, = self.setup_source(); self.source.accept(raw)
        context = multiprocessing.get_context("spawn")
        ready, release, results = context.Event(), context.Event(), context.Queue()
        worker = context.Process(target=lease_child, args=(str(self.directory), self.source.anchor, self.selection,
            str(self.f.f.node), self.f.f.node_sha, self.now, ready, release, results))
        worker.start()
        try:
            self.assertTrue(ready.wait(10))
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_BUSY"):
                self.source.accept(raw)
        finally:
            release.set(); worker.join(10)
            if worker.is_alive(): worker.terminate(); worker.join()
        self.assertEqual(worker.exitcode, 0)
        self.assertEqual(results.get(timeout=2), 1)
        results.close(); results.join_thread()
        self.source.accept(raw)

    def test_unguarded_inner_admission_cannot_use_source_getters(self):
        raw, = self.setup_source(); self.source.accept(raw)
        with self.assertRaisesRegex(b.Invalid, "RUNTIME_EVIDENCE_VERIFICATION_FAILED"):
            self.managed._core.admit(b.encode(self.f.f.request), original=b.encode(self.f.f.original), now=self.now,
                evidence_artifacts={"urn:example:jwt": self.f.f.raw}, caller_proof=self.f.proof)

    def test_source_change_does_not_restore_old_admission(self):
        raw, = self.setup_source(); self.source.accept(raw); self.admit()
        other = AuthorityStore.create(Path(self.tmp.name) / "different", verifier=self.source.verifier, clock=lambda: self.now)
        other.accept(raw)
        with self.assertRaisesRegex(b.Invalid, "STATE_CONFIGURATION_CHANGED"):
            self.configure(other).restore_admission(self.f.f.request["request_id"])

    def test_database_and_lock_replacement_fail_closed(self):
        raw, = self.setup_source(); self.source.accept(raw)
        path = self.directory / "authority.lock"
        path.rename(path.with_suffix(".old")); path.write_bytes(b"")
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_STORE_REPLACED"):
            self.admit()
        self.assertEqual(self.calls, [])

    def test_corrupt_revision_metadata_is_not_repaired_by_update(self):
        raw, = self.setup_source(); self.source.accept(raw)
        connection = sqlite3.connect(self.directory / "authority.sqlite3")
        try:
            connection.execute("UPDATE state SET revision=3"); connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_STATE_CORRUPT"):
            self.source.accept(raw)

    def test_missing_or_malformed_clock_history_cannot_restore_expired_permission(self):
        raw, = self.setup_source(); self.source.accept(raw); self.admit()
        with self.source.lease():
            self.now += timedelta(seconds=31)
            with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_STALE"):
                self.source.authority_policy()
        high = self.source.status()["clock_high"]
        self.now -= timedelta(seconds=31)
        for damaged in (None, "invalid", high.replace("Z", "+00:00"), "1970-01-01T00:00:00Z"):
            with self.subTest(clock_high=damaged):
                connection = sqlite3.connect(self.directory / "authority.sqlite3")
                try:
                    connection.execute("UPDATE state SET clock_high=?", (damaged,)); connection.commit()
                finally:
                    connection.close()
                with self.assertRaisesRegex(s.AuthorityError, "AUTHORITY_STATE_CORRUPT"):
                    self.reopen()
        self.assertEqual(self.calls, [])

    def test_fork_during_descriptor_acquisition_does_not_strand_parent_lock(self):
        raw, = self.setup_source(); self.source.accept(raw)
        acquired, release = threading.Event(), threading.Event()
        child_read, parent_write = os.pipe()
        worker, pid, results = None, None, []
        real_flock = store_module.fcntl.flock
        def paused_flock(fd, operation):
            answer = real_flock(fd, operation)
            if threading.current_thread().name == "authority-fork-gap":
                acquired.set()
                if not release.wait(10): raise RuntimeError("fixture lock pause timeout")
            return answer
        def update():
            try: results.append(self.source.accept(raw)["revision"])
            except Exception as exc: results.append(exc)
        try:
            with patch.object(store_module.fcntl, "flock", paused_flock):
                worker = threading.Thread(target=update, name="authority-fork-gap"); worker.start()
                self.assertTrue(acquired.wait(10))
                pid = os.fork()
                if pid == 0:
                    os.close(parent_write); os.read(child_read, 1); os.close(child_read); os._exit(0)
                os.close(child_read); child_read = None
                release.set(); worker.join(10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(results, [1])
            # The idle child is still alive. Its inherited fd must already be
            # closed, so the parent's completed lease cannot remain busy.
            self.assertEqual(self.source.accept(raw)["revision"], 1)
        finally:
            release.set()
            if worker is not None: worker.join(12)
            if child_read is not None: os.close(child_read)
            if parent_write is not None: os.close(parent_write)
            if pid is not None:
                _, status = os.waitpid(pid, 0)
                self.assertEqual(status, 0)

    def test_forked_handle_rejected_and_child_does_not_release_parent_lease(self):
        raw, = self.setup_source(); self.source.accept(raw)
        read_fd, write_fd = os.pipe()
        with self.source.lease():
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                outcomes = []
                for action in (self.source.authority_policy, lambda: self.reopen()):
                    try: action(); outcomes.append("accepted")
                    except Exception as exc: outcomes.append(getattr(exc, "cause", type(exc).__name__))
                os.write(write_fd, b.encode(outcomes)); os.close(write_fd); os._exit(0)
            os.close(write_fd)
            _, status = os.waitpid(pid, 0)
            result = b.decode(os.read(read_fd, 4096)); os.close(read_fd)
            self.assertEqual(status, 0)
            self.assertEqual(result, ["AUTHORITY_FORK_REOPEN_REQUIRED", "AUTHORITY_BUSY"])
            self.source.authority_policy()
        self.source.accept(raw)


if __name__ == "__main__":
    unittest.main()
