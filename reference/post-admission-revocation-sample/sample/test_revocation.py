from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import contract

from contract import (PROFILE, PROOF_TYP, STATUS_TYP, b64, decode, encode, safe_read, sha,
                      unb64, unurl64, url64, verify_jws)
from fixture import BASE, Case, Clock, Keys
from provider import Provider
from read_evidence import verify


class IntegratedChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_temp = tempfile.TemporaryDirectory(prefix="vate-test-keys-")
        cls.keys = Keys(Path(cls.key_temp.name))

    @classmethod
    def tearDownClass(cls):
        cls.key_temp.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vate-revocation-check-")
        self.root = Path(self.temporary.name)
        self.counter = 0
        self.c = self.case()

    def tearDown(self):
        self.temporary.cleanup()

    def case(self, **kwargs):
        self.counter += 1
        return Case(self.root / ("case-" + str(self.counter)), self.keys, **kwargs)

    def count(self, case=None):
        with (case or self.c).provider.connect() as db:
            return db.execute("SELECT count(*) FROM accepted").fetchone()[0]

    def exported(self, case=None):
        c = case or self.c
        destination = c.path / "evidence.json"
        c.provider.export(destination)
        raw = safe_read(destination)
        return raw, verify(raw, c.selection_raw, c.provider.anchor_raw)

    def test_nominal_real_signatures_effects_query_and_reader(self):
        original = unb64(self.c.selection["authorization"]["receipt"])
        self.assertEqual(self.c.submit()["status"], "effect_observed")
        self.assertEqual(self.c.provider.query()["status"], "effect_observed")
        raw, result = self.exported()
        self.assertEqual(result["outcome"], "effect_observed")
        self.assertEqual(result["observed_files"], 2)
        self.assertEqual(original, self.c.provider.selection.auth.receipt)
        self.assertNotIn(b"PRIVATE KEY", raw)

    def test_revocation_prevents_new_acceptance_and_preserves_allow(self):
        before = self.c.provider.selection.auth.receipt
        self.assertEqual(self.c.provider.notify(self.c.signed_status(sequence=2, state="revoked"))["status"], "stored")
        self.assertEqual(self.c.submit()["reason"], "revoked")
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.c.provider.query()["files"], [])
        self.assertEqual(self.exported()[1]["outcome"], "not_accepted")
        self.assertEqual(self.c.provider.selection.auth.receipt, before)

    def test_late_expired_lower_version_revocation_latches_across_restart(self):
        self.c.set_status(sequence=3)
        self.c.provider.notify(safe_read(self.c.path / "authority-status.jws"))
        self.c.clock.value = BASE + 51
        self.c.provider.notify(self.c.signed_status(sequence=2, state="revoked", next_update_at=BASE + 50))
        self.c.provider = Provider(self.c.path, clock=self.c.clock)
        self.c.set_status(sequence=4, generated_at=BASE + 51, next_update_at=BASE + 111)
        self.assertEqual(self.c.submit()["reason"], "revoked")
        self.assertEqual(self.count(), 0)
        self.exported()

    def test_pro_M1_expired_conflict_never_reopens(self):
        for notification in (False, True):
            for restart in (False, True):
                with self.subTest(notification=notification, restart=restart):
                    c = self.case()
                    c.submit(input_sha256="0" * 64)
                    c.clock.value = BASE + 51
                    conflicting = c.signed_status(next_update_at=BASE + 50)
                    if notification:
                        c.provider.notify(conflicting)
                    else:
                        (c.path / "authority-status.jws").write_bytes(conflicting)
                        self.assertEqual(c.submit()["reason"], "authority_conflict")
                    if restart:
                        c.provider = Provider(c.path, clock=c.clock)
                    c.clock.value = BASE + 52
                    c.set_status()
                    self.assertEqual(c.submit()["reason"], "authority_conflict")
                    self.assertEqual(self.count(c), 0)
                    self.exported(c)

    def test_invalid_conflict_cannot_poison_state(self):
        for changes in ({"role": "untrusted"}, {"issuer": "wrong"}, {"runtime": "wrong"},
                        {"runtime_spki_sha256": "wrong"}, {"epoch": "wrong"}):
            with self.subTest(changes=changes):
                c = self.case()
                c.provider.notify(c.signed_status())
                c.clock.value = BASE + 51
                self.assertEqual(c.provider.notify(c.signed_status(next_update_at=BASE + 50, **changes))["status"], "not_stored")
                self.assertEqual(c.submit()["status"], "effect_observed")

    def test_pro_M2_resigning_same_input_is_not_conflict(self):
        one, two = self.c.signed_status(), self.c.signed_status()
        self.assertNotEqual(one, two)
        self.assertEqual(one.rsplit(b".", 1)[0], two.rsplit(b".", 1)[0])
        self.c.provider.notify(one)
        (self.c.path / "authority-status.jws").write_bytes(two)
        self.assertEqual(self.c.submit()["status"], "effect_observed")
        self.exported()

    def test_historical_conflict_blocks_pull_and_notification_across_restart(self):
        for journal in ("WAL", "DELETE"):
            for notification in (False, True):
                for expired in (False, True):
                    with self.subTest(journal=journal, notification=notification, expired=expired):
                        c = self.case(journal=journal)
                        c.provider.notify(c.signed_status(sequence=1))
                        c.provider.notify(c.signed_status(sequence=2))
                        c.provider = Provider(c.path, clock=c.clock)
                        c.clock.value = BASE + 51
                        changed = ({"next_update_at": BASE + 50} if expired else {"state": "suspended"})
                        raw = c.signed_status(sequence=1, **changed)
                        if notification:
                            self.assertEqual(c.provider.notify(raw)["status"], "stored")
                        else:
                            (c.path / "authority-status.jws").write_bytes(raw)
                            self.assertEqual(c.submit()["reason"], "authority_conflict")
                        c.provider = Provider(c.path, clock=c.clock)
                        c.set_status(sequence=3, generated_at=BASE + 51, next_update_at=BASE + 111)
                        self.assertEqual(c.submit()["reason"], "authority_conflict")
                        self.assertEqual(self.count(c), 0)
                        self.assertEqual(c.provider.observe(), [])
                        self.assertEqual(self.exported(c)[1]["outcome"], "not_accepted")

    def test_historical_untrusted_or_other_subject_cannot_create_conflict(self):
        for changes in ({"role": "untrusted"}, {"issuer": "wrong"}, {"runtime": "wrong"},
                        {"runtime_spki_sha256": "wrong"}, {"epoch": "wrong"}):
            with self.subTest(changes=changes):
                c = self.case()
                c.provider.notify(c.signed_status(sequence=1))
                c.provider.notify(c.signed_status(sequence=2))
                self.assertEqual(c.provider.notify(c.signed_status(sequence=1, state="suspended", **changes)),
                                 {"status": "not_stored"})
                c.set_status(sequence=2)
                self.assertEqual(c.submit()["status"], "effect_observed")
                self.exported(c)

    def test_historical_same_input_resigning_does_not_create_conflict(self):
        one, two = self.c.signed_status(), self.c.signed_status()
        self.assertNotEqual(one, two)
        self.assertEqual(one.rsplit(b".", 1)[0], two.rsplit(b".", 1)[0])
        self.c.provider.notify(one)
        self.c.provider.notify(self.c.signed_status(sequence=2))
        self.c.provider = Provider(self.c.path, clock=self.c.clock)
        self.c.provider.notify(two)
        self.c.set_status(sequence=2)
        self.assertEqual(self.c.submit()["status"], "effect_observed")
        self.exported()

    def test_reader_rejects_history_that_missed_a_historical_conflict(self):
        c = self.c
        merge = c.provider.merge_status
        def discard_conflict(db, verified, now, source):
            merge(db, verified, now, source)
            # Fault injection models a producer that loses its conflict flag.
            db.execute("UPDATE state SET conflict=0")
            row = db.execute("SELECT id,body FROM events ORDER BY id DESC LIMIT 1").fetchone()
            body = decode(row["body"]); body["conflict"] = False
            db.execute("UPDATE events SET body=? WHERE id=?", (encode(body), row["id"]))
        with patch.object(c.provider, "merge_status", side_effect=discard_conflict):
            c.provider.notify(c.signed_status(sequence=1))
            c.provider.notify(c.signed_status(sequence=2))
            c.provider.notify(c.signed_status(sequence=1, state="suspended"))
            c.set_status(sequence=2)
            self.assertEqual(c.submit()["status"], "effect_observed")
        dest = c.path / "incorrect-producer.json"
        c.provider.export(dest)
        value = decode(dest.read_bytes())
        with self.assertRaisesRegex(ValueError, "terminal state mismatch"):
            verify(encode(value), c.selection_raw, c.provider.anchor_raw)
        conflict_seen = False
        for event in value["events"]:
            if event["kind"] == "status":
                payload = decode(unurl64(unb64(event["body"]["raw"]).decode().split(".")[1]))
                conflict_seen |= payload["state"] == "suspended"
                event["body"]["conflict"] = conflict_seen
            elif event["kind"] == "decision" and conflict_seen:
                event["body"]["output_before_acceptance"] = None
        with self.assertRaisesRegex(ValueError, "decision reason inconsistent"):
            verify(encode(value), c.selection_raw, c.provider.anchor_raw)

    def test_historical_conflict_observed_after_acceptance_does_not_cancel(self):
        c = self.c
        c.provider.notify(c.signed_status(sequence=1))
        c.set_status(sequence=2)
        self.assertEqual(c.submit()["status"], "effect_observed")
        before = c.provider.observe()
        c.provider.notify(c.signed_status(sequence=1, state="suspended"))
        c.provider = Provider(c.path, clock=c.clock)
        self.assertEqual(c.submit()["reason"], "already_accepted")
        self.assertEqual(c.provider.query()["status"], "effect_observed")
        self.assertEqual(self.exported(c)[1]["outcome"], "effect_observed")
        self.assertEqual(c.provider.observe(), before)
        self.assertEqual(self.count(c), 1)

    def test_pro_M2_padding_padbits_whitespace_rejected_not_conflict(self):
        raw = self.c.signed_status()
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        last = alphabet[alphabet.index(chr(raw[-1])) | 1].encode()
        for bad in (raw + b"==", raw[:-1] + last, b" " + raw, raw + b"\n", raw + b".x"):
            with self.subTest(bad_length=len(bad)):
                self.assertEqual(self.c.provider.notify(bad)["status"], "not_stored")
        self.assertEqual(self.c.submit()["status"], "effect_observed")

    def test_signature_only_tamper_cannot_be_used(self):
        raw = self.c.signed_status()
        parts = raw.split(b".")
        signature = bytearray(unurl64(parts[2].decode())); signature[12] ^= 1
        parts[2] = url64(signature).encode()
        (self.c.path / "authority-status.jws").write_bytes(b".".join(parts))
        self.assertEqual(self.c.submit()["reason"], "status_unavailable")
        self.assertEqual(self.count(), 0)
        self.exported()

    def test_strict_json_fields_types_algorithm_and_times(self):
        base = self.c.status_payload()
        wrong = [{**base, "sequence": True}, {**base, "sequence": 0}, {**base, "sequence": 1.0},
                 {**base, "generated_at": "100"}, {**base, "generated_at": BASE + 1},
                 {**base, "last_changed_at": BASE + 1}, {**base, "next_update_at": BASE},
                 {**base, "state": "unknown-state"}, {**base, "extra": 1}]
        tokens = [self.keys.sign(p, "authority", STATUS_TYP) for p in wrong]
        tokens += [self.keys.sign(base, "authority", STATUS_TYP,
                                 payload_raw=b'{"sequence":1,' + encode(base)[1:])]
        for header in ({"alg": "none", "typ": STATUS_TYP, "kid": "x"},
                       {"alg": "HS256", "typ": STATUS_TYP, "kid": "x"},
                       {"alg": "ES256", "typ": PROOF_TYP, "kid": "x"},
                       {"alg": "ES256", "typ": STATUS_TYP, "kid": "x", "jku": "https://invalid.example"}):
            tokens.append(self.keys.sign(base, "authority", STATUS_TYP, header=header))
        for raw in tokens:
            with self.subTest(token_sha=sha(raw)):
                self.assertEqual(self.c.provider.notify(raw)["status"], "not_stored")
        self.assertEqual(self.c.submit()["status"], "effect_observed")

    def test_signed_wrong_status_target_is_not_authorized(self):
        for key in ("issuer", "epoch", "runtime", "runtime_spki_sha256", "object_type", "profile"):
            with self.subTest(key=key):
                c = self.case(); c.set_status(**{key: "wrong"})
                self.assertEqual(c.submit()["reason"], "status_unavailable")
                self.assertEqual(self.count(c), 0)

    def test_runtime_proof_is_K_signature_not_attestor_or_caller_flag(self):
        for role in ("authority", "untrusted"):
            with self.subTest(role=role):
                c = self.case()
                self.assertEqual(c.submit(role=role)["reason"], "proof_invalid")
                self.assertEqual(self.count(c), 0)

    def test_runtime_proof_binds_every_request_surface(self):
        for key in ("runtime", "runtime_spki_sha256", "receiver", "provider", "operation_key",
                    "input_sha256", "admission_sha256", "attempt_id", "nonce", "profile"):
            with self.subTest(key=key):
                c = self.case()
                self.assertEqual(c.submit(**{key: "wrong"})["reason"], "proof_invalid")
                self.assertEqual(self.count(c), 0)

    def test_proof_type_window_and_duplicate_json(self):
        for changes in ({"issued_at": True}, {"issued_at": BASE + 1}, {"expires_at": BASE},
                        {"expires_at": BASE + 61}, {"expires_at": "wrong"}):
            with self.subTest(changes=changes):
                c = self.case()
                self.assertEqual(c.submit(**changes)["reason"], "proof_invalid")
        challenge, raw = self.c.challenge_and_proof()
        payload = decode(unurl64(raw.decode().split(".")[1]))
        duplicate = self.keys.sign(payload, "runtime", PROOF_TYP,
                                   payload_raw=b'{"nonce":"duplicate",' + encode(payload)[1:])
        self.assertEqual(self.c.provider.submit(challenge["attempt_id"], duplicate)["reason"], "proof_invalid")

    def test_nonselected_states_defer_without_permanent_revocation(self):
        for state in ("suspended", "quarantined", "attenuated"):
            with self.subTest(state=state):
                c = self.case(); c.set_status(state=state)
                self.assertEqual(c.submit()["reason"], "status_not_active")
                c.set_status(sequence=2)
                self.assertEqual(c.submit()["status"], "effect_observed")

    def test_rereceive_does_not_extend_freshness(self):
        self.c.provider.notify(self.c.signed_status())
        self.c.clock.value = BASE + 60
        self.c.provider.notify(self.c.signed_status())
        self.assertEqual(self.c.submit()["reason"], "status_stale")

    def test_max_age_checked_separately(self):
        self.c.set_status(next_update_at=BASE + 200)
        self.c.clock.value = BASE + 61
        self.assertEqual(self.c.submit()["reason"], "status_stale")

    def test_lower_active_sequence_cannot_rewind(self):
        self.c.provider.notify(self.c.signed_status(sequence=3))
        self.assertEqual(self.c.submit()["reason"], "status_rollback")

    def test_unavailable_pull_not_replaced_by_notification(self):
        self.c.provider.notify(self.c.signed_status())
        (self.c.path / "authority-status.jws").unlink()
        self.assertEqual(self.c.submit()["reason"], "status_unavailable")
        self.c.set_status()
        self.assertEqual(self.c.submit()["status"], "effect_observed")

    def test_failed_submission_consumes_ticket_and_fresh_attempt_recovers(self):
        challenge, bad = self.c.challenge_and_proof(input_sha256="wrong")
        self.assertEqual(self.c.provider.submit(challenge["attempt_id"], bad)["reason"], "proof_invalid")
        self.assertEqual(self.c.provider.submit(challenge["attempt_id"], bad)["status"], "unknown")
        self.assertEqual(self.c.submit()["status"], "effect_observed")

    def test_oversized_and_wrong_type_proof_consume_identified_attempt(self):
        for invalid in (b"x" * 65537, "not-bytes", None):
            with self.subTest(kind=type(invalid).__name__):
                c = self.case()
                attempt, valid = c.challenge_and_proof()
                self.assertEqual(c.provider.submit(attempt["attempt_id"], invalid)["status"], "unknown")
                with c.provider.connect() as db:
                    row = db.execute("SELECT state FROM attempts WHERE attempt_id=?", (attempt["attempt_id"],)).fetchone()
                    self.assertEqual(row["state"], "consumed")
                self.assertEqual(c.provider.submit(attempt["attempt_id"], valid)["status"], "unknown")
                self.assertEqual(c.provider.query()["status"], "not_accepted")
                self.assertEqual(self.count(c), 0)
                self.assertEqual(c.submit()["status"], "effect_observed")
                self.assertEqual(self.count(c), 1)
                self.exported(c)

    def test_restart_does_not_reuse_pending_attempt(self):
        challenge, proof = self.c.challenge_and_proof()
        self.c.provider = Provider(self.c.path, clock=self.c.clock)
        self.assertEqual(self.c.provider.submit(challenge["attempt_id"], proof)["status"], "unknown")
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.c.submit()["status"], "effect_observed")

    def test_alias_and_new_nonce_cannot_repeat_same_operation(self):
        self.assertEqual(self.c.submit()["status"], "effect_observed")
        first_files = self.c.provider.observe()
        header = {"alg": "ES256", "typ": PROOF_TYP, "kid": "another-label-for-same-K"}
        self.assertEqual(self.c.submit(header=header)["reason"], "already_accepted")
        self.assertEqual(self.c.provider.observe(), first_files)
        self.assertEqual(self.count(), 1)
        self.exported()

    def test_new_permit_cannot_override_receiver_selection(self):
        raw = safe_read(self.c.path / "selection.json")
        changed = decode(raw)
        permit = decode(unb64(changed["authorization"]["permit"]))
        permit["authorization_key"] = "different-permit"
        changed["authorization"]["permit"] = b64(encode(permit))
        (self.c.path / "selection.json").write_bytes(encode(changed))
        self.assertEqual(self.c.provider.query()["status"], "unknown")
        with self.assertRaises(ValueError):
            Provider(self.c.path, clock=self.c.clock)

    def test_clock_rollback_latches_across_restart(self):
        self.c.submit(input_sha256="wrong")
        self.c.clock.value = BASE - 1
        with self.assertRaisesRegex(ValueError, "clock_uncertain"):
            self.c.provider.challenge()
        self.c.clock.value = BASE + 1
        self.c.provider = Provider(self.c.path, clock=self.c.clock)
        with self.assertRaisesRegex(ValueError, "clock_uncertain"):
            self.c.provider.challenge()

    def test_failed_challenge_clock_observation_is_retained_for_reader(self):
        attempt, proof = self.c.challenge_and_proof()
        self.c.clock.value = BASE - 1
        with self.assertRaisesRegex(ValueError, "clock_uncertain"):
            self.c.provider.challenge()
        self.c.clock.value = BASE + 1
        result = self.c.provider.submit(attempt["attempt_id"], proof)
        self.assertEqual(result["reason"], "clock_uncertain")
        raw, checked = self.exported()
        self.assertEqual(checked["outcome"], "not_accepted")
        changed = decode(raw)
        next(x["body"] for x in changed["events"] if x["kind"] == "decision")["reason"] = "revoked"
        with self.assertRaisesRegex(ValueError, "decision reason"):
            verify(encode(changed), self.c.selection_raw, self.c.provider.anchor_raw)

    def test_admission_expiry_cannot_be_refreshed_by_new_status(self):
        self.c.clock.value = BASE + 600
        self.c.set_status(sequence=2, generated_at=BASE + 600, next_update_at=BASE + 660)
        self.assertEqual(self.c.submit()["reason"], "admission_expired")

    def check_admission_boundary(self, *, second, accepted, **kwargs):
        # Every boundary gets a fresh store and a proof/status valid at its clock.
        c = self.case(clock=Clock(BASE + second), **kwargs)
        original = c.provider.selection.auth.receipt
        c.set_status(generated_at=c.clock(), next_update_at=c.clock()+60, last_changed_at=c.clock())
        result = c.submit()
        self.assertEqual(result["status"], "effect_observed" if accepted else "denied_before_acceptance")
        if not accepted:
            self.assertEqual(result["reason"], "admission_expired")
        self.assertEqual(self.count(c), int(accepted))
        self.assertEqual(len(c.provider.query()["files"]), 2 if accepted else 0)
        checked = self.exported(c)[1]
        self.assertEqual(checked["outcome"], "effect_observed" if accepted else "not_accepted")
        self.assertEqual(checked["observed_files"], 2 if accepted else 0)
        self.assertEqual(c.provider.selection.auth.receipt, original)

    def test_admission_time_conversion_preserves_full_microseconds(self):
        for digits in range(1, 7):
            text = "1" * digits
            self.assertEqual(contract.time_microseconds("1970-01-01T00:00:00."+text+"Z"),
                             int(text.ljust(6, "0")))
        self.assertEqual(contract.time_microseconds("1969-12-31T23:59:59.999999Z"), -1)
        self.assertEqual(contract.time_microseconds("9999-12-31T23:59:59.999999Z"),
                         253402300799999999)
        self.assertFalse(self.c.provider.selection.admission_current(9007199254740991))

    def test_original_allow_issue_time_is_an_admission_lower_bound(self):
        for journal in ("WAL", "DELETE"):
            for second, accepted in ((0, False), (29, False), (30, True), (599, True), (600, False)):
                with self.subTest(journal=journal, second=second):
                    self.check_admission_boundary(journal=journal, second=second, accepted=accepted,
                                                  evaluated_at="2026-10-23T00:00:30Z")

    def test_fractional_permit_start_and_expiry_are_not_truncated(self):
        for journal in ("WAL", "DELETE"):
            for fraction in ("5", "000001", "999999"):
                for second, accepted in ((0, False), (1, True), (600, True), (601, False)):
                    with self.subTest(journal=journal, fraction=fraction, second=second):
                        self.check_admission_boundary(journal=journal, second=second, accepted=accepted,
                            permit_issued_at="2026-10-23T00:00:00."+fraction+"Z")

    def test_fractional_allow_start_is_preserved_when_permit_starts_earlier(self):
        for journal in ("WAL", "DELETE"):
            for second, accepted in ((30, False), (31, True)):
                with self.subTest(journal=journal, second=second):
                    self.check_admission_boundary(journal=journal, second=second, accepted=accepted,
                                                  evaluated_at="2026-10-23T00:00:30.500000Z")

    def test_reader_rejects_legacy_admission_time_decisions(self):
        def old_permit_only(selected, now):
            permit = decode(selected.auth.permit)
            return int(contract.time_value(permit["issued_at"]).timestamp()) <= now < int(
                contract.time_value(permit["expires_at"]).timestamp())
        cases = [(0, {"permit_issued_at":"2026-10-23T00:00:00.500000Z"}, True),
                 (600, {"permit_issued_at":"2026-10-23T00:00:00.500000Z"}, False),
                 (29, {"evaluated_at":"2026-10-23T00:00:30Z"}, True)]
        for journal in ("WAL", "DELETE"):
            for second, kwargs, old_accepted in cases:
                with self.subTest(journal=journal, second=second):
                    c = self.case(journal=journal, clock=Clock(BASE+second), **kwargs)
                    c.set_status(generated_at=c.clock(), next_update_at=c.clock()+60)
                    # Reproduce only the former provider rule. The reader below
                    # uses the real current implementation and must reject it.
                    with patch.object(contract.Selection, "admission_current", old_permit_only):
                        c.submit()
                    self.assertEqual(self.count(c), int(old_accepted))
                    destination = c.path / "legacy-time.json"
                    c.provider.export(destination)
                    rejection = "unreached output observation" if old_accepted else "invalid file inventory"
                    with self.assertRaisesRegex(ValueError, rejection):
                        verify(safe_read(destination), c.selection_raw, c.provider.anchor_raw)

    def test_admission_expiry_during_acceptance_lock_wait(self):
        for journal in ("WAL", "DELETE"):
            with self.subTest(journal=journal):
                c = self.case(journal=journal, clock=Clock(BASE+5),
                              permit_expires_at="2026-10-23T00:00:05.500000Z")
                arrived, proceed = threading.Event(), threading.Event()
                def hook(point):
                    if point == "before_accept_lock":
                        arrived.set()
                        if not proceed.wait(10):
                            raise RuntimeError("test barrier timeout")
                c.provider.hook = hook
                challenge, proof = c.challenge_and_proof()
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(c.provider.submit, challenge["attempt_id"], proof)
                    self.assertTrue(arrived.wait(10))
                    with c.provider.connect() as db:
                        db.execute("BEGIN IMMEDIATE")
                        proceed.set()
                        c.clock.value = BASE+6
                        db.commit()
                    result = future.result(timeout=10)
                self.assertEqual(result["reason"], "admission_expired")
                self.assertEqual(self.count(c), 0)
                self.assertEqual(self.exported(c)[1]["outcome"], "not_accepted")

    def test_revoke_commits_between_pull_and_acceptance(self):
        q = Provider(self.c.path, clock=self.c.clock)
        self.c.provider.hook = lambda point: q.notify(self.c.signed_status(sequence=2, state="revoked")) if point == "after_pull" else None
        self.assertEqual(self.c.submit()["reason"], "revoked")
        self.assertEqual(self.count(), 0)
        self.exported()

    def test_accept_commits_before_revocation_effect_is_not_claimed_cancelled(self):
        q = Provider(self.c.path, clock=self.c.clock)
        self.c.provider.hook = lambda point: q.notify(self.c.signed_status(sequence=2, state="revoked")) if point == "before_effect" else None
        self.assertEqual(self.c.submit()["status"], "effect_observed")
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.exported()[1]["outcome"], "effect_observed")

    def test_lock_wait_rechecks_clock_and_committed_status(self):
        for revoke in (False, True):
            with self.subTest(revoke=revoke):
                c = self.case()
                arrived, proceed = threading.Event(), threading.Event()
                def hook(point):
                    if point == "before_accept_lock":
                        arrived.set()
                        if not proceed.wait(10):
                            raise RuntimeError("test barrier timeout")
                c.provider.hook = hook
                challenge, proof = c.challenge_and_proof()
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(c.provider.submit, challenge["attempt_id"], proof)
                    self.assertTrue(arrived.wait(10))
                    with c.provider.connect() as db:
                        db.execute("BEGIN IMMEDIATE")
                        proceed.set()
                        if revoke:
                            v = c.provider.selection.status(c.signed_status(sequence=2, state="revoked"), BASE)
                            c.provider.merge_status(db, v, BASE, "notification")
                        else:
                            c.clock.value = BASE + 61
                        db.commit()
                    result = future.result(timeout=10)
                self.assertEqual(result["reason"], "revoked" if revoke else "proof_invalid")
                self.assertEqual(self.count(c), 0)

    def test_concurrent_requests_accept_at_most_once(self):
        other = Provider(self.c.path, clock=self.c.clock)
        one, proof_one = self.c.challenge_and_proof()
        previous = self.c.provider
        self.c.provider = other
        two, proof_two = self.c.challenge_and_proof()
        self.c.provider = previous
        barrier = threading.Barrier(2)
        def submit(p, challenge, proof):
            barrier.wait(timeout=10)
            return p.submit(challenge["attempt_id"], proof)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(submit, previous, one, proof_one), pool.submit(submit, other, two, proof_two)]
            results = [f.result(timeout=10) for f in futures]
        self.assertEqual(sum(r["status"] == "effect_observed" for r in results), 1)
        self.assertEqual(self.count(), 1)
        self.exported()

    def test_commit_busy_rolls_back_and_fences_writer_before_recovery(self):
        c = self.case(journal="DELETE")
        c.provider.timeout = .03
        blocker = []
        def hook(point):
            if point == "before_commit":
                reader = sqlite3.connect(c.path / "provider.sqlite3", isolation_level=None)
                reader.execute("BEGIN")
                reader.execute("SELECT count(*) FROM accepted").fetchone()
                blocker.append(reader)
        c.provider.hook = hook
        try:
            self.assertEqual(c.submit()["status"], "unknown")
        finally:
            for r in blocker:
                r.close()
        self.assertEqual(self.count(c), 0)
        self.assertEqual(c.provider.query()["status"], "not_accepted")
        c.provider.hook = lambda point: None
        self.assertEqual(c.submit()["status"], "effect_observed")

    def test_wal_old_snapshot_is_not_used_for_recovery(self):
        old = sqlite3.connect(self.c.path / "provider.sqlite3", isolation_level=None)
        try:
            old.execute("BEGIN")
            self.assertEqual(old.execute("SELECT count(*) FROM accepted").fetchone()[0], 0)
            self.assertEqual(self.c.submit()["status"], "effect_observed")
            self.assertEqual(old.execute("SELECT count(*) FROM accepted").fetchone()[0], 0)
            self.assertTrue(self.c.provider.query()["accepted"])
        finally:
            old.close()

    def test_live_worker_prevents_absence_claim(self):
        with self.c.provider.worker():
            self.assertEqual(self.c.provider.query()["status"], "unknown")

    def test_missing_replaced_corrupt_store_never_auto_initializes(self):
        for fault in ("missing", "replaced", "corrupt"):
            with self.subTest(fault=fault):
                c = self.case()
                db = c.path / "provider.sqlite3"
                if fault == "missing":
                    db.unlink()
                elif fault == "replaced":
                    raw = db.read_bytes(); db.unlink(); db.write_bytes(raw)
                    # Inode may be recycled on some filesystems; a changed identity is definitive too.
                    with closing(sqlite3.connect(db, isolation_level=None)) as conn:
                        conn.execute("UPDATE identity SET store_id='wrong'")
                else:
                    db.write_bytes(b"corrupt database")
                self.assertEqual(c.provider.query()["status"], "unknown")
                if fault == "missing":
                    self.assertFalse(db.exists())

    def test_symlink_status_output_or_store_does_not_create_effect(self):
        for target in ("authority-status.jws", "provider.sqlite3", "sandbox"):
            with self.subTest(target=target):
                c = self.case()
                path = c.path / target
                real = c.path / (target + "-real")
                path.rename(real); path.symlink_to(real)
                if target == "authority-status.jws":
                    self.assertEqual(c.submit()["reason"], "status_unavailable")
                else:
                    self.assertEqual(c.provider.query()["status"], "unknown")

    def test_fault_positions_preserve_acceptance_and_never_repeat_effect(self):
        for point, accepted, files, outcome in (
            ("before_commit", False, 0, "not_accepted"), ("after_commit", True, 0, "unknown"),
            ("before_effect", True, 0, "unknown"), ("after_file_1", True, 1, "unknown"),
            ("after_native", True, 2, "effect_observed")):
            with self.subTest(point=point):
                c = self.case()
                def fail(where):
                    if where == point:
                        raise RuntimeError("controlled test fault")
                c.provider.hook = fail
                self.assertEqual(c.submit()["status"], "unknown")
                c.provider = Provider(c.path, clock=c.clock)
                observed = c.provider.query()
                self.assertEqual(observed["status"], outcome)
                self.assertEqual(observed["accepted"], accepted)
                self.assertEqual(len(observed["files"]), files)
                if accepted:
                    self.assertEqual(c.submit()["reason"], "already_accepted")
                    self.assertEqual(len(c.provider.observe()), files)
                    self.assertEqual(self.exported(c)[1]["outcome"], outcome)
                else:
                    self.assertEqual(c.submit()["status"], "effect_observed")

    def test_process_exit_releases_worker_and_recovers_actual_sqlite_boundary(self):
        for point, accepted, files in (("before_commit", False, 0), ("after_commit", True, 0), ("after_file_1", True, 1)):
            with self.subTest(point=point):
                folder = self.root / ("crash-" + point)
                child_keys = self.root / ("keys-" + point)
                result = subprocess.run([sys.executable, "-E", "-s", "-B", __file__, "--crash-worker", str(folder), str(child_keys), point],
                                        capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 77, result.stderr.decode())
                p = Provider(folder, clock=Clock())
                query = p.query()
                self.assertEqual(query["accepted"], accepted)
                self.assertEqual(len(query["files"]), files)
                self.assertEqual(query["status"], "unknown" if accepted else "not_accepted")
                output = folder / "recovery.json"
                p.export(output)
                verify(output.read_bytes(), safe_read(folder / "selection.json"), p.anchor_raw)

    def test_export_failure_retry_never_reexecutes(self):
        self.c.submit()
        before = self.c.provider.observe()
        def hook(point):
            if point == "before_export_publish":
                raise RuntimeError("controlled export fault")
        self.c.provider.hook = hook
        out = self.c.path / "export.json"
        with self.assertRaises(RuntimeError):
            self.c.provider.export(out)
        self.assertFalse(out.exists())
        self.assertEqual(list(self.c.path.glob(".export.json.*")), [])
        self.c.provider.hook = lambda point: None
        self.c.provider.export(out)
        self.assertTrue(verify(out.read_bytes(), self.c.selection_raw, self.c.provider.anchor_raw)["verified"])
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.c.provider.observe(), before)

    def test_reader_rejects_substituted_missing_or_overstated_evidence(self):
        self.c.submit()
        original = decode(self.exported()[0])
        variants = []
        x = copy.deepcopy(original); x["selection_sha256"] = "0" * 64; variants.append(x)
        x = copy.deepcopy(original); x["events"].pop(2); variants.append(x)
        x = copy.deepcopy(original); x["acceptance"]["body"]["input_sha256"] = "0" * 64; variants.append(x)
        x = copy.deepcopy(original); x["native"]["attempt_id"] = "other"; variants.append(x)
        x = copy.deepcopy(original); x["file_bytes"]["first.txt"] = b64(b"wrong"); variants.append(x)
        x = copy.deepcopy(original); x["worker_fenced"] = False; variants.append(x)
        x = copy.deepcopy(original); x["observation"]["status"] = "not_accepted"; variants.append(x)
        for x in variants:
            with self.subTest(index=variants.index(x)):
                with self.assertRaises(ValueError):
                    verify(encode(x), self.c.selection_raw, self.c.provider.anchor_raw)

    def test_reader_recomputes_refusal_instead_of_accepting_reason_enum(self):
        cases = (("proof_invalid", ("revoked", "authority_conflict", "already_accepted", "status_stale")),
                 ("revoked", ("proof_invalid",)))
        for actual, invented in cases:
            c = self.case()
            if actual == "revoked":
                c.provider.notify(c.signed_status(sequence=2, state="revoked"))
                result = c.submit()
            else:
                result = c.submit(input_sha256="wrong")
            self.assertEqual(result["reason"], actual)
            original = decode(self.exported(c)[0])
            for reason in invented:
                with self.subTest(actual=actual, invented=reason):
                    changed = copy.deepcopy(original)
                    next(x["body"] for x in changed["events"] if x["kind"] == "decision")["reason"] = reason
                    with self.assertRaisesRegex(ValueError, "decision reason"):
                        verify(encode(changed), c.selection_raw, c.provider.anchor_raw)

    def test_reader_binds_unavailable_and_output_observations(self):
        for unavailable in (True, False):
            with self.subTest(unavailable=unavailable):
                c = self.case()
                if unavailable:
                    (c.path / "authority-status.jws").unlink()
                else:
                    (c.path / "sandbox" / "first.txt").write_bytes(b"pre-existing")
                result = c.submit()
                self.assertEqual(result["reason"], "status_unavailable" if unavailable else "output_not_empty")
                raw, checked = self.exported(c)
                self.assertEqual(checked["outcome"], "not_accepted" if unavailable else "unknown")
                changed = decode(raw)
                decision = next(x["body"] for x in changed["events"] if x["kind"] == "decision")
                if unavailable:
                    decision["pull_outcome"] = "received"
                else:
                    decision["output_before_acceptance"] = []
                with self.assertRaises(ValueError):
                    verify(encode(changed), c.selection_raw, c.provider.anchor_raw)

    def test_reader_requires_separately_selected_store_anchor(self):
        other = self.case()
        self.assertEqual(other.selection_raw, self.c.selection_raw)
        self.assertNotEqual(other.provider.anchor_raw, self.c.provider.anchor_raw)
        self.assertEqual(other.submit()["status"], "effect_observed")
        raw, checked = self.exported(other)
        self.assertTrue(checked["verified"])
        with self.assertRaisesRegex(ValueError, "store substitution"):
            verify(raw, self.c.selection_raw, self.c.provider.anchor_raw)
        with self.assertRaises(ValueError):
            verify(raw, other.selection_raw, encode({}))
        altered = decode(other.provider.anchor_raw)
        altered["selection_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "anchor selection"):
            verify(raw, other.selection_raw, encode(altered))

    def test_partial_files_never_become_no_effect_or_success(self):
        def fail(point):
            if point == "after_file_1":
                raise RuntimeError("controlled partial write")
        self.c.provider.hook = fail
        self.c.submit()
        bundle = decode(self.exported()[0])
        self.assertEqual(bundle["observation"]["status"], "unknown")
        for invented in ("not_accepted", "effect_observed"):
            altered = copy.deepcopy(bundle); altered["observation"]["status"] = invented
            with self.assertRaises(ValueError):
                verify(encode(altered), self.c.selection_raw, self.c.provider.anchor_raw)

    def verifier_fault(self, target, fault, hits):
        real_run = subprocess.run
        def run(cmd, *args, **kwargs):
            if len(cmd) > 1 and cmd[1] == "dgst":
                header = decode(unurl64(Path(cmd[-1]).read_text().split(".")[0]))
                stage = "proof" if header["typ"] == PROOF_TYP else "status"
                if target in (stage, "both"):
                    hits.append(stage)
                    if fault == "timeout":
                        raise subprocess.TimeoutExpired("synthetic-openssl", 10)
                    if fault == "launch":
                        raise OSError("controlled process launch failure")
                    return subprocess.CompletedProcess(cmd, -9 if fault == "signal" else 1,
                                                       stdout=b"", stderr=b"controlled verifier failure")
            return real_run(cmd, *args, **kwargs)
        return patch.object(contract.subprocess, "run", side_effect=run)

    def test_verifier_outage_preserves_history_and_consumes_attempt(self):
        for stage in ("status", "proof", "both"):
            for fault in ("timeout", "launch", "signal", "error_exit"):
                with self.subTest(stage=stage, fault=fault):
                    c = self.case(); attempt, proof = c.challenge_and_proof(); hits = []
                    with self.verifier_fault(stage, fault, hits):
                        result = c.provider.submit(attempt["attempt_id"], proof)
                    self.assertEqual(set(hits), {"status", "proof"} if stage == "both" else {stage})
                    self.assertEqual(result["status"], "unknown")
                    self.assertEqual(result["next"], "query")
                    self.assertEqual(self.count(c), 0)
                    self.assertEqual(c.provider.query()["files"], [])
                    raw, checked = self.exported(c)
                    self.assertEqual(checked["outcome"], "not_accepted")
                    self.assertEqual(checked["verification_unavailable"], 1)
                    self.assertEqual(checked["decisions"], 0)
                    events = decode(raw)["events"]
                    observed = next(e["body"] for e in events if e["kind"] == "verification_unavailable")
                    self.assertEqual(set(observed["unavailable_checks"]), set(hits))
                    self.assertEqual(unb64(observed["proof"]), proof)
                    self.assertEqual(unb64(observed["pull"]), safe_read(c.path / "authority-status.jws"))
                    self.assertFalse(any(e["kind"] == "decision" for e in events))
                    self.assertEqual(c.provider.submit(attempt["attempt_id"], proof)["status"], "unknown")
                    self.assertEqual(self.count(c), 0)
                    self.assertEqual(c.submit()["status"], "effect_observed")
                    self.assertEqual(self.count(c), 1)
                    c.provider.export(c.path / "recovered.json")
                    self.assertEqual(verify(safe_read(c.path / "recovered.json"), c.selection_raw,
                                            c.provider.anchor_raw)["verification_unavailable"], 1)

    def test_proof_verifier_outage_retains_authenticated_terminal_status(self):
        for terminal in ("revoked", "authority_conflict"):
            with self.subTest(terminal=terminal):
                c = self.case()
                if terminal == "authority_conflict":
                    c.provider.notify(c.signed_status())
                    c.clock.value = BASE + 51
                    c.set_status(next_update_at=BASE + 50)  # Expired, authenticated same-version conflict.
                else:
                    c.set_status(sequence=2, state="revoked")
                attempt, proof = c.challenge_and_proof()
                with self.verifier_fault("proof", "timeout", []):
                    self.assertEqual(c.provider.submit(attempt["attempt_id"], proof)["status"], "unknown")
                c.provider = Provider(c.path, clock=c.clock)
                c.set_status(sequence=3, generated_at=c.clock(), next_update_at=c.clock()+60)
                self.assertEqual(c.submit()["reason"], terminal)
                self.assertEqual(self.count(c), 0)
                self.exported(c)

    def test_status_verifier_outage_does_not_clear_committed_revocation(self):
        self.c.provider.notify(self.c.signed_status(sequence=2, state="revoked"))
        attempt, proof = self.c.challenge_and_proof()
        with self.verifier_fault("status", "timeout", []):
            self.assertEqual(self.c.provider.submit(attempt["attempt_id"], proof)["status"], "unknown")
        self.assertEqual(self.c.submit()["reason"], "revoked")
        self.assertEqual(self.count(), 0)
        self.exported()

    def test_verifier_outage_commit_failures_release_writer_and_preserve_ticket(self):
        for fault in ("before_commit", "after_commit", "commit_busy"):
            with self.subTest(fault=fault):
                c = self.case(journal="DELETE"); c.provider.timeout = .03
                c.set_status(sequence=2, state="revoked")
                attempt, proof = c.challenge_and_proof(); blockers = []
                def hook(point):
                    if fault == "commit_busy" and point == "before_commit":
                        db = sqlite3.connect(c.path / "provider.sqlite3", isolation_level=None)
                        db.execute("BEGIN"); db.execute("SELECT count(*) FROM accepted").fetchone()
                        blockers.append(db)
                    elif point == fault:
                        raise RuntimeError("controlled interruption")
                c.provider.hook = hook
                try:
                    with self.verifier_fault("proof", "timeout", []):
                        self.assertEqual(c.provider.submit(attempt["attempt_id"], proof)["status"], "unknown")
                finally:
                    for db in blockers:
                        db.close()
                c.provider.hook = lambda point: None
                self.assertEqual(c.provider.submit(attempt["attempt_id"], proof)["status"], "unknown")
                self.assertEqual(self.count(c), 0)
                raw, checked = self.exported(c)
                self.assertEqual(checked["verification_unavailable"], int(fault == "after_commit"))
                self.assertEqual(checked["outcome"], "not_accepted")
                self.assertEqual(c.provider.notify(c.signed_status(sequence=2, state="revoked"))["status"], "stored")
                self.assertEqual(c.submit()["reason"], "revoked")

    def test_reader_verifier_outage_is_not_a_signed_refusal_or_acceptance(self):
        attempt, proof = self.c.challenge_and_proof()
        with self.verifier_fault("proof", "timeout", []):
            self.c.provider.submit(attempt["attempt_id"], proof)
        original = decode(self.exported()[0])
        variants = []
        for faults in ({}, {"proof": True}, {"proof": "invented"}, {"status": "timeout"}):
            x = copy.deepcopy(original)
            next(e["body"] for e in x["events"] if e["kind"] == "verification_unavailable")["unavailable_checks"] = faults
            variants.append(x)
        for reason in ("proof_invalid", "accepted"):
            x = copy.deepcopy(original)
            e = next(e for e in x["events"] if e["kind"] == "verification_unavailable")
            e["kind"] = "decision"; e["body"].pop("unavailable_checks")
            e["body"].update(reason=reason, output_before_acceptance=None)
            variants.append(x)
        x = copy.deepcopy(original)
        next(e["body"] for e in x["events"] if e["kind"] == "verification_unavailable")["proof_sha256"] = "0"*64
        variants.append(x)
        x = copy.deepcopy(original); x["observation"]["accepted"] = True; variants.append(x)
        for index, value in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify(encode(value), self.c.selection_raw, self.c.provider.anchor_raw)

    def test_missing_executable_and_temporary_io_failure_are_verifier_outages(self):
        for fault in ("executable_missing", "io_failed"):
            with self.subTest(fault=fault):
                c = self.case(); attempt, proof = c.challenge_and_proof()
                context = (patch.object(contract, "OPENSSL", None) if fault == "executable_missing" else
                           patch.object(contract.tempfile, "TemporaryDirectory", side_effect=OSError("controlled temp failure")))
                with context:
                    self.assertEqual(c.provider.submit(attempt["attempt_id"], proof)["status"], "unknown")
                raw, checked = self.exported(c)
                observed = next(e["body"] for e in decode(raw)["events"] if e["kind"] == "verification_unavailable")
                self.assertEqual(observed["unavailable_checks"], {"proof":fault, "status":fault})
                self.assertEqual(checked["outcome"], "not_accepted")

    def test_real_invalid_proof_is_still_a_recomputable_refusal(self):
        attempt, proof = self.c.challenge_and_proof()
        parts = proof.split(b"."); sig = bytearray(unurl64(parts[2].decode())); sig[12] ^= 1
        parts[2] = url64(sig).encode()
        self.assertEqual(self.c.provider.submit(attempt["attempt_id"], b".".join(parts))["reason"], "proof_invalid")
        checked = self.exported()[1]
        self.assertEqual(checked["decisions"], 1)
        self.assertEqual(checked["verification_unavailable"], 0)
        self.assertEqual(self.count(), 0)

    def test_expiry_during_crypto_is_checked_after_verification_and_lock(self):
        for journal in ("WAL", "DELETE"):
            for expiring in ("proof", "status", "admission"):
                with self.subTest(journal=journal, expiring=expiring):
                    kwargs = {"permit_expires_at": "2026-10-23T00:00:05.500000Z"} if expiring == "admission" else {}
                    c = self.case(journal=journal, **kwargs)
                    if expiring == "status":
                        c.set_status(next_update_at=BASE+5)
                    attempt, proof = c.challenge_and_proof()
                    c.clock.value = BASE+59 if expiring == "proof" else BASE+4
                    real_run = subprocess.run
                    def advance(cmd, *args, **kwargs):
                        r = real_run(cmd, *args, **kwargs)
                        if len(cmd) > 1 and cmd[1] == "dgst":
                            header = decode(unurl64(Path(cmd[-1]).read_text().split(".")[0]))
                            if header["typ"] == PROOF_TYP:
                                c.clock.value += 2
                        return r
                    with patch.object(contract.subprocess, "run", side_effect=advance):
                        result = c.provider.submit(attempt["attempt_id"], proof)
                    self.assertEqual(result["reason"], {"proof":"proof_invalid", "status":"status_stale",
                                                       "admission":"admission_expired"}[expiring])
                    self.assertEqual(self.count(c), 0)
                    raw, checked = self.exported(c)
                    decision = next(e["body"] for e in decode(raw)["events"] if e["kind"] == "decision")
                    self.assertEqual(decision["checked_at"], c.clock())
                    self.assertEqual(checked["outcome"], "not_accepted")

    def test_unattempted_export_has_bound_initialization_and_roundtrips(self):
        raw, checked = self.exported()
        self.assertEqual(checked["outcome"], "not_accepted")
        self.assertEqual(checked["decisions"], 0)
        changed = decode(raw)
        self.assertEqual(changed["events"][0]["kind"], "initialized")
        changed["events"][0]["body"]["store_id"] = "different-store"
        with self.assertRaisesRegex(ValueError, "initialization binding"):
            verify(encode(changed), self.c.selection_raw, self.c.provider.anchor_raw)

    def test_new_cli_database_failure_is_structured_and_readonly(self):
        for fault in ("missing", "corrupt", "replaced"):
            with self.subTest(fault=fault):
                c = self.case(); db = c.path / "provider.sqlite3"
                if fault == "missing":
                    db.unlink()
                elif fault == "corrupt":
                    db.write_bytes(b"corrupt database")
                else:
                    with closing(sqlite3.connect(db, isolation_level=None)) as conn:
                        conn.execute("UPDATE identity SET store_id='different'")
                before = db.read_bytes() if db.exists() else None
                for command in ("query", "export"):
                    dest = c.path / "should-not-exist.json"
                    args = [sys.executable, "-E", "-s", "-B", str(Path(__file__).with_name("run_demo.py")), command, str(c.path)]
                    if command == "export":
                        args += ["--out", str(dest)]
                    r = subprocess.run(args, capture_output=True, text=True, timeout=30)
                    self.assertEqual(r.returncode, 2, r.stderr)
                    result = json.loads(r.stdout)
                    self.assertEqual(result["status"], "unknown")
                    self.assertIs(result["retry_effect"], False)
                    self.assertIsNone(result["accepted"])
                    self.assertNotIn("Traceback", r.stderr)
                    self.assertFalse(dest.exists())
                    self.assertEqual(db.read_bytes() if db.exists() else None, before)

    def test_malformed_anchor_is_rejected_before_opening_database(self):
        original = decode(self.c.provider.anchor_raw)
        invalid = [None, [], {}, {k: v for k, v in original.items() if k != "db_ino"},
                   {**original, "unexpected": True}, {**original, "store_id": ""},
                   {**original, "store_id": 1}, {**original, "selection_sha256": "0" * 64},
                   {**original, "db_dev": True}, {**original, "db_dev": -1},
                   {**original, "db_ino": str(original["db_ino"])},
                   {**original, "db_ino": float(original["db_ino"])}]
        for anchor in invalid:
            with self.subTest(anchor=anchor):
                (self.c.path / "anchor.json").write_bytes(encode(anchor))
                with patch("provider.sqlite3.connect") as connection:
                    with self.assertRaises(ValueError):
                        Provider(self.c.path)
                    connection.assert_not_called()

    def test_new_cli_malformed_anchor_is_structured_and_preserves_store(self):
        for fault, state, missing_db in (("empty", "unattempted", False), ("null", "completed", False),
                                         ("missing-field", "partial", False), ("empty", "unattempted", True)):
            with self.subTest(fault=fault, state=state, missing_db=missing_db):
                c = self.case()
                if state == "partial":
                    def stop(point):
                        if point == "after_file_1":
                            raise RuntimeError("controlled partial effect")
                    c.provider.hook = stop
                if state != "unattempted":
                    result = c.submit()
                    self.assertEqual(result["status"], "unknown" if state == "partial" else "effect_observed")
                    self.assertEqual(self.count(c), 1)
                anchor = {} if fault == "empty" else None
                if fault == "missing-field":
                    anchor = {k: v for k, v in decode(c.provider.anchor_raw).items() if k != "db_ino"}
                (c.path / "anchor.json").write_bytes(encode(anchor))
                if missing_db:
                    (c.path / "provider.sqlite3").unlink()
                def snapshot():
                    return {str(p.relative_to(c.path)): p.read_bytes() for p in c.path.rglob("*") if p.is_file()}
                before = snapshot()
                for command in ("query", "export"):
                    dest = c.path / "should-not-exist.json"
                    args = [sys.executable, "-E", "-s", "-B", str(Path(__file__).with_name("run_demo.py")), command, str(c.path)]
                    if command == "export":
                        args += ["--out", str(dest)]
                    r = subprocess.run(args, capture_output=True, text=True, timeout=30)
                    self.assertEqual(r.returncode, 2, r.stderr)
                    self.assertEqual(json.loads(r.stdout), {
                        "status": "unknown", "error": "local_evidence_unavailable", "accepted": None,
                        "files": None, "native": None, "next": "inspect_local_store", "retry_effect": False})
                    self.assertNotIn("Traceback", r.stderr)
                    self.assertFalse(dest.exists())
                    self.assertEqual(snapshot(), before)

    def test_new_cli_query_and_export_do_not_repeat_effects(self):
        for partial in (False, True):
            with self.subTest(partial=partial):
                c = self.case()
                if partial:
                    def stop(point):
                        if point == "after_file_1":
                            raise RuntimeError("controlled partial effect")
                    c.provider.hook = stop
                c.submit(); before = c.provider.observe()
                base = [sys.executable, "-E", "-s", "-B", str(Path(__file__).with_name("run_demo.py"))]
                query = subprocess.run(base+["query", str(c.path)], capture_output=True, text=True, timeout=30)
                self.assertEqual(query.returncode, 2 if partial else 0, query.stderr)
                self.assertEqual(json.loads(query.stdout)["status"], "unknown" if partial else "effect_observed")
                dest = c.path / "cli-export.json"
                exported = subprocess.run(base+["export", str(c.path), "--out", str(dest)], capture_output=True, text=True, timeout=30)
                self.assertEqual(exported.returncode, 0, exported.stderr)
                reader = subprocess.run([sys.executable, "-E", "-s", "-B", str(Path(__file__).with_name("read_evidence.py")),
                                         str(dest), "--selection", str(c.path / "selection.json"),
                                         "--anchor", str(c.path / "anchor.json")], capture_output=True, text=True, timeout=30)
                self.assertEqual(reader.returncode, 0, reader.stderr)
                self.assertEqual(json.loads(reader.stdout)["outcome"], "unknown" if partial else "effect_observed")
                self.assertEqual(c.provider.observe(), before)
                self.assertEqual(self.count(c), 1)

    def test_malformed_authorization_selection_fails_before_database_connect(self):
        variants = []
        for field in contract.AUTH_FIELDS:
            for invalid in (None, 1, "!", "e31="):
                value = copy.deepcopy(self.c.selection)
                value["authorization"][field] = invalid
                variants.append((field, invalid, value))
        for invalid in (None, [], {}, {"evaluated_at": None}, {"evaluated_at": 1},
                        {"evaluated_at": "not-a-time"}):
            value = copy.deepcopy(self.c.selection)
            value["authorization"]["record"] = b64(encode(invalid))
            variants.append(("record", invalid, value))
        for field, invalid, selection in variants:
            with self.subTest(field=field, invalid=invalid):
                (self.c.path / "selection.json").write_bytes(encode(selection))
                with patch("provider.sqlite3.connect") as connection:
                    with self.assertRaises(ValueError):
                        Provider(self.c.path)
                    connection.assert_not_called()

    def test_new_cli_malformed_selection_is_structured_and_preserves_store(self):
        for partial in (False, True):
            c = self.case()
            if partial:
                def stop(point):
                    if point == "after_file_1":
                        raise RuntimeError("controlled partial effect")
                c.provider.hook = stop
            self.assertEqual(c.submit()["status"], "unknown" if partial else "effect_observed")
            for fault in ("original-null", "record-empty"):
                value = copy.deepcopy(c.selection)
                value["authorization"]["original" if fault == "original-null" else "record"] = (
                    None if fault == "original-null" else b64(b"{}"))
                (c.path / "selection.json").write_bytes(encode(value))
                def snapshot():
                    return {str(p.relative_to(c.path)): p.read_bytes() for p in c.path.rglob("*") if p.is_file()}
                before = snapshot()
                for command in ("query", "export"):
                    with self.subTest(partial=partial, fault=fault, command=command):
                        dest = c.path / "should-not-exist.json"
                        args = [sys.executable, "-E", "-s", "-B", str(Path(__file__).with_name("run_demo.py")), command, str(c.path)]
                        if command == "export":
                            args += ["--out", str(dest)]
                        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
                        self.assertEqual(r.returncode, 2, r.stderr)
                        self.assertEqual(json.loads(r.stdout), {
                            "status": "unknown", "error": "local_evidence_unavailable", "accepted": None,
                            "files": None, "native": None, "next": "inspect_local_store", "retry_effect": False})
                        self.assertNotIn("Traceback", r.stderr)
                        self.assertFalse(dest.exists())
                        self.assertEqual(snapshot(), before)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--crash-worker":
        path, keys_path, point = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
        keys = Keys(keys_path)
        def crash(where):
            if where == point:
                os._exit(77)
        case = Case(path, keys, hook=crash)
        case.submit()
        sys.exit(78)
    unittest.main(verbosity=2)
