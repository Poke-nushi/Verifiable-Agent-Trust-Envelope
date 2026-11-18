"""Deterministic contract/fault/race tests using synthetic keys and isolated stores."""
from __future__ import annotations

import copy
import multiprocessing as mp
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from dependencies import crypto, demo, fixture_crypto
from fixture import Case, Keys, Clock, BASE
from handoff_contract import (PROFILE, PROOF_TYP, STATUS_TYP, OBS_TYP, encode, decode, sha, b64, unb64, iso,
                              linkage, binding, MAX_COUNTER, MAX_EVENTS, MAX_JOURNAL_BYTES,
                              RESERVED_EVENT_BYTES, reserved_event_count)
from handoff_provider import Provider, initialize
from handoff_reader import assess
from handoff_model import apply, replay


def child_action(path, at, action, data, target_hook, pipe, crash=False):
    """Fresh interpreter/DB connection; rendezvous at an exact boundary, never sleep ordering."""
    owner = object()

    def hook(point):
        if point == "effect_entry":
            with open(Path(path) / "effect-entries.test", "ab", buffering=0) as f:
                f.write(b"1\n")
        if point == target_hook:
            pipe.send({"at": point})
            if crash:
                os._exit(71)
            if not pipe.poll(30):
                raise RuntimeError("test barrier timeout")
            pipe.recv()

    try:
        p = Provider(path, clock=Clock(at), hook=hook, owner_capability=owner, timeout=0.15)
        if action == "submit":
            result = p.submit("operation-one", data[0], data[1])
        elif action == "handoff":
            result = p.handoff(owner, data)
        elif action == "ticket":
            result = p.ticket("operation-one", "runtime-a")
        else:
            raise ValueError("invalid test action")
        pipe.send({"result": result})
    except Exception as e:
        pipe.send({"error": type(e).__name__ + ":" + str(e)})
    finally:
        pipe.close()


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keydir = tempfile.TemporaryDirectory(prefix="vate-handoff-synthetic-keys-")
        cls.keys = Keys(Path(cls.keydir.name))

    @classmethod
    def tearDownClass(cls):
        cls.keydir.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vate-handoff-case-")
        self.root = Path(self.tmp.name)
        self.cases = []
        self.children = []

    def tearDown(self):
        for process, pipe in self.children:
            if process.is_alive():
                process.terminate()
            process.join(5)
            pipe.close()
        evidence = os.environ.get("HANDOFF_EVIDENCE_DIR")
        if evidence:
            base = Path(evidence) / self._testMethodName
            base.mkdir(parents=True, exist_ok=True)
            for i, case in enumerate(self.cases):
                out = base / str(i)
                out.mkdir(exist_ok=True)
                (out / "context.json").write_bytes(case.context_raw)
                (out / "operation.json").write_bytes(encode(case.operation))
                try:
                    bundle = case.provider.export("operation-one")
                    result = assess(case.context_raw, encode(case.operation), bundle)
                    (out / "bundle.json").write_bytes(bundle)
                    (out / "assessment.json").write_bytes(encode(result))
                except Exception as e:
                    (out / "unavailable.json").write_bytes(encode({"error": type(e).__name__, "reason": str(e)}))
        self.tmp.cleanup()

    def case(self, **kwargs):
        c = Case(self.root / ("case-" + str(len(self.cases))), self.keys, **kwargs)
        self.cases.append(c)
        return c

    def state(self, case):
        with case.provider.connection() as c:
            return case.provider.load(c)[0]

    def op(self, case):
        return self.state(case)["operations"]["operation-one"]

    def query(self, case):
        return case.provider.query("operation-one")

    def read(self, case):
        return assess(case.context_raw, encode(case.operation), case.provider.export("operation-one"))

    def crash_hook(self, target):
        def hook(point):
            if point == target:
                raise RuntimeError("injected response/commit uncertainty")
        return hook

    def child(self, case, action, data, point, *, crash=False):
        parent, child = mp.get_context("spawn").Pipe()
        proc = mp.get_context("spawn").Process(target=child_action,
            args=(str(case.path), case.clock(), action, data, point, child, crash))
        proc.start(); child.close()
        self.children.append((proc, parent))
        self.assertTrue(parent.poll(30), "child must reach deterministic barrier")
        first = parent.recv()
        self.assertEqual(first, {"at": point})
        if crash:
            proc.join(10)
            self.assertEqual(proc.exitcode, 71)
        return proc, parent

    def finish_child(self, proc, pipe):
        pipe.send("continue")
        self.assertTrue(pipe.poll(30), "child must finish")
        result = pipe.recv()
        proc.join(10)
        self.assertEqual(proc.exitcode, 0)
        self.assertIn("result", result, result)
        return result["result"]

    def test_H01_normal_A(self):
        c = self.case()
        self.assertEqual(c.submit()["status"], "completed")
        r = self.read(c)
        self.assertEqual(r["acceptance_count"], 1)
        self.assertEqual(r["accepted"]["runtime"], "runtime-a")
        self.assertEqual(r["linkage"]["outcome"], "success")
        self.assertFalse(r["is_execution_ticket"])

    def test_H02_preaccept_unknown_handoff_B_positive(self):
        c = self.case(hook=self.crash_hook("accept_before_commit"))
        t, proof = c.attempt()
        self.assertEqual(c.provider.submit("operation-one", t["attempt_id"], proof)["status"], "unknown")
        c.reopen(); c.unknown(t)
        h = c.handoff()
        self.assertEqual(h["result"]["effect_state"], "confirmed_unexecuted")
        self.assertEqual(c.submit("runtime-b")["status"], "completed")
        r = self.read(c)
        self.assertEqual(r["accepted"]["runtime"], "runtime-b")
        self.assertEqual(r["linkage"]["outcome"], "success")
        self.assertEqual([o["attempt_id"] for o in r["unknown"]], [t["attempt_id"]])

    def test_H03_accepted_zero_outputs_hold(self):
        c = self.case()
        t, p = c.attempt()
        self.child(c, "submit", (t["attempt_id"], p), "accepted_before_effect", crash=True)
        c.reopen(); c.unknown(t)
        self.assertEqual(c.handoff()["result"]["effect_state"], "unresolved")
        self.assertEqual(self.query(c)["inventory"], {})
        with self.assertRaisesRegex(ValueError, "no new ticket"):
            c.attempt("runtime-b")
        self.assertEqual(self.read(c)["acceptance_count"], 1)

    def test_H04_partial_hold(self):
        c = self.case()
        t, p = c.attempt()
        self.child(c, "submit", (t["attempt_id"], p), "after_file_1", crash=True)
        c.reopen(); c.unknown(t)
        self.assertEqual(c.handoff()["result"]["effect_state"], "unresolved")
        self.assertEqual(len(self.query(c)["inventory"]), 1)
        self.assertEqual(self.read(c)["linkage"]["outcome"], "unassessable")

    def test_H05_success_response_loss_preserves_unknown(self):
        c = self.case(hook=self.crash_hook("native_after_commit"))
        t, p = c.attempt()
        self.assertEqual(c.provider.submit("operation-one", t["attempt_id"], p)["status"], "unknown")
        c.reopen(); c.unknown(t)
        c.provider.observe(c.owner, "operation-one")
        self.assertEqual(c.handoff()["result"]["effect_state"], "completed")
        r = self.read(c)
        self.assertEqual(r["accepted"]["runtime"], "runtime-a")
        self.assertEqual(len(r["unknown"]), 1)
        self.assertEqual(len(r["later_observations"]), 1)
        self.assertEqual(r["linkage"]["outcome"], "success")

    def test_H06_no_new_allow_over_uncertainty(self):
        c = self.case()
        t, _ = c.attempt(); c.unknown(t)
        self.assertEqual(c.submit()["reason"], "unresolved_current_attempt")
        # No acceptance is not enough when unexplained files exist.
        (c.provider.resource_path(c.operation) / "first.txt").write_text("unexplained")
        self.assertEqual(c.handoff()["result"]["effect_state"], "unresolved")
        self.assertEqual(c.submit("runtime-b")["reason"], "effect_evidence_unresolved")
        self.assertIsNone(self.query(c)["accepted"])

    def test_H07_delayed_A_fenced_B_positive(self):
        c = self.case(); t, p = c.attempt()
        c.handoff()
        self.assertEqual(c.provider.submit("operation-one", t["attempt_id"], p)["reason"], "old_generation")
        self.assertEqual(c.submit("runtime-b")["status"], "completed")

    def test_H08_live_old_worker_busy_not_unexecuted(self):
        c = self.case(); t, p = c.attempt(); request = c.request()
        proc, pipe = self.child(c, "submit", (t["attempt_id"], p), "submit_locked")
        self.assertEqual(c.provider.handoff(c.owner, request)["status"], "busy")
        self.assertIsNone(self.op(c)["accepted"])
        self.assertEqual(self.op(c)["generation"], 1)
        self.assertEqual(self.finish_child(proc, pipe)["status"], "completed")

    def test_H09_submit_wins_handoff(self):
        c = self.case(); t, p = c.attempt()
        proc, pipe = self.child(c, "submit", (t["attempt_id"], p), "accepted_before_effect")
        self.assertEqual(c.handoff()["status"], "busy")
        self.assertEqual(self.finish_child(proc, pipe)["status"], "completed")
        self.assertEqual(c.handoff()["result"]["effect_state"], "completed")
        self.assertEqual(self.read(c)["accepted"]["runtime"], "runtime-a")

    def test_H10_handoff_wins_submit(self):
        c = self.case(); t, p = c.attempt()
        proc, pipe = self.child(c, "handoff", c.request(), "handoff_commit_return")
        self.assertEqual(c.provider.submit("operation-one", t["attempt_id"], p)["status"], "busy")
        self.assertEqual(self.finish_child(proc, pipe)["status"], "committed")
        self.assertEqual(c.provider.submit("operation-one", t["attempt_id"], p)["reason"], "old_generation")
        self.assertEqual(c.submit("runtime-b")["status"], "completed")

    def test_H11_new_ids_do_not_reset(self):
        c = self.case(); t, _ = c.attempt(); c.unknown(t)
        for _ in range(2):
            self.assertEqual(c.submit()["reason"], "unresolved_current_attempt")
        c.handoff()
        old, _ = c.attempt("runtime-b")
        c.handoff(target="runtime-a")
        altered = {**old, "generation": 3, "runtime": "runtime-a", "nonce": "nonce-new"}
        signed = c.keys.sign(altered, "runtime-a", PROOF_TYP)
        self.assertNotEqual(c.provider.submit("operation-one", old["attempt_id"], signed)["status"], "completed")
        self.assertIsNone(self.query(c)["accepted"])

    def test_H12_each_binding_and_cross_admission(self):
        c = self.case(); t, p = c.attempt()
        fields = ("runtime", "runtime_spki_sha256", "provider", "store", "namespace", "operation_id", "input_sha256",
                  "admission_sha256", "authorization_sha256", "generation", "attempt_id", "nonce", "context_sha256",
                  "issued_at", "expires_at")
        for field in fields:
            with self.subTest(field=field):
                value = t[field] + 1 if type(t[field]) is int else t[field] + "-other"
                raw = c.keys.sign({**t, field: value}, "runtime-a", PROOF_TYP)
                result = c.provider.submit("operation-one", t["attempt_id"], raw)
                self.assertEqual(result["reason"], "proof binding mismatch")
                self.assertIsNone(self.query(c)["accepted"])
        self.assertEqual(c.provider.submit("operation-one", t["attempt_id"], p)["status"], "completed")
        op = self.op(c)
        auth_b = c.authorization("runtime-b")
        wrong_hash = sha(encode(auth_b))
        op["authorizations"][wrong_hash] = auth_b
        op["tickets"][t["attempt_id"]]["authorization_sha256"] = wrong_hash
        self.assertIn("POST_EXEC_RUNTIME_MISMATCH", linkage(op)["reason_codes"])

    def test_H13_runtime_not_owner(self):
        c = self.case()
        for cap in (None, object(), c.keys.sign({"admin": True}, "runtime-a", PROOF_TYP)):
            with self.subTest(cap=type(cap).__name__):
                with self.assertRaisesRegex(ValueError, "owner control"):
                    c.provider.handoff(cap, c.request())
                with self.assertRaisesRegex(ValueError, "owner control"):
                    c.provider.register(cap, c.operation, c.auth_a)
        self.assertEqual(self.op(c)["generation"], 1)

    def test_H14_new_intent_fresh_resource_positive(self):
        c = self.case(); self.assertEqual(c.submit()["status"], "completed")
        op = c.provider.prepare_operation(c.owner, "operation-two", c.operation["target"]["files"])
        a = c.authorization("runtime-a", operation=op)
        c.provider.register(c.owner, op, a)
        t, p = c.attempt(operation_id="operation-two")
        self.assertEqual(c.provider.submit("operation-two", t["attempt_id"], p)["status"], "completed")
        duplicate = copy.deepcopy(c.operation); duplicate["operation_key"] = "operation-three"
        auth = c.authorization("runtime-a", operation=duplicate)
        with self.assertRaisesRegex(ValueError, "resource already assigned"):
            c.provider.register(c.owner, duplicate, auth)

    def test_H15_omitted_history_not_canonical(self):
        c = self.case(); t, _ = c.attempt(); c.unknown(t)
        h = c.handoff(read_attempts=[])
        self.assertEqual(h["result"]["retained_attempts"], [t["attempt_id"]])
        r = self.read(c)
        self.assertEqual(len(r["unknown"]), 1)
        bundle = decode(c.provider.export("operation-one"))
        bundle["records"].pop(1)
        with self.assertRaisesRegex(ValueError, "chain"):
            assess(c.context_raw, encode(c.operation), encode(bundle))

    def test_H16_stale_and_concurrent_handoffs(self):
        c = self.case(); req = c.request()
        other = decode(req); other["request_id"] = "handoff-other"
        proc, pipe = self.child(c, "handoff", req, "handoff_before_commit")
        self.assertEqual(c.provider.handoff(c.owner, encode(other))["status"], "busy")
        self.finish_child(proc, pipe)
        with self.assertRaisesRegex(ValueError, "old assignment|stale"):
            c.provider.handoff(c.owner, encode(other))
        self.assertEqual(self.op(c)["generation"], 2)

    def test_H17_dedup_before_CAS_after_later_updates(self):
        c = self.case(); req = c.request()
        first = c.provider.handoff(c.owner, req)
        self.assertEqual(c.submit("runtime-b")["status"], "completed")
        c.handoff(target="runtime-a")
        before = self.state(c)
        self.assertEqual(c.provider.handoff(c.owner, req), first)
        self.assertEqual(self.state(c), before)

    def test_H18_same_handoff_ID_changed_bytes(self):
        c = self.case(); req = c.request(); c.provider.handoff(c.owner, req)
        changed = decode(req); changed["expected_revision"] += 1
        before = self.state(c)
        with self.assertRaisesRegex(ValueError, "different bytes"):
            c.provider.handoff(c.owner, encode(changed))
        self.assertEqual(self.state(c), before)

    def test_H19_handoff_crash_and_commit_uncertainty(self):
        for point, committed in (("handoff_before_commit", False), ("handoff_commit_return", True)):
            for real_crash in (False, True):
                with self.subTest(point=point, process_crash=real_crash):
                    c = self.case(); req = c.request()
                    if real_crash:
                        self.child(c, "handoff", req, point, crash=True)
                    else:
                        c.provider.hook = self.crash_hook(point)
                        result = c.provider.handoff(c.owner, req)
                        self.assertEqual(result["status"], "committed" if committed else "not_committed")
                    c.reopen()
                    self.assertEqual(self.op(c)["generation"], 2 if committed else 1)
                    read = c.provider.handoff_result(decode(req)["request_id"], req)
                    self.assertEqual(read["status"], "committed" if committed else "not_committed")

    def test_H20_missing_replaced_corrupt_and_fresh_WAL(self):
        for mode in ("missing", "replaced", "corrupt", "anchor", "context", "journal_row"):
            with self.subTest(mode=mode):
                c = self.case(journal="DELETE"); db = c.path / "provider.sqlite3"
                if mode == "missing":
                    db.unlink()
                elif mode == "replaced":
                    other = c.path / "replacement"; shutil.copyfile(db, other); other.replace(db)
                elif mode == "corrupt":
                    db.write_bytes(b"invalid sqlite")
                elif mode in ("anchor", "context"):
                    (c.path / (mode + ".json")).write_bytes(b"{}")
                else:
                    x = sqlite3.connect(db); x.execute("DELETE FROM events"); x.commit(); x.close()
                with self.assertRaises((ValueError, OSError, sqlite3.Error)):
                    self.query(c)
        c = self.case()
        old = sqlite3.connect(c.path / "provider.sqlite3", isolation_level=None)
        old.execute("BEGIN"); old.execute("SELECT count(*) FROM events").fetchone()
        old_count = old.execute("SELECT count(*) FROM events").fetchone()[0]
        c.handoff()
        self.assertEqual(old.execute("SELECT count(*) FROM events").fetchone()[0], old_count)
        self.assertEqual(self.query(c)["generation"], 2)
        old.close()

    def test_H21_B_current_authorization_and_status(self):
        for mode, reason in (("expired", "admission_expired"), ("revoked", "status_revoked"),
                             ("conflict", "status_conflict"), ("unavailable", None)):
            with self.subTest(mode=mode):
                c = self.case()
                auth = c.authorization("runtime-b", expires=iso(BASE + 1))
                c.handoff(authorization=auth)
                if mode == "expired":
                    c.clock.value += 1
                elif mode == "revoked":
                    c.set_status("runtime-b", state="revoked")
                elif mode == "conflict":
                    c.provider.notify(c.signed_status("runtime-b"))
                    c.provider.notify(c.signed_status("runtime-b", state="suspended"))
                else:
                    (c.path / "authority/runtime-b.jws").unlink()
                r = c.submit("runtime-b")
                if reason:
                    self.assertEqual(r["reason"], reason)
                else:
                    self.assertEqual(r["status"], "unknown")
                self.assertIsNone(self.query(c)["accepted"])

    def test_H22_expiry_after_crypto_and_lock_delay(self):
        for mode in ("authorization", "proof_status", "db_lock"):
            with self.subTest(mode=mode):
                c = self.case(); auth = c.authorization("runtime-b", expires=iso(BASE + 2))
                c.handoff(authorization=auth)
                t, p = c.attempt("runtime-b")
                if mode != "db_lock":
                    def hook(point):
                        if point == "submit_after_crypto":
                            c.clock.value = BASE + (2 if mode == "authorization" else 60)
                    c.provider.hook = hook
                    self.assertIn(c.provider.submit("operation-one", t["attempt_id"], p)["reason"],
                                  ("admission_expired", "ticket_expired"))
                else:
                    # An unresolved other writer must yield unknown, never an empty-store assumption.
                    x = sqlite3.connect(c.path / "provider.sqlite3", isolation_level=None)
                    x.execute("BEGIN IMMEDIATE")
                    try:
                        self.assertEqual(c.provider.submit("operation-one", t["attempt_id"], p)["status"], "unknown")
                    finally:
                        x.rollback(); x.close()
                self.assertIsNone(self.query(c)["accepted"])

    def test_H23_read_export_failure_and_false_success(self):
        c = self.case(); t, _ = c.attempt(); c.unknown(t)
        before = self.state(c)
        for _ in range(2):
            self.query(c); self.read(c)
        destination = c.path / "already-exists"; destination.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            c.provider.export("operation-one", destination)
        self.assertEqual(destination.read_bytes(), b"keep")
        self.assertEqual(self.state(c), before)
        bundle = decode(c.provider.export("operation-one")); bundle["success"] = True
        with self.assertRaisesRegex(ValueError, "unexpected object"):
            assess(c.context_raw, encode(c.operation), encode(bundle))

    def test_H24_capacity_never_resets(self):
        c = self.case(); t, _ = c.attempt(); c.unknown(t)
        before = self.state(c)
        with patch("handoff_provider.MAX_EVENTS", 3):
            with self.assertRaisesRegex(ValueError, "capacity"):
                c.handoff()
        with patch("handoff_provider.MAX_JOURNAL_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "capacity"):
                c.handoff()
        self.assertEqual(self.state(c), before)
        for which in ("revision", "generation"):
            synthetic = copy.deepcopy(before)
            op = synthetic["operations"]["operation-one"]
            op[which] = MAX_COUNTER
            req = decode(c.request()); req["expected_" + which] = MAX_COUNTER
            event = {"index": 4, "previous": "0" * 64, "context_sha256": c.provider.context.digest,
                     "at": BASE, "kind": "handoff", "operation_id": "operation-one", "body": {
                         "request_raw": b64(encode(req)), "inventory": {}, "retained_attempts": sorted(op["tickets"]),
                         "effect_state": "confirmed_unexecuted", "worker_excluded": True}}
            with self.assertRaisesRegex(ValueError, "capacity"):
                apply(c.provider.context, synthetic, event)

    def test_H25_expiry_or_revocation_after_acceptance(self):
        for mode in ("expired", "revoked"):
            with self.subTest(mode=mode):
                c = self.case()
                def hook(point):
                    if point == "accepted_before_effect":
                        if mode == "expired":
                            c.clock.value = BASE + 601
                        else:
                            c.provider.notify(c.signed_status("runtime-a", state="revoked", sequence=2))
                c.provider.hook = hook
                self.assertEqual(c.submit()["status"], "completed")
                c.provider.hook = lambda point: None
                self.assertEqual(c.handoff()["result"]["effect_state"], "completed")
                r = self.read(c)
                self.assertEqual(r["effect_state"], "completed")
                self.assertEqual(r["linkage"]["outcome"], "failed" if mode == "expired" else "success")
                if mode == "expired":
                    self.assertIn("POST_EXEC_ADMISSION_EXPIRED", r["linkage"]["reason_codes"])
                self.assertEqual(r["acceptance_count"], 1)

    def test_H26_actual_times_not_observation_times(self):
        c = self.case(); c.submit(); c.clock.value += 700
        self.assertEqual(self.read(c)["linkage"]["outcome"], "success")
        op = self.op(c)
        op["native"]["finished_at"] = None
        self.assertEqual(linkage(op)["outcome"], "unassessable")
        self.assertIsNotNone(op["accepted"])
        # The actual-time-missing native is retained as an explicitly unassessable
        # observation; replay must not silently fill it from acceptance or export time.
        c = self.case(hook=self.crash_hook("after_file_2"))
        c.submit(); c.reopen()
        op = self.op(c); ticket = op["tickets"][op["accepted"]["attempt_id"]]
        with c.provider.connection(write=True) as db:
            state, records = c.provider.load(db)
            native = {k: ticket[k] for k in ("attempt_id", "runtime", "admission_sha256", "input_sha256")}
            native.update(started_at=None, finished_at=None, outputs=c.provider.inventory(c.operation))
            c.provider.append(db, state, records, "native", "operation-one", native, c.clock())
            db.commit()
        r = self.read(c)
        self.assertEqual(r["effect_state"], "completed")
        self.assertEqual(r["linkage"]["outcome"], "unassessable")
        self.assertIsNone(r["post_execution_receipt"])

    def test_H27_subject_isolation_same_sequence(self):
        c = self.case(); c.provider.notify(c.signed_status("runtime-a", state="revoked"))
        c.handoff()
        self.assertEqual(c.submit("runtime-b")["status"], "completed")
        r = self.read(c)
        self.assertTrue(r["subjects"]["runtime-a"]["revoked"])
        self.assertFalse(r["subjects"]["runtime-b"]["revoked"])
        self.assertFalse(r["subjects"]["runtime-b"]["conflict"])

    def test_H28_conflict_persists_and_status_commit_order(self):
        c = self.case()
        c.provider.notify(c.signed_status("runtime-b"))
        c.provider.notify(c.signed_status("runtime-b", state="suspended"))
        c.handoff(); self.assertEqual(c.submit("runtime-b")["reason"], "status_conflict")
        c.handoff(target="runtime-a"); c.handoff(target="runtime-b")
        c.reopen(); self.assertEqual(c.submit("runtime-b")["reason"], "status_conflict")
        for status_first in (True, False):
            with self.subTest(status_first=status_first):
                c = self.case(); c.handoff(); t, p = c.attempt("runtime-b")
                point = "submit_after_crypto" if status_first else "accepted_before_effect"
                proc, pipe = self.child(c, "submit", (t["attempt_id"], p), point)
                c.provider.notify(c.signed_status("runtime-b", state="revoked", sequence=2))
                r = self.finish_child(proc, pipe)
                self.assertEqual(r["status"], "denied" if status_first else "completed")
                self.assertEqual(self.read(c)["acceptance_count"], 0 if status_first else 1)

    def test_H29_ticket_commit_and_late_unknown(self):
        for point, persisted in (("ticket_before_commit", False), ("ticket_after_commit", True)):
            c = self.case(); self.child(c, "ticket", None, point, crash=True); c.reopen()
            self.assertEqual(len(self.op(c)["tickets"]), int(persisted))
        c = self.case(); t, _ = c.attempt(); c.handoff(); c.submit("runtime-b")
        before = self.query(c)
        c.unknown(t, observed_at=BASE)
        after = self.query(c)
        self.assertEqual(after["accepted"], before["accepted"])
        self.assertEqual(after["generation"], 2)
        self.assertEqual(after["effect_state"], "completed")
        self.assertEqual(len(after["unknown"]), 1)

    def test_H30_acceptance_commit_itself_uncertain(self):
        for point, persisted in (("accept_before_commit", False), ("accept_commit_return", True)):
            for actual_crash in (False, True):
                with self.subTest(point=point, process_crash=actual_crash):
                    c = self.case(); t, p = c.attempt()
                    if actual_crash:
                        self.child(c, "submit", (t["attempt_id"], p), point, crash=True)
                    else:
                        c.provider.hook = self.crash_hook(point)
                        result = c.provider.submit("operation-one", t["attempt_id"], p)
                        self.assertEqual(result["status"], "unknown")
                        self.assertEqual(result["saved"]["accepted"] is not None, persisted)
                    c.reopen(); c.unknown(t)
                    self.assertEqual(self.query(c)["inventory"], {})
                    self.assertEqual(self.op(c)["accepted"] is not None, persisted)
                    self.assertEqual(c.handoff()["result"]["effect_state"], "unresolved" if persisted else "confirmed_unexecuted")
                    if persisted:
                        self.assertEqual(c.provider.submit("operation-one", t["attempt_id"], p)["reason"], "already_accepted")
                    else:
                        self.assertEqual(c.submit("runtime-b")["status"], "completed")
        # An active acceptance writer still holds the operation lock: no absent-row inference.
        c = self.case(); t, p = c.attempt()
        proc, pipe = self.child(c, "submit", (t["attempt_id"], p), "accept_before_commit")
        self.assertEqual(c.handoff()["status"], "busy")
        self.assertIsNone(self.op(c)["accepted"])
        self.finish_child(proc, pipe)

    def test_H31_same_generation_concurrent_submits(self):
        for same_ticket in (True, False):
            with self.subTest(same_ticket=same_ticket):
                c = self.case(); t1, p1 = c.attempt()
                t2, p2 = (t1, p1) if same_ticket else c.attempt()
                proc, pipe = self.child(c, "submit", (t1["attempt_id"], p1), "accepted_before_effect")
                self.assertEqual(c.provider.submit("operation-one", t2["attempt_id"], p2)["status"], "busy")
                self.assertEqual(self.finish_child(proc, pipe)["status"], "completed")
                before = self.op(c)["native"]
                self.assertEqual(c.provider.submit("operation-one", t2["attempt_id"], p2)["reason"], "already_accepted")
                self.assertEqual((c.path / "effect-entries.test").read_bytes(), b"1\n")
                self.assertEqual(self.op(c)["native"], before)
                self.assertEqual(self.read(c)["acceptance_count"], 1)

    def test_precision_clock_rollback_and_signature_identity(self):
        c = self.case()
        one = c.signed_status("runtime-a")
        two = c.signed_status("runtime-a")  # ECDSA bytes may differ; signed input is the identity.
        c.provider.notify(one); c.provider.notify(two)
        self.assertFalse(self.state(c)["subjects"]["runtime-a"]["conflict"])
        c.clock.value -= 1
        with self.assertRaisesRegex(ValueError, "clock_uncertain"):
            c.attempt()
        c.clock.value = BASE + 1
        c.reopen()
        with self.assertRaisesRegex(ValueError, "clock_uncertain"):
            c.attempt()
        self.assertTrue(self.read(c)["clock_uncertain"])
        c = self.case()
        auth = c.authorization("runtime-b", expires=iso(BASE + 1))
        c.handoff(authorization=auth)
        c.clock.value = BASE + 1
        self.assertEqual(c.submit("runtime-b")["reason"], "admission_expired")
        c = self.case()
        auth = c.authorization("runtime-b", expires=iso(BASE + 1).replace("Z", ".000001Z"))
        c.handoff(authorization=auth)
        c.clock.value = BASE + 1
        self.assertEqual(c.submit("runtime-b")["status"], "completed")
        self.assertEqual(self.read(c)["linkage"]["outcome"], "success")
        # Acceptance uses < expires; existing core linkage permits finish == expires.
        c = self.case()
        c.handoff(authorization=c.authorization("runtime-b", expires=iso(BASE + 1)))
        def finish_at_boundary(point):
            if point == "accepted_before_effect":
                c.clock.value = BASE + 1
        c.provider.hook = finish_at_boundary
        self.assertEqual(c.submit("runtime-b")["status"], "completed")
        self.assertEqual(self.read(c)["linkage"]["outcome"], "success")

    def test_status_freshness_after_crypto_and_old_sequence_conflict(self):
        c = self.case(); c.handoff(); c.clock.value = BASE + 30
        t, p = c.attempt("runtime-b")
        def age_status(point):
            if point == "submit_after_crypto":
                c.clock.value = BASE + 60
        c.provider.hook = age_status
        self.assertEqual(c.provider.submit("operation-one", t["attempt_id"], p)["reason"], "status_expired")
        c = self.case()
        c.provider.notify(c.signed_status("runtime-b"))
        c.provider.notify(c.signed_status("runtime-b", sequence=2))
        c.provider.notify(c.signed_status("runtime-b", sequence=1, state="suspended"))
        c.handoff()
        self.assertEqual(c.submit("runtime-b")["reason"], "status_conflict")
        self.assertTrue(self.read(c)["subjects"]["runtime-b"]["conflict"])

    def test_review_R1_decision_pull_original_must_match(self):
        c = self.case(); c.submit()
        bundle = decode(c.provider.export("operation-one"))
        previous = "0" * 64
        for rec in bundle["records"]:
            event = decode(unb64(rec["raw"]))
            if event["kind"] == "status":
                # A validly signed but DIFFERENT original with the same subject/seq.
                raw = c.signed_status("runtime-a", state="suspended")
                v = c.provider.context.status(raw, BASE)
                event["body"] = {"raw": b64(raw), "raw_sha256": sha(raw),
                                 "signing_input_sha256": v.signing_input_sha256}
            event["previous"] = previous
            raw = encode(event); rec.update(raw=b64(raw), sha256=sha(raw)); previous = rec["sha256"]
        bundle["head"] = previous
        with self.assertRaisesRegex(ValueError, "pull original mismatch"):
            assess(c.context_raw, encode(c.operation), encode(bundle))

    def test_review_R2_bool_is_not_generation_integer(self):
        c = self.case(); t, p = c.attempt()
        raw = c.keys.sign({**t, "generation": True}, "runtime-a", PROOF_TYP)
        r = c.provider.submit("operation-one", t["attempt_id"], raw)
        self.assertEqual(r["reason"], "proof binding mismatch")
        self.assertIsNone(self.query(c)["accepted"])
        self.assertEqual(self.query(c)["inventory"], {})
        self.assertEqual(c.provider.submit("operation-one", t["attempt_id"], p)["status"], "completed")
        # Replay must enforce the same comparison, even with a newly valid hash chain.
        bundle = decode(c.provider.export("operation-one")); previous = "0" * 64
        for rec in bundle["records"]:
            event = decode(unb64(rec["raw"]))
            if event["kind"] == "accepted":
                event["body"]["proof"] = b64(raw)
            event["previous"] = previous
            original = encode(event); rec.update(raw=b64(original), sha256=sha(original)); previous = rec["sha256"]
        bundle["head"] = previous
        with self.assertRaisesRegex(ValueError, "proof binding mismatch"):
            assess(c.context_raw, encode(c.operation), encode(bundle))

    def test_review_R3_post_accept_clock_fault_survives_restart(self):
        for point, outputs in (("accepted_before_effect", 0), ("after_file_1", 2)):
            with self.subTest(point=point):
                c = self.case()
                def hook(where):
                    if where == point:
                        c.clock.value = BASE - 1
                c.provider.hook = hook
                self.assertEqual(c.submit()["status"], "unknown")
                c.clock.value = BASE; c.reopen()
                self.assertTrue(self.state(c)["clock_bad"])
                self.assertIsNotNone(self.query(c)["accepted"])
                self.assertEqual(len(self.query(c)["inventory"]), outputs)
                self.assertIsNone(self.op(c)["native"])
                op = c.provider.prepare_operation(c.owner, "operation-new", c.operation["target"]["files"])
                with self.assertRaisesRegex(ValueError, "clock_uncertain"):
                    c.provider.register(c.owner, op, c.authorization("runtime-a", operation=op))
                self.assertTrue(self.read(c)["clock_uncertain"])

    def test_review_R4_reserve_native_capacity_before_acceptance(self):
        c = self.case(); t, p = c.attempt(); raw = c.signed_status("runtime-a")
        for _ in range(252):
            c.provider.notify(raw)
        before = self.state(c)
        r = c.provider.submit("operation-one", t["attempt_id"], p)
        self.assertEqual(r["reason"], "reserved result capacity")
        self.assertEqual(self.state(c), before)
        self.assertIsNone(self.query(c)["accepted"])
        self.assertEqual(self.query(c)["inventory"], {})
        # The byte budget has the same pre-acceptance guarantee.
        c = self.case(); t, p = c.attempt()
        with c.provider.connection() as db:
            used = db.execute("SELECT journal_bytes FROM metadata").fetchone()[0]
        before = self.state(c)
        with patch("handoff_provider.MAX_JOURNAL_BYTES", used + 11000):
            self.assertIn("capacity", c.provider.submit("operation-one", t["attempt_id"], p)["reason"])
        self.assertEqual(self.state(c), before)
        # A competing notifier cannot steal the accepted worker's reserved slots.
        c = self.case(); t, p = c.attempt(); raw = c.signed_status("runtime-a")
        for _ in range(245):
            c.provider.notify(raw)
        proc, pipe = self.child(c, "submit", (t["attempt_id"], p), "accepted_before_effect")
        try:
            for _ in range(16):
                try:
                    c.provider.notify(raw)
                except ValueError as e:
                    self.assertIn("capacity", str(e))
                    break
            else:
                self.fail("journal must reach its bounded capacity")
            self.assertEqual(self.op(c)["reserved_events"], 3)
            self.assertEqual(self.finish_child(proc, pipe)["status"], "completed")
            self.assertEqual(self.op(c)["reserved_events"], 0)
            self.assertIsNotNone(self.op(c)["native"])
            self.assertEqual(self.read(c)["linkage"]["outcome"], "success")
        finally:
            if proc.is_alive():
                proc.terminate(); proc.join(5)

    def test_review_optional_close_after_rollback_failure(self):
        c = self.case(); closed = []
        original_connect = sqlite3.connect
        class RollbackFault(sqlite3.Connection):
            def rollback(self):
                raise sqlite3.OperationalError("synthetic rollback failure")
            def close(self):
                closed.append(True)
                return super().close()
        def fault_connection(*args, **kwargs):
            return original_connect(*args, **kwargs, factory=RollbackFault)
        with patch("handoff_provider.sqlite3.connect", fault_connection):
            with self.assertRaisesRegex(sqlite3.OperationalError, "rollback failure"):
                with c.provider.connection(write=True):
                    pass
        self.assertEqual(closed, [True])
        # The failed rollback's connection is gone; a fresh writer can proceed.
        self.assertEqual(c.submit()["status"], "completed")

    def test_review_R4_reader_rejects_historical_capacity_overcommit(self):
        c = self.case(); c.submit()
        bundle = decode(c.provider.export("operation-one"))
        events = [decode(unb64(r["raw"])) for r in bundle["records"]]
        status = next(e for e in events if e["kind"] == "status")
        events = [e for e in events if e["kind"] != "execution_clock"]
        for e in events:
            if e["kind"] == "native":
                e["body"].update(started_at=None, finished_at=None)
        # Terminal history fits 256 slots, but at acceptance its promised future
        # result slots could never fit. Releasing them later cannot repair that decision.
        events[2:2] = [copy.deepcopy(status) for _ in range(251)]
        previous = "0" * 64; bundle["records"] = []
        for i, event in enumerate(events, 1):
            event.update(index=i, previous=previous)
            raw = encode(event); previous = sha(raw)
            bundle["records"].append({"raw": b64(raw), "sha256": previous})
        bundle["head"] = previous
        with self.assertRaisesRegex(ValueError, "historical reservation capacity"):
            assess(c.context_raw, encode(c.operation), encode(bundle))

    def test_review_R5_actual_finish_precedes_persistence_wait(self):
        for intervening_status in (False, True):
            with self.subTest(intervening_status=intervening_status):
                c = self.case()
                c.handoff(authorization=c.authorization("runtime-b", expires=iso(BASE + 1)))
                def delay_recording(point):
                    if point == "execution_clock_sampled_finish":
                        self.assertEqual(len(c.provider.inventory(c.operation)), 2)
                        c.clock.value = BASE + 2
                        if intervening_status:
                            c.provider.notify(c.signed_status("runtime-a", sequence=2))
                c.provider.hook = delay_recording
                self.assertEqual(c.submit("runtime-b")["status"], "completed")
                op = self.op(c)
                self.assertEqual(op["native"]["finished_at"], iso(BASE))
                self.assertEqual(op["execution_clocks"]["finish"], {"sampled_at": BASE, "recorded_at": BASE + 2})
                r = self.read(c)
                self.assertFalse(r["clock_uncertain"])
                self.assertEqual(r["linkage"]["outcome"], "success")
        # A backwards actual sample remains a fault even if the clock recovers
        # while waiting to persist that sample.
        c = self.case()
        def rollback_and_recover(point):
            if point == "after_file_2":
                c.clock.value = BASE - 1
            elif point == "execution_clock_sampled_finish":
                c.clock.value = BASE + 2
        c.provider.hook = rollback_and_recover
        self.assertEqual(c.submit()["status"], "unknown")
        c.reopen()
        self.assertTrue(self.read(c)["clock_uncertain"])
        # Files start only after the start-clock transaction commits. The finish
        # sample must therefore follow start.recorded_at, not merely its old sample.
        c = self.case()
        def rollback_after_start_commit(point):
            if point == "execution_clock_sampled_start":
                c.clock.value = BASE + 2
            elif point == "after_file_2":
                c.clock.value = BASE + 1
            elif point == "execution_clock_sampled_finish":
                c.clock.value = BASE + 3
        c.provider.hook = rollback_after_start_commit
        self.assertEqual(c.submit()["status"], "unknown")
        self.assertTrue(self.read(c)["clock_uncertain"])

    def padded_signature(self, payload, role, typ, padding, *, sign=True):
        # Whitespace is inside the signed JSON payload; its meaning is unchanged.
        header = {"alg": "ES256", "typ": typ, "kid": "synthetic-local-key"}
        data = (crypto.url64(encode(header)) + "." +
                crypto.url64(encode(payload) + b" " * padding)).encode("ascii")
        signature = (fixture_crypto.der_to_raw_ecdsa(fixture_crypto.sign_bytes(data, self.keys.items[role]["private_key"]))
                     if sign else b"0" * 64)  # size estimation only; never submitted
        return data + b"." + crypto.url64(signature).encode("ascii")

    def fill_normal_capacity(self, c, dimension):
        raw = c.signed_status("runtime-a", sequence=100)
        if dimension == "bytes":
            payload = c.provider.context.status(raw, BASE).payload
            raw = self.padded_signature(payload, "authority", STATUS_TYP, 24000)
        while True:
            try:
                c.provider.notify(raw)
            except ValueError as e:
                self.assertIn("capacity", str(e))
                break
        if dimension == "bytes":
            # Use one valid signed status to fill the remaining ordinary bytes.
            # The exact real 1 MiB limit is exercised, without patching constants.
            with c.provider.connection() as db:
                state, records = c.provider.load(db)
                used = db.execute("SELECT journal_bytes FROM metadata").fetchone()[0]
            available = MAX_JOURNAL_BYTES - used - reserved_event_count(state) * RESERVED_EVENT_BYTES
            payload = {**payload, "sequence": 101}
            def event_size(padding):
                body_raw = self.padded_signature(payload, "authority", STATUS_TYP, padding, sign=False)
                body = {"raw": b64(body_raw), "raw_sha256": "0" * 64, "signing_input_sha256": "0" * 64}
                return len(encode({"index": len(records) + 1, "previous": records[-1]["sha256"],
                    "context_sha256": c.provider.context.digest, "at": BASE, "kind": "status", "operation_id": None,
                    "body": body}))
            self.assertLessEqual(event_size(0), available)
            low, high = 0, 30000
            while low < high:
                mid = (low + high + 1) // 2
                if event_size(mid) <= available:
                    low = mid
                else:
                    high = mid - 1
            c.provider.notify(self.padded_signature(payload, "authority", STATUS_TYP, low))
        with c.provider.connection() as db:
            state, records = c.provider.load(db)
            used = db.execute("SELECT journal_bytes FROM metadata").fetchone()[0]
        self.assertFalse(state["subjects"]["runtime-a"]["conflict"])
        if dimension == "events":
            self.assertEqual(len(records) + reserved_event_count(state), MAX_EVENTS)
        else:
            self.assertLess(MAX_JOURNAL_BYTES - used - reserved_event_count(state) * RESERVED_EVENT_BYTES, 8)
            self.assertLess(len(records), MAX_EVENTS - 10)

    def test_pro_N1_full_store_clock_fault_persists(self):
        for dimension in ("events", "bytes"):
            for point, outputs in (("accepted_before_effect", 0), ("after_file_2", 2)):
                with self.subTest(dimension=dimension, point=point):
                    c = self.case(); old, _ = c.attempt(); c.unknown(old); c.handoff()
                    def hook(where):
                        if where != point:
                            return
                        self.fill_normal_capacity(c, dimension)
                        before = self.state(c)
                        c.clock.value = BASE - 1
                        with self.assertRaisesRegex(ValueError, "clock_uncertain"):
                            c.provider.notify(c.signed_status("runtime-a", generated_at=BASE, next_update_at=BASE + 60))
                        c.clock.value = BASE
                        fresh = Provider(c.path, clock=c.clock)
                        with fresh.connection() as db:
                            after, _ = fresh.load(db)
                        self.assertTrue(after["clock_bad"])
                        self.assertEqual(after["operations"], before["operations"])
                    c.provider.hook = hook
                    self.assertEqual(c.submit("runtime-b")["status"], "unknown")
                    c.reopen()
                    self.assertEqual(len(self.query(c)["inventory"]), outputs)
                    self.assertIsNone(self.op(c)["native"])
                    r = self.read(c)
                    self.assertTrue(r["clock_uncertain"])
                    self.assertEqual(r["acceptance_count"], 1)
                    self.assertEqual(len(r["unknown"]), 1)
                    self.assertEqual(r["linkage"]["outcome"], "unassessable")
                    before = self.state(c)
                    for _ in range(2):
                        with self.assertRaisesRegex(ValueError, "clock_uncertain"):
                            c.provider.notify(c.signed_status("runtime-a"))
                    self.assertEqual(self.state(c), before)
                    new = c.provider.prepare_operation(c.owner, "new-operation", c.operation["target"]["files"])
                    with self.assertRaisesRegex(ValueError, "clock_uncertain"):
                        c.provider.register(c.owner, new, c.authorization("runtime-a", operation=new))

    def test_pro_N1_normal_full_store_worker_completes(self):
        for dimension in ("events", "bytes"):
            with self.subTest(dimension=dimension):
                c = self.case()
                c.provider.hook = lambda point: self.fill_normal_capacity(c, dimension) if point == "accepted_before_effect" else None
                self.assertEqual(c.submit()["status"], "completed")
                self.assertFalse(self.read(c)["clock_uncertain"])
                self.assertEqual(self.read(c)["linkage"]["outcome"], "success")

    def test_pro_N1_no_pending_worker_still_has_fault_capacity(self):
        for dimension in ("events", "bytes"):
            with self.subTest(dimension=dimension):
                c = self.case()
                self.fill_normal_capacity(c, dimension)
                c.clock.value = BASE - 1
                with self.assertRaisesRegex(ValueError, "clock_uncertain"):
                    c.provider.notify(c.signed_status("runtime-a", generated_at=BASE, next_update_at=BASE + 60))
                c.clock.value = BASE; c.reopen()
                self.assertTrue(self.read(c)["clock_uncertain"])
                self.assertIsNone(self.query(c)["accepted"])
                self.assertEqual(self.query(c)["inventory"], {})

    def authority_named_actor(self):
        c = self.case()
        context = decode(c.context_raw)
        context["actors"]["authority"] = context["actors"].pop("runtime-a")
        c.context_raw = encode(context)
        c.path = c.path.with_name(c.path.name + "-authority-actor")
        initialize(c.path, c.context_raw)
        c.provider = Provider(c.path, clock=c.clock, owner_capability=c.owner)
        c.operation = c.provider.prepare_operation(c.owner, "operation-one", c.operation["target"]["files"])
        c.provider.register(c.owner, c.operation, c.authorization("authority"))
        c.set_status("authority", runtime_spki_sha256=self.keys.items["runtime-a"]["spki_sha256"])
        return c

    def changed_event_bundle(self, c, kind, update):
        bundle = decode(c.provider.export("operation-one")); previous = "0" * 64
        for record in bundle["records"]:
            event = decode(unb64(record["raw"]))
            if event["kind"] == kind:
                update(event)
            event["previous"] = previous
            raw = encode(event); previous = sha(raw)
            record.update(raw=b64(raw), sha256=previous)
        bundle["head"] = previous
        return encode(bundle)

    def test_pro_N2_actor_named_authority_uses_actor_key(self):
        c = self.authority_named_actor()
        ticket = c.provider.ticket("operation-one", "authority")
        wrong = self.keys.sign(ticket, "authority", PROOF_TYP)
        right = self.keys.sign(ticket, "runtime-a", PROOF_TYP)
        self.assertEqual(c.provider.submit("operation-one", ticket["attempt_id"], wrong)["reason"], "signature_invalid")
        self.assertIsNone(self.query(c)["accepted"])
        self.assertEqual(c.provider.submit("operation-one", ticket["attempt_id"], right)["status"], "completed")
        self.assertEqual(self.read(c)["linkage"]["outcome"], "success")
        tampered = self.changed_event_bundle(c, "accepted", lambda e: e["body"].update(proof=b64(wrong)))
        with self.assertRaisesRegex(ValueError, "signature_invalid"):
            assess(c.context_raw, encode(c.operation), tampered)

    def test_pro_N2_observation_and_status_roles_are_separate(self):
        c = self.authority_named_actor()
        ticket = c.provider.ticket("operation-one", "authority")
        payload = {"profile": PROFILE, "context_sha256": c.provider.context.digest, "operation_id": "operation-one",
                   "attempt_id": ticket["attempt_id"], "runtime": "authority", "observed_at": BASE, "outcome": "unknown"}
        wrong = self.keys.sign(payload, "authority", OBS_TYP)
        with self.assertRaisesRegex(ValueError, "signature_invalid"):
            c.provider.record_unknown("operation-one", ticket["attempt_id"], "authority", wrong)
        c.provider.record_unknown("operation-one", ticket["attempt_id"], "authority", self.keys.sign(payload, "runtime-a", OBS_TYP))
        self.assertEqual(len(self.read(c)["unknown"]), 1)
        tampered = self.changed_event_bundle(c, "unknown", lambda e: e["body"].update(raw=b64(wrong)))
        with self.assertRaisesRegex(ValueError, "signature_invalid"):
            assess(c.context_raw, encode(c.operation), tampered)
        raw = c.set_status("authority", runtime_spki_sha256=self.keys.items["runtime-a"]["spki_sha256"])
        status_payload = c.provider.context.status(raw, BASE).payload
        with self.assertRaisesRegex(ValueError, "signature_invalid"):
            c.provider.notify(self.keys.sign(status_payload, "runtime-a", STATUS_TYP))
        c.provider.notify(raw)

    def test_pro_O1_provider_reader_enforce_event_byte_limit(self):
        c = self.case(); ticket, _ = c.attempt()
        payload = {"profile": PROFILE, "context_sha256": c.provider.context.digest, "operation_id": "operation-one",
                   "attempt_id": ticket["attempt_id"], "runtime": "runtime-a", "observed_at": BASE, "outcome": "unknown"}
        raw = self.padded_signature(payload, "runtime-a", OBS_TYP, 40000)
        c.provider.context.verify_actor(raw, "runtime-a", OBS_TYP)  # authentic, within JWS's own 64 KiB bound
        before = self.state(c)
        with self.assertRaisesRegex(ValueError, "journal event capacity"):
            c.provider.record_unknown("operation-one", ticket["attempt_id"], "runtime-a", raw)
        self.assertEqual(self.state(c), before)
        bundle = decode(c.provider.export("operation-one"))
        event_raw = encode({"index": len(bundle["records"]) + 1, "previous": bundle["head"],
            "context_sha256": c.provider.context.digest, "at": BASE, "kind": "unknown", "operation_id": "operation-one",
            "body": {"attempt_id": ticket["attempt_id"], "runtime": "runtime-a", "raw": b64(raw)}})
        self.assertGreater(len(event_raw), 65536)
        bundle["records"].append({"raw": b64(event_raw), "sha256": sha(event_raw)})
        bundle["head"] = sha(event_raw)
        with self.assertRaisesRegex(ValueError, "journal event capacity"):
            assess(c.context_raw, encode(c.operation), encode(bundle))

    def test_pro_O2_current_ticket_does_not_reuse_old_confirmation(self):
        c = self.case(); old, _ = c.attempt(); c.unknown(old)
        past = c.handoff()["result"]
        self.assertEqual(self.read(c)["effect_state"], "confirmed_unexecuted")
        ticket, proof = c.attempt("runtime-b")
        self.assertEqual(self.read(c)["effect_state"], "unresolved")
        c.unknown(ticket)
        c.reopen()
        self.assertEqual(self.read(c)["effect_state"], "unresolved")
        self.assertEqual(self.query(c)["effect_state"], "unresolved")
        self.assertEqual(self.read(c)["handoffs"], [past])
        self.assertEqual(c.provider.submit("operation-one", ticket["attempt_id"], proof)["reason"], "unresolved_current_attempt")
        self.assertEqual(len(self.read(c)["unknown"]), 2)

    def signed_unknown(self, c, ticket):
        return self.keys.sign({"profile": PROFILE, "context_sha256": c.provider.context.digest,
            "operation_id": ticket["operation_id"], "attempt_id": ticket["attempt_id"],
            "runtime": ticket["runtime"], "observed_at": BASE, "outcome": "unknown"}, ticket["runtime"], OBS_TYP)

    def record_unknown_raw(self, c, ticket, raw):
        return c.provider.record_unknown(ticket["operation_id"], ticket["attempt_id"], ticket["runtime"], raw)

    def clock_event_count(self, c):
        with c.provider.connection() as db:
            _, records = c.provider.load(db)
        return sum(decode(unb64(record["raw"]))["kind"] == "clock" for record in records)

    def test_pro_N3_unknown_clock_fault_survives_rejection_and_restart(self):
        for dimension in ("normal", "events", "bytes"):
            with self.subTest(dimension=dimension):
                c = self.case(); ticket, proof = c.attempt()
                raw = self.signed_unknown(c, ticket)
                c.provider.context.verify_actor(raw, "runtime-a", OBS_TYP)
                if dimension != "normal":
                    self.fill_normal_capacity(c, dimension)
                before = self.state(c)
                c.clock.value = BASE - 1
                with self.assertRaisesRegex(ValueError, "clock_uncertain"):
                    self.record_unknown_raw(c, ticket, raw)
                c.clock.value = BASE; c.reopen()
                self.assertTrue(self.state(c)["clock_bad"])
                self.assertEqual(self.state(c)["operations"], before["operations"])
                self.assertEqual(self.clock_event_count(c), 1)
                self.assertTrue(self.read(c)["clock_uncertain"])
                self.assertEqual(self.read(c)["unknown"], [])
                with self.assertRaisesRegex(ValueError, "clock_uncertain"):
                    c.provider.ticket("operation-one", "runtime-a")
                operation = c.provider.prepare_operation(c.owner, "new-operation", c.operation["target"]["files"])
                with self.assertRaisesRegex(ValueError, "clock_uncertain"):
                    c.provider.register(c.owner, operation, c.authorization("runtime-a", operation=operation))
                self.assertEqual(c.provider.submit("operation-one", ticket["attempt_id"], proof)["reason"],
                                 "clock_uncertain")
                self.assertEqual(self.query(c)["inventory"], {})
                # A repeated invalid observation neither appends another fault nor changes the operation.
                c.clock.value = BASE - 1
                for _ in range(2):
                    with self.assertRaises(ValueError):
                        self.record_unknown_raw(c, ticket, raw)
                c.clock.value = BASE
                self.assertEqual(self.clock_event_count(c), 1)
                self.assertEqual(self.state(c)["operations"], before["operations"])

    def test_pro_N3_other_operation_unknown_stops_accepted_worker(self):
        for dimension in ("normal", "events", "bytes"):
            for point, outputs in (("accepted_before_effect", 0), ("after_file_2", 2)):
                with self.subTest(dimension=dimension, point=point):
                    c = self.case(); old, _ = c.attempt(); c.unknown(old); c.handoff()
                    second = c.provider.prepare_operation(c.owner, "operation-two", c.operation["target"]["files"])
                    c.provider.register(c.owner, second, c.authorization("runtime-a", operation=second))
                    ticket, _ = c.attempt(operation_id="operation-two")
                    raw = self.signed_unknown(c, ticket)
                    hits = []
                    def hook(where):
                        if where != point:
                            return
                        if dimension != "normal":
                            self.fill_normal_capacity(c, dimension)
                        before = self.state(c)
                        c.clock.value = BASE - 1
                        with self.assertRaisesRegex(ValueError, "clock_uncertain"):
                            self.record_unknown_raw(c, ticket, raw)
                        c.clock.value = BASE
                        fresh = Provider(c.path, clock=c.clock)
                        with fresh.connection() as db:
                            after, _ = fresh.load(db)
                        self.assertTrue(after["clock_bad"])
                        self.assertEqual(after["operations"], before["operations"])
                        hits.append(where)
                    c.provider.hook = hook
                    self.assertEqual(c.submit("runtime-b")["status"], "unknown")
                    self.assertEqual(hits, [point])
                    c.reopen()
                    self.assertEqual(len(self.query(c)["inventory"]), outputs)
                    self.assertIsNone(self.op(c)["native"])
                    r = self.read(c)
                    self.assertTrue(r["clock_uncertain"])
                    self.assertEqual(r["acceptance_count"], 1)
                    self.assertEqual(len(r["unknown"]), 1)
                    self.assertEqual(r["linkage"]["outcome"], "unassessable")
                    self.assertEqual(self.clock_event_count(c), 1)
                    self.assertEqual(self.state(c)["operations"]["operation-two"]["unknown"], [])

    def test_pro_N3_known_fault_preserves_completed_native_and_late_unknown(self):
        c = self.case(); old, _ = c.attempt(); c.unknown(old); c.handoff()
        self.assertEqual(c.submit("runtime-b")["status"], "completed")
        native = copy.deepcopy(self.op(c)["native"])
        raw = self.signed_unknown(c, old)
        c.clock.value = BASE - 1
        with self.assertRaisesRegex(ValueError, "clock_uncertain"):
            self.record_unknown_raw(c, old, raw)
        c.clock.value = BASE; c.reopen()
        self.record_unknown_raw(c, old, raw)
        c.reopen()
        self.assertEqual(self.op(c)["native"], native)
        r = self.read(c)
        self.assertTrue(r["clock_uncertain"])
        self.assertEqual(r["effect_state"], "completed")
        self.assertEqual(r["linkage"]["outcome"], "success")
        self.assertEqual(len(r["unknown"]), 2)
        self.assertEqual(self.clock_event_count(c), 1)

    def test_pro_N3_clock_fault_precedes_signature_binding_and_size_errors(self):
        for invalid in ("signature", "binding", "size"):
            with self.subTest(invalid=invalid):
                c = self.case(); ticket, _ = c.attempt()
                raw = self.signed_unknown(c, ticket)
                payload = c.provider.context.verify_actor(raw, "runtime-a", OBS_TYP).payload
                if invalid == "signature":
                    raw = b"not-a-jws"
                elif invalid == "binding":
                    raw = self.keys.sign({**payload, "operation_id": "wrong-operation"}, "runtime-a", OBS_TYP)
                else:
                    raw = self.padded_signature(payload, "runtime-a", OBS_TYP, 40000)
                    c.provider.context.verify_actor(raw, "runtime-a", OBS_TYP)
                # The same input is independently invalid even at a normal clock.
                with self.assertRaises(ValueError):
                    self.record_unknown_raw(c, ticket, raw)
                self.assertFalse(self.state(c)["clock_bad"])
                c.clock.value = BASE - 1
                with self.assertRaisesRegex(ValueError, "clock_uncertain"):
                    self.record_unknown_raw(c, ticket, raw)
                c.clock.value = BASE; c.reopen()
                self.assertTrue(self.read(c)["clock_uncertain"])
                self.assertEqual(self.clock_event_count(c), 1)
                self.assertEqual(self.op(c)["unknown"], [])

    def test_pro_N3_unknown_uses_one_clock_sample(self):
        c = self.case(); ticket, _ = c.attempt()
        raw = self.signed_unknown(c, ticket)
        with patch.object(c.provider, "clock", return_value=BASE) as clock:
            self.record_unknown_raw(c, ticket, raw)
            clock.assert_called_once_with()
        self.assertEqual(len(self.read(c)["unknown"]), 1)
        self.assertFalse(self.read(c)["clock_uncertain"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
