"""Local dispatch boundary regression tests; callbacks have no external effects."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo

import request_binding as b
import test_runtime_evidence as fixtures


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RuntimeEvidenceTests()
        self.fixture.setUp()
        self.now = self.fixture.now
        self.calls = []
        self.boundary = b.DispatchBoundary(execute=self.execute, clock=lambda: self.now)
        self.verifier = self.fixture.verifier
        self.verifier.dispatch_boundary = self.boundary

    def execute(self, effective, checkpoint):
        self.calls.append((effective, checkpoint))
        return b"local callback returned"

    def admit(self, **options):
        return self.fixture.admit(**options)

    def reject(self, bound, cause):
        with self.assertRaisesRegex(b.Invalid, "^" + cause + "$"):
            self.verifier.dispatch(bound)
        self.assertEqual(self.calls, [])

    def test_reauthenticates_then_calls_exact_effective_bytes(self):
        bound = self.admit()
        self.now += timedelta(seconds=2)
        with patch.object(self.verifier, "_evaluate_policy", wraps=self.verifier._evaluate_policy) as policy:
            result = self.verifier.dispatch(bound)
            policy.assert_not_called()
        self.assertEqual(result.value, b"local callback returned")
        self.assertEqual(self.calls, [(bound.effective, result.checkpoint)])
        self.assertNotEqual(bound.original, bound.effective)
        self.assertEqual(len(self.fixture.calls), 2)
        self.assertEqual(self.fixture.calls[-1].now, self.now)
        check = b.decode(result.checkpoint)
        for name, raw in (("receipt", bound.receipt), ("admission_request", bound.request),
                          ("original", bound.original), ("effective", bound.effective)):
            self.assertEqual(check[name + "_ref"], b.reference(raw))
        self.assertEqual(check["runtime_verification"]["verification"]["checked_at"], b.core.iso(self.now))
        self.assertEqual(check["usable_until"], b.decode(bound.receipt)["expires_at"])
        self.assertEqual(self.verifier._seen_request_ids, {self.fixture.request["request_id"]})
        self.assertEqual([c["status"] for c in b.decode(bound.assessment)["checks"][-2:]],
                         ["not_checked", "not_checked"])
        with self.assertRaises(FrozenInstanceError):
            result.checkpoint = b"changed"

    def test_checkpoint_schema_and_runtime_record(self):
        try:
            from jsonschema import Draft202012Validator, FormatChecker
            from referencing import Registry, Resource
        except ImportError:
            self.skipTest("jsonschema is available in the repository venv")
        record = b.decode(self.verifier.dispatch(self.admit()).checkpoint)
        schemas = Path(b.__file__).parent / "schemas"
        schema = json.loads((schemas / "pre-dispatch.schema.json").read_text())
        runtime = json.loads((schemas / "runtime-verification.schema.json").read_text())
        registry = Registry().with_resource(runtime["$id"], Resource.from_contents(runtime))
        validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
        Draft202012Validator.check_schema(schema)
        validator.validate(record)
        Draft202012Validator(runtime, format_checker=FormatChecker()).validate(record["runtime_verification"])
        for changed in ({**record, "usable_until": None}, {**record, "contract": "other"},
                        {**record, "effective_ref": record["effective_ref"]["digest"]}):
            self.assertFalse(validator.is_valid(changed))

    def test_dispatch_requires_configuration_before_admission(self):
        self.verifier.dispatch_boundary = None
        bound = self.admit()
        self.reject(bound, "INVALID_DISPATCH_BOUNDARY")
        self.verifier.dispatch_boundary = self.boundary
        self.reject(bound, "DISPATCH_ADMISSION_NOT_ISSUED")

    def test_runtime_authentication_cannot_be_optional_at_dispatch(self):
        self.verifier.runtime_evidence_verifier = None
        with self.assertRaisesRegex(b.Invalid, "DISPATCH_REQUIRES_RUNTIME_VERIFIER"):
            self.admit()
        self.assertEqual(self.verifier._seen_request_ids, set())

    def test_async_and_generator_callbacks_rejected_before_admission(self):
        async def asynchronous(*args):
            pass

        def generator(*args):
            yield 1

        class AsyncCallable:
            async def __call__(self, *args):
                pass

        for execute in (asynchronous, generator, AsyncCallable()):
            self.verifier.dispatch_boundary = b.DispatchBoundary(execute=execute)
            with self.assertRaisesRegex(b.Invalid, "DISPATCH_CALLBACK_NOT_SYNCHRONOUS"):
                self.admit()
        self.assertEqual(self.verifier._seen_request_ids, set())

    def test_dispatch_does_not_accept_caller_time_callback_or_new_input(self):
        bound = self.admit()
        for extra in ({"now": self.now}, {"execute": self.execute}, {"effective": bound.original}):
            with self.assertRaises(TypeError):
                self.verifier.dispatch(bound, **extra)
        self.assertEqual(self.calls, [])

    def test_received_copied_and_other_verifier_admissions_rejected(self):
        bound = self.admit()
        for fake in (replace(bound), replace(bound, effective=bound.original), bound.receipt, True):
            self.reject(fake, "DISPATCH_ADMISSION_NOT_ISSUED")
        other = self.fixture.new_verifier()
        other.dispatch_boundary = self.boundary
        with self.assertRaisesRegex(b.Invalid, "DISPATCH_ADMISSION_NOT_ISSUED"):
            other.dispatch(bound)
        self.verifier.dispatch(bound)
        self.assertEqual(len(self.calls), 1)

    def test_no_dispatch_for_new_permit_or_replay_denial(self):
        candidate = self.admit(require_new_permit=True)
        self.reject(candidate, "DISPATCH_ADMISSION_NOT_ISSUED")
        denied = self.admit()
        self.assertEqual(b.decode(denied.receipt)["decision"]["outcome"], "deny")
        self.reject(denied, "DISPATCH_ADMISSION_NOT_ISSUED")

    def test_denied_request_never_registered(self):
        self.fixture.policy["allowed_actions"] = ["other"]
        self.fixture.request["evidence_refs"][0]["digest"] = b.digest(b.encode(self.fixture.policy))
        self.fixture.claims["context_hash"] = b.runtime_context_hash(
            b.encode(self.fixture.request), b.encode(self.fixture.original))
        self.fixture.attach()
        denied = self.admit()
        self.assertEqual(b.decode(denied.receipt)["decision"]["outcome"], "deny")
        self.reject(denied, "DISPATCH_ADMISSION_NOT_ISSUED")

    def test_receipt_expiry_is_inclusive_and_never_extended(self):
        bound = self.admit()
        end = b.core.parse_time(b.decode(bound.receipt)["expires_at"])
        self.now = end + timedelta(microseconds=1)
        self.reject(bound, "DISPATCH_OUTSIDE_WINDOW")
        self.assertEqual(len(self.fixture.calls), 1)
        # A new boundary is deliberately not a way to revive an old admission.
        self.verifier.dispatch_boundary = b.DispatchBoundary(execute=self.execute, clock=lambda: end)
        self.reject(bound, "DISPATCH_CONFIGURATION_CHANGED")

    def test_exact_receipt_deadline_is_accepted(self):
        bound = self.admit()
        self.now = b.core.parse_time(b.decode(bound.receipt)["expires_at"])
        self.verifier.dispatch(bound)
        self.assertEqual(len(self.calls), 1)

    def test_dispatch_before_receipt_issuance_rejected(self):
        bound = self.admit()
        self.now -= timedelta(microseconds=1)
        self.reject(bound, "DISPATCH_OUTSIDE_WINDOW")

    def test_observed_revocation_or_unavailable_verification_stops_callback(self):
        bound = self.admit()
        with patch.object(b, "_verify_runtime_evidence", side_effect=b.Invalid("RUNTIME_EVIDENCE_VERIFICATION_FAILED")):
            self.reject(bound, "RUNTIME_EVIDENCE_VERIFICATION_FAILED")
        self.verifier.dispatch(bound)
        self.assertEqual(len(self.calls), 1)

    def test_slow_authentication_cannot_outlive_receipt(self):
        bound = self.admit()
        original = b._verify_runtime_evidence

        def slow(*args):
            result = original(*args)
            self.now += timedelta(seconds=51)
            return result

        with patch.object(b, "_verify_runtime_evidence", side_effect=slow):
            self.reject(bound, "DISPATCH_OUTSIDE_WINDOW")

    def test_current_evidence_deadline_can_be_shorter(self):
        bound = self.admit()
        original = b._verify_runtime_evidence

        def shortened(*args):
            result = original(*args)
            result["usable_until"] = b.core.iso(self.now + timedelta(seconds=1))
            self.now += timedelta(seconds=2)
            return result

        with patch.object(b, "_verify_runtime_evidence", side_effect=shortened):
            self.reject(bound, "DISPATCH_OUTSIDE_WINDOW")

    def test_record_serialization_time_counts_against_deadline(self):
        bound = self.admit()
        encode = b.encode

        def delayed(value):
            raw = encode(value)
            if isinstance(value, dict) and value.get("contract") == b.PRE_DISPATCH:
                self.now += timedelta(seconds=51)
            return raw

        with patch.object(b, "encode", side_effect=delayed):
            self.reject(bound, "DISPATCH_OUTSIDE_WINDOW")

    def test_configuration_changes_require_new_admission(self):
        bound = self.admit()
        with self.boundary.update():
            self.verifier.policy = {**self.verifier.policy, "policy_version": "changed"}
        self.reject(bound, "DISPATCH_CONFIGURATION_CHANGED")
        self.assertEqual(len(self.fixture.calls), 1)

    def test_adapter_replacement_and_removal_rejected(self):
        bound = self.admit()
        self.verifier.runtime_evidence_verifier = replace(self.fixture.adapter)
        self.reject(bound, "DISPATCH_CONFIGURATION_CHANGED")
        self.verifier.runtime_evidence_verifier = None
        self.reject(bound, "DISPATCH_REQUIRES_RUNTIME_VERIFIER")

    def test_configuration_changed_during_authentication_rejected(self):
        bound = self.admit()
        verify = b._verify_runtime_evidence

        def changed(*args):
            result = verify(*args)
            self.verifier.policy["policy_version"] = "changed"
            return result

        with patch.object(b, "_verify_runtime_evidence", side_effect=changed):
            self.reject(bound, "DISPATCH_CONFIGURATION_CHANGED")

    def test_clock_rollback_rejected_before_callback(self):
        times = iter((self.now + timedelta(seconds=2), self.now + timedelta(seconds=1)))
        self.boundary = b.DispatchBoundary(execute=self.execute, clock=lambda: next(times))
        self.verifier.dispatch_boundary = self.boundary
        self.reject(self.admit(), "DISPATCH_CLOCK_ROLLBACK")

    def test_forward_dst_change_is_an_increasing_clock(self):
        first = datetime(2026, 11, 1, 5, 59, 59, tzinfo=timezone.utc)
        second = first + timedelta(seconds=1)
        zone = ZoneInfo("America/New_York")
        self.now = first.astimezone(zone)
        self.assertEqual(self.boundary._now(), first)
        self.now = second.astimezone(zone)
        self.assertEqual(self.boundary._now(), second)

    def test_backward_dst_change_cannot_hide_clock_rollback(self):
        zone = ZoneInfo("America/New_York")
        self.now = datetime(2026, 11, 1, 6, 10, tzinfo=timezone.utc).astimezone(zone)
        self.boundary._now()
        self.now = datetime(2026, 11, 1, 5, 20, tzinfo=timezone.utc).astimezone(zone)
        with self.assertRaisesRegex(b.Invalid, "DISPATCH_CLOCK_ROLLBACK"):
            self.boundary._now()

    def test_deadline_checked_after_waiting_for_another_admission(self):
        bound = self.admit()
        self.fixture.request["request_id"] = "second-admission"
        self.fixture.claims["context_hash"] = b.runtime_context_hash(
            b.encode(self.fixture.request), b.encode(self.fixture.original))
        self.fixture.attach()
        dispatch_auth, admission_held, dispatch_waiting, release = (threading.Event() for _ in range(4))
        dispatch_thread = None
        original_issue, original_verify = b._issue_bound, b._verify_runtime_evidence

        class ObservedLock:
            def __init__(self):
                self.lock = threading.RLock()
            def __enter__(self):
                if threading.get_ident() == dispatch_thread and admission_held.is_set():
                    dispatch_waiting.set()
                self.lock.acquire()
                return self
            def __exit__(self, *args):
                self.lock.release()

        self.verifier._replay_lock = ObservedLock()

        def verify(*args):
            if threading.get_ident() == dispatch_thread:
                dispatch_auth.set()
                self.assertTrue(admission_held.wait(3))
            return original_verify(*args)

        def issue(*args, **kwargs):
            admission_held.set()
            self.assertTrue(release.wait(3))
            return original_issue(*args, **kwargs)

        def dispatch():
            nonlocal dispatch_thread
            dispatch_thread = threading.get_ident()
            return self.verifier.dispatch(bound)

        with patch.object(b, "_verify_runtime_evidence", side_effect=verify), \
                patch.object(b, "_issue_bound", side_effect=issue), ThreadPoolExecutor(max_workers=2) as pool:
            operation = pool.submit(dispatch)
            try:
                self.assertTrue(dispatch_auth.wait(3))
                admission = pool.submit(self.admit)
                self.assertTrue(dispatch_waiting.wait(3))
                self.now = b.core.parse_time(b.decode(bound.receipt)["expires_at"]) + timedelta(microseconds=1)
            finally:
                release.set()
            admission.result(timeout=3)
            with self.assertRaisesRegex(b.Invalid, "DISPATCH_OUTSIDE_WINDOW"):
                operation.result(timeout=3)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.verifier._dispatch_entries[id(bound)].attempted)

    def test_invalid_or_unavailable_clock_stops_callback(self):
        for instant in (None, True, self.now.replace(tzinfo=None)):
            self.setUp()
            self.now = instant
            self.reject(self.admit(), "INVALID_DISPATCH_TIME")
        self.setUp()
        self.verifier.dispatch_boundary = b.DispatchBoundary(execute=self.execute,
            clock=lambda: (_ for _ in ()).throw(RuntimeError("private clock diagnostic")))
        self.reject(self.admit(), "DISPATCH_CLOCK_UNAVAILABLE")

    def test_callback_exception_does_not_allow_repeat(self):
        def uncertain(effective, checkpoint):
            self.calls.append((effective, checkpoint))
            raise RuntimeError("local callback outcome unknown")

        self.verifier.dispatch_boundary = b.DispatchBoundary(execute=uncertain, clock=lambda: self.now)
        bound = self.admit()
        with self.assertRaisesRegex(b.DispatchAttemptError, "^DISPATCH_OUTCOME_UNCONFIRMED$") as caught:
            self.verifier.dispatch(bound)
        self.assertEqual(caught.exception.checkpoint, self.calls[0][1])
        with self.assertRaisesRegex(b.Invalid, "DISPATCH_ALREADY_ATTEMPTED"):
            self.verifier.dispatch(bound)
        self.assertEqual(len(self.calls), 1)

    def test_base_exception_also_consumes_attempt(self):
        def interrupted(*args):
            self.calls.append(args)
            raise KeyboardInterrupt()

        self.verifier.dispatch_boundary = b.DispatchBoundary(execute=interrupted, clock=lambda: self.now)
        bound = self.admit()
        with self.assertRaises(KeyboardInterrupt):
            self.verifier.dispatch(bound)
        with self.assertRaisesRegex(b.Invalid, "DISPATCH_ALREADY_ATTEMPTED"):
            self.verifier.dispatch(bound)
        self.assertFalse(self.verifier.dispatch_boundary._state.active)

    def test_deferred_result_does_not_allow_repeat(self):
        async def later():
            pass

        self.verifier.dispatch_boundary = b.DispatchBoundary(execute=lambda *args: later(), clock=lambda: self.now)
        bound = self.admit()
        with self.assertRaises(b.DispatchAttemptError):
            self.verifier.dispatch(bound)
        self.reject(bound, "DISPATCH_ALREADY_ATTEMPTED")

    def test_callback_error_cannot_masquerade_as_precheck_rejection(self):
        def callback(*args):
            self.calls.append(args)
            raise b.Invalid("DISPATCH_OUTSIDE_WINDOW")
        self.verifier.dispatch_boundary = b.DispatchBoundary(execute=callback, clock=lambda: self.now)
        bound = self.admit()
        with self.assertRaises(b.DispatchAttemptError) as caught:
            self.verifier.dispatch(bound)
        self.assertNotIsInstance(caught.exception, b.Invalid)
        self.assertEqual(caught.exception.checkpoint, self.calls[0][1])
        with self.assertRaisesRegex(b.Invalid, "DISPATCH_ALREADY_ATTEMPTED"):
            self.verifier.dispatch(bound)

    def test_concurrent_dispatch_invokes_callback_once(self):
        bound = self.admit()
        def call():
            try:
                return self.verifier.dispatch(bound).value
            except b.Invalid as exc:
                return exc.cause
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda _: call(), range(4)))
        self.assertEqual(outcomes.count(b"local callback returned"), 1)
        self.assertEqual(outcomes.count("DISPATCH_ALREADY_ATTEMPTED"), 3)
        self.assertEqual(len(self.calls), 1)

    def test_nested_dispatch_and_update_cannot_enter_from_callback(self):
        def nested(*args):
            with self.assertRaisesRegex(b.Invalid, "DISPATCH_REENTRANT"):
                self.verifier.dispatch(bound)
            with self.assertRaisesRegex(b.Invalid, "DISPATCH_REENTRANT_UPDATE"):
                with self.boundary.update():
                    self.fail("update entered")
            return self.execute(*args)
        self.boundary = b.DispatchBoundary(execute=nested, clock=lambda: self.now)
        self.verifier.dispatch_boundary = self.boundary
        bound = self.admit()
        self.verifier.dispatch(bound)
        self.assertEqual(len(self.calls), 1)

    def test_update_waits_for_callback_to_return(self):
        entered, updater_waiting, release, updated = (threading.Event() for _ in range(4))
        def execute(*args):
            entered.set()
            self.assertTrue(release.wait(3))
            self.assertFalse(updated.is_set())
            return self.execute(*args)
        self.boundary = b.DispatchBoundary(execute=execute, clock=lambda: self.now)
        self.verifier.dispatch_boundary = self.boundary
        bound = self.admit()
        def update():
            updater_waiting.set()
            with self.boundary.update():
                updated.set()
        with ThreadPoolExecutor(max_workers=2) as pool:
            dispatch = pool.submit(self.verifier.dispatch, bound)
            self.assertTrue(entered.wait(3))
            writer = pool.submit(update)
            self.assertTrue(updater_waiting.wait(3))
            self.assertFalse(updated.is_set())
            release.set()
            dispatch.result(timeout=3)
            writer.result(timeout=3)
        self.assertTrue(updated.is_set())

    def test_serialization_failure_does_not_consume_attempt(self):
        bound = self.admit()
        original = b.encode
        def fail(value):
            if isinstance(value, dict) and value.get("contract") == b.PRE_DISPATCH:
                raise b.Invalid("ARTIFACT_TOO_LARGE")
            return original(value)
        with patch.object(b, "encode", side_effect=fail):
            self.reject(bound, "ARTIFACT_TOO_LARGE")
        self.verifier.dispatch(bound)
        self.assertEqual(len(self.calls), 1)

    def test_failed_issuance_leaves_no_dispatch_entry(self):
        with patch.object(b, "_issue_bound", side_effect=b.Invalid("ARTIFACT_TOO_LARGE")):
            with self.assertRaises(b.Invalid):
                self.admit()
        self.assertEqual(self.verifier._dispatch_entries, {})
        self.assertEqual(self.verifier._seen_request_ids, set())
        self.verifier.dispatch(self.admit())


if __name__ == "__main__":
    unittest.main()
