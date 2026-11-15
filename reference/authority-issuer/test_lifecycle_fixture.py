"""Bounded controller failures and credential-free fixture observations."""
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import lifecycle_fixture as f


def controlled_child(role, config, channel):
    if role == "timeout":
        time.sleep(10)
    elif role == "reject":
        channel.send({"ok": False, "cause": "FIXTURE_STARTUP_REJECTED"})
    elif role == "malformed":
        channel.send({"ok": "true"})
    elif role == "eof":
        channel.close()
    else:
        channel.send({"ok": True, "pid": os.getpid()})
        while True:
            action = channel.recv()["action"]
            if action == "timeout":
                time.sleep(10)
            channel.send({"ok": True})
            if action == "stop":
                break
    channel.close()


class LifecycleControllerTests(unittest.TestCase):
    def test_fresh_process_and_repeated_cleanup(self):
        child = f.OwnedProcess("normal", {}, target=controlled_child)
        try:
            self.assertNotEqual(child.initial["pid"], os.getpid())
            self.assertTrue(child.ask("status")["ok"])
        finally:
            child.close()
        child.close()
        self.assertFalse(child.process.is_alive())
        self.assertEqual(child.process.exitcode, 0)

    def test_startup_failures_leave_no_child(self):
        for mode in ("reject", "malformed", "eof", "timeout"):
            with self.subTest(mode=mode):
                before = {child.pid for child in multiprocessing.active_children()}
                with self.assertRaises(RuntimeError):
                    f.OwnedProcess(mode, {}, target=controlled_child, timeout=1)
                self.assertEqual({child.pid for child in multiprocessing.active_children()}, before)

    def test_response_timeout_reaps_its_child(self):
        child = f.OwnedProcess("normal", {}, target=controlled_child)
        child.timeout = 0.1
        try:
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                child.ask("timeout")
            self.assertFalse(child.process.is_alive())
        finally:
            child.close()

    def test_explicit_abrupt_exit_is_reaped(self):
        child = f.OwnedProcess("normal", {}, target=controlled_child)
        child.kill()
        child.close()
        self.assertFalse(child.process.is_alive())
        self.assertNotEqual(child.process.exitcode, 0)


class LifecycleObservationTests(unittest.TestCase):
    def test_recipient_configuration_has_no_publisher_capability(self):
        class Inputs(dict):
            def __missing__(self, key):
                return "fixture-value:" + key
        publisher = f.role_configuration("publisher", Inputs())
        recipient = f.role_configuration("recipient", Inputs())
        for key in ("token", "pdp_credential", "helper", "keychain", "tls_key", "publisher_anchor", "registration"):
            self.assertIn(key, publisher)
            self.assertNotIn(key, recipient)
        self.assertIn("recipient_anchor", recipient)
        self.assertNotIn("recipient_anchor", publisher)
        with self.assertRaises(KeyError):
            f.role_configuration("unselected-role", Inputs())

    def test_observations_exclude_credentials_and_unselected_response_fields(self):
        secret = "ephemeral-fixture-credential"
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "events.jsonl"
            service = f.ObservedService("introspection", log, "http://127.0.0.1:1", development_loopback=True)
            with patch.object(f.JsonService, "request", return_value={"active": True, "token": secret, "allowed": "false"}):
                service.request("/introspect", form={"token": secret})
            with patch.object(f.JsonService, "request", side_effect=RuntimeError(secret)):
                with self.assertRaises(RuntimeError):
                    service.request("/introspect", form={"token": secret})
            records = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(records, [
                {"kind": "introspection", "path": "/introspect", "pid": os.getpid(), "returned": True, "active": True},
                {"kind": "introspection", "path": "/introspect", "pid": os.getpid(), "returned": False}])
            self.assertNotIn(secret, log.read_text())
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
