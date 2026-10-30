"""Fixture signer restrictions remain active with Python optimization."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent


class FixtureSignerTests(unittest.TestCase):
    def run_in_both_modes(self, code):
        environment = dict(os.environ)
        environment.pop("PYTHONOPTIMIZE", None)
        for mode in ([], ["-O"]):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    [sys.executable, "-B", *mode, "-c", code], cwd=ROOT,
                    env=environment, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_fixture_subset_is_enforced_with_optimization(self):
        self.run_in_both_modes('''
from jcs_trial_fixtures import fixture_canonical
import unittest

case = unittest.TestCase()
for raw in (b'{"n":9007199254740993}', b'-9007199254740992', b'1.5',
            b'NaN', b'"\\\\u00e9"'):
    with case.subTest(raw=raw), case.assertRaises(ValueError):
        fixture_canonical(raw)
case.assertEqual(fixture_canonical(b'{"z":[true,null,-9007199254740991],"a":9007199254740991}'),
                 b'{"a":9007199254740991,"z":[true,null,-9007199254740991]}')
''')

    def test_der_checks_are_enforced_with_optimization(self):
        self.run_in_both_modes('''
from jcs_trial_fixtures import p1363
import unittest

case = unittest.TestCase()
valid = bytes.fromhex("3006020101020102")
malformed = [
    b"", b"0", valid[:-1],
    bytes.fromhex("3106020101020102"),
    bytes.fromhex("3006030101020102"),
    bytes.fromhex("3006020201020102"),
    bytes.fromhex("3006020180020102"),
    bytes.fromhex("300702020001020102"),
    bytes.fromhex("3006020100020102"),
    bytes.fromhex("30050200020102"),
    bytes([0x30, 0x26, 2, 0x21, 1]) + bytes(32) + bytes.fromhex("020102"),
    bytes.fromhex("300702010102010200"),
]
for raw in malformed:
    with case.subTest(raw=raw.hex()), case.assertRaises(ValueError):
        p1363(raw)
case.assertEqual(p1363(valid), (1).to_bytes(32, "big") + (2).to_bytes(32, "big"))
case.assertEqual(p1363(bytes.fromhex("300702020080020102")),
                 (128).to_bytes(32, "big") + (2).to_bytes(32, "big"))
''')


if __name__ == "__main__":
    unittest.main()
