"""Offline HS51 acceptance regression checks against an explicit frozen evidence root.

No upstream source or record is distributed by this harness. It verifies the
source bytes before executing them, then checks the real signed records and
unsigned/tampered inputs. It never creates signatures or changes the fixtures.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

from acceptance_checks import (EXPECTED_KEYS, MAX_CRITERIA, MAX_DEPTH, MAX_RAW,
                               MAX_ROOTS, MAX_STRING, MAX_TOKEN, MAX_TOKENS,
                               PROFILE, WAR_SOURCE_SHA256, evaluate)
from receiving import decode as receiving_decode

PINS = {
    'sources/context/bundle.json': 'c4ecb8830a69f4a8e8c31f5c8d4c32460651d1cf63cabf77db08a7a4a62a3668',
    'sources/context/audit-selection.json': 'a9feccbfbc99dfd83051945cd41d81efbfaa0363bd5fac8db1b4bd3879bae29c',
    'sources/acceptance/hs51-musubi-2-A.json': '204915d07bacd0ba0589c3a98c92af4b9feb0a4ef5dd5b1786c9ad5cc5eb5dac',
    'sources/acceptance/hs51-musubi-2-B.json': '7e05c6c112111bd1cbebfd63b28fbb3375e54851d2a453eb9ed750b2f1c31f0f',
    'sources/acceptance/hs51-aps-A.json': '254a789f07b24354deb55db33cfa4c4dbc3f8321e9438bc94253c0d0b3fc4e00',
    'sources/acceptance/hs51-aps-B.json': '0b2a26dc95b28d3c529c2b196357ec3c4aa02dc97eb8c5aa02c2b52170df993b',
    'sources/war/vectors/31-tsa-freetsa-verified.json': '3bdbd6cc0f401fe8a834fba962d3b139830bf3e1807434f6d8d3607cc3ca2862',
    'sources/war/vectors/32-tsa-digicert-verified.json': '83a81b8a02ab780f6e1bd4653ca5c0218cddef55b460d81fd479e9c7409b1859',
}
EVIDENCE_ROOT = None


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('utf-8')


def _b64(raw):
    return base64.b64encode(raw).decode('ascii')


def _load_pinned_source(path):
    source = path.read_bytes()
    if _sha(source) != WAR_SOURCE_SHA256:
        raise ValueError('WAR source does not match the approved source pin')
    module = ModuleType('pinned_hs51_war')
    module.__file__ = str(path)
    # Execute the bytes just checked, without a second path read or .pyc cache.
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module


class AcceptanceTests(unittest.TestCase):
    checks_run = 0

    @classmethod
    def setUpClass(cls):
        cls.war = _load_pinned_source(EVIDENCE_ROOT / 'sources/war/verifier/war_verify.py')
        cls.raw = {}
        cls.docs = {}
        for name, expected_hash in PINS.items():
            raw = (EVIDENCE_ROOT / name).read_bytes()
            if _sha(raw) != expected_hash:
                raise ValueError('frozen fixture pin mismatch: ' + name)
            cls.raw[name] = raw
            cls.docs[name] = json.loads(raw)
        cls.a = cls.docs['sources/acceptance/hs51-musubi-2-A.json']
        cls.b = cls.docs['sources/acceptance/hs51-musubi-2-B.json']
        cls.aps_a = cls.docs['sources/acceptance/hs51-aps-A.json']
        cls.aps_b = cls.docs['sources/acceptance/hs51-aps-B.json']
        cls.a_raw = cls.raw['sources/acceptance/hs51-musubi-2-A.json']
        cls.b_raw = cls.raw['sources/acceptance/hs51-musubi-2-B.json']
        cls.roots = []
        for number, suffix in ((31, 'freetsa'), (32, 'digicert')):
            vector = cls.docs[f'sources/war/vectors/{number}-tsa-{suffix}-verified.json']
            for encoded in vector['inputs']['tsa_roots_base64']:
                root = base64.b64decode(encoded, validate=True)
                if root not in cls.roots:
                    cls.roots.append(root)
        bundle = cls.docs['sources/context/bundle.json']
        selection = cls.docs['sources/context/audit-selection.json']
        cls.expected = {}
        for case in selection['cases']:
            request = next(r for r in bundle['requests'] if r['occurrence_id'] == case['occurrence_id'])
            request_hash = _sha(cls.war.jcs(request).encode('utf-8'))
            if request_hash != case['request_sha256']:
                raise ValueError('frozen request pin mismatch')
            items = [entry['item'] for entry in bundle['log']['entries']]
            execution = next(i for i in items if i['type'] == 'musubi.ca2a.execution-receipt.v0'
                             and i['request_sha256'] == request_hash)
            criteria = next(i for i in items if i['type'] == 'musubi.ca2a.criteria-commitment.v0'
                            and i['request_sha256'] == request_hash)
            if (criteria['checker'], criteria['criteria_sha256']) != (case['checker'], case['criteria_sha256']):
                raise ValueError('frozen criteria/checker pin mismatch')
            cls.expected[case['occurrence_id']] = {
                'occurrence_id': case['occurrence_id'], 'request_sha256': request_hash,
                'execution_sha256': _sha(cls.war.jcs(execution).encode('utf-8')),
                'audit_sha256': execution['outcome']['response_sha256'],
                'producer_public_key_hex': execution['responder'],
                'criteria_sha256': criteria['criteria_sha256'],
                'checker_public_key_hex': criteria['checker'],
            }
        cls.expected_a = cls.expected['hs51-musubi-2-A']
        cls.baseline = evaluate(cls.a_raw, cls.expected_a, cls.roots, cls.war)
        if cls.baseline['status'] != 'verified':
            raise ValueError('real A baseline did not verify: ' + str(cls.baseline['reason_codes']))

    def run_case(self, doc=None, raw=None, expected=None, roots=None, status='rejected', code=None,
                 work_verdict=None):
        raw = raw if raw is not None else _encoded(self.a if doc is None else doc)
        result = evaluate(raw, self.expected_a if expected is None else expected,
                          self.roots if roots is None else roots, self.war)
        type(self).checks_run += 1
        # The actual receiver contract rejects floating-point JSON numbers.
        # Check every result, including rejection and unavailable diagnostics.
        self.assertEqual(result, receiving_decode(json.dumps(result, allow_nan=False).encode('utf-8')))
        self.assertEqual(status, result['status'], result)
        self.assertEqual(work_verdict, result['work_verdict'], result)
        self.assertEqual(_sha(raw), result['raw_sha256'])
        if code is not None:
            self.assertIn(code, result['reason_codes'], result)
        if status != 'verified':
            self.assertEqual({}, result['verified_claims'], result)
        else:
            self.assertEqual([], result['reason_codes'], result)
        return result

    def test_real_A_pass(self):
        result = self.run_case(raw=self.a_raw, status='verified', work_verdict='pass')
        self.assertEqual(PROFILE, result['profile'])
        self.assertEqual(2, result['verified_claims']['criteria_timestamp_unique_tokens'])
        self.assertEqual(1, result['verified_claims']['receipt_timestamp_unique_tokens'])

    def test_real_B_is_verified_failing_work(self):
        result = self.run_case(raw=self.b_raw, expected=self.expected['hs51-musubi-2-B'],
                               status='verified', work_verdict='fail')
        self.assertTrue(all(result['checks'].values()))

    def test_APS_same_audit_cannot_fill_MUSUBI_A(self):
        result = self.run_case(doc=self.aps_a, code='request_binding_mismatch')
        self.assertTrue(result['checks']['audit'])
        self.assertTrue(result['checks']['receipt_signature'])
        self.assertFalse(result['checks']['execution'])

    def test_APS_B_cannot_fill_MUSUBI_B(self):
        self.run_case(doc=self.aps_b, expected=self.expected['hs51-musubi-2-B'], code='execution_binding_mismatch')

    def test_A_cannot_fill_B(self):
        self.run_case(expected=self.expected['hs51-musubi-2-B'], code='occurrence_binding_mismatch')

    def test_A_same_audit_cannot_fill_C(self):
        result = self.run_case(expected=self.expected['hs51-musubi-2-C'], code='request_binding_mismatch')
        self.assertTrue(result['checks']['audit'])

    def test_intact_B_sidecar_cannot_fill_A(self):
        doc = copy.deepcopy(self.a); doc['bindings_sidecar'] = self.b['bindings_sidecar']
        result = self.run_case(doc=doc, code='receipt_digest_mismatch')
        self.assertTrue(result['checks']['sidecar_signature'])

    def test_receipt_tamper(self):
        doc = copy.deepcopy(self.a); doc['record']['receipt']['verdict'] = 'fail'
        self.run_case(doc=doc, code='receipt_signature_invalid')

    def test_sidecar_tamper(self):
        doc = copy.deepcopy(self.a)
        doc['bindings_sidecar']['bindings']['request_occurrence_sha256'] = '0' * 64
        self.run_case(doc=doc, code='sidecar_signature_invalid')

    def test_selected_checker_not_incoming_keyset(self):
        doc = copy.deepcopy(self.a)
        doc['keys']['keys'][0]['public_key_base64'] = _b64(bytes.fromhex(self.expected_a['producer_public_key_hex']))
        self.run_case(doc=doc, code='checker_key_mismatch')

    def test_checker_signature_ids_must_align(self):
        doc = copy.deepcopy(self.a); doc['record']['signature']['key_id'] = 'another-checker'
        self.run_case(doc=doc, code='checker_identity_mismatch')

    def test_ambiguous_duplicate_key_id(self):
        doc = copy.deepcopy(self.a); doc['keys']['keys'] *= 2
        self.run_case(doc=doc, code='checker_keyset_ambiguous')

    def test_identity_or_small_order_checker_is_rejected(self):
        for public in (b'\x01' + b'\x00' * 31, b'\x00' * 32, b'\xff' * 32):
            with self.subTest(public=public.hex()):
                doc = copy.deepcopy(self.a); doc['keys']['keys'][0]['public_key_base64'] = _b64(public)
                expected = dict(self.expected_a, checker_public_key_hex=public.hex())
                self.run_case(doc=doc, expected=expected, code='checker_key_invalid')

    def test_unsigned_optional_sidecar_producer_does_not_set_trust(self):
        for value in ('foreign-producer', {'key_id': '0' * 64}, None):
            with self.subTest(value=value):
                doc = copy.deepcopy(self.a); doc['bindings_sidecar']['producer'] = value
                result = self.run_case(doc=doc, status='verified', work_verdict='pass')
                self.assertEqual(['producer'], result['unsigned_sidecar_fields_ignored'])
                self.assertEqual(self.expected_a['producer_public_key_hex'], result['declared']['producer_key_id'])

    def test_signed_producer_is_bound(self):
        doc = copy.deepcopy(self.a); doc['record']['receipt']['parties']['producer']['key_id'] = '0' * 64
        self.run_case(doc=doc, code='producer_binding_mismatch')

    def test_every_receiver_expected_binding_is_required(self):
        for key in EXPECTED_KEYS:
            with self.subTest(key=key):
                expected = dict(self.expected_a); expected.pop(key)
                self.run_case(expected=expected, status='unavailable', code='receiver_expected_invalid')

    def test_receiver_expected_types_and_extra_fields(self):
        for expected in ({}, [], dict(self.expected_a, profile=PROFILE),
                         dict(self.expected_a, checker_public_key_hex='A' * 64),
                         dict(self.expected_a, occurrence_id=7)):
            with self.subTest(expected=expected):
                self.run_case(expected=expected, status='unavailable', code='receiver_expected_invalid')

    def test_every_receiver_pin_is_checked(self):
        codes = {'request_sha256': 'request_binding_mismatch', 'execution_sha256': 'execution_binding_mismatch',
                 'audit_sha256': 'audit_binding_mismatch', 'criteria_sha256': 'criteria_pin_mismatch',
                 'producer_public_key_hex': 'producer_binding_mismatch',
                 'checker_public_key_hex': 'checker_key_mismatch'}
        for key, code in codes.items():
            with self.subTest(key=key):
                self.run_case(expected=dict(self.expected_a, **{key: '0' * 64}), code=code)

    def test_missing_roots_never_verifies(self):
        self.run_case(roots=[], status='unavailable', code='tsa_roots_unavailable')

    def test_malformed_receiver_roots(self):
        for roots in ([b'not-DER'], [self.roots[0]] * 2, [self.roots[0]] * (MAX_ROOTS + 1), ['not-bytes']):
            with self.subTest(root_count=len(roots)):
                self.run_case(roots=roots, status='unavailable', code='tsa_roots_invalid')

    def test_only_one_authority_anchor_is_not_all_proof(self):
        for root in self.roots:
            with self.subTest(root=_sha(root)):
                self.run_case(roots=[root])

    def test_incoming_roots_cannot_replace_receiver_roots(self):
        doc = copy.deepcopy(self.a); doc['tsa_roots_base64'] = [_b64(r) for r in self.roots]
        self.run_case(doc=doc, roots=[], status='unavailable', code='tsa_roots_unavailable')
        doc['tsa_roots_base64'] = ['not a root']
        self.run_case(doc=doc, status='verified', work_verdict='pass')

    def test_unknown_versions_and_suites_are_unsupported(self):
        edits = [('schema', 'other/1', 'unsupported_receipt_schema'),
                 ('canonicalization', 'other', 'unsupported_canonicalization'),
                 ('suite', {'digest': 'sha-512', 'signature': 'Ed25519'}, 'unsupported_signature_suite')]
        for field, value, code in edits:
            with self.subTest(field=field):
                doc = copy.deepcopy(self.a); doc['record']['receipt'][field] = value
                self.run_case(doc=doc, status='unsupported', code=code)
        doc = copy.deepcopy(self.a); doc['bindings_sidecar']['version'] = 'future/v2'
        self.run_case(doc=doc, status='unsupported', code='unsupported_bindings_version')
        doc = copy.deepcopy(self.a); doc['keys']['version'] = 'future/v2'
        self.run_case(doc=doc, status='unsupported', code='unsupported_keys_version')

    def test_malformed_json_and_shapes(self):
        for raw in (b'', b'{', b'[]', b'null', b'{"record":[]}', b'\xff', b'{} trailing'):
            with self.subTest(raw=raw):
                self.run_case(raw=raw)

    def test_missing_profile_fields_are_malformed(self):
        for field in ('schema', 'canonicalization', 'suite'):
            with self.subTest(field=field):
                doc = copy.deepcopy(self.a); doc['record']['receipt'].pop(field)
                self.run_case(doc=doc, code='acceptance_structure_invalid')
        doc = copy.deepcopy(self.a); doc['bindings_sidecar'].pop('version')
        self.run_case(doc=doc, code='acceptance_structure_invalid')

    def test_duplicate_json_keys(self):
        self.run_case(raw=b'{"status":"success",' + self.a_raw.lstrip()[1:], code='duplicate_json_key')
        self.run_case(raw=b'{"a":{"nested":1,"nested":2}}', code='duplicate_json_key')

    def test_nonfinite_float_and_unsafe_numbers(self):
        for value in (b'NaN', b'Infinity', b'-Infinity', b'1.0', b'1e-999',
                      b'9007199254740992', b'9' * 5000):
            with self.subTest(value=value[:30]):
                self.run_case(raw=b'{"ignored":' + value + b'}', code='unsafe_json_number')

    def test_bad_unicode_and_strings(self):
        self.run_case(raw=b'{"x":"\\ud800"}', code='invalid_unicode')
        doc = copy.deepcopy(self.a); doc['extra'] = 'x' * (MAX_STRING + 1)
        self.run_case(doc=doc, code='json_string_limit')
        self.run_case(raw=_encoded({'x' * 129: 1}), code='json_key_limit')

    def test_raw_depth_item_and_node_bounds(self):
        self.run_case(raw=b' ' * (MAX_RAW + 1), code='input_size_limit')
        self.run_case(raw=b'[' * (MAX_DEPTH + 1) + b'0' + b']' * (MAX_DEPTH + 1), code='json_depth_limit')
        self.run_case(raw=_encoded([0] * 129), code='json_item_limit')
        self.run_case(raw=_encoded([[0] * 128 for _ in range(40)]), code='json_node_limit')

    def test_invalid_base64(self):
        for value in ('!', 'a===', '雪', 'AA==\n'):
            with self.subTest(value=value):
                doc = copy.deepcopy(self.a); doc['criteria_file_base64'] = value
                self.run_case(doc=doc, code='base64_invalid')

    def test_criteria_raw_hash_is_pinned(self):
        doc = copy.deepcopy(self.a)
        doc['criteria_file_base64'] = _b64(base64.b64decode(doc['criteria_file_base64']) + b' ')
        self.run_case(doc=doc, code='criteria_hash_mismatch')

    def test_reordered_criteria_bytes_are_not_silently_rehashed(self):
        doc = copy.deepcopy(self.a)
        criteria = json.loads(base64.b64decode(doc['criteria_file_base64']))
        criteria['criteria'].reverse()
        doc['criteria_file_base64'] = _b64(_encoded(criteria))
        self.run_case(doc=doc, code='criteria_hash_mismatch')

    def test_missing_primary_timestamp_proofs(self):
        for key, code in (('criteria_tsr_base64', 'criteria_timestamp_missing'),
                          ('receipt_tsr_base64', 'receipt_timestamp_missing')):
            with self.subTest(key=key):
                doc = copy.deepcopy(self.a); doc.pop(key)
                self.run_case(doc=doc, code=code)

    def test_valid_token_for_wrong_receipt(self):
        doc = copy.deepcopy(self.a); doc['receipt_tsr_base64'] = self.b['receipt_tsr_base64']
        result = self.run_case(doc=doc, code='receipt_timestamp_imprint_mismatch')
        self.assertEqual('verified', result['upstream_outcome']['tsa_signature']['receipt'])

    def test_wrong_primary_criteria_token(self):
        doc = copy.deepcopy(self.a); doc['criteria_tsr_base64'] = self.a['receipt_tsr_base64']
        self.run_case(doc=doc, code='upstream_problems_present')

    def test_tampered_extra_token_signature(self):
        doc = copy.deepcopy(self.a)
        token = base64.b64decode(doc['criteria_rfc3161_all'][1]['token_base64'])
        doc['criteria_rfc3161_all'][1]['token_base64'] = _b64(token[:-1] + bytes([token[-1] ^ 1]))
        self.run_case(doc=doc, code='criteria_extra_1_token_not_verified')

    def test_valid_extra_signature_wrong_imprint(self):
        doc = copy.deepcopy(self.a)
        doc['criteria_rfc3161_all'][1]['token_base64'] = self.a['receipt_tsr_base64']
        result = self.run_case(doc=doc, code='criteria_extra_1_token_not_verified')
        extra = next(row for row in result['timestamp_tokens'] if row['role'] == 'criteria_extra_1')
        self.assertEqual('verified', extra['authority_signature']['status'])
        self.assertFalse(extra['imprint']['imprint'])

    def test_optional_extra_proofs_and_descriptors_count_separately(self):
        doc = copy.deepcopy(self.a); doc.pop('criteria_rfc3161_all')
        result = self.run_case(doc=doc, status='verified', work_verdict='pass')
        self.assertEqual(1, result['verified_claims']['criteria_timestamp_unique_tokens'])
        self.assertEqual(2, len(result['declared']['criteria_TSA_descriptors']))
        self.assertEqual(1, result['verified_claims']['receipt_timestamp_unique_tokens'])
        self.assertEqual(2, len(result['declared']['receipt_TSA_descriptors']))

    def test_duplicate_extra_token_does_not_inflate_proofs(self):
        doc = copy.deepcopy(self.a); doc['criteria_rfc3161_all'] *= 2
        result = self.run_case(doc=doc, status='verified', work_verdict='pass')
        self.assertEqual(2, result['verified_claims']['criteria_timestamp_unique_tokens'])

    def test_unsigned_metadata_and_OTS_do_not_set_trust(self):
        doc = copy.deepcopy(self.a)
        doc.update(status='failure', price_sats=0, criteria_ots_base64=_b64(b'not an OTS proof'),
                   verify='untrusted verification instructions', expected={'verdict': 'fail'})
        result = self.run_case(doc=doc, status='verified', work_verdict='pass')
        self.assertIn('OpenTimestamps', result['not_checked'])
        self.assertIn('organizational_independence', result['not_checked'])

    def test_token_size_count_and_der_bounds(self):
        doc = copy.deepcopy(self.a); doc['receipt_tsr_base64'] = _b64(b'0' * (MAX_TOKEN + 1))
        self.run_case(doc=doc, code='base64_invalid')
        doc = copy.deepcopy(self.a); doc['criteria_file_base64'] = _b64(b'0' * (MAX_CRITERIA + 1))
        self.run_case(doc=doc, code='base64_invalid')
        doc = copy.deepcopy(self.a); doc['criteria_rfc3161_all'] = [doc['criteria_rfc3161_all'][0]] * (MAX_TOKENS + 1)
        self.run_case(doc=doc, code='criteria_token_count_limit')
        for token in (b'\x30\x80', b'\x30\x00\x00', b'\x30\x84\xff\xff\xff\xff'):
            with self.subTest(token=token.hex()):
                doc = copy.deepcopy(self.a); doc['criteria_rfc3161_all'][0]['token_base64'] = _b64(token)
                self.run_case(doc=doc, code='der_malformed')

    def test_upstream_success_object_is_not_sufficient(self):
        changes = [('signature_valid', False), ('problem_codes', ['BAD']), ('warning_codes', ['SELF_CHECKED']),
                   ('criteria_hash', 'unavailable'), ('criteria_committed_before_check', 'unknown'),
                   ('verdict_recomputed', 'fail'), ('receipt_timestamp', 'none'),
                   ('tsa_signature', {'criteria': 'verified'}), ('tsa_signature', {}), ('refused', True)]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                outcome = copy.deepcopy(self.baseline['upstream_outcome']); outcome[field] = value
                with patch.object(self.war, 'vector_outcome', return_value=outcome):
                    self.run_case()
        with patch.object(self.war, 'vector_outcome', return_value={'refused': True}):
            self.run_case()

    def test_upstream_unsupported_TSA_is_not_invalid_signature(self):
        for label in ('criteria', 'receipt'):
            with self.subTest(label=label):
                outcome = copy.deepcopy(self.baseline['upstream_outcome'])
                outcome['tsa_signature'][label] = 'unsupported'
                with patch.object(self.war, 'vector_outcome', return_value=outcome):
                    self.run_case(status='unsupported', code='tsa_signature_unsupported')

    def test_actual_TSA_failure_or_imprint_mismatch_overrides_unsupported(self):
        for other in ('failed', 'untrusted'):
            with self.subTest(other=other):
                outcome = copy.deepcopy(self.baseline['upstream_outcome'])
                outcome['tsa_signature'] = {'criteria': 'unsupported', 'receipt': other}
                with patch.object(self.war, 'vector_outcome', return_value=outcome):
                    self.run_case(code='tsa_signatures_not_verified')
        outcome = copy.deepcopy(self.baseline['upstream_outcome'])
        outcome['tsa_signature']['criteria'] = 'unsupported'
        outcome['receipt_timestamp'] = 'imprint_mismatch'
        with patch.object(self.war, 'vector_outcome', return_value=outcome):
            self.run_case(code='receipt_timestamp_imprint_mismatch')

    def unknown_primary_token(self):
        """Change only the frozen primary token's unsigned signature OID."""
        token = base64.b64decode(self.a['criteria_tsr_base64'])
        module = self.war._tsa_module()
        content = module._find_content_info(module.parse_one(token)).children()
        signed_data = module.parse_one(content[1].val).children()
        signers = next(node for node in signed_data[3:] if node.tag == 0x31)
        signer = signers.children()[0].children()
        algorithm = signer[4 if signer[3].tag == 0xA0 else 3]
        oid = algorithm.children()[0]
        self.assertEqual('1.2.840.10045.4.3.4', module.oid_str(oid))
        self.assertEqual(1, token.count(oid.raw))
        changed = token.replace(oid.raw, oid.raw[:-1] + b'\x63')
        self.assertEqual(1, sum(left != right for left, right in zip(token, changed)))
        self.assertEqual('unsupported', module.verify_tsa_signature(changed, self.roots)['status'])
        self.assertTrue(self.war.tsr_time_for(changed, bytes.fromhex(self.expected_a['criteria_sha256']))['imprint'])
        return changed

    def test_real_primary_unsupported_and_extra_signature_failure_combinations(self):
        # Real DER mutations, with no mocked verifier and no new signature.
        primary = self.unknown_primary_token()
        extra = base64.b64decode(self.a['criteria_rfc3161_all'][1]['token_base64'])
        failed_extra = extra[:-1] + bytes([extra[-1] ^ 1])
        self.assertEqual('failed', self.war._tsa_module().verify_tsa_signature(failed_extra, self.roots)['status'])
        for unsupported, failed in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(primary_unsupported=unsupported, extra_failed=failed):
                doc = copy.deepcopy(self.a)
                if unsupported:
                    doc['criteria_tsr_base64'] = _b64(primary)
                if failed:
                    doc['criteria_rfc3161_all'][1]['token_base64'] = _b64(failed_extra)
                status = 'rejected' if failed else 'unsupported' if unsupported else 'verified'
                result = self.run_case(doc=doc, status=status,
                                       work_verdict='pass' if status == 'verified' else None)
                rows = {row['role']: row for row in result['timestamp_tokens']}
                self.assertEqual({'criteria', 'criteria_extra_0', 'criteria_extra_1', 'receipt'}, set(rows))
                self.assertEqual('unsupported' if unsupported else 'verified',
                                 rows['criteria']['authority_signature']['status'])
                self.assertEqual('failed' if failed else 'verified',
                                 rows['criteria_extra_1']['authority_signature']['status'])
                if failed:
                    self.assertIn('criteria_extra_1_token_not_verified', result['reason_codes'])

    def test_primary_unsupported_does_not_hide_evaluator_runtime_failure(self):
        doc = copy.deepcopy(self.a); doc['criteria_tsr_base64'] = _b64(self.unknown_primary_token())
        extra = base64.b64decode(self.a['criteria_rfc3161_all'][1]['token_base64'])
        module = self.war._tsa_module()
        actual = module.verify_tsa_signature
        def authority(raw, roots):
            if raw == extra:
                raise RuntimeError('injected extra-token evaluator failure')
            return actual(raw, roots)
        with patch.object(module, 'verify_tsa_signature', side_effect=authority):
            self.run_case(doc=doc, status='unavailable', code='evaluator_failed')

    def test_extra_TSA_support_and_actual_failure_are_separate(self):
        token = base64.b64decode(self.a['criteria_rfc3161_all'][1]['token_base64'])
        module = self.war._tsa_module()
        actual_authority, actual_timing = module.verify_tsa_signature, self.war.tsr_time_for
        for authority_status, imprint_match, expected_status in (
                ('unsupported', True, 'unsupported'), ('failed', True, 'rejected'),
                ('untrusted', True, 'rejected'), ('unsupported', False, 'rejected')):
            def authority(raw, roots, authority_status=authority_status):
                result = actual_authority(raw, roots)
                return dict(result, status=authority_status) if raw == token else result
            def timing(raw, digest, imprint_match=imprint_match):
                result = actual_timing(raw, digest)
                return dict(result, imprint=imprint_match) if raw == token else result
            with self.subTest(authority=authority_status, imprint=imprint_match), \
                    patch.object(module, 'verify_tsa_signature', side_effect=authority), \
                    patch.object(self.war, 'tsr_time_for', side_effect=timing):
                result = self.run_case(status=expected_status)
                code = 'criteria_extra_1_tsa_unsupported' if expected_status == 'unsupported' else 'criteria_extra_1_token_not_verified'
                self.assertIn(code, result['reason_codes'])

    def test_DER_accuracy_decimals_roundtrip_on_verified_and_rejected_paths(self):
        # Exercise the actual pinned Accuracy parser, then inject its returned
        # numeric values into timing diagnostics; no new token is signed here.
        token = base64.b64decode(self.a['criteria_rfc3161_all'][1]['token_base64'])
        actual = self.war.tsr_time_for
        for der, expected_accuracy in (('3004800201f4', 500.0), ('3003810101', 0.001)):
            accuracy = self.war._accuracy_at(bytes.fromhex(der), 0)
            self.assertIs(type(accuracy), float)
            self.assertEqual(expected_accuracy, accuracy)
            for status in ('verified', 'rejected'):
                def timing(raw, digest, accuracy=accuracy, status=status):
                    result = dict(actual(raw, digest), accuracy_ms=accuracy)
                    if status == 'rejected' and raw == token:
                        result['time'] = self.a['record']['receipt']['issued_utc']
                    return result
                with self.subTest(accuracy=accuracy, status=status), \
                        patch.object(self.war, 'tsr_time_for', side_effect=timing):
                    result = self.run_case(status=status, work_verdict='pass' if status == 'verified' else None)
                    for row in result['timestamp_tokens']:
                        self.assertNotIn('accuracy_ms', row['imprint'])
                        value = row['imprint']['accuracy_ms_decimal']
                        self.assertEqual(repr(accuracy), value)
                        self.assertEqual(accuracy, float(value))

    def test_nonfinite_or_negative_token_accuracy_fails_without_JSON_leak(self):
        token = base64.b64decode(self.a['criteria_rfc3161_all'][1]['token_base64'])
        actual = self.war.tsr_time_for
        for accuracy in (float('nan'), float('inf'), float('-inf'), -0.001, True):
            def timing(raw, digest, accuracy=accuracy):
                result = actual(raw, digest)
                return dict(result, accuracy_ms=accuracy) if raw == token else result
            with self.subTest(accuracy=accuracy), patch.object(self.war, 'tsr_time_for', side_effect=timing):
                self.run_case(code='timestamp_accuracy_invalid')

    def test_missing_evaluator_is_unavailable(self):
        with patch.object(self.war, 'vector_outcome', None):
            self.run_case(status='unavailable', code='evaluator_unavailable')

    def test_evaluator_runtime_failure_is_unavailable(self):
        with patch.object(self.war, 'vector_outcome', side_effect=RuntimeError('private input must not leak')):
            result = self.run_case(status='unavailable', code='evaluator_failed')
            self.assertNotIn('private input', json.dumps(result))

    def test_extra_timestamp_time_and_accuracy_must_precede_check(self):
        token = base64.b64decode(self.a['criteria_rfc3161_all'][1]['token_base64'])
        actual = self.war.tsr_time_for
        for field, value in (('time', self.a['record']['receipt']['issued_utc']),
                             ('accuracy_ms', 2**53 - 1)):
            def changed(raw, digest, field=field, value=value):
                result = actual(raw, digest)
                return dict(result, **{field: value}) if raw == token else result
            with self.subTest(field=field), patch.object(self.war, 'tsr_time_for', side_effect=changed):
                self.run_case(code='criteria_commitment_not_before_check')

    def test_selected_mapping_root_and_JSON_key_order_are_irrelevant(self):
        expected = dict(reversed(list(self.expected_a.items())))
        result = self.run_case(raw=json.dumps(self.a, sort_keys=True, ensure_ascii=False).encode('utf-8'),
                               expected=expected, roots=list(reversed(self.roots)),
                               status='verified', work_verdict='pass')
        self.assertEqual(self.baseline['provenance']['canonical_receipt_sha256'],
                         result['provenance']['canonical_receipt_sha256'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', required=True, type=Path,
                        help='approved frozen HS51 acquisition directory; no files are changed')
    args = parser.parse_args()
    global EVIDENCE_ROOT
    EVIDENCE_ROOT = args.evidence_root.resolve(strict=True)
    capture = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AcceptanceTests)
    result = unittest.TextTestRunner(stream=capture, verbosity=1).run(suite)
    if not result.wasSuccessful():
        sys.stderr.write(capture.getvalue())
    print(json.dumps({'status': 'pass' if result.wasSuccessful() else 'fail',
                      'test_methods': result.testsRun, 'evaluations': AcceptanceTests.checks_run,
                      'failures': len(result.failures), 'errors': len(result.errors),
                      'python': platform.python_version(), 'profile': PROFILE,
                      'war_source_sha256': WAR_SOURCE_SHA256}, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
