"""Bounded HS51 WAR/bindings checks; the caller pins and isolates the WAR module.

This module uses no incoming path, trust anchor, executable, or network resource.
The caller supplies bindings from already evaluated MUSUBI originals and the
receiver's selected DER roots. A verified record may contain a failing work
verdict. These checks do not create a native MUSUBI acceptance log entry.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import math
import re

PROFILE = 'hs51-war-bindings-v0-1'
WAR_SOURCE_SHA256 = 'ac3ac35d9356cbb5f3371c19a2113ad03c1fd486c247a2ed586bdfdbdd32ae49'
WAR_SOURCE_COMMIT = '6b2f730b81e0818826f274742d883c2b475d5227'
EXPECTED_KEYS = frozenset(('occurrence_id', 'request_sha256', 'execution_sha256',
                           'audit_sha256', 'checker_public_key_hex',
                           'producer_public_key_hex', 'criteria_sha256'))
MAX_RAW = 256 * 1024
MAX_DEPTH = 24
MAX_NODES = 4096
MAX_ITEMS = 128
MAX_STRING = 48 * 1024
MAX_CRITERIA = 32 * 1024
MAX_TOKEN = 24 * 1024
MAX_ROOT = 16 * 1024
MAX_TOKENS = 8
MAX_ROOTS = 8
MAX_RESULTS = 64
SAFE_INTEGER = 2**53 - 1
RESULTS = frozenset(('pass', 'fail', 'not-evaluated', 'error'))
HEX = re.compile(r'[0-9a-f]{64}\Z')
UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z')


class _Stop(ValueError):
    def __init__(self, code, status='rejected'):
        self.code, self.status = code, status
        super().__init__(code)


def _need(condition, code, status='rejected'):
    if not condition:
        raise _Stop(code, status)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _bounded_json(raw, maximum=MAX_RAW):
    _need(type(raw) is bytes and len(raw) <= maximum, 'input_size_limit')
    try:
        text = raw.decode('utf-8')
    except UnicodeError as exc:
        raise _Stop('invalid_json') from exc
    # Check nesting before json.loads can allocate a deeply recursive tree.
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            _need(depth <= MAX_DEPTH, 'json_depth_limit')
        elif char in ']}':
            depth -= 1

    def pairs(items):
        _need(len(items) <= MAX_ITEMS, 'json_item_limit')
        result = {}
        for key, value in items:
            _need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result

    def integer(token):
        _need(len(token.lstrip('-')) <= 16, 'unsafe_json_number')
        value = int(token)
        _need(abs(value) <= SAFE_INTEGER, 'unsafe_json_number')
        return value

    def unsupported_number(_):
        raise _Stop('unsafe_json_number')

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                           parse_float=unsupported_number, parse_constant=unsupported_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _Stop('invalid_json') from exc
    nodes = 0

    def walk(item):
        nonlocal nodes
        nodes += 1
        _need(nodes <= MAX_NODES, 'json_node_limit')
        if type(item) is str:
            try:
                _need(len(item.encode('utf-8')) <= MAX_STRING, 'json_string_limit')
            except UnicodeError as exc:
                raise _Stop('invalid_unicode') from exc
        elif type(item) is list:
            _need(len(item) <= MAX_ITEMS, 'json_item_limit')
            for child in item:
                walk(child)
        elif type(item) is dict:
            for key, child in item.items():
                _need(len(key) <= 128, 'json_key_limit')
                walk(key)
                walk(child)
    walk(value)
    return value


def _object(value, code='acceptance_structure_invalid'):
    _need(type(value) is dict, code)
    return value


def _text(value, maximum=256, code='acceptance_structure_invalid'):
    _need(type(value) is str and 0 < len(value) <= maximum, code)
    return value


def _hex(value, code='acceptance_structure_invalid'):
    _need(type(value) is str and HEX.fullmatch(value) is not None, code)
    return value


def _b64(value, maximum, code='base64_invalid'):
    _need(type(value) is str and 0 < len(value) <= 4 * ((maximum + 2) // 3), code)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _Stop(code) from exc
    _need(len(raw) <= maximum and base64.b64encode(raw).decode('ascii') == value, code)
    return raw


def _bounded_der(raw):
    """Bound DER structure before the pinned upstream certificate/token parser."""
    nodes = 0

    def node(offset, end, depth):
        nonlocal nodes
        nodes += 1
        _need(nodes <= 512 and depth <= MAX_DEPTH, 'der_structure_limit')
        _need(offset + 2 <= end, 'der_malformed')
        tag, length = raw[offset], raw[offset + 1]
        _need(tag & 31 != 31, 'der_malformed')
        offset += 2
        if length & 128:
            count = length & 127
            _need(0 < count <= 3 and offset + count <= end, 'der_malformed')
            _need(raw[offset] != 0, 'der_malformed')
            length = int.from_bytes(raw[offset:offset + count], 'big')
            _need(length >= 128, 'der_malformed')
            offset += count
        stop = offset + length
        _need(stop <= end, 'der_malformed')
        if tag == 2:
            _need(0 < length <= 1024, 'der_integer_limit')
        if tag & 32:
            while offset < stop:
                offset = node(offset, stop, depth + 1)
        return stop

    _need(node(0, len(raw), 1) == len(raw), 'der_malformed')


def _milliseconds(value):
    _need(type(value) is str and UTC.fullmatch(value) is not None, 'timestamp_time_invalid')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(
            tzinfo=timezone.utc).timestamp() * 1000
    except (ValueError, OverflowError) as exc:
        raise _Stop('timestamp_time_invalid') from exc


def _timing_diagnostic(timing):
    """JSON-safe token timing; arithmetic keeps the original WAR numeric value.

    accuracy_ms_decimal is null for absent accuracy, otherwise a decimal string.
    For a float, repr preserves the original finite Python value on conversion
    back to float, including sub-millisecond precision; integers use str. This
    is an output diagnostic convention, not a change to signed JSON/JCS input.
    """
    accuracy = timing.get('accuracy_ms')
    _need(accuracy is None or (type(accuracy) in (int, float) and accuracy >= 0
          and (type(accuracy) is int or math.isfinite(accuracy))), 'timestamp_accuracy_invalid')
    _need(type(timing.get('imprint')) is bool, 'evaluator_output_invalid')
    _need(timing.get('time') is None or type(timing['time']) is str, 'evaluator_output_invalid')
    decimal = None if accuracy is None else repr(accuracy) if type(accuracy) is float else str(accuracy)
    return {'imprint': timing['imprint'], 'time': timing.get('time'), 'accuracy_ms_decimal': decimal}


def _criteria_rows(value):
    _need(type(value) is list and 0 < len(value) <= MAX_RESULTS, 'criteria_structure_invalid')
    result = {}
    for row in value:
        _object(row, 'criteria_structure_invalid')
        key = _text(row.get('id'), 128, 'criteria_structure_invalid')
        _need(key not in result and type(row.get('required')) is bool, 'criteria_structure_invalid')
        result[key] = row['required']
    return result


def evaluate(raw: bytes, expected: dict, roots: list[bytes], war) -> dict:
    """Check one raw record against receiver-selected bindings and trust anchors.

    The caller MUST verify WAR_SOURCE_SHA256 before importing ``war`` and run it
    with bounded resources and without network/home access. No source is loaded
    here. JSON numbers are restricted to safe integers; unsupported numeric
    semantics are rejected before upstream JCS or cryptographic processing.
    """
    result = {
        'profile': PROFILE, 'status': 'rejected', 'reason_codes': [], 'work_verdict': None,
        'raw_sha256': _sha(raw) if type(raw) is bytes else None,
        'checks': {}, 'declared': {}, 'verified_claims': {},
        'provenance': {'required_war_source_sha256': WAR_SOURCE_SHA256,
                       'required_war_source_commit': WAR_SOURCE_COMMIT,
                       'verifier_identity_check': 'caller_required'},
        'not_checked': ['audit_content_reassessment', 'organizational_independence',
                        'current_certificate_revocation', 'full_PKI_policy',
                        'OpenTimestamps', 'native_MUSUBI_acceptance',
                        'text_only_TSA_descriptors'],
    }
    checks = result['checks']
    unsupported_reasons = set()

    def check(name, condition, code, status='rejected'):
        checks[name] = bool(condition)
        if not condition:
            result['reason_codes'].append(code)
            if status == 'unsupported':
                unsupported_reasons.add(code)

    def finish_checks(defer_unsupported=False):
        if result['reason_codes']:
            status = 'unsupported' if all(code in unsupported_reasons for code in result['reason_codes']) else 'rejected'
            if status == 'unsupported' and defer_unsupported:
                return
            raise _Stop(result['reason_codes'][0], status)

    try:
        doc = _object(_bounded_json(raw))
        record = _object(doc.get('record'))
        body = _object(record.get('receipt'))
        side = _object(doc.get('bindings_sidecar'))
        _need(all(name in body for name in ('schema', 'canonicalization', 'suite'))
              and 'version' in side, 'acceptance_structure_invalid')
        _need(body.get('schema') == 'trilatic.acceptance-receipt/1.2',
              'unsupported_receipt_schema', 'unsupported')
        _need(body.get('canonicalization') == 'JCS-RFC8785',
              'unsupported_canonicalization', 'unsupported')
        _need(body.get('suite') == {'digest': 'sha-256', 'signature': 'Ed25519'},
              'unsupported_signature_suite', 'unsupported')
        _need(side.get('version') == 'invinoveritas.work-acceptance-bindings/v0',
              'unsupported_bindings_version', 'unsupported')
        _need(type(expected) is dict and set(expected) == EXPECTED_KEYS,
              'receiver_expected_invalid', 'unavailable')
        try:
            _text(expected['occurrence_id'])
            for key in EXPECTED_KEYS - {'occurrence_id'}:
                _hex(expected[key])
        except _Stop as exc:
            raise _Stop('receiver_expected_invalid', 'unavailable') from exc
        result['provenance']['selected_bindings'] = dict(expected)
        _need(type(roots) is list and len(roots) <= MAX_ROOTS,
              'tsa_roots_invalid', 'unavailable')
        _need(bool(roots), 'tsa_roots_unavailable', 'unavailable')
        try:
            for root in roots:
                _need(type(root) is bytes and 0 < len(root) <= MAX_ROOT, 'tsa_roots_invalid')
                _bounded_der(root)
            _need(len(set(roots)) == len(roots), 'tsa_roots_invalid')
        except _Stop as exc:
            raise _Stop('tsa_roots_invalid', 'unavailable') from exc
        result['provenance']['selected_tsa_root_sha256'] = [_sha(root) for root in roots]
        required_functions = ('jcs', 'key_is_canonical_prime_order', 'verify_ed25519',
                              'vector_outcome', 'tsr_time_for', '_tsa_module')
        _need(all(callable(getattr(war, name, None)) for name in required_functions),
              'evaluator_unavailable', 'unavailable')

        signature = _object(record.get('signature'))
        timestamp = _object(record.get('timestamp'))
        bindings = _object(side.get('bindings'))
        criteria = _object(body.get('criteria'))
        parties = _object(body.get('parties'))
        checker = _object(parties.get('checker'))
        producer = _object(parties.get('producer'))
        remediated = _object(_object(body.get('files')).get('remediated'))
        keyset = _object(doc.get('keys'))
        _need('version' in keyset and 'alg' in signature and 'commitment' in criteria,
              'acceptance_structure_invalid')
        _need(keyset.get('version') == 'invinoveritas.checker-keys/v1',
              'unsupported_keys_version', 'unsupported')
        key_id = _text(body.get('key_id'), 128)
        _text(body.get('issuer'))
        _text(body.get('receipt_id'))
        _text(body.get('client_ref'))
        _text(checker.get('name'))
        _text(producer.get('name'))
        _hex(producer.get('key_id'))
        _hex(remediated.get('sha256'))
        _hex(criteria.get('sha256'))
        _hex(side.get('receipt_sha256'))
        _hex(side.get('criteria_id'))
        for name in ('execution_receipt_sha256', 'request_occurrence_sha256'):
            _hex(bindings.get(name))
        _milliseconds(body.get('issued_utc'))
        _milliseconds(criteria.get('committed_at'))
        _need(criteria.get('commitment') == 'rfc3161', 'unsupported_criteria_commitment', 'unsupported')
        _need(signature.get('alg') == 'Ed25519', 'unsupported_signature_suite', 'unsupported')
        _need(timestamp.get('status') == 'granted', 'receipt_timestamp_missing')
        keys = keyset.get('keys')
        _need(type(keys) is list and 0 < len(keys) <= 16, 'checker_keyset_invalid')
        by_id = {}
        for key in keys:
            _object(key, 'checker_keyset_invalid')
            ident = _text(key.get('key_id'), 128, 'checker_keyset_invalid')
            _need(ident not in by_id, 'checker_keyset_ambiguous')
            by_id[ident] = key
        _need(key_id in by_id, 'checker_key_missing')
        selected = by_id[key_id]
        _need(selected.get('alg') == 'Ed25519', 'unsupported_checker_key_algorithm', 'unsupported')
        public = _b64(selected.get('public_key_base64'), 32)
        _need(len(public) == 32, 'checker_key_invalid')
        receipt_signature = _b64(signature.get('value'), 64)
        side_signature = _b64(side.get('signature'), 64)
        _need(len(receipt_signature) == len(side_signature) == 64, 'signature_encoding_invalid')
        check('checker_identity', key_id == checker.get('key_id') == signature.get('key_id'),
              'checker_identity_mismatch')
        check('selected_checker_key', public.hex() == expected['checker_public_key_hex'],
              'checker_key_mismatch')
        check('checker_prime_order_key', war.key_is_canonical_prime_order(public) is True,
              'checker_key_invalid')
        finish_checks()
        canonical = war.jcs(body).encode('utf-8')
        receipt_hash = _sha(canonical)
        side_body = {key: value for key, value in side.items() if key not in ('signature', 'producer')}
        check('receipt_signature', war.verify_ed25519(receipt_signature, canonical, public) is True,
              'receipt_signature_invalid')
        check('sidecar_signature', war.verify_ed25519(
            side_signature, war.jcs(side_body).encode('utf-8'), public) is True,
            'sidecar_signature_invalid')
        check('receipt_digest', side['receipt_sha256'] == receipt_hash, 'receipt_digest_mismatch')
        check('criteria_pin', side['criteria_id'] == criteria['sha256'] == expected['criteria_sha256'],
              'criteria_pin_mismatch')
        check('occurrence', body['client_ref'] == expected['occurrence_id'], 'occurrence_binding_mismatch')
        check('execution', bindings['execution_receipt_sha256'] == expected['execution_sha256'],
              'execution_binding_mismatch')
        check('request', bindings['request_occurrence_sha256'] == expected['request_sha256'],
              'request_binding_mismatch')
        check('audit', remediated['sha256'] == expected['audit_sha256'], 'audit_binding_mismatch')
        check('producer', producer['key_id'] == expected['producer_public_key_hex'],
              'producer_binding_mismatch')
        result['declared'] = {
            'receipt_id': body['receipt_id'], 'issuer': body['issuer'],
            'occurrence_id': body['client_ref'], 'verdict': body.get('verdict'),
            'independence': body.get('independence'), 'issued_utc': body['issued_utc'],
            'checker_key_id': key_id, 'producer_key_id': producer['key_id'],
            'criteria_TSA_descriptors': side.get('criteria_rfc3161', []),
            'receipt_TSA_descriptors': side.get('receipt_rfc3161', []),
        }
        result['unsigned_sidecar_fields_ignored'] = ['producer'] if 'producer' in side else []
        result['provenance']['canonical_receipt_sha256'] = receipt_hash
        finish_checks()

        criteria_raw = _b64(doc.get('criteria_file_base64'), MAX_CRITERIA)
        check('criteria_raw_hash', _sha(criteria_raw) == expected['criteria_sha256'], 'criteria_hash_mismatch')
        finish_checks()
        criteria_doc = _object(_bounded_json(criteria_raw, MAX_CRITERIA), 'criteria_structure_invalid')
        want = _criteria_rows(criteria_doc.get('criteria'))
        got = _criteria_rows(body.get('results'))
        _need(type(body.get('human_review')) is dict, 'acceptance_structure_invalid')
        _need(all(row.get('result') in RESULTS for row in body['results']), 'result_vocabulary_invalid')
        vocabulary = criteria_doc.get('result_vocabulary')
        _need(type(vocabulary) is list and len(vocabulary) == 4 and
              all(type(value) is str for value in vocabulary) and set(vocabulary) == RESULTS,
              'criteria_structure_invalid')
        check('criteria_results', want == got and criteria_doc.get('criteria_set') == criteria.get('id')
              and type(criteria_doc.get('version')) is type(criteria.get('version'))
              and criteria_doc.get('version') == criteria.get('version'), 'criteria_results_mismatch')
        finish_checks()
        _need(bool(doc.get('criteria_tsr_base64')), 'criteria_timestamp_missing')
        _need(bool(doc.get('receipt_tsr_base64')), 'receipt_timestamp_missing')
        primary = _b64(doc['criteria_tsr_base64'], MAX_TOKEN)
        receipt_token = _b64(doc['receipt_tsr_base64'], MAX_TOKEN)
        extras = doc.get('criteria_rfc3161_all', [])
        _need(type(extras) is list and len(extras) <= MAX_TOKENS, 'criteria_token_count_limit')
        tokens = [('criteria', primary, expected['criteria_sha256'])]
        for number, extra in enumerate(extras):
            _object(extra)
            tokens.append(('criteria_extra_' + str(number),
                           _b64(extra.get('token_base64'), MAX_TOKEN), expected['criteria_sha256']))
        tokens.append(('receipt', receipt_token, receipt_hash))
        for _, token, _ in tokens:
            _bounded_der(token)
        # Pass only the selected inputs and anchors; incoming roots/expected
        # outcomes/verification instructions cannot select trust or success.
        upstream = war.vector_outcome({'inputs': {
            'receipt': record, 'keys': keyset,
            'criteria_file_base64': doc['criteria_file_base64'],
            'criteria_tsr_base64': doc['criteria_tsr_base64'],
            'receipt_tsr_base64': doc['receipt_tsr_base64'],
        }}, tsa_roots=roots)
        _object(upstream, 'evaluator_output_invalid')
        result['upstream_outcome'] = upstream
        check('upstream_not_refused', upstream.get('refused', False) is False, 'upstream_refused')
        check('upstream_signature', upstream.get('signature_valid') is True, 'upstream_signature_invalid')
        check('upstream_problems', upstream.get('problem_codes') == [], 'upstream_problems_present')
        check('upstream_warnings', upstream.get('warning_codes') == [], 'upstream_warnings_present')
        check('upstream_criteria_hash', upstream.get('criteria_hash') == 'match', 'criteria_hash_mismatch')
        check('upstream_criteria_order', upstream.get('criteria_committed_before_check') == 'yes',
              'criteria_commitment_not_before_check')
        verdict = upstream.get('verdict_recomputed')
        check('work_verdict_consistent', verdict in ('pass', 'fail', 'incomplete') and
              verdict == upstream.get('verdict_stated') == body.get('verdict'), 'work_verdict_mismatch')
        check('upstream_receipt_imprint', upstream.get('receipt_timestamp') == 'imprint_match',
              'receipt_timestamp_imprint_mismatch')
        tsa_statuses = upstream.get('tsa_signature')
        unsupported_tsa = (type(tsa_statuses) is dict and set(tsa_statuses) == {'criteria', 'receipt'}
                           and all(value in ('verified', 'unsupported') for value in tsa_statuses.values())
                           and 'unsupported' in tsa_statuses.values())
        check('upstream_TSA_signatures', tsa_statuses == {'criteria': 'verified', 'receipt': 'verified'},
              'tsa_signature_unsupported' if unsupported_tsa else 'tsa_signatures_not_verified',
              'unsupported' if unsupported_tsa else 'rejected')
        # An unsupported primary algorithm cannot hide a known failure in an
        # additional supplied token. Structure and hard failures still stop.
        finish_checks(defer_unsupported=True)

        cache = {}
        reports = []
        timings = []
        for label, token, imprint in tokens:
            cache_key = (_sha(token), imprint)
            if cache_key not in cache:
                timing = war.tsr_time_for(token, bytes.fromhex(imprint))
                authority = war._tsa_module().verify_tsa_signature(token, roots)
                cache[cache_key] = (timing, authority)
            timing, authority = cache[cache_key]
            _object(timing, 'evaluator_output_invalid')
            _object(authority, 'evaluator_output_invalid')
            valid = timing.get('imprint') is True and authority.get('status') == 'verified'
            unsupported = timing.get('imprint') is True and authority.get('status') == 'unsupported'
            check(label + '_token', valid, label + ('_tsa_unsupported' if unsupported else '_token_not_verified'),
                  'unsupported' if unsupported else 'rejected')
            reports.append({'role': label, 'token_sha256': cache_key[0],
                            'imprint': _timing_diagnostic(timing), 'authority_signature': authority})
            timings.append(timing)
        result['timestamp_tokens'] = reports
        # Keep checking usable timing fields before resolving unsupported;
        # an observable ordering failure also takes precedence over it.
        finish_checks(defer_unsupported=True)
        receipt_time = timings[-1]
        cover, issued = receipt_time.get('time'), body['issued_utc']
        reference = cover if _milliseconds(cover) < _milliseconds(issued) else issued
        reference_accuracy = (receipt_time.get('accuracy_ms') or 0) if reference == cover else 0
        _need(type(reference_accuracy) in (int, float) and reference_accuracy >= 0,
              'timestamp_accuracy_invalid')
        for report, timing in zip(reports[:-1], timings[:-1]):
            accuracy = timing.get('accuracy_ms') or 0
            _need(type(accuracy) in (int, float) and accuracy >= 0, 'timestamp_accuracy_invalid')
            # Identical to the pinned WAR rule: use the earlier of issued time
            # and receipt-token time, including each token's accuracy interval.
            before = _milliseconds(timing.get('time')) + accuracy < _milliseconds(reference) - reference_accuracy
            check(report['role'] + '_before_check', before, 'criteria_commitment_not_before_check')
        finish_checks()
        result['verified_claims'] = {
            'receipt_signature_and_selected_checker': True,
            'sidecar_signature_and_receipt_digest': True,
            'selected_MUSUBI_bindings': True, 'criteria_raw_hash_and_results': True,
            'work_verdict_recomputed': True,
            'criteria_timestamp_unique_tokens': len({row['token_sha256'] for row in reports[:-1]}),
            'receipt_timestamp_unique_tokens': 1,
            'all_supplied_timestamp_signatures_and_imprints': True,
            'all_supplied_criteria_tokens_before_check': True,
        }
        result['status'], result['work_verdict'] = 'verified', verdict
    except _Stop as exc:
        result['status'] = exc.status
        result['reason_codes'] = list(dict.fromkeys(result['reason_codes'] + [exc.code]))
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError, RecursionError) as exc:
        # A malformed object or bounded upstream parse failure cannot become an
        # acceptance. Do not leak exception text or incoming content in output.
        result['status'] = 'rejected'
        result['reason_codes'] = list(dict.fromkeys(result['reason_codes'] + ['malformed_acceptance']))
        result['error_type'] = type(exc).__name__
    except Exception as exc:
        result['status'] = 'unavailable'
        result['reason_codes'] = list(dict.fromkeys(result['reason_codes'] + ['evaluator_failed']))
        result['error_type'] = type(exc).__name__
    return result
