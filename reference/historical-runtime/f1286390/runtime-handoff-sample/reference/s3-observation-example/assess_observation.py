#!/usr/bin/env python3
"""Offline S3 observation assessment composed with the existing VATE checker."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from contract import (ACTION, COLLECTOR, CONTRACT, RUNTIME, SOURCE_PATHS, ROOT, Bundle, Invalid,
                      action_binding, decode, descriptor, digest, encode, exact, make_post, mint,
                      need, object_hash, parse_headers, recipient, result_view, same, sources, target,
                      time_value, validate_effective, MAX_BODY)


def assess(bundle_path, trust):
    trust = trust if isinstance(trust, dict) else {}
    out = {'contract': CONTRACT, 'record_linkage': 'not_assessed', 'request_binding': 'not_assessed',
           'target_observation': 'not_observed', 'attempt_binding': 'unknown',
           'post_observation_binding': 'not_assessed', 'source_trust': 'unverified',
           'version_scope': None, 'assessment': 'insufficient', 'diagnostics': [],
           'receipt_check': None, 'retry_authorized': False,
           'scope': 'unsigned local collector/store assumptions; no current permission or independent causality proof'}
    diagnostics = out['diagnostics']
    def note(kind, code, detail=None):
        diagnostics.append({'kind': kind, 'code': code, 'detail': detail})
    def compare(ok, stage, code):
        if not ok:
            out[stage] = 'mismatch'
            note('contradiction', code)
        return bool(ok)
    def stage(name, fn):
        try:
            return fn()
        except (Invalid, OSError, ValueError, KeyError, TypeError, IndexError, RecursionError) as exc:
            note('missing_or_invalid', name, str(exc))
            return None
    try:
        b = Bundle(bundle_path)
    except (Invalid, OSError, ValueError, TypeError, RecursionError) as exc:
        note('bundle_invalid', 'BUNDLE_INVALID', str(exc))
        return out
    if b.contract != CONTRACT:
        out['assessment'] = 'unsupported'
        note('unsupported', 'UNKNOWN_BUNDLE_CONTRACT')
        return out

    docs = {}
    for name in sorted(b.raw):
        if name.endswith('.json'):
            value = stage(name, lambda n=name: b.get(n))
            if value is not None:
                docs[name] = value
    for name in ('effective-request.json', 'permit.json', 'attempt.json', 'put-request.json',
                 'put-transport.json', 'get-request.json', 'get-transport.json'):
        doc = docs.get(name)
        if doc is not None and (not isinstance(doc, dict) or not isinstance(doc.get('contract'), str) or not doc.get('contract')):
            note('missing_or_invalid', 'INVALID_COMPONENT_CONTRACT', name)
            del docs[name]
        elif doc is not None and doc['contract'] != CONTRACT:
            note('unsupported', 'UNKNOWN_COMPONENT_CONTRACT', name)
            del docs[name]  # Never interpret an unknown contract using this profile's rules.
    # Use installed, pinned local VATE code, never execute code from the bundle.
    checker = stage('REFERENCE_SOURCE_UNAVAILABLE', recipient)
    if checker is not None:
        linkage = stage('RECEIPT_CHECK_FAILED', lambda: checker.assess(b.raw.get('admission.json'), b.raw.get('post.json')))
        if linkage:
            out['receipt_check'] = linkage  # Preserve the original not_checked and reason codes.
            out['record_linkage'] = linkage['record_linkage']
            if linkage['record_linkage'] == 'mismatch':
                note('contradiction', 'RECEIPT_LINKAGE_MISMATCH', linkage['core_result'])
            elif linkage['record_linkage'] == 'not_assessed':
                note('missing_or_invalid', 'RECEIPT_NOT_ASSESSED', linkage['input_issues'])

    for name in ('admission.json', 'post.json'):
        doc = docs.get(name)
        if doc is None:
            continue
        if checker is None or not isinstance(doc, dict) or not all(isinstance(doc.get(k), str) and doc[k] for k in ('version', 'profile')):
            note('missing_or_invalid', 'RECEIPT_PROFILE_UNAVAILABLE', name)
            del docs[name]
        elif doc['version'] != checker.core.VERSION or doc['profile'] != checker.core.PROFILE:
            note('unsupported', 'UNKNOWN_RECEIPT_PROFILE', name)
            del docs[name]
    effective = docs.get('effective-request.json')
    admission = docs.get('admission.json')
    attempt = docs.get('attempt.json')
    post = docs.get('post.json')
    if isinstance(trust.get('contract'), str) and trust['contract'] and trust['contract'] != CONTRACT:
        note('unsupported', 'UNKNOWN_RECEIVER_POLICY_CONTRACT')
        trust = {}  # Do not use unknown policy targets or identities in known-contract comparisons.

    target_policy = None
    def check_trust():
        nonlocal target_policy
        exact(trust, ('contract', 'collector_id', 'store_id', 'endpoint_profile_id', 'endpoint', 'bucket', 'source_hashes', 'accept_local_unsigned'), 'receiver policy')
        need(trust['contract'] == CONTRACT, 'invalid receiver policy contract')
        need(all(isinstance(trust[k], str) and trust[k] for k in ('endpoint', 'endpoint_profile_id', 'bucket')), 'invalid receiver target')
        target_policy = trust
        need(trust['accept_local_unsigned'] is True, 'local trust not accepted')
        need(trust['collector_id'] == COLLECTOR and trust['store_id'] == 'seaweedfs-4.48-530be3e', 'unsupported local source')
        expected = sources()
        need(trust['source_hashes'] == expected and set(expected) == set(SOURCE_PATHS), 'receiver source pins differ')
        need(docs.get('sources.json') == expected, 'capture source missing/different')
        out['source_trust'] = 'accepted_local_assumption'
        return True
    stage('SOURCE_TRUST_UNVERIFIED', check_trust)

    def read_request(prefix):
        q = docs.get(prefix + '-request.json')
        need(q is not None, prefix + ' request missing')
        exact(q, ('contract', 'collector_id', 'exchange_id', 'method', 'endpoint', *('endpoint_profile_id', 'bucket', 'key'),
                  'requested_version_id', 'headers', 'body_ref', 'attempt_ref', 'requested_at'), prefix + ' request')
        return q
    requests = {prefix: stage(prefix.upper() + '_REQUEST_UNAVAILABLE', lambda p=prefix: read_request(p)) for prefix in ('put', 'get')}
    for prefix, q in requests.items():
        if q is not None and target_policy:
            compare(q['endpoint'] == target_policy['endpoint'] and q['endpoint_profile_id'] == target_policy['endpoint_profile_id'],
                    'attempt_binding' if prefix == 'put' else 'target_observation', prefix.upper() + '_ENDPOINT_MISMATCH')

    def check_admission():
        need(checker is not None and effective is not None and admission is not None, 'request/admission/core unavailable')
        validate_effective(effective)
        permit = docs.get('permit.json')
        need(permit is not None, 'permit preimage missing')
        req, decision, expected_admission = mint(effective, permit, admission['issued_at'], checker)
        ok = compare(same(admission, expected_admission), 'request_binding', 'ADMISSION_PREIMAGE_MISMATCH')
        for name, expected in (('admission-request.json', req), ('admission-decision.json', decision)):
            if name not in docs:
                note('missing_or_invalid', 'ADMISSION_ORIGINAL_UNAVAILABLE', name)
                ok = False
            else:
                ok = compare(same(docs[name], expected), 'request_binding', name + '_MISMATCH') and ok
        return ok
    admission_ok = stage('ADMISSION_NOT_ASSESSED', check_admission)

    def check_request():
        # Missing authorization evidence must not suppress independently visible contradictions.
        need(effective is not None, 'effective request unavailable')
        validate_effective(effective)
        ok = True
        sent, q = b.raw.get('put-body.bin'), requests['put']
        if sent is None:
            note('missing_or_invalid', 'REQUEST_BODY_UNAVAILABLE')
            ok = False
        else:
            ok = compare(len(sent) == effective['byte_length'] and digest(sent) == effective['body_digest'], 'request_binding', 'REQUEST_BODY_MISMATCH') and ok
        if q is None:
            note('missing_or_invalid', 'REQUEST_CAPTURE_UNAVAILABLE')
            ok = False
        else:
            ok = compare(q['method'] == 'PUT' and target(q) == target(effective) and q['requested_version_id'] is None
                         and q['headers'] == ['If-None-Match: *'], 'request_binding', 'CAPTURED_REQUEST_MISMATCH') and ok
            if sent is not None:
                ok = compare(b.ref_ok(q['body_ref'], 'put-body.bin'), 'request_binding', 'REQUEST_BODY_REFERENCE_MISMATCH') and ok
            if target_policy:
                ok = compare(q['endpoint'] == target_policy['endpoint'] and effective['endpoint_profile_id'] == target_policy['endpoint_profile_id']
                             and effective['bucket'] == target_policy['bucket'], 'request_binding', 'RECEIVER_TARGET_MISMATCH') and ok
        if post is not None:
            ok = compare(post['execution']['effective_request_hash'] == object_hash(effective), 'request_binding', 'POST_REQUEST_HASH_MISMATCH') and ok
        if ok and admission_ok:
            out['request_binding'] = 'matched'
        return ok
    stage('REQUEST_NOT_ASSESSED', check_request)

    def check_attempt():
        need(isinstance(attempt, dict) and effective is not None, 'attempt inputs missing')
        exact(attempt, ('contract', 'operation_id', 'attempt_id', 'transaction_id', 'runtime', 'collector_id',
                        'admission_digest', 'effective_request_hash', *target(effective).keys(), 'body_ref', 'created_at'), 'attempt')
        need(attempt['contract'] == CONTRACT, 'unknown attempt contract')
        ok = compare(attempt['operation_id'] == attempt['transaction_id'] == effective['operation_id']
                     and attempt['runtime'] == RUNTIME
                     and attempt['effective_request_hash'] == object_hash(effective)
                     and target(attempt) == target(effective),
                     'attempt_binding', 'ATTEMPT_CONTEXT_MISMATCH')
        need(isinstance(attempt['attempt_id'], str) and attempt['attempt_id'], 'missing attempt ID')
        if 'put-body.bin' in b.raw:
            ok = compare(b.ref_ok(attempt['body_ref'], 'put-body.bin'), 'attempt_binding', 'ATTEMPT_BODY_REFERENCE_MISMATCH') and ok
        else:
            note('missing_or_invalid', 'ATTEMPT_BODY_UNAVAILABLE')
            ok = False
        if admission is not None:
            ok = compare(attempt['runtime'] == admission['subject']['runtime'] and attempt['admission_digest'] == digest(encode(admission)),
                         'attempt_binding', 'ATTEMPT_ADMISSION_MISMATCH') and ok
            ok = compare(time_value(admission['issued_at']) <= time_value(attempt['created_at']) <= time_value(admission['expires_at']),
                         'attempt_binding', 'ATTEMPT_TIME_MISMATCH') and ok
        else:
            note('missing_or_invalid', 'ATTEMPT_ADMISSION_UNAVAILABLE')
            ok = False
        if attempt['collector_id'] != trust.get('collector_id'):
            out['source_trust'] = 'unverified'
            note('missing_or_invalid', 'ATTEMPT_COLLECTOR_UNTRUSTED')
        return ok
    attempt_ok = stage('ATTEMPT_NOT_ASSESSED', check_attempt)

    def transport(prefix):
        q = requests[prefix]
        t = docs.get(prefix + '-transport.json')
        need(t is not None, prefix + ' transport missing')
        exact(t, ('contract', 'collector_id', 'request_ref', 'attempt_ref', 'started_at', 'finished_at',
                  'curl_exit', 'http_status', 'headers_ref', 'body_ref', 'returned_version_id', 'invocation_error', 'validation_errors'), prefix + ' transport')
        output_name = 'put-response-body.bin' if prefix == 'put' else 'get-body.bin'
        refs = [('request_ref', prefix + '-request.json'), ('headers_ref', prefix + '-headers.txt'), ('body_ref', output_name)]
        stage_name = 'attempt_binding' if prefix == 'put' else 'target_observation'
        good = q is not None
        for field, name in refs:
            if name in b.raw:
                good = compare(b.ref_ok(t[field], name), stage_name, prefix.upper() + '_RAW_REFERENCE_MISMATCH') and good
            else:
                note('missing_or_invalid', prefix.upper() + '_RAW_ARTIFACT_UNAVAILABLE', name)
                good = False
        need(isinstance(t['validation_errors'], list), 'invalid validation_errors')
        if (q is not None and q['collector_id'] != trust.get('collector_id')) or t['collector_id'] != trust.get('collector_id'):
            out['source_trust'] = 'unverified'
            note('missing_or_invalid', prefix.upper() + '_COLLECTOR_UNTRUSTED')
        h = stage(prefix.upper() + '_HEADERS_UNAVAILABLE', lambda: parse_headers(b.raw[prefix + '-headers.txt']))
        # A timed-out capture can retain response headers but no curl write-out status.
        if h is not None:
            good = compare((t['http_status'] is None or h['status'] == t['http_status'])
                           and h['version_id'] == t['returned_version_id'],
                           stage_name, prefix.upper() + '_HEADER_TRANSCRIPTION_MISMATCH') and good
        else:
            good = False
        transfer_complete = (type(t['curl_exit']) is int and t['curl_exit'] == 0
                             and t['invocation_error'] is None and t['validation_errors'] == [])
        if transfer_complete and h is not None and h['content_length'] is not None and output_name in b.raw:
            good = compare(h['content_length'] == len(b.raw[output_name]), stage_name, prefix.upper() + '_BODY_LENGTH_MISMATCH') and good
        good = compare(time_value(t['started_at']) <= time_value(t['finished_at']),
                       stage_name, prefix.upper() + '_LOCAL_TIME_MISMATCH') and good
        if q is not None:
            good = compare(time_value(q['requested_at']) <= time_value(t['started_at']), stage_name, prefix.upper() + '_REQUEST_TIME_MISMATCH') and good
        if prefix == 'put':
            if 'attempt.json' in b.raw:
                good = compare(b.ref_ok(t['attempt_ref'], 'attempt.json') and (q is None or b.ref_ok(q['attempt_ref'], 'attempt.json')),
                               stage_name, 'PUT_ATTEMPT_REFERENCE_MISMATCH') and good
            else:
                note('missing_or_invalid', 'PUT_ATTEMPT_ORIGINAL_UNAVAILABLE')
                good = False
            if attempt is not None and q is not None:
                good = compare(q['exchange_id'] == attempt['attempt_id'] and time_value(attempt['created_at']) <= time_value(t['started_at']),
                               stage_name, 'PUT_ATTEMPT_CONTEXT_MISMATCH') and good
        else:
            good = compare(t['attempt_ref'] is None, stage_name, 'GET_TRANSPORT_ATTEMPT_REFERENCE_MISMATCH') and good
        # Response status/version can still be compared if a body original was not disclosed.
        # Missing raw files keep good=False; full observation additionally requires body bytes.
        usable = q is not None and h is not None and transfer_complete and t['http_status'] == 200
        if not usable:
            note('native_not_observed', prefix.upper() + '_UNUSABLE_RESPONSE',
                 {k: t[k] for k in ('curl_exit', 'http_status', 'invocation_error', 'validation_errors')})
        return q, t, good, usable

    put = stage('PUT_TRANSPORT_UNAVAILABLE', lambda: transport('put'))
    get = stage('GET_OBSERVATION_UNAVAILABLE', lambda: transport('get'))
    def check_observation():
        q = requests['get']
        need(q is not None, 'GET request unavailable')
        good = compare(q['method'] == 'GET' and q['headers'] == [] and q['body_ref'] is None and q['attempt_ref'] is None,
                       'target_observation', 'GET_METHOD_OR_REFERENCE_MISMATCH')
        need(effective is not None, 'effective request unavailable')
        good = compare(target(q) == target(effective), 'target_observation', 'GET_TARGET_MISMATCH') and good
        need(get is not None, 'GET transport unavailable')
        _, t, transport_good, usable = get
        good = transport_good and good
        selector, version = q['requested_version_id'], t['returned_version_id']
        out['version_scope'] = 'latest_at_observed_time' if selector is None else 'specified_version'
        if not usable:
            return False
        need(isinstance(version, str) and version not in ('', 'null'), 'GET native version missing')
        need(selector is None or (isinstance(selector, str) and selector not in ('', 'null')), 'invalid GET version selector')
        good = compare(selector is None or selector == version, 'target_observation', 'GET_VERSION_SELECTOR_MISMATCH') and good
        body = b.raw['get-body.bin']
        good = compare(type(effective['byte_length']) is int and len(body) <= MAX_BODY
                       and len(body) == effective['byte_length'] and digest(body) == effective['body_digest'],
                       'target_observation', 'OBSERVED_BODY_MISMATCH') and good
        if good and out['target_observation'] != 'mismatch':
            out['target_observation'] = 'matched'
        return good
    observed = stage('OBSERVATION_NOT_ASSESSED', check_observation)

    def link_attempt():
        need(put is not None and get is not None, 'response linkage unavailable')
        pq, pt, pg, pu = put
        gq, gt, gg, gu = get
        need(pu and gu, 'response not usable for attempt linkage')
        version = pt['returned_version_id']
        need(isinstance(version, str) and version not in ('', 'null'), 'PUT native version missing')
        need(isinstance(gt['returned_version_id'], str) and gt['returned_version_id'] not in ('', 'null'), 'GET native version missing')
        if gq['requested_version_id'] is None:
            note('missing_or_invalid', 'LATEST_GET_DOES_NOT_BIND_ORIGINAL_ATTEMPT')
            return False
        ok = compare(version == gq['requested_version_id'] == gt['returned_version_id']
                     and target(pq) == target(gq), 'attempt_binding', 'PUT_GET_VERSION_TARGET_MISMATCH')
        if attempt is not None:
            ok = compare(target(pq) == target(attempt), 'attempt_binding', 'RESPONSE_ATTEMPT_TARGET_MISMATCH') and ok
        ok = compare(time_value(pt['finished_at']) <= time_value(gt['started_at']), 'attempt_binding', 'GET_PRECEDES_PUT_RESPONSE') and ok
        if admission is not None:
            ok = compare(time_value(admission['issued_at']) <= time_value(pt['started_at']) <= time_value(pt['finished_at']) <= time_value(admission['expires_at']),
                         'attempt_binding', 'CAPTURED_EXECUTION_OUTSIDE_ADMISSION') and ok
        if not attempt_ok:
            note('missing_or_invalid', 'RESPONSE_ATTEMPT_CONTEXT_UNVERIFIED')
        if ok and attempt_ok and pg and gg and out['attempt_binding'] != 'mismatch':
            out['attempt_binding'] = 'response_linked'
        return ok
    stage('ATTEMPT_LINKAGE_UNKNOWN', link_attempt)

    def check_post():
        need(post is not None, 'post not supplied')
        outcome = post['result']['outcome']
        if outcome != 'success':
            out['post_observation_binding'] = 'unsupported'
            note('unsupported', 'POST_RESULT_PROFILE_UNSUPPORTED', outcome)
            return
        need(put is not None and get is not None and observed and attempt is not None and admission is not None, 'post observation inputs incomplete')
        need(put[3] and get[3], 'post observation lacks usable responses')
        pt, gt = put[1], get[1]
        expected = make_post(admission, attempt, pt, gt, b.raw['get-body.bin'])
        ok = compare(same(post['result'], expected['result']), 'post_observation_binding', 'POST_RESULT_PROJECTION_MISMATCH')
        ok = compare(same(post['execution'], expected['execution']), 'post_observation_binding', 'POST_EXECUTION_PROJECTION_MISMATCH') and ok
        ok = compare(time_value(post['issued_at']) >= time_value(gt['finished_at']), 'post_observation_binding', 'POST_PRECEDES_OBSERVATION') and ok
        if ok:
            out['post_observation_binding'] = 'matched'
    stage('POST_OBSERVATION_NOT_ASSESSED', check_post)

    if any(d['kind'] == 'contradiction' for d in diagnostics):
        out['assessment'] = 'contradictory'
    elif any(d['kind'] == 'unsupported' for d in diagnostics):
        out['assessment'] = 'unsupported'
    elif (all(out[k] == 'matched' for k in ('record_linkage', 'request_binding', 'target_observation', 'post_observation_binding'))
          and out['attempt_binding'] == 'response_linked' and out['source_trust'] == 'accepted_local_assumption'
          and out['version_scope'] == 'specified_version' and not diagnostics):
        out['assessment'] = 'supported_under_local_assumptions'
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--trust', type=Path, required=True, help='Receiver-selected policy outside the bundle')
    args = parser.parse_args()
    try:
        need(not args.trust.resolve().is_relative_to(args.bundle.resolve()), 'trust policy must be supplied outside the bundle')
        with args.trust.open('rb') as f:
            trust = decode(f.read(256 * 1024 + 1))
        need(isinstance(trust, dict), 'trust policy object required')
        value = assess(args.bundle, trust)
    except (Invalid, OSError, ValueError) as exc:
        value = {'assessment': 'insufficient', 'diagnostics': [{'kind': 'receiver_configuration', 'detail': str(exc)}], 'retry_authorized': False}
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return {'supported_under_local_assumptions': 0, 'contradictory': 1, 'insufficient': 2, 'unsupported': 3}[value['assessment']]


if __name__ == '__main__':
    raise SystemExit(main())
