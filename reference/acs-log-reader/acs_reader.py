"""Offline ACS capture reader. Observations only; no execution or trust decision."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
import re
import stat
import sys

PROFILE = 'vate-local-acs-log-reader-v1'
SOURCES = ('host_audit', 'guardian_envelopes', 'host_events', 'proxy')
COMMAND_TIMESTAMP_SOURCES = ('command_start', 'command_end')
REQUEST = 'steps/toolCallRequest'
RESULT = 'steps/toolCallResult'
MAX_BYTES = 1024 * 1024
MAX_LINE = 65536
MAX_ROWS = 512
MAX_DEPTH = 32
MAX_RELATION_RECORDS = 1024
MAX_INTEGER = 9007199254740991


class InputError(ValueError):
    def __init__(self, code, source, line=None):
        self.code, self.source, self.line = code, source, line
        super().__init__(code)

    def report(self):
        return {'kind': 'acs-log-reader-error', 'status': 'invalid_input',
                'reason': self.code, 'input': self.source, 'line': self.line}


def need(ok, code, source, line=None):
    if not ok:
        raise InputError(code, source, line)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def identifier(value):
    return type(value) is str and 0 < len(value) <= 256 and not re.search(r'[\x00-\x20\x7f]', value)


def parse_json(raw, source, line=None):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'INVALID_BYTES_OR_SIZE', source, line)

    def pairs(items):
        obj = {}
        for key, value in items:
            need(key not in obj, 'DUPLICATE_JSON_KEY', source, line)
            obj[key] = value
        return obj

    def integer(token):
        need(len(token) <= 17, 'NUMBER_OUT_OF_RANGE', source, line)
        value = int(token)
        need(abs(value) <= MAX_INTEGER, 'NUMBER_OUT_OF_RANGE', source, line)
        return value

    def decimal(token):
        need(len(token) <= 100, 'NUMBER_OUT_OF_RANGE', source, line)
        value = Decimal(token)
        # copy_abs is exact and context-free; abs() may round or overflow first.
        need(value.is_finite() and value.copy_abs() <= MAX_INTEGER, 'NUMBER_OUT_OF_RANGE', source, line)
        return value

    def constant(_):
        raise InputError('NONFINITE_NUMBER', source, line)

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_int=integer, parse_float=decimal, parse_constant=constant)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            need(depth <= MAX_DEPTH, 'JSON_DEPTH', source, line)
            if type(item) is dict:
                pending.extend((part, depth + 1) for pair in item.items() for part in pair)
            elif type(item) is list:
                pending.extend((part, depth + 1) for part in item)
            elif type(item) is str:
                item.encode('utf-8')
        need(type(value) is dict, 'EXPECTED_OBJECT', source, line)
        return value
    except InputError:
        raise
    except (UnicodeError, ValueError, RecursionError, InvalidOperation, OverflowError):
        raise InputError('INVALID_JSON', source, line) from None


def read_jsonl(raw, name):
    if raw is None:
        return [], {'state': 'absent'}
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'INVALID_BYTES_OR_SIZE', name)
    # Split only on JSONL's LF, not arbitrary Unicode or control-character separators.
    lines = raw.split(b'\n')
    if lines[-1] == b'':
        lines.pop()
    need(0 < len(lines) <= MAX_ROWS, 'ROW_LIMIT', name)
    result = []
    for index, line in enumerate(lines, 1):
        need(0 < len(line) <= MAX_LINE, 'INVALID_LINE_SIZE', name, index)
        value = parse_json(line, name, index)
        result.append((value, {'input': name, 'line': index, 'line_raw_sha256': digest(line)}))
    return result, {'state': 'present', 'raw_sha256': digest(raw), 'byte_length': len(raw), 'rows': len(lines)}


def text(value, ref, *, optional=False):
    if optional and value is None:
        return None
    need(identifier(value), 'INVALID_IDENTIFIER', ref['input'], ref['line'])
    return value


def timestamp(value, ref):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value),
         'INVALID_TIMESTAMP', ref['input'], ref['line'])
    try:
        datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise InputError('INVALID_TIMESTAMP', ref['input'], ref['line']) from None
    return value


def millis(value, ref):
    need(type(value) is int and 0 <= value <= MAX_INTEGER, 'INVALID_EPOCH_MS', ref['input'], ref['line'])
    try:
        # Integer arithmetic avoids float rounding in source-time comparisons.
        sec, remainder = divmod(value, 1000)
        dt = datetime.fromtimestamp(sec, timezone.utc).replace(microsecond=remainder * 1000)
    except (ValueError, OSError, OverflowError):
        raise InputError('INVALID_EPOCH_MS', ref['input'], ref['line']) from None
    return dt.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def read_command_timestamp(raw, name):
    if raw is None:
        return [], {'state': 'absent'}
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'INVALID_BYTES_OR_SIZE', name)
    # Preserve raw line identity, including CR in CRLF, just like JSONL sources.
    line = raw[:-1] if raw.endswith(b'\n') else raw
    need(b'\n' not in line, 'EXPECTED_SINGLE_TIMESTAMP', name, 1)
    need(0 < len(line) <= MAX_LINE, 'INVALID_LINE_SIZE', name, 1)
    value_bytes = line[:-1] if raw.endswith(b'\r\n') else line
    try:
        value = value_bytes.decode('ascii')
    except UnicodeError:
        raise InputError('INVALID_TIMESTAMP', name, 1) from None
    need(re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', value),
         'INVALID_TIMESTAMP', name, 1)
    try:
        # Constructor ranges are stable across Python versions; some ISO
        # parsers normalize 24:00:00. Keep that spelling outside this format.
        datetime(int(value[:4]), int(value[5:7]), int(value[8:10]),
                 int(value[11:13]), int(value[14:16]), int(value[17:19]))
    except ValueError:
        raise InputError('INVALID_TIMESTAMP', name, 1) from None
    ref = {'input': name, 'line': 1, 'line_raw_sha256': digest(line)}
    return [{'source': ref, 'reported_at': value, 'supported': True}], {
        'state': 'present', 'raw_sha256': digest(raw), 'byte_length': len(raw), 'rows': 1}


def timestamp_nanoseconds(value):
    """Exact arithmetic for already validated UTC timestamps, without floats."""
    seconds, _, fraction = value[:-1].partition('.')
    dt = datetime.fromisoformat(seconds)
    whole = ((dt.toordinal() * 24 + dt.hour) * 60 + dt.minute) * 60 + dt.second
    return whole * 1000000000 + int(fraction.ljust(9, '0'))


def command_wall_order(first, second):
    if first is None or second is None:
        return {'status': 'unresolved', 'reason': 'UNIQUE_SUPPORTED_OBSERVATIONS_REQUIRED'}
    delta = timestamp_nanoseconds(second) - timestamp_nanoseconds(first)
    return {'status': 'observed_timestamp_order',
            'relation': 'after' if delta > 0 else 'before' if delta < 0 else 'equal',
            # Decimal text avoids lossy JSON-number conversion for large intervals.
            'delta_nanoseconds': str(delta),
            'clock_basis': 'source_wall_clocks_not_independently_verified',
            'association_basis': 'receiver_supplied_files_only',
            'same_execution_proven': False, 'host_arrival_or_dispatch_order_proven': False}


def obj(value, ref):
    need(type(value) is dict, 'INVALID_RECORD_SHAPE', ref['input'], ref['line'])
    return value


def rpc_ids(row):
    envelope = row.get('envelope')
    return [row.get('rpc_id'), envelope.get('id') if type(envelope) is dict else None]


def ids(row):
    values = rpc_ids(row)
    envelope = row.get('envelope')
    if type(envelope) is not dict:
        return values
    # Hello responses have no defined inner request_id. An unknown extension
    # must not select a different RPC exchange through this field.
    if row.get('direction') == 'response' and row.get('method') == 'handshake/hello':
        return values
    inner = envelope.get('params') if row.get('direction') == 'request' else envelope.get('result')
    return values + [inner.get('request_id') if type(inner) is dict else None]


def envelope(row, ref):
    rpc = text(row.get('rpc_id'), ref)
    method = text(row.get('method'), ref)
    env = obj(row.get('envelope'), ref)
    need(env.get('jsonrpc') == '2.0' and env.get('id') == rpc, 'INCONSISTENT_RPC_ID', ref['input'], ref['line'])
    timestamp(row.get('recorded_at'), ref)
    direction = row.get('direction')
    need(direction in ('request', 'response'), 'INVALID_DIRECTION', ref['input'], ref['line'])
    if direction == 'request':
        need(env.get('method') == method and 'result' not in env and 'error' not in env,
             'INCONSISTENT_RPC_METHOD', ref['input'], ref['line'])
        body = obj(env.get('params'), ref)
        need(body.get('request_id') == rpc, 'INCONSISTENT_RPC_ID', ref['input'], ref['line'])
        metadata = obj(body.get('metadata'), ref)
        session = text(metadata.get('session_id'), ref)
        payload = obj(body.get('payload'), ref)
        timestamp(body.get('timestamp'), ref)
        return env, body, payload, session
    need('method' not in env and ('result' in env) != ('error' in env), 'INVALID_RESPONSE', ref['input'], ref['line'])
    if 'error' in env:
        obj(env['error'], ref)
        return env, None, None, None
    body = obj(env['result'], ref)
    if method != 'handshake/hello':
        need(body.get('request_id') == rpc, 'INCONSISTENT_RPC_ID', ref['input'], ref['line'])
    return env, body, None, None


def group(records, source):
    status = ('unavailable' if source['state'] == 'absent' else 'not_observed') if not records else (
        'ambiguous' if len(records) > 1 else 'observed' if records[0]['supported'] else 'not_assessed')
    return {'status': status, 'records': records}


def sole(grouped):
    return grouped['records'][0] if grouped['status'] == 'observed' else None


def wall_order(first, second):
    if first is None or second is None:
        return {'status': 'unresolved', 'reason': 'UNIQUE_SUPPORTED_OBSERVATIONS_REQUIRED'}
    delta = datetime.fromisoformat(second.replace('Z', '+00:00')) - datetime.fromisoformat(first.replace('Z', '+00:00'))
    micros = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
    return {'status': 'observed_timestamp_order', 'relation': 'after' if micros > 0 else 'before' if micros < 0 else 'equal',
            'delta_microseconds': micros, 'clock_basis': 'source_wall_clocks_not_independently_verified',
            'host_arrival_or_dispatch_order_proven': False}


def guardian_sequence_numbers(records):
    """Check the supplied log's optional sequence without repairing or sorting it."""
    numbers, previous, reason = {}, None, None
    for row, ref in records:
        value = row.get('seq')
        if type(value) is not int or not 0 <= value <= MAX_INTEGER:
            reason = reason or ('MISSING_GUARDIAN_SEQUENCE' if 'seq' not in row else 'INVALID_GUARDIAN_SEQUENCE')
            continue
        numbers[ref['line']] = value
        if previous is not None and value <= previous:
            reason = reason or 'NON_INCREASING_GUARDIAN_SEQUENCE'
        previous = value
    return numbers, reason


def guardian_log_order(request, hook, numbers, sequence_reason):
    """Compare log observations, without associating a result with an action."""
    unresolved = {'status': 'unresolved', 'reason': 'UNIQUE_SUPPORTED_OBSERVATIONS_REQUIRED'}
    request_line = request['source']['line'] if request else None
    result_line = hook['source']['line']
    order = {'selected_request_source': request['source'] if request else None,
             'selected_request_seq': numbers.get(request_line), 'result_seq': numbers.get(result_line),
             'file_order': dict(unresolved), 'sequence_order': dict(unresolved),
             'recorded_time_order': wall_order(None, None),
             'scope': 'supplied_guardian_log_only', 'same_action_proven': False}
    if request is None or not hook['supported']:
        return order
    order['file_order'] = {'status': 'observed_file_order',
                           'relation': 'before' if result_line < request_line else 'after',
                           'clock_comparison_required': False}
    if sequence_reason is None:
        order['sequence_order'] = {'status': 'observed_sequence_order',
            'relation': 'before' if numbers[result_line] < numbers[request_line] else 'after',
            'clock_comparison_required': False}
    else:
        order['sequence_order'] = {'status': 'unresolved', 'reason': sequence_reason}
    order['recorded_time_order'] = wall_order(request['recorded_at'], hook['recorded_at'])
    return order


def assess(inputs, selection_raw, *, command_timestamps=None):
    need(type(inputs) is dict and set(inputs) == set(SOURCES), 'INVALID_INPUT_SET', 'inputs')
    if command_timestamps is not None:
        need(type(command_timestamps) is dict and len(command_timestamps) == 2
             and all(name in command_timestamps for name in COMMAND_TIMESTAMP_SOURCES),
             'INVALID_COMMAND_TIMESTAMP_SET', 'command_timestamps')
    selection = parse_json(selection_raw, 'selection')
    need(set(selection) == {'profile', 'request_id', 'acs_session_id', 'host_session_id'}, 'INVALID_SELECTION', 'selection')
    need(selection['profile'] == PROFILE, 'UNSUPPORTED_PROFILE', 'selection')
    need(all(identifier(selection[k]) for k in ('request_id', 'acs_session_id', 'host_session_id')), 'INVALID_SELECTION_ID', 'selection')
    records, sources = {}, {}
    for name in SOURCES:
        records[name], sources[name] = read_jsonl(inputs[name], name)
    target = selection['request_id']
    host, requests, decisions, hooks, executions, proxy, handshakes, hellos = [], [], [], [], [], [], [], []
    grows = records['guardian_envelopes']
    # Validate recognized envelopes before direction/session selection. Otherwise
    # a corrupt direction can hide a conflicting request or response. Unknown
    # methods remain opaque; their inner IDs are not counted as RPC identities.
    for row, ref in grows:
        env = row.get('envelope')
        inner_method = env.get('method') if type(env) is dict else None
        if row.get('method') in (REQUEST, RESULT, 'handshake/hello') or inner_method in (REQUEST, RESULT, 'handshake/hello'):
            envelope(row, ref)
    relation_records = 0
    for row, ref in records['host_audit']:
        if row.get('rpc_id') != target:
            continue
        failure = obj(row.get('failure'), ref)
        posture, outcome = text(row.get('posture'), ref), text(row.get('outcome'), ref)
        host.append({'source': ref, 'recorded_at': timestamp(row.get('recorded_at'), ref),
                     'rpc_id': target, 'session_id': text(row.get('session_id'), ref),
                     'posture': posture, 'posture_source': text(row.get('posture_source'), ref),
                     'outcome': outcome, 'failure_kind': text(failure.get('kind'), ref),
                     'supported': row.get('method') == REQUEST and row['session_id'] == selection['host_session_id']
                     and (posture, outcome) in (('proceed', 'proceeded'), ('deny', 'blocked'))})

    for row, ref in grows:
        method = row.get('method')
        env_method = row.get('envelope', {}).get('method') if type(row.get('envelope')) is dict else None
        if target in ids(row) and (method == REQUEST or env_method == REQUEST):
            _, body, payload, session = envelope(row, ref)
            supported = body is not None and body.get('acs_version') == '0.1.0'
            if row['direction'] == 'request':
                tool = obj(payload.get('tool'), ref)
                command = payload.get('raw_command')
                need(command is None or type(command) is str, 'INVALID_COMMAND_SHAPE', ref['input'], ref['line'])
                requests.append({'source': ref, 'recorded_at': row['recorded_at'], 'rpc_id': target,
                                 'session_id': session, 'tool': text(tool.get('name'), ref),
                                 'command_sha256': digest(command.encode()) if command is not None else None,
                                 'supported': supported and session == selection['acs_session_id']})
            else:
                decision = body.get('decision') if body else None
                codes = body.get('reason_codes', []) if body else []
                need(type(codes) is list and len(codes) <= 64 and all(identifier(c) for c in codes),
                     'INVALID_REASON_CODES', ref['input'], ref['line'])
                decisions.append({'source': ref, 'recorded_at': row['recorded_at'], 'rpc_id': target,
                                  'decision': decision if decision in ('allow', 'deny', 'modify', 'ask', 'defer') else None,
                                  'reason_codes': codes, 'supported': supported and body.get('type') == 'final'
                                  and decision in ('allow', 'deny')})
        if (method == RESULT or env_method == RESULT) and row.get('direction') == 'request':
            _, body, payload, session = envelope(row, ref)
            if session != selection['acs_session_id']:
                continue
            hook_id = row['rpc_id']
            request_count = sum(1 for other, _ in grows if other.get('direction') == 'request' and hook_id in rpc_ids(other))
            replies = []
            for response, response_ref in grows:
                if response.get('method') == RESULT and response.get('direction') == 'response' and hook_id in ids(response):
                    relation_records += 1
                    need(relation_records <= MAX_RELATION_RECORDS, 'RELATION_LIMIT', 'guardian_envelopes')
                    _, value, _, _ = envelope(response, response_ref)
                    replies.append({'source': response_ref, 'recorded_at': response['recorded_at'],
                                    'decision': value.get('decision') if value and value.get('decision') in ('allow', 'deny') else None,
                                    'supported': value is not None and value.get('acs_version') == '0.1.0'
                                    and value.get('type') == 'final' and value.get('decision') in ('allow', 'deny')})
            response_group = group(replies, sources['guardian_envelopes'])
            if request_count > 1 and replies:
                response_group['status'] = 'ambiguous'
            response_association = {'status': 'matched_by_rpc_id' if request_count == 1
                and body.get('acs_version') == '0.1.0' and sole(response_group) else 'unresolved',
                'requests_with_same_rpc_id': request_count, 'authenticated': False}
            hooks.append({'source': ref, 'recorded_at': row['recorded_at'], 'result_rpc_id': hook_id,
                          'reported_exit_status': payload.get('exit_status') if payload.get('exit_status') in ('success', 'failure') else None,
                          'supported': body.get('acs_version') == '0.1.0' and request_count == 1,
                          'responses': response_group, 'response_association': response_association,
                          'request_binding': {'status': 'unresolved', 'reason': 'NO_SUPPORTED_ACTION_REFERENCE'},
                          'response_is_permission_for_original_request': False})
        if (method == 'handshake/hello' or env_method == 'handshake/hello') and row.get('direction') == 'request':
            _, body, _, session = envelope(row, ref)
            if session != selection['acs_session_id']:
                continue
            hello_id = row['rpc_id']
            replies = [(r, rref) for r, rref in grows if r.get('method') == 'handshake/hello'
                       and r.get('direction') == 'response' and hello_id in ids(r)]
            same_id_requests = [r for r, _ in grows if r.get('direction') == 'request' and hello_id in rpc_ids(r)]
            hellos.append({'source': ref, 'rpc_id': hello_id, 'recorded_at': row['recorded_at'],
                           'supported': body.get('acs_version') == '0.1.0' and len(same_id_requests) == 1,
                           'candidate_response_count': len(replies),
                           'response_observation': 'not_observed' if not replies else
                           'ambiguous' if len(replies) != 1 or len(same_id_requests) != 1 else 'candidate_present'})
            for reply, reply_ref in replies:
                relation_records += 1
                need(relation_records <= MAX_RELATION_RECORDS, 'RELATION_LIMIT', 'guardian_envelopes')
                _, value, _, _ = envelope(reply, reply_ref)
                timeout = value.get('timeout_config') if value else None
                fallback = value.get('on_decision_failure') if value else None
                timeout_supported = type(timeout) is dict and set(timeout) == {'default_ms'} and type(timeout['default_ms']) is int and 0 < timeout['default_ms'] <= MAX_INTEGER
                handshakes.append({'source': reply_ref, 'request_source': ref, 'rpc_id': hello_id,
                                   'on_decision_failure': fallback if fallback in ('proceed', 'deny') else None,
                                   'default_timeout_ms': timeout['default_ms'] if timeout_supported else None,
                                   'supported': len(same_id_requests) == 1 and body.get('acs_version') == '0.1.0'
                                   and value is not None and value.get('negotiated_version') == '0.1.0'
                                   and fallback in ('proceed', 'deny') and timeout_supported})

    request_group = group(requests, sources['guardian_envelopes'])
    request = sole(request_group)
    for row, ref in records['host_events']:
        if row.get('type') != 'tool_use' or row.get('sessionID') != selection['host_session_id']:
            continue
        part = obj(row.get('part'), ref)
        need(part.get('type') == 'tool', 'INCONSISTENT_HOST_EVENT_TYPE', ref['input'], ref['line'])
        need(part.get('sessionID') == row['sessionID'], 'INCONSISTENT_HOST_SESSION', ref['input'], ref['line'])
        state = obj(part.get('state'), ref)
        tool_input, timing = obj(state.get('input'), ref), obj(state.get('time'), ref)
        metadata = obj(state.get('metadata'), ref)
        start, end = millis(timing.get('start'), ref), millis(timing.get('end'), ref)
        need(timing['end'] >= timing['start'], 'REVERSED_TOOL_INTERVAL', ref['input'], ref['line'])
        command = tool_input.get('command')
        need(command is None or type(command) is str, 'INVALID_COMMAND_SHAPE', ref['input'], ref['line'])
        exit_code = metadata.get('exit')
        need(exit_code is None or type(exit_code) is int, 'INVALID_EXIT_CODE', ref['input'], ref['line'])
        tool = text(part.get('tool'), ref)
        same_command = None
        if request and request['tool'] == tool == 'bash' and command is not None and request['command_sha256'] is not None:
            same_command = request['command_sha256'] == digest(command.encode())
        executions.append({'source': ref, 'host_call_id': text(part.get('callID'), ref), 'tool': tool,
                           'reported_status': text(state.get('status'), ref), 'reported_exit_code': exit_code,
                           'reported_tool_start': start, 'reported_tool_end': end,
                           'command_text_matches_selected_request': same_command,
                           'candidate_only': True, 'request_binding': 'unresolved', 'actual_dispatch_at': None,
                           'basis': 'host_reported_tool_interval_may_include_guardian_wait'})
    for row, ref in records['proxy']:
        if row.get('rpc_id') != target or row.get('method') != REQUEST:
            continue
        proxy.append({'source': ref, 'recorded_at': timestamp(row.get('t_wall'), ref),
                      'event': text(row.get('event'), ref),
                      'reported_decision': row.get('decision') if row.get('decision') in ('allow', 'deny') else None})

    host_group, decision_group = group(host, sources['host_audit']), group(decisions, sources['guardian_envelopes'])
    handshake_group = group(handshakes, sources['guardian_envelopes'])
    h, d, negotiated = sole(host_group), sole(decision_group), sole(handshake_group)
    # Reused RPC IDs, even under another method/session, cannot establish a unique response association.
    all_target_requests = [r for r, _ in grows if r.get('direction') == 'request' and target in rpc_ids(r)]
    unique = request is not None and len(all_target_requests) == 1
    sequence_numbers, sequence_reason = guardian_sequence_numbers(grows)
    for hook in hooks:
        hook['order_vs_selected_request'] = guardian_log_order(
            request if unique else None, hook, sequence_numbers, sequence_reason)
    binding = {'status': 'matched_by_rpc_id' if h and d and unique else 'unresolved',
               'assurance': 'identifier_equality_with_receiver_selected_sessions_only', 'authenticated': False}
    fallback_match = {'status': 'matched_by_value' if h and negotiated and h['posture_source'] == 'negotiated'
                      and h['posture'] == negotiated['on_decision_failure'] else 'not_assessed', 'authenticated': False}
    if h and negotiated and h['posture_source'] == 'negotiated' and h['posture'] != negotiated['on_decision_failure']:
        fallback_match['status'] = 'mismatched'
    report = {'kind': 'acs-log-reading-report', 'profile': PROFILE,
            'selection': {**selection, 'raw_sha256': digest(selection_raw)}, 'sources': sources,
            'scope': 'selected_fields_of_supplied_capture_files_only',
            'host_effective_decision': host_group, 'guardian_request': request_group,
            'guardian_decision': decision_group, 'negotiated_fallback': handshake_group,
            'hello_request_observations': hellos,
            'result_hook_observations': hooks, 'execution_observations': executions, 'proxy_observations': proxy,
            'bindings': {'host_and_guardian_request': binding, 'fallback_and_handshake': fallback_match,
                         'request_to_execution': {'status': 'unresolved', 'reason': 'NO_SUPPORTED_ACTION_REFERENCE'},
                         'request_to_result': {'status': 'unresolved', 'reason': 'NO_SUPPORTED_ACTION_REFERENCE'}},
            'timing': {'guardian_response_vs_host_fallback_log': wall_order(
                h['recorded_at'] if h and unique and d else None, d['recorded_at'] if d else None),
                'decision_committed_at': None, 'dispatch_at': None,
                'commit_rule': 'unknown', 'host_received_late_decision': 'unknown',
                'source_times_are_receiver_arrival_times': False},
            'not_assessed': ['signature', 'issuer_authority', 'clock_synchronization', 'log_completeness',
                             'independent_execution', 'execution_permission', 'retry_permission', 'acs_conformance'],
            'no_execution_ticket': True}
    # Opt-in extension: omitting timestamps adds no command-timestamp fields.
    if command_timestamps is not None:
        stamps = {}
        for name in COMMAND_TIMESTAMP_SOURCES:
            observations, sources[name] = read_command_timestamp(command_timestamps[name], name)
            stamps[name] = group(observations, sources[name])
        start, end = (sole(stamps[name]) for name in COMMAND_TIMESTAMP_SOURCES)
        start_at, end_at = (record['reported_at'] if record else None for record in (start, end))
        report['command_self_timestamps'] = {
            'start': stamps['command_start'], 'end': stamps['command_end'],
            'association_basis': 'receiver_supplied_files_only',
            'pair_binding': 'unresolved', 'request_binding': 'unresolved', 'execution_binding': 'unresolved'}
        report['timing']['command_self_timestamp_comparisons'] = {
            'start_vs_host_fallback_log': command_wall_order(h['recorded_at'] if h else None, start_at),
            'end_vs_start': command_wall_order(start_at, end_at),
            'guardian_response_vs_start': command_wall_order(start_at, d['recorded_at'] if d and unique else None)}
    return report


def read_file(path, source):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
        try:
            need(stat.S_ISREG(os.fstat(fd).st_mode), 'NOT_REGULAR_FILE', source)
            with os.fdopen(os.dup(fd), 'rb') as stream:
                raw = stream.read(MAX_BYTES + 1)
        finally:
            os.close(fd)
    except InputError:
        raise
    except OSError:
        raise InputError('FILE_UNAVAILABLE', source) from None
    need(0 < len(raw) <= MAX_BYTES, 'INVALID_BYTES_OR_SIZE', source)
    return raw


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError('INVALID_ARGUMENTS', 'cli')


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('--selection', required=True)
    for name in SOURCES:
        spelling = name.replace('_', '-')
        choice = parser.add_mutually_exclusive_group(required=True)
        choice.add_argument('--' + spelling, dest=name)
        choice.add_argument('--' + spelling + '-absent', action='store_true')
    for name in COMMAND_TIMESTAMP_SOURCES:
        spelling = name.replace('_', '-')
        choice = parser.add_mutually_exclusive_group()
        choice.add_argument('--' + spelling, dest=name, action='append')
        choice.add_argument('--' + spelling + '-absent', action='store_true')
    try:
        args = parser.parse_args(argv)
        for name in COMMAND_TIMESTAMP_SOURCES:
            paths = getattr(args, name)
            need(paths is None or len(paths) == 1, 'INVALID_ARGUMENTS', 'cli')
            if paths is not None:
                setattr(args, name, paths[0])
        selected = [getattr(args, name) is not None or getattr(args, name + '_absent')
                    for name in COMMAND_TIMESTAMP_SOURCES]
        need(not any(selected) or all(selected), 'INCOMPLETE_COMMAND_TIMESTAMP_INPUTS', 'cli')
        inputs = {name: read_file(getattr(args, name), name) if getattr(args, name) is not None else None for name in SOURCES}
        command_timestamps = None if not any(selected) else {
            name: read_file(getattr(args, name), name) if getattr(args, name) is not None else None
            for name in COMMAND_TIMESTAMP_SOURCES}
        report = assess(inputs, read_file(args.selection, 'selection'), command_timestamps=command_timestamps)
        print(encode(report).decode())
        return 0
    except InputError as exc:
        print(encode(exc.report()).decode())
        return 64
    except Exception:
        print(encode({'kind': 'acs-log-reader-error', 'status': 'error', 'reason': 'INTERNAL_ERROR'}).decode())
        return 70


if __name__ == '__main__':
    raise SystemExit(main())
