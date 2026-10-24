"""Retention regressions against the real Inbox; no native replay or signatures."""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
import sqlite3
from unittest.mock import patch

import receiving as r


def logical_state(database):
    with sqlite3.connect(database) as connection:
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {name: sorted(connection.execute('SELECT * FROM "' + name + '"').fetchall())
                for name in tables}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vate-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    vate = args.vate_root.resolve()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    sample = Path(__file__).resolve().parent / 'sample'
    Engine, Inbox = r.load_inbox(vate)
    engine = Engine(vate)
    cases = []
    base_manifest = (sample/'manifest.json').read_bytes()
    audit_manifest = (sample/'audit-manifest.json').read_bytes()
    baseline = r.verified_files(sample/'originals', r.decode(base_manifest)['files'])
    audits = r.verified_files(sample/'originals', r.decode(audit_manifest)['files'])
    base_selection = r.decode((sample/'selection.json').read_bytes())
    audit_selection = r.decode((sample/'audit-selection.json').read_bytes())

    def payloads(selection):
        return {'selection.json': r.encoded(selection), 'evaluator.json': b'{}',
                'acceptance-source/war_verify.py': b'# unsigned retention test fixture\n',
                'acceptance-evaluator.json': b'{"fixture":"retention-only"}'}

    def assessment(selection, originals):
        bundle = r.decode(originals[selection['bundle']['path']])
        native = r.decode(originals[selection['reference_output']['path']])
        value = r.assess(selection, originals, bundle, native, {'state': 'evaluated'})
        value['comparison'] = {'kind': 'retention_fixture_only'}
        return value

    def save(database, name, selection, originals, manifest, previous=None, extra=None):
        target = output/name; target.mkdir(parents=True)
        inputs = payloads(selection)
        if extra: inputs.update(extra)
        result = r.retain(vate, database, target, copy.deepcopy(selection), originals,
                          manifest, assessment(selection, originals), inputs,
                          previous, (lambda _: engine, Inbox))
        (target/'RESULT.json').write_bytes(r.encoded(result))
        return result, target/'RESULT.json'

    def inspect(database, result):
        box = Inbox(database, engine)
        try:
            _, job = box._run(result['inbox']['run_id'])
            review = r.decode(box.get(job['review_set_ref']))
            index = r.decode(box.get(review['population_basis_refs'][1]))
            snapshot = r.decode(box.get(job['snapshot_ref']))
            return box.get(review['population_basis_refs'][0]), index, snapshot
        finally:
            box.close()

    def original_rows(database):
        return {table: rows for table, rows in logical_state(database).items()
                if table in ('objects', 'deliveries', 'entries', 'slots', 'runs')}

    def preserve(database, prior):
        current = original_rows(database)
        assert all(set(rows) <= set(current[table]) for table, rows in prior.items())

    database = output/'new.sqlite'
    first, first_path = save(database, 'baseline', base_selection, baseline, base_manifest)
    frozen = original_rows(database)
    second, second_path = save(database, 'audits', audit_selection, audits, audit_manifest, first_path)
    preserve(database, frozen)
    first_count = len(inspect(database, first)[2]['entries'])
    second_count = len(inspect(database, second)[2]['entries'])
    assert second_count - first_count == 4  # two originals, changed selection, assessment
    assert all(second['original_refs'][name] == ref for name, ref in first['original_refs'].items())
    assert first['payload_refs']['acceptance-source/war_verify.py'] == second['payload_refs']['acceptance-source/war_verify.py']
    third_originals = {**audits, **{'retention-fixture/addition-%d.json' % i:
                                  r.encoded({'unsigned_retention_fixture': i}) for i in range(4)}}
    third_manifest = r.encoded({'files': [{'path': name, 'sha256': r.sha(raw), 'bytes': len(raw)}
                                        for name, raw in third_originals.items()]})
    third, third_path = save(database, 'third', audit_selection, third_originals, third_manifest, second_path)
    third_count = len(inspect(database, third)[2]['entries'])
    repeated, repeated_path = save(database, 'repeated', audit_selection, third_originals, third_manifest, third_path)
    repeated_count = len(inspect(database, repeated)[2]['entries'])
    assert third_count - second_count == 5 and repeated_count - third_count == 1
    for result, expected in ((first, base_manifest), (second, audit_manifest), (third, third_manifest),
                             (repeated, third_manifest)):
        manifest, index, _ = inspect(database, result)
        assert manifest == expected and index['evaluation/assessment.json'] == result['assessment_ref']
        assert all(index['originals/'+name] == ref for name, ref in result['original_refs'].items())
    preserve(database, frozen)
    cases.append({'case': 'baseline-audit-third-repeat', 'status': 'pass',
                  'snapshot_entries': [first_count, second_count, third_count, repeated_count],
                  'prior_rows_and_assessments_preserved': True, 'each_manifest_and_index_retained': True})

    # Exact bytes are necessary but insufficient: paths and namespaces stay distinct.
    changed = dict(third_originals)
    changed['retention-fixture/addition-0.json'] += b'\n'
    changed['retention-fixture/renamed.json'] = third_originals['retention-fixture/addition-1.json']
    changed_manifest = r.encoded({'fixture': 'changed-bytes-and-path'})
    fourth, fourth_path = save(database, 'changed', audit_selection, changed, changed_manifest, repeated_path)
    changed_count = len(inspect(database, fourth)[2]['entries'])
    assert changed_count - repeated_count == 3  # changed bytes, new path, assessment
    assert fourth['original_refs']['retention-fixture/addition-0.json'] != third['original_refs']['retention-fixture/addition-0.json']
    another = copy.deepcopy(audit_selection); another['namespace'] += '-separate'
    separate, _ = save(database, 'another-namespace', another, audits, audit_manifest)
    assert len(inspect(database, separate)[2]['entries']) == len(audits) + len(payloads(another)) + 1
    preserve(database, frozen)
    cases.append({'case': 'changed-bytes-path-and-namespace', 'status': 'pass',
                  'changed_entries_added': changed_count-repeated_count, 'no_namespace_receipt_reuse': True})

    # Reproduce legacy material receipt IDs without rewriting a historical DB.
    # This seeds the old all-originals-per-manifest behavior using actual Inbox.receive.
    legacy_db = output/'legacy.sqlite'
    old_first, old_first_path = save(legacy_db, 'legacy-baseline', base_selection, baseline, base_manifest)
    box = Inbox(legacy_db, engine)
    try:
        basis = box.put(audit_manifest)
        for name, raw in audits.items():
            ref = box.put(raw, 'application/octet-stream')
            identity = r.digest([audit_selection['namespace'], 'originals/'+name, ref, basis])
            box.receive(r.encoded({'document_type': 'recipient_inbox_delivery', 'version': 1,
                'event_id': identity, 'entry_id': identity, 'source_namespace': audit_selection['namespace'],
                'native_input_kind': 'foreign_musubi_material', 'received_at': None,
                'receipt_basis_ref': basis, 'originals': {'original': ref}}))
    finally:
        box.close()
    old_second, old_second_path = save(legacy_db, 'legacy-audit', audit_selection, audits, audit_manifest, old_first_path)
    legacy_before = original_rows(legacy_db)
    old_third, _ = save(legacy_db, 'legacy-third', audit_selection, third_originals, third_manifest, old_second_path)
    preserve(legacy_db, legacy_before)
    old_count = len(inspect(legacy_db, old_second)[2]['entries'])
    upgraded_count = len(inspect(legacy_db, old_third)[2]['entries'])
    assert upgraded_count-old_count == 5 and upgraded_count < 256
    cases.append({'case': 'legacy-receipt-history-upgrade', 'status': 'pass',
                  'snapshot_entries': [old_count, upgraded_count], 'old_deliveries_not_rewritten': True})

    def seed(box, number, basis, refs, kind='foreign_musubi_material'):
        name = 'capacity-%d' % number
        box.receive(r.encoded({'document_type': 'recipient_inbox_delivery', 'version': 1,
            'event_id': name, 'entry_id': name, 'source_namespace': base_selection['namespace'],
            'native_input_kind': kind, 'received_at': None, 'receipt_basis_ref': basis,
            'originals': refs}))

    def refused(name, database, originals, expected, injected=None):
        before = logical_state(database)
        target = output/name; target.mkdir()
        def attempt():
            return r.retain(vate, database, target, base_selection, originals, b'{}',
                            {'overall_evidence_state': 'partial'}, {'evaluator.json': b'{}'},
                            None, (lambda _: engine, Inbox))
        try:
            if injected:
                with patch.object(Inbox, injected[0], injected[1]): attempt()
            else:
                attempt()
        except (ValueError, engine.validation.Problem) as exc:
            assert getattr(exc, 'code', None) == expected, (name, type(exc).__name__, str(exc))
        else:
            raise AssertionError('accepted '+name)
        assert logical_state(database) == before
        assert not (target/'RECOVERY.json').exists() and not (target/'export').exists()
        cases.append({'case': name, 'status': 'pass', 'code': expected,
                      'all_database_rows_unchanged': True, 'no_unfinished_run': True})

    entries_db = output/'entry-capacity.sqlite'
    box = Inbox(entries_db, engine, create=True)
    try:
        basis = box.put(b'{}'); ref = box.put(b'x', 'application/octet-stream')
        for number in range(255): seed(box, number, basis, {'original': ref})
    finally:
        box.close()
    refused('entry-capacity-batch-rollback', entries_db, {'new-a': b'a', 'new-b': b'b'}, 'ENTRY_LIMIT')

    snapshot_db = output/'snapshot-capacity.sqlite'
    box = Inbox(snapshot_db, engine, create=True)
    try:
        basis = box.put(b'{}'); ref = box.put(b'x', 'application/octet-stream')
        for number in range(256):
            try: seed(box, number, basis, {'slot-%d' % i: ref for i in range(18)})
            except ValueError as exc:
                assert exc.code == 'SNAPSHOT_CAPACITY'
                break
        else: raise AssertionError('snapshot capacity fixture did not reach bound')
    finally:
        box.close()
    refused('snapshot-capacity-batch-rollback', snapshot_db,
            {'new-%d' % i: b'n' for i in range(20)}, 'SNAPSHOT_CAPACITY')

    bytes_db = output/'byte-capacity.sqlite'
    box = Inbox(bytes_db, engine, create=True)
    try:
        basis = box.put(b'{}')
        for number in range(11):
            ref = box.put(bytes([number]) * r.MIB, 'application/octet-stream')
            seed(box, number, basis, {'original': ref})
    finally:
        box.close()
    refused('byte-capacity-batch-rollback', bytes_db,
            {'new-a': b'a'*(3*r.MIB//4), 'new-b': b'b'*(3*r.MIB//4)}, 'READ_CAPACITY')

    # Prepared run rows are rolled back too, not only failed receive steps.
    prepared_db = output/'prepared-rollback.sqlite'
    box = Inbox(prepared_db, engine, create=True); box.close()
    original_prepare = Inbox.prepare
    def fail_after_prepare(box, plan):
        original_prepare(box, plan)
        error = r.InputError('injected failure after actual prepare'); error.code = 'AFTER_PREPARE'
        raise error
    refused('prepared-run-batch-rollback', prepared_db, {'new': b'n'}, 'AFTER_PREPARE',
            ('prepare', fail_after_prepare))

    original_put = Inbox._put
    def rollback_during_put(box, *values, **options):
        original_put(box, *values, **options)
        box.db.execute('ROLLBACK')  # Simulate SQLite abandoning a transaction after an I/O failure.
        error = r.InputError('injected SQLite rollback'); error.code = 'SQLITE_ROLLBACK'
        raise error
    refused('sqlite-rollback-preserves-original-error', prepared_db, {'new': b'n'}, 'SQLITE_ROLLBACK',
            ('_put', rollback_during_put))

    # Existing non-foreign entries still undergo the core native-call bound.
    native_db = output/'native-capacity.sqlite'
    box = Inbox(native_db, engine, create=True)
    try:
        basis = box.put(b'{}'); ref = box.put(b'{}', 'application/octet-stream')
        for number in range(32): seed(box, number, basis, {'admission': ref}, 'receipt_pair')
        before = logical_state(native_db)
        try: seed(box, 32, basis, {'admission': ref}, 'receipt_pair')
        except ValueError as exc: assert exc.code == 'NATIVE_CAPACITY'
        else: raise AssertionError('core native-call bound was bypassed')
        assert logical_state(native_db) == before
    finally:
        box.close()
    # Force the same actual capacity check to reject an injected invalid population
    # during the adapter's batch, without changing the core limit or implementation.
    with sqlite3.connect(native_db) as connection:
        connection.execute("UPDATE entries SET kind='s3_bundle' WHERE entry_id='capacity-0'")
        connection.execute("UPDATE slots SET name=? WHERE entry_id='capacity-0'",
                           (sorted(engine.validation.MEMBERS)[0],))
    refused('native-capacity-batch-rollback', native_db, {'new': b'n'}, 'NATIVE_CAPACITY')

    result = {'status': 'pass', 'cases': cases, 'native_replay_performed': False,
              'core_limits_unchanged': True, 'input_original_counts': [len(baseline), len(audits), len(third_originals)]}
    (output/'CAPACITY-RESULT.json').write_bytes(r.encoded(result))
    print(r.encoded(result).decode(), end='')


if __name__ == '__main__':
    main()
