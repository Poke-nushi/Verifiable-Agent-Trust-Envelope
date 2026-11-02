"""Store the synthetic ACS example and both readings in the VATE recipient inbox."""
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import sys
import tempfile

from acs_reader import assess, encode, digest, read_file, parse_json, SOURCES

HERE = Path(__file__).resolve().parent


def run(destination, source_root=None):
    pins = parse_json(read_file(HERE/'SAMPLE-PINS.json', 'pins'), 'pins')
    if set(pins) != set(SOURCES):
        raise ValueError('unexpected source inventory')
    source = {}
    for name, pin in pins.items():
        raw = read_file(HERE/pin['path'], name)
        if digest(raw) != pin['raw_sha256']:
            raise ValueError('synthetic sample identity changed')
        source[name] = raw
    selection = read_file(HERE/'selection.example.json', 'selection')
    selected_partial = {name: raw if name in ('host_audit', 'host_events') else None for name, raw in source.items()}
    prepared_reports = {1: encode(assess(selected_partial, selection)), 2: encode(assess(source, selection))}
    root = Path(source_root).resolve() if source_root is not None else HERE.parents[1]
    if not (root/'reference/recipient-inbox/recipient_inbox.py').is_file():
        raise ValueError('use a whole VATE source tree or pass --source-root')
    # Storage is optional; importing this module never loads the inbox or its dependencies.
    sys.path.insert(0, str(root/'reference/recipient-inbox'))
    from recipient_inbox import Engine, Inbox, PLAN, DELIVERY
    engine = Engine(root)
    # Invalid sources or selection do not consume the output path.
    destination.mkdir(parents=True, exist_ok=False)
    original_reports, previous = [], None
    with tempfile.TemporaryDirectory(prefix='vate-acs-reader-example-') as temp:
        box = Inbox(Path(temp)/'inbox.sqlite3', engine, create=True)
        try:
            basis = box.put(b'Local staged reading of self-authored synthetic ACS-shaped files. Unknown arrival times. '
                            b'No ACS execution, trusted clock, signature, or completeness established. '
                            b'This empty required-record set is storage/history verification only.\n', 'text/plain')
            now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            namespace = 'urn:local-example:acs-reader'
            plan = {'document_type': PLAN, 'version': 1, 'receiver_id': namespace,
                    'review_set': {'document_type': 'receiver_review_set_design', 'design_revision': 2,
                        'review_set_id': 'acs-reader-storage-history', 'revision': 1, 'namespace': namespace,
                        'population_basis_refs': [basis], 'collection_scope': 'receiver_selected_set_only', 'requirements': []},
                    'review_set_selected_at': now, 'assessment_cutoff': now, 'assessment_time': now,
                    'inventory_state': 'partial', 'collection_basis_ref': basis, 'selection_basis_ref': basis,
                    'revision_basis_ref': basis, 'native_policy_refs': {'s3': None, 'signature': None}}

            def deliver(event, entry, kind, originals):
                value = {'document_type': DELIVERY, 'version': 1, 'event_id': event, 'entry_id': entry,
                         'source_namespace': namespace, 'native_input_kind': kind, 'received_at': None,
                         'receipt_basis_ref': basis,
                         'originals': {name: box.put(raw, 'application/octet-stream') for name, raw in originals.items()}}
                box.receive(encode(value))
                for name, ref in value['originals'].items():
                    if box.get(ref) != originals[name]:
                        raise AssertionError('stored original differs')

            for stage, names in ((1, ('host_audit', 'host_events')), (2, ('guardian_envelopes', 'proxy'))):
                deliver(f'originals-{stage}', 'original-capture', 'acs-capture-opaque', {n: source[n] for n in names})
                report = prepared_reports[stage]
                original_reports.append(report)
                (destination/f'reader-report-{stage}.json').write_bytes(report + b'\n')
                deliver(f'report-{stage}', f'derived-report-{stage}', 'acs-reader-derived-report', {'selection': selection, 'report': report})
                state = box.run(box.prepare(encode(plan))['run_id'])
                if state['status'] != 'completed':
                    raise AssertionError(state)
                storage_raw = box.get(state['report_ref'])
                storage = json.loads(storage_raw)
                if storage['review_set_status'] != 'selected_empty' or storage['native_calls']:
                    raise AssertionError('storage mistakenly became native ACS assessment')
                (destination/f'storage-report-{stage}.json').write_bytes(storage_raw)
                if previous and (state['previous_id'] != previous[0]['run_id'] or box.get(previous[0]['report_ref']) != previous[1]):
                    raise AssertionError('earlier storage assessment not preserved')
                previous = (state, storage_raw)
            # The first derived assessment is retained exactly, alongside the later one.
            box.export(previous[0]['run_id'], destination/'inbox-export')
            exported = [p.read_bytes() for p in (destination/'inbox-export/objects').iterdir()]
            if not all(raw in exported for raw in [*source.values(), *original_reports, selection]):
                raise AssertionError('export omitted original/derived bytes')
            summary = {'reader_profile': json.loads(original_reports[1])['profile'],
                       'sample_kind': 'synthetic',
                       'reader_reports': ['reader-report-1.json', 'reader-report-2.json'],
                       'original_bytes_retained': True, 'previous_assessment_preserved': True,
                       'storage_revision': previous[0]['revision'], 'storage_scope': 'empty_set_history_only',
                       'native_acs_assessment_in_required_records': False, 'example_invoked_acs_host': False}
            (destination/'SUMMARY.json').write_bytes(encode(summary)+b'\n')
            print(json.dumps(summary))
        finally:
            box.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--source-root', type=Path, help='trusted VATE checkout/archive for optional inbox storage')
    args = parser.parse_args()
    run(args.out, args.source_root)
