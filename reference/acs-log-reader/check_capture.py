"""Read locally supplied ACS #435 files after checking the published capture pins."""
from pathlib import Path
import re

from acs_reader import InputError, Parser, SOURCES, assess, digest, encode, need, parse_json, read_file

HERE = Path(__file__).resolve().parent


def check_capture(directory):
    meta = parse_json(read_file(HERE/'PUBLISHED-CAPTURE.json', 'capture_pins'), 'capture_pins')
    files = meta.get('files')
    need(type(files) is dict and set(files) == set(SOURCES), 'INVALID_CAPTURE_PINS', 'capture_pins')
    need(meta.get('selection_file') == 'published-selection.json', 'INVALID_CAPTURE_PINS', 'capture_pins')
    for key in ('selection_sha256', 'expected_report_sha256'):
        need(type(meta.get(key)) is str and re.fullmatch(r'[0-9a-f]{64}', meta[key]),
             'INVALID_CAPTURE_PINS', 'capture_pins')
    inputs = {}
    for name in SOURCES:
        pin = files[name]
        need(type(pin) is dict and pin.get('filename') == name.replace('_', '-')+'.jsonl',
             'INVALID_CAPTURE_PINS', 'capture_pins')
        need(type(pin.get('raw_sha256')) is str and re.fullmatch(r'[0-9a-f]{64}', pin['raw_sha256'])
             and type(pin.get('byte_length')) is int and pin['byte_length'] > 0,
             'INVALID_CAPTURE_PINS', 'capture_pins')
        raw = read_file(Path(directory)/pin['filename'], name)
        need(len(raw) == pin['byte_length'] and digest(raw) == pin['raw_sha256'],
             'CAPTURE_DIGEST_MISMATCH', name)
        inputs[name] = raw
    selection = read_file(HERE/'published-selection.json', 'selection')
    need(digest(selection) == meta['selection_sha256'], 'SELECTION_DIGEST_MISMATCH', 'selection')
    report = assess(inputs, selection)
    need(digest(encode(report)+b'\n') == meta['expected_report_sha256'],
         'EXPECTED_REPORT_MISMATCH', 'expected_report')
    return report


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    try:
        args = parser.parse_args(argv)
        print(encode(check_capture(args.directory)).decode())
        return 0
    except InputError as exc:
        print(encode(exc.report()).decode())
        return 64
    except Exception:
        print(encode({'kind': 'acs-log-reader-error', 'status': 'error', 'reason': 'INTERNAL_ERROR'}).decode())
        return 70


if __name__ == '__main__':
    raise SystemExit(main())
