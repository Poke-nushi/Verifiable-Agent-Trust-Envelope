"""Evaluate synthetic required-record controls and preserve every original/report."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import platform
import sys

from fixture_inputs import Inputs, ROOT, HERE, ATTEMPT, signatures
from required_records import Reviewer, encode, sha


def generate(destination, openssl, expected_sha256):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('output must be a new directory')
    openssl = Path(openssl).resolve(strict=True)
    if sha(openssl.read_bytes()) != expected_sha256:
        raise ValueError('selected OpenSSL does not match the expected SHA-256')
    sig = signatures(openssl)
    if sig.binary_sha256 != expected_sha256:
        raise ValueError('selected OpenSSL changed during fixture creation')
    destination.mkdir(parents=True, exist_ok=False)
    expected = json.loads((HERE/'EXPECTATIONS.json').read_bytes())
    summaries = []
    def save(name, configure):
        folder = destination/name; f = Inputs(folder); configure(f)
        raw = f.seal()
        result = Reviewer(path_bases=f.roots(),source_root=ROOT,
            openssl=str(sig.openssl),openssl_sha256=sig.binary_sha256).assess(raw)
        report = encode(result)+b'\n'; (folder/'report.json').write_bytes(report)
        observed = {'review_set_status':result['review_set_status'],
            'coverage':{r['requirement_id']:r['record_coverage'] for r in result['requirements']},
            'timeliness':{r['requirement_id']:r['timeliness'] for r in result['requirements']},
            'invocation_errors':result['invocation_errors']}
        if observed != expected[name]:
            raise AssertionError((name, expected[name], observed))
        summaries.append({'example':name,**observed,'expectation_matched':True,'usage':result['usage'],
            'report_sha256':sha(report),'selection_sha256':sha(raw)})
    def pair(f): f.row(); f.pair()
    def absent(f): pair(f);f.row('B',context=f.other()[2])
    save('operation-B-missing',absent)
    def unknown_time(f): pair(f);f.snapshot['entries'][0]['originals']['post']['received_at']=None
    save('arrival-unknown-membership-included',unknown_time)
    def unknown_member(f):
        unknown_time(f);f.snapshot['entries'][0]['originals']['post']['cutoff_membership']='unknown'
    save('arrival-and-membership-unknown',unknown_member)
    def s3(f): f.row(attempt=ATTEMPT);f.bundle()
    save('s3-attempt',s3)
    def late_support(f):
        s3(f);f.snapshot['entries'][0]['originals']['attempt.json'].update(received_at='2026-10-20T13:30:00Z',cutoff_membership='after')
    save('s3-late-support',late_support)
    def partial(f): pair(f);f.snapshot['inventory_state']='partial'
    save('partial-even-with-matching-record',partial)
    def with_sig(f):
        pair(f);f.review['requirements'][0]['requested_native_checks'].append('signatures_and_issuer_authority')
        f.selection['native_policy_refs']['signature']=f.store(encode(sig.policy))
        f.snapshot['entries'][0]['detached_proofs']={'admission':f.event(sig.admission_proof),'post':f.event(sig.post_proof)}
    save('signature-and-authority',with_sig)
    def bad_policy(f): with_sig(f);f.selection['native_policy_refs']['signature']=f.store(b'{}')
    save('signature-early-error',bad_policy)
    def revision(f):
        f.row();f.seal()
        prior_set=f.store((f.folder/'review-set.json').read_bytes(),'history/review-set-1.json')
        prior_snapshot=f.store((f.folder/'snapshot.json').read_bytes(),'history/snapshot-1.json')
        f.selection['review_set_ref']=prior_set;f.selection['submission_snapshot_ref']=prior_snapshot
        raw=encode(f.selection);prior=Reviewer(path_bases=f.roots(),source_root=ROOT).assess(raw)
        prior_report=f.store(encode(prior),'history/report-1.json')
        f.store(raw,'history/selection-1.json')
        f.review.update(revision=2,previous_review_set_ref=prior_set,previous_report_ref=prior_report,revision_basis_ref=f.basis)
        f.review['requirements'][0].update(obligation='waived_by_receiver',waiver_ref=f.basis)
    save('receiver-waiver-revision',revision)
    def alias(f): f.row('A');f.row('same-context-new-label')
    save('semantic-alias-rejected',alias)
    if set(expected) != {item['example'] for item in summaries}:
        raise AssertionError('control inventory differs from EXPECTATIONS.json')
    environment={'python':sys.version, 'platform':platform.platform(),
                 'openssl':str(sig.openssl), 'openssl_sha256':sig.binary_sha256,
                 'openssl_version':sig.run(['version']).decode().strip(),
                 'basis':'Saved receipt bytes, synthetic current-source S3 derivatives and receiver decisions; detached signatures use public test scalars, not real keys.'}
    (destination/'SUMMARY.json').write_bytes(encode({'environment':environment,'examples':summaries})+b'\n')
    return summaries


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--openssl', type=Path, required=True)
    parser.add_argument('--openssl-sha256', required=True)
    args = parser.parse_args()
    controls = generate(args.output, args.openssl, args.openssl_sha256)
    print(json.dumps({'summary':str(args.output/'SUMMARY.json'), 'controls':len(controls),
                      'expectations_matched':all(c['expectation_matched'] for c in controls)}))
