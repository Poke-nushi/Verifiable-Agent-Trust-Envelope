"""Synthetic receiver decisions over saved S3 bytes; no live service or real keys."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from required_records import encode, sha, MEMBERS, extract

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'reference/recipient-assessment/vate_recipient.py').is_file())
SAVED = ROOT/'reference/s3-observation-example/inputs/seaweedfs-4.48/instance'
BUNDLE = SAVED/'bundles/supported'
DUE = '2026-10-20T12:00:00Z'
CUTOFF = '2026-10-20T13:00:00Z'
RECEIVED = '2026-10-20T10:00:00Z'
NS = 'urn:example:receiver:archive-intake'
ATTEMPT = json.loads((BUNDLE/'attempt.json').read_bytes())['attempt_id']


class Inputs:
    def __init__(self, folder):
        self.folder = Path(folder); self.folder.mkdir(parents=True, exist_ok=True)
        self.serial = 0
        self.basis = self.store(b'Synthetic receiver selection, arrival times and requirements; archived S3 bytes.\n', 'basis.txt')
        self.review = {'document_type':'receiver_review_set_design', 'design_revision':2,
            'review_set_id':'receiver-A-B', 'revision':1, 'namespace':NS, 'collection_scope':'receiver_selected_set_only',
            'population_basis_refs':[self.basis], 'requirements':[]}
        self.snapshot = {'document_type':'submission_snapshot_design', 'design_revision':2,
            'snapshot_id':'saved-submission', 'as_of':CUTOFF, 'inventory_state':'closed',
            'collection_basis_ref':self.basis, 'entries':[]}
        self.selection = {'document_type':'receiver_selection_design', 'design_revision':2,
            'receiver_id':'urn:example:receiver', 'review_set_selected_at':'2026-10-20T09:00:00Z',
            'snapshot_selected_at':'2026-10-20T13:05:00Z', 'assessment_time':'2026-10-20T14:00:00Z',
            'assessment_cutoff':CUTOFF, 'selection_basis_ref':self.basis,
            'native_policy_refs':{'s3':self.ref(SAVED/'receiver-policy.json'), 'signature':None}}
        self.admission = (BUNDLE/'admission.json').read_bytes(); self.post = (BUNDLE/'post.json').read_bytes()
        self.context = extract(self.post, 'post_execution')[1]

    def ref(self, path):
        path = Path(path)
        raw = path.read_bytes()
        try:
            relative = path.relative_to(self.folder); base = 'inputs'
        except ValueError:
            relative = path.relative_to(ROOT); base = 'repository'
        return {'path_base':base, 'path':str(relative), 'media_type':'application/json' if path.suffix == '.json' else 'application/octet-stream',
            'digest_basis':'raw_file_sha256', 'digest':{'alg':'sha-256','value':sha(raw)}, 'byte_length':len(raw)}

    def store(self, raw, name=None):
        self.serial += 1
        if name is None: name = 'original-'+str(self.serial)+'.json'
        path = self.folder/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        return self.ref(path)

    def event(self, raw=None, *, ref=None, received=RECEIVED, member='included'):
        if raw is None and ref is None: return None
        return {'ref':ref or self.store(raw), 'received_at':received,
                'cutoff_membership':member, 'receipt_basis_ref':self.basis}

    def row(self, name='A', *, context=None, attempt=None, record='post_execution', operation=None):
        subject = {'kind':'attempt' if attempt else 'operation', 'operation_id':operation or name,
                   'native_context':deepcopy(context or self.context)}
        if attempt: subject['attempt_id'] = attempt
        row = {'requirement_id':name, 'subject':subject, 'record_kind':record,
               'binding_profile':'vate_s3_attempt_context' if attempt else 'vate_receipt_operation_context',
               'obligation':'required', 'basis_refs':[self.basis], 'due_at':DUE,
               'requested_native_checks':['receipt_linkage']}
        self.review['requirements'].append(row)
        return row

    def pair(self, name='A', *, admission=None, post=None):
        entry = {'entry_id':name, 'source_namespace':NS, 'native_input_kind':'receipt_pair',
            'originals':{'admission':self.event(self.admission if admission is None else admission),
                         'post':self.event(self.post if post is None else post)}}
        self.snapshot['entries'].append(entry); return entry

    def bundle(self, name='S3', path=BUNDLE):
        entry = {'entry_id':name, 'source_namespace':NS, 'native_input_kind':'s3_bundle',
                 'originals':{n:self.event(ref=self.ref(Path(path)/n)) if (Path(path)/n).is_file() else None for n in sorted(MEMBERS)}}
        self.snapshot['entries'].append(entry); return entry

    def other(self):
        admission, post = json.loads(self.admission), json.loads(self.post)
        admission['request']['transaction_id'] = 'design-only-operation-B'
        post['execution']['transaction_id'] = 'design-only-operation-B'
        # Existing linkage digest basis remains unchanged, and is not raw-file SHA.
        post['admission']['digest']['value'] = sha(encode(admission))
        context = deepcopy(self.context); context['transaction_id'] = 'design-only-operation-B'
        return encode(admission), encode(post), context

    def seal(self):
        self.selection['review_set_ref'] = self.store(encode(self.review), 'review-set.json')
        self.selection['submission_snapshot_ref'] = self.store(encode(self.snapshot), 'snapshot.json')
        raw = encode(self.selection); self.store(raw, 'selection.json')
        return raw

    def roots(self):
        return {'inputs':self.folder,'repository':ROOT}


def signatures(openssl=None):
    sys.path.insert(0, str(ROOT/'reference/recipient-signature-authority'))
    from trial_fixtures import Fixtures
    return Fixtures(openssl)
