"""Real input/byte cases; never pass symbolic design outcomes to the reviewer."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from fixture_inputs import Inputs, ROOT, HERE, BUNDLE, SAVED, ATTEMPT, DUE, CUTOFF, signatures
from required_records import Reviewer, encode, sha, Problem, decode, stamp, MEMBERS


class RequiredRecords(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sig = signatures()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vate-required-test-')
        self.f = Inputs(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def assess(self, raw=None, **kwargs):
        return Reviewer(path_bases=self.f.roots(), source_root=ROOT,
            openssl=str(self.sig.openssl), openssl_sha256=self.sig.binary_sha256,
            **kwargs).assess(self.f.seal() if raw is None else raw)

    def coverage(self, result):
        return {r['requirement_id']:r['record_coverage'] for r in result['requirements']}

    def native(self, result, kind='receipt'):
        return next(c['result'] for c in result['native_calls'] if c['kind'] == kind)

    def setup_pair(self):
        self.f.row(); return self.f.pair()

    def setup_sig(self):
        entry = self.setup_pair()
        self.f.review['requirements'][0]['requested_native_checks'].append('signatures_and_issuer_authority')
        self.f.selection['native_policy_refs']['signature'] = self.f.store(encode(self.sig.policy))
        entry['detached_proofs'] = {'admission':self.f.event(self.sig.admission_proof),'post':self.f.event(self.sig.post_proof)}
        return entry

    def test_RR01_both(self):
        self.setup_pair(); a,p,c = self.f.other(); self.f.row('B',context=c); self.f.pair('B',admission=a,post=p)
        self.assertEqual(self.coverage(self.assess()), {'A':'present','B':'present'})

    def test_RR02_whole_operation_absent(self):
        self.setup_pair(); self.f.row('B',context=self.f.other()[2])
        self.assertEqual(self.coverage(self.assess()), {'A':'present','B':'missing'})

    def test_RR03_post_absent(self):
        entry=self.setup_pair();entry['originals']['post']=None;r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'missing'})
        self.assertEqual(self.native(r)['native_result']['record_linkage'],'not_assessed')

    def test_RR04_review_pin_not_updated(self):
        self.setup_pair(); raw=self.f.seal(); (self.f.folder/'review-set.json').write_bytes(b'{}')
        r=self.assess(raw);self.assertEqual(r['review_set_status'],'invalid');self.assertEqual(r['requirements'],[])

    def test_RR05_review_unavailable(self):
        self.setup_pair();raw=self.f.seal();(self.f.folder/'review-set.json').unlink()
        self.assertEqual(self.assess(raw)['review_set_status'],'not_assessed')

    def test_RR06_selected_empty(self):
        r=self.assess();self.assertEqual(r['review_set_status'],'selected_empty');self.assertEqual(r['requirements'],[])

    def test_RR07_selection_absent(self):
        r=Reviewer(path_bases=self.f.roots(),source_root=ROOT).assess(None)
        self.assertEqual(r['review_set_status'],'not_assessed')

    def test_RR08_no_requirements_from_allow(self):
        self.f.pair(); self.assertEqual(self.assess()['review_set_status'],'selected_empty')

    def test_RR09_due_not_admission_expiry(self):
        row=self.f.row();row['due_at']='2026-10-21T00:00:00Z';self.f.pair()['originals']['post']=None
        self.assertEqual(self.coverage(self.assess()),{'A':'pending'})

    def prior(self):
        self.f.row();before=self.assess();old_raw=(self.f.folder/'review-set.json').read_bytes()
        old_ref=self.f.store(old_raw,'history/review-1.json');report_raw=encode(before)
        report_ref=self.f.store(report_raw,'history/report-1.json')
        self.f.review.update(revision=2, previous_review_set_ref=old_ref,previous_report_ref=report_ref,revision_basis_ref=self.f.basis)
        return before, old_raw, report_raw

    def test_RR10_waiver_keeps_prior(self):
        before,old,report=self.prior();row=self.f.review['requirements'][0]
        row.update(obligation='waived_by_receiver',waiver_ref=self.f.basis);r=self.assess()
        self.assertEqual(self.coverage(before),{'A':'missing'});self.assertEqual(self.coverage(r),{'A':'waived_by_receiver'})
        self.assertEqual((self.f.folder/'history/review-1.json').read_bytes(),old)
        self.assertEqual((self.f.folder/'history/report-1.json').read_bytes(),report)

    def test_RR11_sender_note_cannot_cancel(self):
        self.f.row(); self.f.store(b'Sender says cancelled', 'sender-note.txt')
        self.assertEqual(self.coverage(self.assess()),{'A':'missing'})

    def test_RR12_undetermined_obligation(self):
        self.f.row()['obligation']='undetermined';self.assertEqual(self.coverage(self.assess()),{'A':'unresolved'})

    def boundary(self, cutoff, expected):
        self.f.row();self.f.selection['assessment_cutoff']=cutoff;self.f.snapshot['as_of']=cutoff
        self.assertEqual(self.coverage(self.assess()),{'A':expected})
    def test_RR13_before_due(self): self.boundary('2026-10-20T11:59:59.999999Z','pending')
    def test_RR14_at_due(self): self.boundary(DUE,'pending')
    def test_RR15_after_due(self): self.boundary('2026-10-20T12:00:00.000001Z','missing')

    def test_RR16_received_at_due(self):
        e=self.setup_pair();e['originals']['post']['received_at']=DUE
        self.assertEqual(self.assess()['requirements'][0]['timeliness'],'on_time')

    def test_RR17_late_preserves_old_report(self):
        before,old,report=self.prior();e=self.f.pair();e['originals']['post']['received_at']='2026-10-20T12:30:00Z'
        r=self.assess();self.assertEqual(self.coverage(before),{'A':'missing'})
        self.assertEqual(self.coverage(r),{'A':'present'});self.assertEqual(r['requirements'][0]['timeliness'],'late')
        self.assertEqual((self.f.folder/'history/report-1.json').read_bytes(),report)

    def test_RR18_after_cutoff_excluded(self):
        e=self.setup_pair();e['originals']['post'].update(received_at='2026-10-20T13:30:00Z',cutoff_membership='after')
        r=self.assess();self.assertEqual(self.coverage(r),{'A':'missing'});self.assertEqual(r['requirements'][0]['candidates'][0]['reason'],'AFTER_CUTOFF')

    def test_RR19_membership_known_time_unknown(self):
        self.setup_pair()['originals']['post']['received_at']=None;r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'present'});self.assertEqual(r['requirements'][0]['timeliness'],'unknown')

    def test_RR20_partial_inventory(self):
        self.f.row();self.f.snapshot['inventory_state']='partial';self.assertEqual(self.coverage(self.assess()),{'A':'unresolved'})

    def test_RR21_unavailable_original(self):
        e=self.setup_pair();(self.f.folder/e['originals']['post']['ref']['path']).unlink();r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'unresolved'});self.assertEqual(r['requirements'][0]['candidate_presence'],'unavailable')

    def test_RR22_bad_json(self):
        self.f.row();self.f.pair(post=b'{invalid');r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'unresolved'});self.assertEqual(r['requirements'][0]['candidate_presence'],'bytes_available')

    def test_RR23_invalid_signature_still_present(self):
        e=self.setup_sig();e['originals']['post']=self.f.event(self.f.post+b'\n');r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'present'});self.assertEqual(self.native(r,'signature')['signatures']['post_execution']['status'],'invalid')
        self.assertEqual([c['kind'] for c in r['native_calls']],['signature'])

    def test_RR24_no_issuer_authority(self):
        self.setup_sig();policy=deepcopy(self.sig.policy);policy['grants']=[]
        self.f.selection['native_policy_refs']['signature']=self.f.store(encode(policy));r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'present'});self.assertEqual(self.native(r,'signature')['issuer_authority']['post_execution']['status'],'denied')

    def mismatch(self):
        e=self.setup_pair();post=json.loads(self.f.post);post['admission']['digest']['value']='0'*64
        e['originals']['post']=self.f.event(encode(post))
    def test_RR25_linkage_mismatch_present(self):
        self.mismatch();r=self.assess();self.assertEqual(self.coverage(r),{'A':'present'})
        self.assertEqual(self.native(r)['native_result']['record_linkage'],'mismatch')
    def test_RR26_mismatch_and_missing(self):
        self.mismatch();self.f.row('B',context=self.f.other()[2]);r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'present','B':'missing'});self.assertEqual(self.native(r)['native_result']['record_linkage'],'mismatch')

    def two_attempts(self):
        self.f.row('attempt1',attempt=ATTEMPT,operation='A');self.f.row('attempt2',attempt='attempt-design-only-other',operation='A')
    def test_RR27_whole_attempt_absent(self):
        self.two_attempts();self.f.bundle();self.assertEqual(self.coverage(self.assess()),{'attempt1':'present','attempt2':'missing'})
    def test_RR28_id_only_not_binding(self):
        self.f.row(attempt=ATTEMPT);self.f.pair();self.assertEqual(self.coverage(self.assess()),{'A':'unresolved'})
    def test_RR29_bound_attempt(self):
        self.f.row(attempt=ATTEMPT);self.f.bundle();self.assertEqual(self.coverage(self.assess()),{'A':'present'})
    def test_RR30_other_attempt(self):
        self.f.row(attempt='attempt-other');self.f.bundle();r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'missing'});self.assertEqual(r['requirements'][0]['candidates'][0]['reason'],'ATTEMPT_ID_MISMATCH')

    def test_RR31_same_bytes_resend(self):
        self.setup_pair();e=self.f.pair('resend');e['originals']['post']['received_at']='2026-10-20T12:30:00Z';r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'present'});row=r['requirements'][0]
        self.assertEqual(row['unique_candidates'],1);self.assertEqual(len(row['candidates']),2);self.assertEqual(row['timeliness'],'on_time')
        self.assertEqual(len(r['native_calls']),1)
    def test_RR32_conflicting_bytes(self):
        self.setup_pair();self.f.pair('other',post=self.f.post+b'\n');self.assertEqual(self.coverage(self.assess()),{'A':'unresolved'})
    def test_RR33_unsupported_profile(self):
        self.f.row();p=json.loads(self.f.post);p['profile']='unknown-profile';self.f.pair(post=encode(p))
        self.assertEqual(self.coverage(self.assess()),{'A':'unresolved'})
    def test_RR34_namespace_exclusion(self):
        self.setup_pair()['source_namespace']='another-namespace';self.assertEqual(self.coverage(self.assess()),{'A':'missing'})
    def test_RR35_same_body_other_operation(self):
        self.f.row(context=self.f.other()[2]);self.f.pair();self.assertEqual(self.coverage(self.assess()),{'A':'missing'})
    def test_RR36_original_pin_mismatch(self):
        e=self.setup_pair();ref=e['originals']['post']['ref'];(self.f.folder/ref['path']).write_bytes(self.f.post+b'\n');r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'unresolved'});self.assertTrue(any(x.get('error',{}).get('code')=='RAW_IDENTITY_MISMATCH' for x in r['input_refs']))
    def test_RR37_response_unavailable(self):
        self.f.row(attempt=ATTEMPT);e=self.f.bundle();e['originals']['put-transport.json']=None;r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'unresolved'});self.assertEqual(self.native(r,'s3')['native_result']['assessment'],'insufficient')
    def test_RR38_duplicate_requirement(self):
        row=self.f.row();self.f.review['requirements'].append(deepcopy(row));self.assertEqual(self.assess()['review_set_status'],'invalid')
    def test_RR39_issued_time_not_arrival(self):
        self.setup_pair()['originals']['post']['received_at']='2026-10-20T12:30:00Z';r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'present'});self.assertEqual(r['requirements'][0]['timeliness'],'late')
    def test_RR40_snapshot_time_mismatch(self):
        self.f.row();self.f.snapshot['as_of']=DUE;self.assertEqual(self.assess()['review_set_status'],'invalid')
    def test_RR41_input_budget_stops_candidate(self):
        self.setup_pair();self.f.pair('unknown',post=b' '*10000)
        r=self.assess(limits={'bytes':11000});self.assertEqual(self.coverage(r),{'A':'unresolved'})
        self.assertTrue(any(x.get('error',{}).get('code')=='EVALUATION_LIMIT' for x in r['input_refs']))
    def test_RR42_relabel_cannot_double_assign(self):
        self.two_attempts();self.f.bundle()
        # Build the relabelled control entirely from the distributed originals.
        # Updating unsigned attempt/request refs alone must not assign the same
        # unchanged post receipt to a second explicitly named attempt.
        members={name:(BUNDLE/name).read_bytes() for name in MEMBERS}
        def reference(name):
            raw=members[name]
            return {'path':name,'byte_length':len(raw),'digest':{'alg':'sha-256','value':sha(raw)}}
        attempt=json.loads(members['attempt.json']);attempt['attempt_id']='attempt-design-only-other'
        members['attempt.json']=encode(attempt)
        request=json.loads(members['put-request.json'])
        request.update(exchange_id=attempt['attempt_id'],attempt_ref=reference('attempt.json'))
        members['put-request.json']=encode(request)
        transport=json.loads(members['put-transport.json'])
        transport.update(attempt_ref=reference('attempt.json'),request_ref=reference('put-request.json'))
        members['put-transport.json']=encode(transport)
        manifest=json.loads(members['manifest.json'])
        for name in manifest['artifacts']:
            manifest['artifacts'][name]={k:v for k,v in reference(name).items() if k!='path'}
        members['manifest.json']=encode(manifest)
        entry=self.f.bundle('relabeled')
        for name in ('attempt.json','put-request.json','put-transport.json','manifest.json'):
            entry['originals'][name]=self.f.event(members[name])
        self.assertEqual(members['post.json'],self.f.post)
        r=self.assess()
        self.assertEqual(self.coverage(r),{'attempt1':'present','attempt2':'unresolved'})
        relabeled=next(c for c in r['requirements'][1]['candidates'] if c['entry_id']=='relabeled')
        self.assertEqual(relabeled['reason'],'POST_IDENTIFIER_BINDING_UNSUPPORTED')
        self.assertTrue(all(c['result']['native_result']['assessment']=='supported_under_local_assumptions' for c in r['native_calls'] if c['kind']=='s3'))
    def test_RR43_unknown_cutoff_membership(self):
        self.setup_pair()['originals']['post'].update(received_at=None,cutoff_membership='unknown')
        self.assertEqual(self.coverage(self.assess()),{'A':'unresolved'})
    def test_RR44_cancelled_post_operation_present(self):
        self.f.row();e=self.f.bundle();p=json.loads(self.f.post);p['result']['outcome']='cancelled'
        raw=encode(p);e['originals']['post.json']=self.f.event(raw)
        manifest=json.loads((BUNDLE/'manifest.json').read_bytes())
        manifest['artifacts']['post.json']={'digest':{'alg':'sha-256','value':sha(raw)},'byte_length':len(raw)}
        e['originals']['manifest.json']=self.f.event(encode(manifest));r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'present'});self.assertEqual(self.native(r,'s3')['native_result']['post_observation_binding'],'unsupported')
    def test_RR45_selection_after_cutoff(self):
        self.prior();self.f.selection['review_set_selected_at']='2026-10-20T13:01:00Z';r=self.assess()
        self.assertEqual(r['review_set_status'],'selected');self.assertEqual(r['review_set_selection_timing'],'after_cutoff')
    def test_RR46_snapshot_selected_too_early(self):
        self.f.selection['snapshot_selected_at']=DUE;self.assertEqual(self.assess()['review_set_status'],'invalid')


    def test_attempt_malformed_post_identifier_is_unknown(self):
        self.f.row(attempt=ATTEMPT);e=self.f.bundle()
        for invalid in (None, [], '', True, 'control\x00id'):
            with self.subTest(identifier=invalid):
                post=json.loads(self.f.post)
                if invalid is None:post.pop('receipt_id')
                else:post['receipt_id']=invalid
                raw=encode(post);e['originals']['post.json']=self.f.event(raw)
                manifest=json.loads((BUNDLE/'manifest.json').read_bytes())
                manifest['artifacts']['post.json']={'digest':{'alg':'sha-256','value':sha(raw)},'byte_length':len(raw)}
                e['originals']['manifest.json']=self.f.event(encode(manifest));r=self.assess()
                self.assertEqual(self.coverage(r),{'A':'unresolved'})
                self.assertEqual(r['requirements'][0]['candidates'][0]['reason'],'POST_IDENTIFIER_UNAVAILABLE')

    def test_historical_observation_is_not_missing(self):
        self.f.row(attempt=ATTEMPT);self.f.bundle('historical',SAVED/'bundles/historical-v1')
        r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'unresolved'})
        self.assertEqual(r['requirements'][0]['candidate_presence'],'bytes_available')
        self.assertEqual(r['requirements'][0]['candidates'][0]['reason'],'POST_IDENTIFIER_BINDING_UNSUPPORTED')
        self.assertEqual(self.native(r,'s3')['native_result']['assessment'],'supported_under_local_assumptions')

    def test_historical_observation_remains_an_unknown_competitor(self):
        self.f.row(attempt=ATTEMPT);self.f.bundle('historical',SAVED/'bundles/historical-v1');self.f.bundle('normal')
        r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'unresolved'})
        self.assertEqual(r['requirements'][0]['unique_candidates'],1)
        self.assertIn('UNKNOWN_COMPETING_CANDIDATE',r['requirements'][0]['reasons'])
        self.assertTrue(all(c['result']['native_result']['assessment']=='supported_under_local_assumptions' for c in r['native_calls'] if c['kind']=='s3'))

    def test_same_attempt_unknown_post_identifier_is_not_excluded(self):
        self.f.row(attempt=ATTEMPT);e=self.f.bundle()
        for identifier in ('unrecognized-post-id','post-'+ATTEMPT+'-other-suffix','post-another-attempt'):
            with self.subTest(identifier=identifier):
                post=json.loads(self.f.post);post['receipt_id']=identifier;raw=encode(post)
                e['originals']['post.json']=self.f.event(raw)
                manifest=json.loads((BUNDLE/'manifest.json').read_bytes())
                manifest['artifacts']['post.json']={'digest':{'alg':'sha-256','value':sha(raw)},'byte_length':len(raw)}
                e['originals']['manifest.json']=self.f.event(encode(manifest));r=self.assess()
                self.assertEqual(self.coverage(r),{'A':'unresolved'})
                self.assertEqual(r['requirements'][0]['candidates'][0]['reason'],'POST_IDENTIFIER_BINDING_UNSUPPORTED')

    def test_prior_report_missing_cutoff_is_diagnostic(self):
        before,_,_=self.prior();before.pop('assessment_cutoff')
        self.f.review['previous_report_ref']=self.f.store(encode(before));r=self.assess()
        self.assertEqual(r['review_set_status'],'invalid');self.assertEqual(r['requirements'],[])

    def test_signature_composition_keeps_unsupported_requests(self):
        self.setup_sig();self.f.review['requirements'][0]['requested_native_checks'].append('operation_population_coverage')
        r=self.assess();self.assertEqual(r['entries'][0]['check_support']['unsupported'],['operation_population_coverage'])

    def test_invalid_policy_reference_shape_is_rejected(self):
        for invalid in ([],{},0,False,''):
            with self.subTest(value=invalid):
                self.f.selection['native_policy_refs']['signature']=invalid
                self.assertEqual(self.assess()['review_set_status'],'invalid')

    def test_nonbytes_selection_does_not_escape(self):
        for value in (False,[],{},'text',1):
            with self.subTest(value=value):
                r=Reviewer(path_bases=self.f.roots(),source_root=ROOT).assess(value)
                self.assertEqual(r['review_set_status'],'invalid')


    def test_identical_attempt_resend_unknown_arrival_is_present_unknown(self):
        self.f.row(attempt=ATTEMPT);e=self.f.bundle();e['originals']['post.json']['received_at']='2026-10-20T12:30:00Z'
        again=self.f.bundle('resend');again['originals']['post.json'].update(received_at=None,cutoff_membership='unknown')
        r=self.assess();self.assertEqual(self.coverage(r),{'A':'present'});self.assertEqual(r['requirements'][0]['timeliness'],'unknown')
        self.assertEqual(r['requirements'][0]['candidates'][1]['deduplicated_unknown'],'identical_complete_bundle')

    def test_identical_bundle_unknown_support_does_not_add_competitor(self):
        self.f.row(attempt=ATTEMPT);self.f.bundle();again=self.f.bundle('resend')
        again['originals']['manifest.json'].update(received_at=None,cutoff_membership='unknown')
        self.assertEqual(self.coverage(self.assess()),{'A':'present'})

    def test_same_post_different_unknown_support_stays_unresolved(self):
        self.f.row(attempt=ATTEMPT);self.f.bundle();again=self.f.bundle('resend')
        again['originals']['manifest.json']=self.f.event(b'{}',received=None,member='unknown')
        self.assertEqual(self.coverage(self.assess()),{'A':'unresolved'})

    def test_cli_selection_fifo_rejected(self):
        path=self.f.folder/'selection-fifo';os.mkfifo(path)
        command=[sys.executable,str(HERE/'required_records.py'),'--selection',str(path),
                 '--source-root',str(ROOT),'--output',str(self.f.folder/'no-report.json')]
        run=subprocess.run(command,capture_output=True,timeout=10)
        self.assertEqual(run.returncode,64);self.assertFalse((self.f.folder/'no-report.json').exists())


    def test_processing_deadline_marks_remaining_candidates_unknown(self):
        self.setup_pair();first=deepcopy(self.f.snapshot['entries'][0])
        for i in range(63):
            e=deepcopy(first);e['entry_id']=f'resend-{i:03}';self.f.snapshot['entries'].append(e)
        native_candidate=Reviewer._candidate
        def slow(*args):
            time.sleep(0.03);return native_candidate(*args)
        with patch.object(Reviewer,'_candidate',staticmethod(slow)):
            r=self.assess(limits={'seconds':1})
        self.assertTrue(r['invocation_errors']);self.assertEqual(self.coverage(r),{'A':'unresolved'})
        self.assertTrue(r['requirements'][0]['unprocessed_entry_ids'])

    def test_large_generated_report_is_usable_as_previous_revision(self):
        first=self.f.pair('entry-000')
        for i in range(64):
            context=deepcopy(self.f.context)
            if i:
                context['transaction_id']=f'other-{i:03}'
                e=deepcopy(first);e['entry_id']=f'entry-{i:03}';self.f.snapshot['entries'].append(e)
            self.f.row(f'row-{i:03}',context=context)
        previous=self.assess();raw=encode(previous);self.assertGreater(len(raw),1024*1024)
        self.f.review.update(revision=2,previous_review_set_ref=self.f.store((self.f.folder/'review-set.json').read_bytes(),'history/set.json'),
            previous_report_ref=self.f.store(raw,'history/report.json'),revision_basis_ref=self.f.basis)
        r=self.assess();self.assertEqual(r['review_set_status'],'selected')
        self.assertEqual(r['usage']['history_bytes_read'],len(raw))

    def test_native_hard_deadline_returns_error_and_reaps_worker(self):
        from native_bridge import Bridge
        bridge=Bridge(source_root=ROOT,openssl=None,openssl_sha256=None,limits={'seconds':1,'native_calls':1,'native_result_bytes':2097152},started=time.monotonic(),calls=[])
        owned=[];processes=[];temporary=tempfile.TemporaryDirectory;popen=subprocess.Popen
        def tracked_temp(*args,**kwargs):
            value=temporary(*args,**kwargs);owned.append(Path(value.name));return value
        def delayed_worker(args,**kwargs):
            # Owned synthetic worker proves deadline/reaping without depending on
            # another task's temp paths or on real verifier startup speed.
            value=popen([sys.executable,'-c','import time; time.sleep(10)'],**kwargs)
            processes.append(value);return value
        with patch('native_bridge.tempfile.TemporaryDirectory',side_effect=tracked_temp),patch('native_bridge.subprocess.Popen',side_effect=delayed_worker):
            r=bridge._run(encode({'kind':'receipt','payload':{},'source_root':str(ROOT),'checks':[]}),0.03)
        self.assertEqual(r['error']['code'],'EVALUATION_LIMIT')
        self.assertTrue(owned);self.assertTrue(all(not p.exists() for p in owned))
        self.assertTrue(all(p.poll() is not None for p in processes))


    def test_oversized_proof_and_s3_member_are_logged_read_errors(self):
        e=self.setup_sig();e['detached_proofs']['post']=self.f.event(b' '*4097)
        r=self.assess();self.assertTrue(r['invocation_errors'])
        self.assertEqual(self.coverage(r),{'A':'present'})
        self.assertTrue(any(x.get('error',{}).get('code')=='INPUT_SIZE_ERROR' for x in r['input_refs']))
        # The same ref may already be cached as a basis. Its narrower proof cap
        # still produces a logged failure, rather than silently reusing bytes.
        ref=e['detached_proofs']['post']['ref'];self.f.review['population_basis_refs'].append(ref)
        r=self.assess();self.assertTrue(r['invocation_errors'])
        self.assertTrue(any(x.get('error',{}).get('code')=='INPUT_SIZE_ERROR' for x in r['input_refs']))
        self.f.snapshot['entries']=[];e=self.f.bundle();e['originals']['get-body.bin']=self.f.event(b'x'*(256*1024+1))
        r=self.assess();self.assertTrue(r['invocation_errors'])
        self.assertTrue(any(x.get('error',{}).get('code')=='INPUT_SIZE_ERROR' for x in r['input_refs']))

    def test_partial_inventory_invalidates_uniqueness(self):
        self.setup_pair();self.f.snapshot['inventory_state']='partial'
        self.assertEqual(self.coverage(self.assess()),{'A':'unresolved'})
    def test_hints_and_order_do_not_change_unknown_propagation(self):
        self.setup_pair();self.f.row('B',context=self.f.other()[2]);bad=self.f.pair('unknown',post=b'bad')
        bad['candidate_for']=['B'];first=self.assess();bad['candidate_for']=['A'];self.f.snapshot['entries'].reverse();second=self.assess()
        self.assertEqual(self.coverage(first),{'A':'unresolved','B':'unresolved'});self.assertEqual(self.coverage(first),self.coverage(second))
    def test_unrelated_namespace_bad_json_does_not_spread(self):
        self.setup_pair();self.f.pair('bad',post=b'bad')['source_namespace']='another'
        self.assertEqual(self.coverage(self.assess()),{'A':'present'})
    def test_semantic_alias_rejected(self):
        self.f.row('A');self.f.row('B');self.assertEqual(self.assess()['review_set_status'],'invalid')
    def test_same_label_different_context_rejected(self):
        self.f.row('A');self.f.row('B',operation='A',context=self.f.other()[2]);self.assertEqual(self.assess()['review_set_status'],'invalid')
    def test_operation_attempt_overlap_rejected(self):
        self.f.row('A');self.f.row('A-attempt',operation='A',attempt=ATTEMPT);self.assertEqual(self.assess()['review_set_status'],'invalid')
    def test_late_support_cannot_fill_past_attempt(self):
        self.f.row(attempt=ATTEMPT);e=self.f.bundle();e['originals']['attempt.json'].update(received_at='2026-10-20T13:30:00Z',cutoff_membership='after')
        self.assertEqual(self.coverage(self.assess()),{'A':'unresolved'})
    def test_support_time_distinct_from_receipt_time(self):
        self.f.row(attempt=ATTEMPT);e=self.f.bundle();e['originals']['manifest.json']['received_at']='2026-10-20T12:30:00Z'
        row=self.assess()['requirements'][0];self.assertEqual(row['record_coverage'],'present');self.assertEqual(row['timeliness'],'on_time')
        self.assertEqual(row['candidates'][0]['binding_available_at'],'2026-10-20T12:30:00Z')
    def test_unknown_resend_prevents_late_claim(self):
        self.setup_pair()['originals']['post']['received_at']='2026-10-20T12:30:00Z'
        self.f.pair('resend')['originals']['post'].update(received_at=None,cutoff_membership='unknown');r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'present'});self.assertEqual(r['requirements'][0]['timeliness'],'unknown')
    def test_signature_policy_early_error_preserves_receipt(self):
        self.setup_sig();self.f.selection['native_policy_refs']['signature']=self.f.store(b'{}');r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'present'});self.assertEqual(self.native(r,'signature')['error']['code'],'INVALID_POLICY')
        self.assertEqual(self.native(r)['native_result']['record_linkage'],'matched')
    def test_signature_missing_configuration_is_not_unrequested(self):
        self.setup_sig();self.f.selection['native_policy_refs']['signature']=None;r=self.assess()
        self.assertEqual(self.native(r,'signature')['error']['code'],'MISSING_RECEIVER_POLICY');self.assertEqual(self.native(r)['native_result']['record_linkage'],'matched')
    def test_different_proofs_keep_two_full_native_results(self):
        e=self.setup_sig();other=deepcopy(e);other['entry_id']='other-proof';proof=json.loads(self.sig.sign('post_execution',self.f.post,0));proof['key_sha256']=self.sig.keys[1]['key_sha256'];other['detached_proofs']['post']=self.f.event(encode(proof))
        self.f.snapshot['entries'].append(other);r=self.assess()
        self.assertEqual(self.coverage(r),{'A':'present'});self.assertEqual(len(r['native_calls']),2)
        self.assertEqual({c['result']['signatures']['post_execution']['status'] for c in r['native_calls']},{'verified','invalid'})
    def test_native_full_receipt_response_preserved(self):
        self.setup_pair();r=self.assess();sys.path.insert(0,str(ROOT/'reference/recipient-assessment'))
        from vate_recipient import RecipientAssessor, API_CONTRACT
        direct=RecipientAssessor(expected_api_contract=API_CONTRACT).assess_receipts(self.f.admission,self.f.post,requested_checks=['receipt_linkage'])
        self.assertEqual(self.native(r),direct)
    def test_native_call_budget_does_not_cancel_operation_presence(self):
        self.setup_pair();a,p,c=self.f.other();self.f.row('B',context=c);self.f.pair('B',admission=a,post=p)
        r=self.assess(limits={'native_calls':1});self.assertEqual(self.coverage(r),{'A':'present','B':'present'})
        self.assertTrue(r['invocation_errors']);self.assertEqual(r['native_calls'][1]['result']['error']['code'],'EVALUATION_LIMIT')
    def test_native_result_storage_limit(self):
        self.setup_pair();r=self.assess(limits={'native_result_bytes':1});self.assertEqual(self.coverage(r),{'A':'present'})
        self.assertEqual(self.native(r)['error']['code'],'EVALUATION_LIMIT')
    def test_source_mismatch_is_not_bypassed(self):
        self.setup_sig()
        with patch('native_bridge.source_identity',side_effect=Problem('SOURCE_MISMATCH','test source mismatch')):
            r=self.assess()
        self.assertEqual([c['kind'] for c in r['native_calls']],['signature']);self.assertEqual(self.native(r,'signature')['error']['code'],'SOURCE_MISMATCH')
    def test_path_escape_and_unknown_fields_rejected(self):
        self.f.row();self.f.basis['path']='../outside';self.assertEqual(self.assess()['review_set_status'],'invalid')
    def test_symlink_not_read(self):
        e=self.setup_pair();ref=e['originals']['post']['ref'];path=self.f.folder/ref['path'];path.unlink();path.symlink_to(BUNDLE/'post.json')
        r=self.assess();self.assertEqual(self.coverage(r),{'A':'unresolved'});self.assertTrue(r['invocation_errors'])
    def test_fifo_not_read_or_blocking(self):
        e=self.setup_pair();ref=e['originals']['post']['ref'];path=self.f.folder/ref['path'];path.unlink();os.mkfifo(path)
        r=self.assess();self.assertEqual(self.coverage(r),{'A':'unresolved'});self.assertTrue(r['invocation_errors'])
    def test_membership_conflicting_with_time(self):
        self.setup_pair()['originals']['post']['cutoff_membership']='unknown'
        self.assertEqual(self.assess()['review_set_status'],'invalid')
    def test_removed_prior_requirement_rejected(self):
        self.prior();self.f.review['requirements']=[];self.assertEqual(self.assess()['review_set_status'],'invalid')
    def test_unknown_type_and_boolean_int_rejected(self):
        self.f.review['revision']=True;self.assertEqual(self.assess()['review_set_status'],'invalid')
    def test_strict_json_and_time(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":0.1}',b'{"a":NaN}',b'{"a":"\\ud800"}',b'{"a":'+b'['*20+b'0'+b']'*20+b'}'):
            with self.subTest(raw=raw),self.assertRaises(Problem):decode(raw)
        for v in (True,'2026-10-20T12:00:00+00:00','2026-10-20T12:00:00.1234567Z','2026-10-20T12:00:60Z'):
            with self.subTest(time=v),self.assertRaises(Problem):stamp(v)
        self.assertEqual(stamp('2026-10-20T12:00:00.1Z'),stamp('2026-10-20T12:00:00.100000Z'))
    def test_cli_no_overwrite_and_exit_meaning(self):
        self.f.row();self.f.seal();out=self.f.folder/'result.json'
        command=[sys.executable,str(HERE/'required_records.py'),'--selection',str(self.f.folder/'selection.json'),
                 '--base','inputs='+str(self.f.folder),'--base','repository='+str(ROOT),'--source-root',str(ROOT),'--output',str(out)]
        run=subprocess.run(command,capture_output=True,timeout=10);self.assertEqual(run.returncode,0,run.stderr)
        raw=out.read_bytes();self.assertEqual(self.coverage(json.loads(raw)),{'A':'missing'})
        run=subprocess.run(command,capture_output=True,timeout=10);self.assertEqual(run.returncode,64);self.assertEqual(out.read_bytes(),raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
