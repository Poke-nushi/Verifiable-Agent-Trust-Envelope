"""Offline regressions for bounded diagnostics and explicit historical replay."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
CURRENT=HERE.parents[1]
sys.path.insert(0,str(CURRENT/'reference/runtime-support'))
from historical import historical_root
HISTORICAL=historical_root(CURRENT)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

def encode(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
def sha(raw): return hashlib.sha256(raw).hexdigest()

example=load('bounded_example',CURRENT/'reference/receipt-linkage-example/recipient_example.py')
api=load('bounded_api',CURRENT/'reference/recipient-assessment/vate_recipient.py')
oldapi=load('historical_api',HISTORICAL/'reference/recipient-assessment/vate_recipient.py')
contract=load('bounded_s3_contract',CURRENT/'reference/s3-observation-example/contract.py')
SAVED=HISTORICAL/'reference/s3-observation-example/inputs/seaweedfs-4.48/instance'
BUNDLE=SAVED/'bundles/supported'
sys.path.insert(0,str(CURRENT/'reference/recipient-inbox'))
from recipient_inbox import Engine, Inbox, InboxError
from scenario_inputs import plan_for, delivery, next_plan


def synthetic_bundle(folder, *, admission=None):
    """Derived offline bytes with candidate source declarations; never a new S3 capture."""
    shutil.copytree(BUNDLE,folder)
    (folder/'sources.json').write_bytes(contract.encode(contract.sources()))
    if admission is not None: (folder/'admission.json').write_bytes(admission)
    (folder/'manifest.json').unlink(); contract.seal(folder)
    policy=json.loads((SAVED/'receiver-policy.json').read_bytes())
    policy['source_hashes']=contract.sources()
    return encode(policy)


class BudgetTests(unittest.TestCase):
    def test_count_stops_generation_at_limit_without_lookahead(self):
        def values():
            for _ in range(32): yield {'input':'admission','kind':'schema_invalid','detail':'bad'}
            raise AssertionError('iterator was consumed beyond the diagnostic limit')
        budget=example.DiagnosticBudget(); budget.consume(values())
        self.assertEqual(len(budget.items),32); self.assertTrue(budget.collection_stopped)
        result={}; budget.attach(result,'input_issues')
        self.assertIsNone(result['diagnostic_truncation']['input_issues']['total_errors'])

    def test_under_count_limit_has_no_marker(self):
        budget=example.DiagnosticBudget(); budget.consume(['bad']*31); result={}
        budget.attach(result,'input_issues')
        self.assertNotIn('diagnostic_truncation',result)

    def test_unicode_path_and_detail_have_explicit_truncation(self):
        budget=example.DiagnosticBudget()
        budget.add({'input':'admission','kind':'schema_invalid','path':['😀'*10000]*100,'detail':'😀'*10000})
        item=budget.items[0]
        self.assertEqual(len(item['detail']),512); self.assertEqual(len(item['path']),16)
        self.assertTrue(all(len(p)==128 for p in item['path']))
        self.assertTrue(item['detail_truncated']); self.assertTrue(item['path_truncated'])
        self.assertLessEqual(len(encode(budget.items)),32768)
        self.assertEqual(budget.json_bytes,len(encode(budget.items)))

    def test_encoded_byte_limit_stops_before_overflow(self):
        budget=example.DiagnosticBudget()
        item={'input':'post','kind':'schema_invalid','path':['😀'*128]*16,'detail':'😀'*512}
        self.assertTrue(budget.add(item)); self.assertFalse(budget.add(item))
        self.assertEqual(len(budget.items),1); self.assertTrue(budget.found)
        self.assertLessEqual(len(encode(budget.items)),32768)

    def test_exact_byte_boundary_and_first_item_rejection_stay_invalid(self):
        for limit, count in ((7,1),(6,0)):
            with self.subTest(limit=limit), patch.dict(example.DIAGNOSTIC_LIMITS,{'list_json_bytes':limit}):
                budget=example.DiagnosticBudget(); budget.add('abc'); result={}
                budget.attach(result,'input_issues')
                self.assertEqual(len(budget.items),count); self.assertTrue(budget.found)
                self.assertTrue(result['diagnostic_truncation']['input_issues']['collection_stopped_at_limit'])


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reader=example.RecipientExample()
        cls.admission=(CURRENT/'reference/receipt-linkage-example/inputs/R17/admission.json').read_bytes()
        cls.post=(CURRENT/'reference/receipt-linkage-example/inputs/R17/post.json').read_bytes()

    def link(self,admission,post=None):
        value=json.loads(self.post) if post is None else deepcopy(post)
        value['admission'].update(receipt_id=admission['receipt_id'],digest=self.reader.runner.digest_descriptor(admission),decision=admission['decision']['outcome'])
        value['execution'].update(transaction_id=admission['request']['transaction_id'],runtime=admission['subject']['runtime'],
            effective_request_hash=self.reader.runner.admitted_effective_request_hash(admission),started_at=admission['issued_at'],finished_at=admission['expires_at'])
        value['issued_at']=admission['expires_at']; return value

    def assert_bounded_invalid(self,raw,post=None):
        result=self.reader.assess(raw,self.post if post is None else post)
        self.assertEqual(result['record_linkage'],'not_assessed'); self.assertIsNone(result['core_result'])
        self.assertEqual(result['inputs']['admission']['raw_file_sha256'],sha(raw))
        self.assertTrue(result['inputs']['post']['supplied'])
        self.assertLessEqual(len(result['input_issues']),32)
        self.assertLessEqual(len(encode(result['input_issues'])),32768)
        self.assertIn('input_issues',result['diagnostic_truncation'])
        return result

    def test_hundred_thousand_schema_errors_and_both_original_hashes(self):
        admission=json.loads(self.admission); admission['decision']['reason_codes']=[0]*100000
        result=self.assert_bounded_invalid(encode(admission))
        self.assertEqual(len(result['input_issues']),32)
        self.assertTrue(all(i['kind']=='schema_invalid' for i in result['input_issues']))
        self.assertEqual(result['inputs']['post']['raw_file_sha256'],sha(self.post))
        self.assertLess(len(encode(result)),10000)

    def test_schema_iterator_is_not_exhausted(self):
        seen=[]
        def errors(value):
            for i in range(32):
                seen.append(i)
                yield type('Error',(),{'absolute_path':['decision','reason_codes',i],'message':'bad'})()
            raise AssertionError('schema iterator was exhausted')
        validator=type('Validator',(),{'iter_errors':staticmethod(errors)})()
        with patch.dict(self.reader.validators,{'admission':validator}):
            self.assert_bounded_invalid(self.admission)
        self.assertEqual(len(seen),32)

    def test_cli_io_errors_share_the_same_budget(self):
        admission=json.loads(self.admission); admission['decision']['reason_codes']=[0]*32
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'admission.json'; path.write_bytes(encode(admission))
            result=subprocess.run([sys.executable,'-B',str(example.HERE/'recipient_example.py'),
                '--admission',str(path),'--post',str(Path(temp)/'missing.json')],capture_output=True,timeout=20)
        self.assertEqual(result.returncode,2); self.assertEqual(result.stderr,b'')
        output=json.loads(result.stdout)
        self.assertEqual(output['record_linkage'],'not_assessed')
        self.assertEqual(output['inputs']['post']['file_status'],'unreadable')
        self.assertEqual(len(output['input_issues']),32)
        self.assertTrue(output['diagnostic_truncation']['input_issues']['collection_stopped_at_limit'])

    def test_large_single_message(self):
        for value in ('😀'*30000,'a'*200000):
            with self.subTest(char=value[0]):
                admission=json.loads(self.admission); admission['decision']['outcome']=value
                result=self.assert_bounded_invalid(encode(admission))
                self.assertTrue(any(i.get('detail_truncated') for i in result['input_issues']))
                self.assertLess(len(encode(result)),16000)

    def test_large_key_path_from_jsonschema_is_bounded(self):
        validator=example.Draft202012Validator({'type':'object','additionalProperties':{'type':'number'}})
        value={'😀'*30000:'a'*10000}
        with patch.dict(self.reader.validators,{'admission':validator}):
            result=self.assert_bounded_invalid(encode(value))
        self.assertTrue(result['input_issues'][0]['path_truncated'])
        self.assertTrue(result['input_issues'][0]['detail_truncated'])

    def test_zero_display_capacity_cannot_become_success(self):
        with patch.dict(example.DIAGNOSTIC_LIMITS,{'list_json_bytes':2}):
            result=self.reader.assess(b'{}',self.post)
        self.assertEqual(result['input_issues'],[])
        self.assertEqual(result['record_linkage'],'not_assessed')
        self.assertIsNone(result['core_result'])
        self.assertIn('input_issues',result['diagnostic_truncation'])

    def test_large_semantic_attenuation_uses_lazy_helper(self):
        admission=json.loads((CURRENT/'examples/receipts/admission-attenuate-max-amount.example.json').read_bytes())
        change=deepcopy(admission['attenuation']['changes'][0]); change['reason_code']='NOT_IN_DECISION'
        admission['attenuation']['changes']=[change]*3000
        raw=encode(admission); self.assertLess(len(raw),example.MAX_INPUT_BYTES)
        result=self.assert_bounded_invalid(raw,encode(self.link(admission)))
        self.assertTrue(all(i['kind']=='semantic_input_invalid' for i in result['input_issues']))

    def test_many_declared_descriptor_errors(self):
        admission=json.loads(self.admission)
        sample=deepcopy(admission['evidence'][0]); sample['digest']['value']='a'*64+'\n'
        admission['evidence']=[sample]*1000
        result=self.assert_bounded_invalid(encode(admission))
        self.assertTrue(all(i['kind']=='semantic_input_invalid' for i in result['input_issues']))

    def test_many_tool_precondition_errors(self):
        admission=json.loads(self.admission); admission['request']['constraints']['tool_allowlist']=['allowed']
        post=self.link(admission); post['result']['side_effects']=[{'tool':42}]*3000
        result=self.reader.assess(encode(admission),encode(post))
        self.assertEqual(result['record_linkage'],'not_assessed')
        self.assertEqual(len(result['input_issues']),32)
        self.assertTrue(all(i['kind']=='semantic_input_invalid' for i in result['input_issues']))

    def test_many_currency_mismatches_stay_mismatch(self):
        admission=json.loads(self.admission); admission['request']['constraints']['max_amount']={'currency':'USD','value':'1000'}
        post=self.link(admission); post['result']['side_effects']=[{'amount':{'currency':'EUR','value':'1'}}]*3000
        result=self.reader.assess(encode(admission),encode(post))
        self.assertEqual(result['record_linkage'],'mismatch'); self.assertEqual(result['input_issues'],[])
        self.assertIn('POST_EXEC_EFFECTIVE_CONSTRAINTS_EXCEEDED',result['core_result']['reason_codes'])
        self.assertEqual(len(result['side_effect_check_failures']),32)
        self.assertIn('side_effect_check_failures',result['diagnostic_truncation'])

    def test_small_results_unchanged_except_verified_source_identity(self):
        old=load('historical_receipt',HISTORICAL/'reference/receipt-linkage-example/recipient_example.py').RecipientExample()
        controls=[(self.admission,self.post),(None,None),(b'{',self.post),(b'{}',self.post)]
        post=json.loads(self.post); post['execution']['runtime']='urn:changed'; controls.append((self.admission,encode(post)))
        for admission,post in controls:
            with self.subTest(admission=admission is None):
                current=self.reader.assess(admission,post); previous=old.assess(admission,post)
                self.assertEqual(current.pop('source_files'),self.reader.sources['files'])
                self.assertEqual(previous.pop('source_files'),old.sources['files'])
                self.assertEqual(current,previous)

    def test_runner_list_api_matches_historical_cases(self):
        old=load('old_runner',HISTORICAL/'scripts/vate_conformance.py')
        controls=[({},None),(json.loads(self.admission),json.loads(self.post))]
        for path in (CURRENT/'examples/receipts').glob('admission-*.json'):
            controls.append((json.loads(path.read_bytes()),json.loads(self.post)))
        for admission,post in controls:
            for name,args,kw in [
                ('attenuation_validation_failures',(admission.get('attenuation'),),{'decision_reason_codes':admission.get('decision',{}).get('reason_codes')}),
                ('generated_decision_shape_failures',(admission.get('decision'),'decision'),{}),
                ('generated_admission_receipt_shape_failures',(admission,'admission'),{}),
                ('evaluate_evidence_vocabulary_checks',(None,admission),{}),
                ('post_execution_side_effect_failures',(admission,post or {}),{})]:
                with self.subTest(function=name):
                    self.assertEqual(getattr(self.reader.runner,name)(*args,**kw),getattr(old,name)(*args,**kw))


class IntegrationTests(unittest.TestCase):
    def test_s3_current_synthetic_and_historical_source_boundaries(self):
        old=oldapi.RecipientAssessor(expected_api_contract=oldapi.API_CONTRACT)
        current=api.RecipientAssessor(expected_api_contract=api.API_CONTRACT)
        policy=(SAVED/'receiver-policy.json').read_bytes()
        oldresult=old.assess_s3(BUNDLE,policy)['native_result']
        self.assertEqual(oldresult['assessment'],'supported_under_local_assumptions')
        refused=current.assess_s3(BUNDLE,policy)['native_result']
        self.assertEqual(refused['source_trust'],'unverified')
        self.assertNotEqual(refused['assessment'],'supported_under_local_assumptions')
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'synthetic'; newpolicy=synthetic_bundle(folder)
            result=current.assess_s3(folder,newpolicy)['native_result']
            self.assertEqual(result['assessment'],'supported_under_local_assumptions')
            admission=json.loads((folder/'admission.json').read_bytes()); admission['decision']['reason_codes']=[0]*100000
            (folder/'admission.json').write_bytes(encode(admission)); (folder/'manifest.json').unlink(); contract.seal(folder)
            returned=current.assess_s3(folder,newpolicy)
            self.assertEqual(returned['native_result']['record_linkage'],'not_assessed')
            self.assertIn('diagnostic_truncation',returned['native_result']['receipt_check'])
            self.assertLess(len(encode(returned)),65536)

    def test_signature_wrapper_preserves_invalidity_and_bounded_native(self):
        sys.path.insert(0,str(CURRENT/'reference/recipient-signature-authority'))
        from trial_fixtures import Fixtures
        fixture=Fixtures(os.environ['VATE_TRIAL_OPENSSL']); arguments=fixture.arguments()
        admission=json.loads(arguments['admission']); admission['decision']['reason_codes']=[0]*100000
        arguments['admission']=encode(admission)
        arguments['admission_proof']=fixture.sign('admission',arguments['admission'],0)
        result=fixture.assessor().assess(**arguments)
        native=result['receipt_assessment']['native_result']
        self.assertEqual(native['record_linkage'],'not_assessed')
        self.assertIn('diagnostic_truncation',native)
        self.assertLess(len(encode(result)),65536)

    def test_inbox_recovers_from_old_error_and_preserves_old_records(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'inbox.sqlite3'; box=Inbox(path,Engine(HISTORICAL),create=True)
            plan=plan_for(box); admission=json.loads((BUNDLE/'admission.json').read_bytes()); admission['decision']['reason_codes']=[0]*100000
            raw=encode(admission); ref=box.put(raw)
            box.receive(delivery(box,plan,'noisy',{'admission':raw},entry_id='noisy'))
            pending=box.prepare(encode(plan))
            oldrun=box.run(box.prepare(encode(plan))['run_id'])
            self.assertEqual(oldrun['status'],'assessment_error'); self.assertIsNone(oldrun['head'])
            oldreport=box.get(oldrun['report_ref']); oldstatus=box.status(oldrun['run_id'])
            box.close(); box=Inbox(path,Engine(CURRENT),create=False)
            try:
                with self.assertRaises(InboxError): box.run(pending['run_id'])
                heads=[]
                for p in (plan,next_plan(plan)):
                    state=box.run(box.prepare(encode(p))['run_id']); report=json.loads(box.get(state['report_ref']))
                    self.assertEqual(state['status'],'completed'); self.assertFalse(report['invocation_errors'])
                    self.assertEqual(box.get(ref),raw); heads.append(state['head'])
                    self.assertTrue(any('diagnostic_truncation' in c['result'].get('native_result',{}) for c in report['native_calls']))
                self.assertNotEqual(heads[0],heads[1])
                self.assertEqual(box.get(oldrun['report_ref']),oldreport)
                self.assertEqual(box.status(oldrun['run_id'])['report_ref'],oldstatus['report_ref'])
            finally: box.close()

    def test_historical_signature_baseline_still_exact(self):
        before=json.loads((HISTORICAL/'reference/recipient-signature-authority/BASELINE.json').read_bytes())
        for name,expected in before['protected_files'].items():
            self.assertEqual(sha((HISTORICAL/name).read_bytes()),expected,name)
        result=oldapi.RecipientAssessor(expected_api_contract=oldapi.API_CONTRACT).assess_receipts(
            (BUNDLE/'admission.json').read_bytes(),(BUNDLE/'post.json').read_bytes(),
            requested_checks=['receipt_linkage','signatures_and_issuer_authority'])
        self.assertEqual(result,before['receipt_pair'])

if __name__=='__main__': unittest.main(verbosity=2)
