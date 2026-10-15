"""Source-validation failures remain visible even when no native call is needed."""
import json
import os
from pathlib import Path
import py_compile
import tempfile
import unittest
import subprocess
import sys

from fixture_inputs import Inputs, ROOT, HERE
from required_records import Reviewer, Problem


class SourceDiagnostics(unittest.TestCase):
    def test_stale_bytecode_does_not_claim_the_new_source_hash(self):
        changes=(('required_records.py',b'MIB = 1024*1024',b'MIB = 1023*1024'),
                 ('native_bridge.py',b'OUTPUT_CAP = 2*MIB',b'OUTPUT_CAP = 3*MIB'))
        for name,old,new in changes:
            with self.subTest(module=name),tempfile.TemporaryDirectory() as directory:
                folder=Path(directory);f=Inputs(folder/'inputs');f.row();f.seal()
                code=folder/'composer';code.mkdir()
                for member in ('required_records.py','native_bridge.py','NATIVE-SOURCES.json'):
                    (code/member).write_bytes((HERE/member).read_bytes())
                path=code/name;raw=path.read_bytes();info=path.stat()
                py_compile.compile(str(path),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
                script='''import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from required_records import Reviewer
root=Path(sys.argv[2]);inputs=Path(sys.argv[3])
print(json.dumps(Reviewer(path_bases={'inputs':inputs,'repository':root},source_root=root).assess((inputs/'selection.json').read_bytes())))
'''
                command=[sys.executable,'-I','-B','-c',script,str(code),str(ROOT),str(f.folder)]
                before=subprocess.run(command,capture_output=True,timeout=30)
                self.assertEqual(before.returncode,0,before.stderr)
                self.assertFalse(json.loads(before.stdout)['invocation_errors'])
                changed=raw.replace(old,new);self.assertNotEqual(changed,raw);self.assertEqual(len(changed),len(raw))
                path.write_bytes(changed);os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns))
                after=subprocess.run(command,capture_output=True,timeout=30)
                self.assertEqual(after.returncode,0,after.stderr)
                report=json.loads(after.stdout)
                self.assertTrue(report['invocation_errors'])
                self.assertTrue(any(d['code']=='COMPOSER_CODE_MISMATCH' for d in report['diagnostics']))
                self.assertIsNone(report['source_identity']['composer_sources'][name])

    def test_source_capture_respects_interpreter_optimization(self):
        script='import sys,json;sys.path.insert(0,sys.argv[1]);import required_records as r,native_bridge as b;print(json.dumps([r.LOADED_SOURCE_ERROR,b.LOADED_BRIDGE_ERROR]))'
        for flag in ('-O','-OO'):
            with self.subTest(flag=flag):
                result=subprocess.run([sys.executable,'-I','-B',flag,'-c',script,str(HERE)],capture_output=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads(result.stdout),[None,None])

    def test_source_errors_remain_visible_with_unknown_and_normal_entries(self):
        for changed in (False,True):
            for kind in ('unknown_format','receipt_pair'):
                with self.subTest(changed=changed,kind=kind),tempfile.TemporaryDirectory() as directory:
                    folder=Path(directory);f=Inputs(folder/'inputs');f.row();f.pair()['native_input_kind']=kind
                    source=folder/'source'
                    if changed:
                        for name in json.loads((HERE/'NATIVE-SOURCES.json').read_bytes()):
                            target=source/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
                        target.write_bytes(target.read_bytes()+b'\n')
                    report=Reviewer(path_bases=f.roots(),source_root=source).assess(f.seal())
                    self.assertTrue(report['invocation_errors'])
                    self.assertTrue(any(d['code']==('SOURCE_MISMATCH' if changed else 'SOURCE_UNAVAILABLE') for d in report['diagnostics']))
                    self.assertEqual(report['requirements'][0]['record_coverage'],'present' if kind=='receipt_pair' else 'unresolved')

    def test_worker_rejects_a_different_composer_identity(self):
        from native_bridge import worker
        with self.assertRaises(Problem) as caught:
            worker({'source_identity':{'composer_sources':{
                'required_records.py':'0'*64, 'native_bridge.py':'0'*64,
                'NATIVE-SOURCES.json':'0'*64}}})
        self.assertEqual(caught.exception.code,'COMPOSER_SOURCE_MISMATCH')

    def test_update_after_import_keeps_loaded_identity_and_reports_error(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory); f=Inputs(folder/'inputs'); f.row(); f.pair(); f.seal()
            code=folder/'composer'; code.mkdir()
            for name in ('required_records.py','native_bridge.py','NATIVE-SOURCES.json'):
                (code/name).write_bytes((HERE/name).read_bytes())
            script='''import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import required_records as rr
file=Path(sys.argv[1])/'required_records.py'
loaded=rr.LOADED_SOURCE_SHA256
file.write_bytes(file.read_bytes()+b'\\n# synthetic update after importing\\n')
root=Path(sys.argv[2]);inputs=Path(sys.argv[3])
report=rr.Reviewer(path_bases={'inputs':inputs,'repository':root},source_root=root).assess((inputs/'selection.json').read_bytes())
print(json.dumps({'loaded':loaded,'report':report}))
'''
            result=subprocess.run([sys.executable,'-I','-B','-c',script,str(code),str(ROOT),str(f.folder)],capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            value=json.loads(result.stdout); report=value['report']
            self.assertTrue(report['invocation_errors'])
            self.assertTrue(any(d['code']=='COMPOSER_SOURCE_MISMATCH' for d in report['diagnostics']))
            self.assertEqual(report['source_identity']['composer_sources']['required_records.py'],value['loaded'])

    def test_unavailable_sources_without_calls(self):
        for empty in (False, True):
            with self.subTest(empty=empty), tempfile.TemporaryDirectory() as directory:
                folder=Path(directory); f=Inputs(folder/'inputs')
                if not empty: f.row()
                report=Reviewer(path_bases=f.roots(),source_root=folder/'absent').assess(f.seal())
                self.assertTrue(report['invocation_errors'])
                self.assertEqual(report['native_calls'],[])
                self.assertTrue(any(d['code']=='SOURCE_UNAVAILABLE' for d in report['diagnostics']))
                self.assertEqual(report['review_set_status'],'selected_empty' if empty else 'selected')
                self.assertEqual([r['record_coverage'] for r in report['requirements']],[] if empty else ['missing'])

    def test_changed_native_source_without_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory); f=Inputs(folder/'inputs'); f.row()
            source=folder/'source'
            pins=json.loads((HERE/'NATIVE-SOURCES.json').read_bytes())
            for name in pins:
                target=source/name; target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((ROOT/name).read_bytes())
            target=source/next(iter(pins)); target.write_bytes(target.read_bytes()+b'\n')
            report=Reviewer(path_bases=f.roots(),source_root=source).assess(f.seal())
            self.assertTrue(report['invocation_errors'])
            self.assertEqual(report['native_calls'],[])
            self.assertTrue(any(d['code']=='SOURCE_MISMATCH' for d in report['diagnostics']))
            self.assertEqual(report['requirements'][0]['record_coverage'],'missing')


if __name__=='__main__':
    unittest.main()
