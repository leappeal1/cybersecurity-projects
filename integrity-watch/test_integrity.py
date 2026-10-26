import tempfile, unittest, subprocess, sys
from pathlib import Path
from integrity import snapshot, compare, load_baseline

class Tests(unittest.TestCase):
    def test_all_change_types(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in ('change','remove','stable'): (root/name).write_text('original')
            first=snapshot(root)
            (root/'change').write_text('tampered'); (root/'remove').unlink(); (root/'new').touch()
            result=compare(first,snapshot(root))
            self.assertEqual(result,dict(added=['new'],deleted=['remove'],modified=['change'],unchanged=1,skipped=[]))
    def test_same_size_change(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'file'; p.write_bytes(b'abc'); first=snapshot(folder); p.write_bytes(b'xyz')
            self.assertEqual(compare(first,snapshot(folder))['modified'],['file'])
    def test_nested_empty_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); (root/'nested').mkdir(); (root/'nested'/'empty').touch()
            first=snapshot(root)
            self.assertEqual(first['files']['nested/empty']['sha256'],'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
            self.assertEqual(compare(first,snapshot(root))['unchanged'],1)
    def test_invalid_baseline(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'bad.json'; p.write_text('{"version":1,"root":"x","files":{"a":{}}}')
            with self.assertRaises(ValueError): load_baseline(p)
    def test_cli_preserves_baseline_and_rejects_inside_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'target'; root.mkdir(); (root/'file').write_text('hello')
            baseline=Path(folder)/'baseline.json'
            command=[sys.executable,str(Path(__file__).with_name('integrity.py')),'baseline',str(root),'--baseline']
            self.assertEqual(subprocess.run(command+[str(baseline)],capture_output=True).returncode,0)
            first=baseline.read_bytes()
            self.assertEqual(subprocess.run(command+[str(baseline)],capture_output=True).returncode,2)
            self.assertEqual(first,baseline.read_bytes())
            self.assertEqual(subprocess.run(command+[str(root/'baseline.json')],capture_output=True).returncode,2)

if __name__=='__main__': unittest.main()
