"""Run a reproducible demo without modifying the supplied demo-files."""
import json, shutil, tempfile
from pathlib import Path
from integrity import snapshot, compare

with tempfile.TemporaryDirectory() as folder:
    root=Path(folder)/'lab'
    shutil.copytree(Path(__file__).with_name('demo-files'),root)
    baseline=snapshot(root)
    (root/'settings.ini').write_text('[application]\nenvironment = lab\ndebug = true\n')
    (root/'access-policy.txt').unlink()
    (root/'unexpected.txt').write_text('Synthetic demonstration file.\n')
    result=compare(baseline,snapshot(root))
    print(json.dumps(result,indent=2))
    Path(__file__).with_name('sample-report.json').write_text(json.dumps(result,indent=2)+'\n')
