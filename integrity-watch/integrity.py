"""SHA-256 file integrity monitor. Python 3.10+, no dependencies."""
import argparse, hashlib, json, os, sys
from datetime import datetime, timezone
from pathlib import Path


def snapshot(root):
    root=Path(root).resolve(strict=True)
    if not root.is_dir(): raise ValueError('Target must be a directory')
    files,skipped={},[]
    def fail(e): raise e
    for folder,dirs,names in os.walk(root,followlinks=False,onerror=fail):
        for name in dirs[:]:
            item=Path(folder)/name
            if item.is_symlink() or (hasattr(item,'is_junction') and item.is_junction()):
                skipped.append(item.relative_to(root).as_posix()); dirs.remove(name)
        for name in names:
            item=Path(folder)/name; relative=item.relative_to(root).as_posix()
            if item.is_symlink() or not item.is_file(): skipped.append(relative); continue
            before=item.stat(); digest=hashlib.sha256()
            with item.open('rb') as f:
                while chunk:=f.read(1024*1024): digest.update(chunk)
            after=item.stat()
            if (before.st_size,before.st_mtime_ns,before.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ino):
                raise ValueError(f'File changed during scan: {relative}; retry with idle files')
            files[relative]=dict(sha256=digest.hexdigest(),size=after.st_size)
    return dict(version=1,root=str(root),created_at=datetime.now(timezone.utc).isoformat(),files=dict(sorted(files.items())),skipped=sorted(skipped))


def compare(old,new):
    a,b=old['files'],new['files']
    return dict(added=sorted(b.keys()-a.keys()),deleted=sorted(a.keys()-b.keys()),
                modified=sorted(k for k in a.keys()&b.keys() if a[k]['sha256']!=b[k]['sha256']),
                unchanged=sum(a[k]['sha256']==b[k]['sha256'] for k in a.keys()&b.keys()),skipped=new['skipped'])


def load_baseline(path):
    data=json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if not isinstance(data,dict) or data.get('version')!=1 or not isinstance(data.get('files'),dict) or not isinstance(data.get('root'),str):
        raise ValueError('Invalid baseline schema')
    for record in data['files'].values():
        if not isinstance(record,dict) or not isinstance(record.get('sha256'),str) or len(record['sha256'])!=64 or any(c not in '0123456789abcdef' for c in record['sha256']):
            raise ValueError('Invalid baseline digest')
    return data


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['baseline','check']); p.add_argument('directory',type=Path)
    p.add_argument('--baseline',required=True,type=Path); p.add_argument('--json',type=Path)
    a=p.parse_args()
    try:
        root=a.directory.resolve(strict=True)
        for path in (a.baseline,a.json):
            if path and path.resolve().is_relative_to(root): raise ValueError('Baseline/report must be outside target directory')
        if a.json and a.json.resolve()==a.baseline.resolve(): raise ValueError('Report cannot overwrite baseline')
        if a.command=='baseline':
            if a.json: raise ValueError('--json is only supported for check')
            data=snapshot(root)
            with a.baseline.open('x',encoding='utf-8') as f: json.dump(data,f,indent=2)
            print(f"Baseline created: {len(data['files'])} files, {len(data['skipped'])} skipped."); return 0
        baseline=load_baseline(a.baseline)
        if Path(baseline['root']).resolve()!=root: raise ValueError('Baseline belongs to another directory')
        report=compare(baseline,snapshot(root))
        if a.json: a.json.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        for category in ('added','modified','deleted','skipped'):
            print(f'{category.upper()}: {len(report[category])}')
            for name in report[category]: print(f'  {name}')
        print(f"UNCHANGED: {report['unchanged']}")
        return 1 if any(report[k] for k in ('added','modified','deleted')) else 0
    except (OSError,ValueError,TypeError) as e:
        print(f'Error: {e}',file=sys.stderr); return 2

if __name__=='__main__': sys.exit(main())
