"""Authentication log analyzer. Python 3.10+, no dependencies."""
import argparse, csv, ipaddress, json, sys
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path


def load(path):
    events = []
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if not {'timestamp','source_ip','username','outcome'}.issubset(reader.fieldnames or []):
            raise ValueError('Required columns: timestamp,source_ip,username,outcome')
        for line, row in enumerate(reader, 2):
            try:
                t = datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
                if t.tzinfo is None: raise ValueError('Timezone required')
                ip = str(ipaddress.ip_address(row['source_ip'].strip()))
                user, outcome = row['username'].strip(), row['outcome'].strip().lower()
                if not user or outcome not in ('success','failure'): raise ValueError('Invalid username/outcome')
                events.append((t,ip,user,outcome))
            except (ValueError, AttributeError, TypeError) as e:
                raise ValueError(f'Row {line}: {e}') from e
    return sorted(events, key=lambda e:e[0])


def analyze(events, threshold=5, minutes=10, spray_users=4):
    if min(threshold,minutes,spray_users)<1: raise ValueError('Settings must be positive')
    ips, accounts = defaultdict(deque), defaultdict(deque)
    active, alerts = set(), []
    for t,ip,user,outcome in sorted(events,key=lambda e:e[0]):
        account=(ip,user)
        iq,aq=ips[ip],accounts[account]
        for q in (iq,aq):
            while q and t-q[0][0]>timedelta(minutes=minutes): q.popleft()
        if len(aq)<threshold: active.discard(('repeated_failures',account))
        if len({u for _,u in iq})<spray_users: active.discard(('password_spray',ip))
        rules=[]
        if outcome=='failure':
            iq.append((t,user)); aq.append((t,user))
            if len(aq)>=threshold: rules.append(('repeated_failures',account,'medium',len(aq)))
            if len({u for _,u in iq})>=spray_users: rules.append(('password_spray',ip,'medium',len(iq)))
        elif len(aq)>=threshold:
            rules.append(('success_after_failures',account,'high',len(aq)))
            aq.clear(); active.discard(('repeated_failures',account))
        for rule,key,severity,count in rules:
            if (rule,key) not in active or rule=='success_after_failures':
                alerts.append(dict(timestamp=t.isoformat(),rule=rule,severity=severity,source_ip=ip,username=user,failure_count=count))
                if rule!='success_after_failures': active.add((rule,key))
    return dict(event_count=len(events),alert_count=len(alerts),alerts=alerts)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('log',type=Path); p.add_argument('--json',type=Path)
    p.add_argument('--threshold',type=int,default=5); p.add_argument('--minutes',type=int,default=10)
    p.add_argument('--spray-users',type=int,default=4)
    a=p.parse_args()
    try:
        report=analyze(load(a.log),a.threshold,a.minutes,a.spray_users)
        if a.json:
            if a.json.resolve()==a.log.resolve(): raise ValueError('Report cannot overwrite input')
            a.json.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(f"Processed {report['event_count']} events; found {report['alert_count']} alerts.")
        for alert in report['alerts']: print(f"[{alert['severity'].upper()}] {alert['rule']} | {alert['source_ip']} | {alert['username']}")
        return 1 if report['alerts'] else 0
    except (OSError,ValueError,csv.Error) as e:
        print(f'Error: {e}',file=sys.stderr); return 2

if __name__=='__main__': sys.exit(main())
