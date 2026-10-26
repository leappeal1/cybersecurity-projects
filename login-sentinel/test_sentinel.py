import tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from sentinel import analyze, load

def event(m,user='admin',outcome='failure',ip='192.0.2.1'):
    return (datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(minutes=m),ip,user,outcome)

class Tests(unittest.TestCase):
    def test_sample(self):
        self.assertEqual([a['rule'] for a in analyze(load(Path(__file__).with_name('sample-auth.csv')))['alerts']],['repeated_failures','success_after_failures','password_spray'])
    def test_expired_window(self):
        self.assertEqual(analyze([event(i*11) for i in range(5)])['alert_count'],0)
    def test_inclusive_boundary_and_sorting(self):
        self.assertEqual(analyze([event(10),event(0)],threshold=2)['alert_count'],1)
    def test_success_requires_same_account_and_ip(self):
        events=[event(i) for i in range(5)]+[event(6,'other','success'),event(7,outcome='success',ip='192.0.2.2')]
        self.assertEqual(analyze(events)['alert_count'],1)
    def test_distinct_users(self):
        self.assertEqual(analyze([event(i) for i in range(4)])['alert_count'],0)
        self.assertEqual(analyze([event(i,str(i)) for i in range(4)])['alerts'][0]['rule'],'password_spray')
    def test_dedup_and_rearm(self):
        self.assertEqual(analyze([event(i) for i in range(8)])['alert_count'],1)
        self.assertEqual(analyze([event(i) for i in list(range(5))+list(range(20,25))])['alert_count'],2)
    def test_bad_input(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'input.csv'
            for row in ['bad,192.0.2.1,admin,failure','2026-01-01T00:00:00,192.0.2.1,admin,failure','2026-01-01T00:00:00Z,bad,admin,failure']:
                p.write_text('timestamp,source_ip,username,outcome\n'+row)
                with self.assertRaises(ValueError): load(p)
    def test_invalid_settings(self):
        with self.assertRaises(ValueError): analyze([],threshold=0)

if __name__=='__main__': unittest.main()
