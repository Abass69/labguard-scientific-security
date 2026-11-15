import json,tempfile,unittest,sqlite3
from pathlib import Path
from labguard.core import Lab,POLICY
class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.lab=Lab.initialize(Path(self.tmp.name)/'state')
        for role in POLICY: self.lab.provision(role,'local-test-password-123',role,'food-a')
    def tearDown(self): self.lab.db.close();self.tmp.cleanup()
    def token(self,role='technician'): return self.lab.login(role,'local-test-password-123')
    def test_role_action_matrix(self):
        for role,actions in POLICY.items():
            token=self.token(role)
            for action in ['read','write','export','audit','delete','provision']:
                if action in actions: self.lab.act(token,action,value='Simulated update')
                else:
                    with self.assertRaises(PermissionError): self.lab.act(token,action,value='x')
    def test_project_isolation_and_export_scope(self):
        with self.assertRaises(PermissionError): self.lab.act(self.token(),'read','S002')
        self.assertEqual({r['project'] for r in self.lab.act(self.token('researcher'),'export')},{'food-a'})
    def test_unknown_and_injection_denied(self):
        for sample in ['missing',"S001' OR 1=1 --"]:
            with self.assertRaises(PermissionError): self.lab.act(self.token(),'read',sample)
    def test_expired_and_revoked_sessions(self):
        token=self.token();self.lab.act(token,'logout')
        with self.assertRaises(PermissionError): self.lab.act(token,'read')
        token=self.token();self.lab.db.execute('UPDATE sessions SET expires=0');self.lab.db.commit()
        with self.assertRaises(PermissionError): self.lab.act(token,'read')
    def test_unknown_session_audited(self):
        with self.assertRaises(PermissionError): self.lab.act('bad-token','read')
        self.assertEqual(self.lab.events()[-1]['outcome'],'deny')
    def test_lockout(self):
        for _ in range(5):
            with self.assertRaises(PermissionError): self.lab.login('technician','wrong')
        with self.assertRaises(PermissionError): self.token()
    def test_no_secrets_in_audit(self):
        token=self.token();self.lab.act(token,'write',value='private-result-content');text=json.dumps(self.lab.events())
        for secret in [token,'local-test-password-123','private-result-content']: self.assertNotIn(secret,text)
    def test_edit_detection(self):
        self.lab.db.execute("UPDATE audit SET payload='{}' WHERE seq=1");self.lab.db.commit()
        with self.assertRaises((ValueError,KeyError)): self.lab.verify()
    def test_truncation_checkpoint(self):
        head=self.lab.verify();self.lab.db.execute('DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)');self.lab.db.commit()
        self.lab.verify()
        with self.assertRaises(ValueError): self.lab.verify(head)
    def test_fail_closed_when_audit_write_fails(self):
        token=self.token();before=self.lab.db.execute("SELECT result FROM samples WHERE id='S001'").fetchone()[0]
        self.lab.db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'disk simulation'); END");self.lab.db.commit()
        with self.assertRaises(sqlite3.DatabaseError): self.lab.act(token,'write',value='must roll back')
        self.assertEqual(self.lab.db.execute("SELECT result FROM samples WHERE id='S001'").fetchone()[0],before)
