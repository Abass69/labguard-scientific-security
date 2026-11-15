"""Local-only lab simulation. SQLite transactions couple access and audit."""
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from pathlib import Path

POLICY = {'technician': {'read', 'write'}, 'researcher': {'read', 'export'},
          'auditor': {'audit'}, 'admin': {'audit'}}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))

class Lab:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.key = (self.directory / 'audit.key').read_bytes()
        self.db = sqlite3.connect(self.directory / 'lab.sqlite')
        self.db.row_factory = sqlite3.Row

    @classmethod
    def initialize(cls, directory):
        root = Path(directory)
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        key = root / 'audit.key'
        key.write_bytes(secrets.token_bytes(32))
        key.chmod(0o600)
        db = sqlite3.connect(root / 'lab.sqlite')
        db.executescript('''
        CREATE TABLE users(name TEXT PRIMARY KEY, salt BLOB, digest BLOB, role TEXT, project TEXT, failures INTEGER DEFAULT 0, locked REAL DEFAULT 0);
        CREATE TABLE sessions(token TEXT PRIMARY KEY, name TEXT, expires REAL);
        CREATE TABLE samples(id TEXT PRIMARY KEY, project TEXT, result TEXT);
        CREATE TABLE audit(seq INTEGER PRIMARY KEY, payload TEXT, previous TEXT, mac TEXT);
        INSERT INTO samples VALUES ('S001','food-a','Simulated pH: 6.4'),('S002','food-b','Simulated pH: 4.1');
        ''')
        db.commit()
        db.close()
        (root / 'lab.sqlite').chmod(0o600)
        return cls(root)

    def _log(self, actor, action, outcome, project='', count=0):
        last = self.db.execute('SELECT seq, mac FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        seq, previous = (last['seq'] + 1, last['mac']) if last else (1, '0' * 64)
        event = {'seq': seq, 'ts': time.time(), 'actor': actor, 'action': action,
                 'outcome': outcome, 'project': project, 'records': count}
        payload = canonical(event)
        mac = hmac.new(self.key, (previous + payload).encode(), hashlib.sha256).hexdigest()
        self.db.execute('INSERT INTO audit VALUES (?,?,?,?)', (seq, payload, previous, mac))

    def provision(self, name, password, role, project):
        """Trusted local operator only; deliberately absent from authenticated actions."""
        if role not in POLICY or len(password) < 14:
            raise ValueError('Known role and password of at least 14 characters required')
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('INSERT INTO users(name,salt,digest,role,project) VALUES (?,?,?,?,?)',
                            (name, salt, digest, role, project))
            self._log('local-operator', 'provision', 'allow', project)

    def login(self, name, password):
        token = None
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            user = self.db.execute('SELECT * FROM users WHERE name=?', (name,)).fetchone()
            salt = user['salt'] if user else b'unknown-user-salt'
            digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
            if user and user['locked'] <= time.time() and hmac.compare_digest(digest, user['digest']):
                token = secrets.token_urlsafe(32)
                self.db.execute('INSERT INTO sessions VALUES (?,?,?)',
                                (hashlib.sha256(token.encode()).hexdigest(), name, time.time()+900))
                self.db.execute('UPDATE users SET failures=0,locked=0 WHERE name=?', (name,))
            elif user:
                failures = user['failures'] + 1
                self.db.execute('UPDATE users SET failures=?,locked=? WHERE name=?',
                                (failures, time.time()+60 if failures >= 5 else 0, name))
            self._log(name[:100], 'login', 'allow' if token else 'deny')
        if token is None:
            raise PermissionError('Invalid credentials or temporary lockout')
        return token

    def act(self, token, action, sample_id='S001', value=None):
        allowed = False
        output = None
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            user = self.db.execute('''SELECT u.* FROM sessions s JOIN users u ON s.name=u.name
                WHERE s.token=? AND s.expires>?''',
                (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
            sample = self.db.execute('SELECT * FROM samples WHERE id=?', (sample_id,)).fetchone()
            project = sample['project'] if sample else ''
            if user and action == 'logout':
                self.db.execute('DELETE FROM sessions WHERE token=?', (hashlib.sha256(token.encode()).hexdigest(),))
                allowed, output = True, 'Logged out'
            elif user and action in POLICY.get(user['role'], set()):
                if action == 'audit':
                    allowed = True
                    output = [dict(row) for row in self.db.execute('SELECT * FROM audit ORDER BY seq')]
                elif action == 'export':
                    allowed = True
                    project = user['project']
                    output = [dict(row) for row in self.db.execute('SELECT * FROM samples WHERE project=?', (project,))]
                elif sample and project == user['project']:
                    if action == 'read':
                        allowed, output = True, dict(sample)
                    elif action == 'write' and isinstance(value, str) and 0 < len(value) <= 1000:
                        self.db.execute('UPDATE samples SET result=? WHERE id=?', (value, sample_id))
                        allowed, output = True, 'Updated'
            self._log(user['name'] if user else 'anonymous', action[:40], 'allow' if allowed else 'deny', project,
                      len(output) if allowed and action == 'export' else int(allowed and action in {'read','write'}))
        if not allowed:
            raise PermissionError('Access denied')
        return output

    def verify(self, expected_head=None):
        previous, count = '0' * 64, 0
        for row in self.db.execute('SELECT * FROM audit ORDER BY seq'):
            count += 1
            expected = hmac.new(self.key, (previous + row['payload']).encode(), hashlib.sha256).hexdigest()
            if row['seq'] != count or json.loads(row['payload'])['seq'] != count or row['previous'] != previous or not hmac.compare_digest(expected, row['mac']):
                raise ValueError('Audit integrity failure')
            previous = row['mac']
        if expected_head is not None and previous != expected_head:
            raise ValueError('Audit head differs from trusted checkpoint')
        return previous

    def events(self):
        self.verify()
        return [json.loads(row['payload']) for row in self.db.execute('SELECT payload FROM audit ORDER BY seq')]
