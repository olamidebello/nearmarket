"""Super-admin-only gateway control plane with encrypted, write-only secrets."""
import contextlib
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import urllib.error
import urllib.request
from cryptography.fernet import Fernet, InvalidToken

GATEWAYS = ('stripe', 'paystack')
MODES = ('test', 'live')


def init(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS gateway_configs(tenant_id INTEGER REFERENCES tenants(id),gateway TEXT,mode TEXT,secret_cipher TEXT,webhook_cipher TEXT,public_key TEXT DEFAULT '',label TEXT DEFAULT '',updated REAL,updated_by INTEGER,PRIMARY KEY(tenant_id,gateway,mode));
    CREATE TABLE IF NOT EXISTS gateway_preferences(tenant_id INTEGER REFERENCES tenants(id),gateway TEXT,mode TEXT,live_allowed INTEGER DEFAULT 0,PRIMARY KEY(tenant_id,gateway));
    CREATE TABLE IF NOT EXISTS gateway_checks(tenant_id INTEGER,gateway TEXT,mode TEXT,fingerprint TEXT,checked_at REAL,ok INTEGER,note TEXT,PRIMARY KEY(tenant_id,gateway,mode));
    CREATE TABLE IF NOT EXISTS gateway_auth_attempts(user_id INTEGER PRIMARY KEY,window INTEGER,count INTEGER);
    ''')


@contextlib.contextmanager
def connection():
    root = Path(os.environ.get('NEARMARKET_DATA', str(Path(__file__).parent / 'data')))
    c = sqlite3.connect(root / 'market.db')
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


def cipher():
    configured = os.environ.get('NEARMARKET_GATEWAY_KEY_FILE')
    path = Path(configured) if configured else Path(os.environ.get('CREDENTIALS_DIRECTORY', '/run/credentials/nearmarket.service')) / 'nearmarket_gateway_key'
    try:
        return Fernet(path.read_bytes().strip())
    except (OSError, ValueError):
        raise ValueError('Gateway credential vault is unavailable; rerun the updated deployment playbook') from None


def vault_ready():
    try:
        cipher()
        return True
    except ValueError:
        return False


def env_secret(tid, g, suffix='SECRET', mode=None):
    value = os.environ.get(f'NEARMARKET_T{tid}_{g.upper()}_{suffix}', '')
    primary = os.environ.get(f'NEARMARKET_T{tid}_{g.upper()}_SECRET', '')
    actual = 'live' if primary.startswith(('sk_live_', 'rk_live_')) else 'test'
    return value if mode is None or actual == mode else ''


def preference(c, tid, g):
    row = c.execute('SELECT * FROM gateway_preferences WHERE tenant_id=? AND gateway=?', (tid, g)).fetchone()
    if row:
        return dict(row)
    mode = 'live' if env_secret(tid, g).startswith(('sk_live_', 'rk_live_')) else 'test'
    return {'mode': mode, 'live_allowed': int(os.environ.get('NEARMARKET_ALLOW_LIVE_PAYMENTS') == '1')}


def read_secret(tid, g, suffix='SECRET', mode=None, c=None):
    if c is None:
        with connection() as own:
            return read_secret(tid, g, suffix, mode, own)
    mode = mode or preference(c, tid, g)['mode']
    row = c.execute('SELECT secret_cipher,webhook_cipher FROM gateway_configs WHERE tenant_id=? AND gateway=? AND mode=?', (tid, g, mode)).fetchone()
    if row is None:
        return env_secret(tid, g, suffix, mode)
    token = row['secret_cipher' if suffix == 'SECRET' else 'webhook_cipher']
    if not token:
        return ''  # Explicit clear overrides a legacy environment credential.
    try:
        payload = json.loads(cipher().decrypt(token.encode()).decode())
        if (payload.get('tenant'), payload.get('gateway'), payload.get('mode'), payload.get('field')) != (tid, g, mode, suffix):
            raise ValueError('Gateway credential context mismatch')
        return payload['value']
    except (InvalidToken, json.JSONDecodeError, KeyError, UnicodeDecodeError):
        raise ValueError('Gateway credentials could not be decrypted; check the server vault key') from None


def encrypt(tid, g, mode, field, value):
    if not value:
        return ''
    payload = {'tenant': tid, 'gateway': g, 'mode': mode, 'field': field, 'value': value}
    return cipher().encrypt(json.dumps(payload).encode()).decode()


def metadata(c, t, g, mode):
    row = c.execute('SELECT * FROM gateway_configs WHERE tenant_id=? AND gateway=? AND mode=?', (t['id'], g, mode)).fetchone()
    error = ''
    try:
        secret = read_secret(t['id'], g, mode=mode, c=c)
        webhook = read_secret(t['id'], g, 'WEBHOOK_SECRET', mode, c) if g == 'stripe' else ''
    except ValueError:
        secret = webhook = ''
        error = 'Encrypted credentials unavailable'
    check = c.execute('SELECT * FROM gateway_checks WHERE tenant_id=? AND gateway=? AND mode=?', (t['id'], g, mode)).fetchone()
    if check and check['fingerprint'] != hashlib.sha256(secret.encode()).hexdigest():
        check = None
    return {'mode': mode, 'source': 'encrypted vault' if row else 'server environment',
            'secret_configured': bool(secret), 'webhook_configured': bool(webhook),
            'secret_mask': '•••••••• (saved)' if secret else 'Not configured',
            'webhook_mask': '•••••••• (saved)' if webhook else 'Not configured',
            'public_key': row['public_key'] if row else '', 'label': row['label'] if row else '',
            'updated': row['updated'] if row else None, 'error': error,
            'connection_check': {'checked_at': check['checked_at'], 'ok': bool(check['ok']), 'note': check['note']} if check else None}


def status(t):
    result = {}
    with connection() as c:
        for g in GATEWAYS:
            pref = preference(c, t['id'], g)
            mode = pref['mode']
            info = metadata(c, t, g, mode)
            configured = info['secret_configured'] and (g != 'stripe' or info['webhook_configured'])
            server_live = os.environ.get('NEARMARKET_ALLOW_LIVE_PAYMENTS') == '1'
            allowed = mode != 'live' or (server_live and pref['live_allowed'])
            result[g] = {'enabled': bool(t['payments'] and t[g]), 'configured': configured,
                         'mode': mode, 'ready': bool((t['active'] if 'active' in t.keys() else 1) and t['payments'] and t[g] and configured and allowed),
                         'secret_env': f"NEARMARKET_T{t['id']}_{g.upper()}_SECRET",
                         'webhook_path': f"/api/webhooks/{g}/{t['id']}",
                         'live_server_allowed': server_live, 'live_allowed': bool(pref['live_allowed'])}
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def provider_check(g, secret, mode):
    url = {'stripe': 'https://api.stripe.com/v1/balance', 'paystack': 'https://api.paystack.co/balance'}[g]
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + secret})
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=10) as response:
            payload = json.load(response)
        if g == 'stripe' and (payload.get('object') != 'balance' or payload.get('livemode') != (mode == 'live')):
            return False, 'Provider mode or response did not match the selected environment'
        if g == 'paystack' and not payload.get('status'):
            return False, 'Provider did not confirm the connection'
        return True, 'API connection verified; webhook delivery must be tested separately'
    except urllib.error.HTTPError as exc:
        return False, 'Provider rejected the read-only check (HTTP ' + str(exc.code) + ')'
    except (OSError, ValueError):
        return False, 'Provider connection could not be verified'


def reauthenticate(c, u, password):
    window = int(time.time() // 300)
    row = c.execute('SELECT count FROM gateway_auth_attempts WHERE user_id=? AND window=?', (u['id'], window)).fetchone()
    if row and row[0] >= 5:
        return 429
    record = c.execute('SELECT password,salt FROM users WHERE id=?', (u['id'],)).fetchone()
    valid = isinstance(password, str) and 1 <= len(password) <= 128
    if valid:
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(record['salt']), n=16384, r=8, p=1).hex()
        valid = hmac.compare_digest(digest, record['password'])
    if not valid:
        c.execute('INSERT INTO gateway_auth_attempts VALUES(?,?,1) ON CONFLICT(user_id) DO UPDATE SET window=excluded.window,count=CASE WHEN window=excluded.window THEN count+1 ELSE 1 END', (u['id'], window))
        return 403
    c.execute('DELETE FROM gateway_auth_attempts WHERE user_id=?', (u['id'],))
    return 200


def handle(h, c, u, route, method, d):
    if route != '/api/admin/gateways':
        return False
    if not u or u['role'] != 'superadmin':
        h.send(403, {'error': 'Super admin access required'})
        return True
    if method == 'GET':
        tenants = [dict(r) for r in c.execute('SELECT * FROM tenants ORDER BY name')]
        h.send(200, {'vault_ready': vault_ready(), 'live_server_allowed': os.environ.get('NEARMARKET_ALLOW_LIVE_PAYMENTS') == '1',
                     'tenants': [{**t, 'gateways': {g: {**status(t)[g], 'environments': {m: metadata(c, t, g, m) for m in MODES}} for g in GATEWAYS}} for t in tenants]})
        return True
    tid = int(d.get('tenant_id', 0))
    t = c.execute('SELECT * FROM tenants WHERE id=?', (tid,)).fetchone()
    g, mode, action = d.get('gateway'), d.get('mode'), d.get('action')
    if not t or g not in GATEWAYS or mode not in MODES or action not in ('save', 'clear', 'check', 'import'):
        raise ValueError('Choose a valid tenant, gateway, environment and action')
    c.execute('BEGIN IMMEDIATE')
    code = reauthenticate(c, u, d.get('current_password'))
    if code != 200:
        h.send(code, {'error': 'Too many failed password checks; retry in five minutes' if code == 429 else 'Your current account password is required'})
        return True
    if action == 'check':
        secret = read_secret(tid, g, mode=mode, c=c)
        if not secret:
            raise ValueError('Save a secret before checking the connection')
        c.commit()  # Never hold a SQLite write lock during a provider request.
        ok, note = provider_check(g, secret, mode)
        c.execute('INSERT INTO gateway_checks VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant_id,gateway,mode) DO UPDATE SET fingerprint=excluded.fingerprint,checked_at=excluded.checked_at,ok=excluded.ok,note=excluded.note', (tid, g, mode, hashlib.sha256(secret.encode()).hexdigest(), time.time(), int(ok), note))
        c.execute('INSERT INTO audit(actor,action,target,created) VALUES(?,?,?,?)', (u['id'], 'gateway:check', f'{tid}:{g}:{mode}', time.time()))
        h.send(200, {'ok': ok, 'message': note})
        return True
    cipher()  # Refuse credential changes until server-provisioned encryption is available.
    if action == 'clear':
        secret = webhook = public_key = label = ''
    else:
        if action == 'import':
            secret = env_secret(tid, g, mode=mode)
            webhook = env_secret(tid, g, 'WEBHOOK_SECRET', mode) if g == 'stripe' else ''
            if not secret:
                raise ValueError('No server environment credential matches this mode')
        else:
            secret = str(d.get('secret') or read_secret(tid, g, mode=mode, c=c)).strip()
            webhook = str(d.get('webhook_secret') or read_secret(tid, g, 'WEBHOOK_SECRET', mode, c)).strip() if g == 'stripe' else ''
        if not re.fullmatch(r'(?:sk|rk)_' + mode + r'_[A-Za-z0-9]{8,512}', secret):
            raise ValueError('Secret must match the selected test/live mode')
        if g == 'stripe' and not re.fullmatch(r'whsec_[A-Za-z0-9]{8,512}', webhook):
            raise ValueError('Enter a Stripe endpoint signing secret beginning with whsec_')
        public_key = str(d.get('public_key', '')).strip()
        if public_key and not re.fullmatch('pk_' + mode + r'_[A-Za-z0-9]{8,512}', public_key):
            raise ValueError('Publishable key must match the selected mode')
        label = str(d.get('label', '')).strip()
        if len(label) > 80:
            raise ValueError('Label must contain at most 80 characters')
    c.execute('INSERT INTO gateway_configs VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,gateway,mode) DO UPDATE SET secret_cipher=excluded.secret_cipher,webhook_cipher=excluded.webhook_cipher,public_key=excluded.public_key,label=excluded.label,updated=excluded.updated,updated_by=excluded.updated_by', (tid, g, mode, encrypt(tid, g, mode, 'SECRET', secret), encrypt(tid, g, mode, 'WEBHOOK_SECRET', webhook), public_key, label, time.time(), u['id']))
    c.execute('DELETE FROM gateway_checks WHERE tenant_id=? AND gateway=? AND mode=?', (tid, g, mode))
    if action == 'save':
        for field in ('payments_enabled', 'enabled', 'allow_live'):
            if not isinstance(d.get(field), bool):
                raise ValueError('Gateway switches must be boolean values')
        c.execute('INSERT INTO gateway_preferences VALUES(?,?,?,?) ON CONFLICT(tenant_id,gateway) DO UPDATE SET mode=excluded.mode,live_allowed=excluded.live_allowed', (tid, g, mode, int(d['allow_live'])))
        c.execute(f'UPDATE tenants SET payments=?,{g}=? WHERE id=?', (int(d['payments_enabled']), int(d['enabled']), tid))
    elif action == 'clear':
        if preference(c, tid, g)['mode'] == mode:
            c.execute(f'UPDATE tenants SET {g}=0 WHERE id=?', (tid,))
    c.execute('INSERT INTO audit(actor,action,target,created) VALUES(?,?,?,?)', (u['id'], 'gateway:' + action, f'{tid}:{g}:{mode}', time.time()))
    h.send(200, {'ok': True, 'message': 'Credentials removed for this environment' if action == 'clear' else 'Gateway settings saved; secrets are write-only'})
    return True
