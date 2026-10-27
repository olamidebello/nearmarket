#!/usr/bin/env python3
"""NearMarket deployment worker; invoked by Ansible as root on the panel host."""
import argparse
import contextlib
import fcntl
import grp
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time

BASE = Path('/opt/nearmarket')
STATE = Path('/var/lib/nearmarket-deploy')
BACKUPS = Path('/var/backups/nearmarket')
UNIT = Path('/etc/systemd/system/nearmarket.service')
ENV = Path('/etc/nearmarket/runtime.env')
DATA = Path('/var/lib/nearmarket')
ACME = Path('/var/lib/nearmarket-acme')
NGINX_AVAILABLE = Path('/etc/nginx/sites-available')
NGINX_ENABLED = Path('/etc/nginx/sites-enabled')
MARK = '# Managed by NearMarket Olamidepanel deployment v1\n'
DOMAIN = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')


class DeploymentError(RuntimeError):
    pass


def run(argv, timeout=60, binary=False):
    try:
        p = subprocess.run([str(a) for a in argv], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeploymentError('Command unavailable or timed out: ' + str(argv[0])) from exc
    if p.returncode:
        # Never return environment values, provider secrets, SQL, or arbitrary command output.
        raise DeploymentError('Command failed: ' + str(argv[0]) + ' (exit ' + str(p.returncode) + ')')
    return p.stdout if binary else p.stdout.decode('utf-8', errors='replace')


def active(unit):
    return subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def atomic(path, content, mode=0o644):
    path = Path(path)
    if path.is_symlink():
        raise DeploymentError('Refusing to replace symlink: ' + str(path))
    payload = content.encode() if isinstance(content, str) else content
    fd, temp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)


def switch(target):
    temp = BASE / ('.current-' + str(os.getpid()))
    temp.unlink(missing_ok=True)
    temp.symlink_to(target)
    os.replace(temp, BASE / 'current')


def validate(cfg):
    domain = cfg.get('domain', '')
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain) or len(domain) > 253:
        raise DeploymentError('Set a valid lowercase DNS domain')
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', cfg.get('email', '')):
        raise DeploymentError('Set the certificate contact email')
    try:
        ipaddress.IPv4Address(cfg['expected_ipv4'])
    except (ValueError, KeyError):
        raise DeploymentError('Set the expected server IPv4 address')
    if not isinstance(cfg.get('port'), int) or not 1024 <= cfg['port'] <= 65535:
        raise DeploymentError('Application port must be 1024–65535')
    if not re.fullmatch('[a-f0-9]{40}', cfg.get('commit', '')):
        raise DeploymentError('Resolved repository commit is invalid')


def check_dns(domain, expected):
    reports = []
    for resolver in ('1.1.1.1', '8.8.8.8'):
        records = {}
        for kind in ('A', 'AAAA'):
            output = run(['dig', '@' + resolver, '+time=4', '+tries=1', '+noall', '+answer', domain, kind], timeout=10)
            values = []
            for line in output.splitlines():
                fields = line.split()
                if len(fields) >= 5 and fields[3] == kind:
                    values.append(str(ipaddress.ip_address(fields[4])))
            records[kind] = sorted(set(values))
        reports.append({'resolver': resolver, **records})
        if set(records['A']) != {expected} or records['AAAA']:
            raise DeploymentError('DNS is not ready: A must point exclusively to ' + expected + '; AAAA must be absent. DNS was not modified.')
    return reports


def check_port(port):
    output = run(['ss', '-H', '-ltnp', 'sport', '=', ':' + str(port)])
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 4 or fields[3] != '127.0.0.1:' + str(port):
            raise DeploymentError('Application port has an incompatible listener; select another port')
        pids = re.findall(r'pid=(\d+)', line)
        if not pids:
            raise DeploymentError('Cannot identify process on application port')
        for pid in pids:
            try:
                group = Path('/proc/' + pid + '/cgroup').read_text()
            except OSError:
                raise DeploymentError('Cannot identify process on application port')
            if not any(row.rstrip().endswith('/nearmarket.service') for row in group.splitlines()):
                raise DeploymentError('Application port belongs to another service; no process was stopped')


def check_nginx(domain, target, link, dump):
    if not NGINX_AVAILABLE.is_dir() or not link.parent.is_dir():
        raise DeploymentError('Expected Debian Nginx sites-available/sites-enabled directories')
    if target.is_symlink():
        raise DeploymentError('Managed vhost target must not be a symlink')
    if target.exists() and not target.read_text().startswith(MARK):
        raise DeploymentError('Vhost exists without NearMarket ownership marker')
    if link.exists() or link.is_symlink():
        if not link.is_symlink() or link.resolve() != target.resolve():
            raise DeploymentError('Enabled vhost path is already owned by another configuration')
    chunks = re.split(r'^# configuration file (.+):\s*$', dump, flags=re.M)
    for i in range(1, len(chunks), 2):
        config_path, text = Path(chunks[i].strip()), chunks[i + 1]
        if config_path.resolve() == target.resolve():
            continue
        managed_nearmarket = text.startswith(MARK)
        text = re.sub(r'#[^\n]*', '', text)
        names = [name.strip('"\'') for value in re.findall(r'\bserver_name\s+([^;]+);', text) for name in value.split()]
        if managed_nearmarket and 'nearmarket_auth' in text:
            raise DeploymentError('Another NearMarket domain is configured; migrate its vhost before changing domains')
        if domain in names or ('.' + domain) in names:
            raise DeploymentError('Existing exact hostname found in ' + str(config_path) + '; migrate that vhost explicitly first')
        # Exact names outrank wildcard names in Nginx. Existing regex hosts are left intact.


def export_release(source, commit):
    release = BASE / 'releases' / commit
    if release.exists():
        if release.is_symlink() or (release / 'REVISION').read_text().strip() != commit:
            raise DeploymentError('Existing release has an invalid revision marker')
        return release
    archive = run(['git', '-C', source, 'archive', '--format=tar', commit], binary=True)
    staging = Path(tempfile.mkdtemp(prefix='.release-', dir=release.parent))
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tf:
            for member in tf.getmembers():
                name = Path(member.name)
                if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir()):
                    raise DeploymentError('Unsupported or unsafe file in repository archive')
                dest = staging / name
                if member.isdir():
                    dest.mkdir(parents=True, exist_ok=True, mode=0o755)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                    with tf.extractfile(member) as stream:
                        dest.write_bytes(stream.read())
                    dest.chmod(0o755 if member.mode & 0o111 else 0o644)
        for required in ('app.py', 'tenants.py', 'payments.py', 'static/index.html'):
            if not (staging / required).is_file():
                raise DeploymentError('Release is missing ' + required)
        for folder in staging.rglob('*'):
            if folder.is_dir():folder.chmod(0o755)
        (staging / 'REVISION').write_text(commit + '\n')
        (staging / 'REVISION').chmod(0o644)
        staging.chmod(0o755)
        staging.rename(release)
        return release
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def unit_text():
    return MARK + '''[Unit]
Description=NearMarket local marketplace
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=nearmarket
Group=nearmarket
WorkingDirectory=/opt/nearmarket/current
EnvironmentFile=/etc/nearmarket/runtime.env
EnvironmentFile=-/etc/nearmarket/secrets.env
ExecStart=/usr/bin/python3 -B -u /opt/nearmarket/current/app.py
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/nearmarket
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
[Install]
WantedBy=multi-user.target
'''


def environment(cfg):
    return ('HOST=127.0.0.1\nPORT=' + str(cfg['port']) +
            '\nNEARMARKET_DATA=/var/lib/nearmarket\nCOOKIE_SECURE=1\n' +
            'NEARMARKET_PUBLIC_URL=https://' + cfg['domain'] +
            '\nNEARMARKET_RELEASE=' + cfg['commit'] + '\n')


def listener_policy(cfg, dump):
    """Join existing address-specific server groups without creating new groups."""
    found = {80: [], 443: []}
    text = re.sub(r'#[^\n]*', '', dump)
    for value in re.findall(r'\blisten\s+([^;]+);', text):
        endpoint = value.split()[0]
        for port in found:
            for address in ('127.0.0.1', cfg['expected_ipv4']):
                if endpoint == address + ':' + str(port) and address not in found[port]:
                    if 'proxy_protocol' in value.split():
                        raise DeploymentError('Address-specific Nginx listener requires PROXY protocol; configure its routing explicitly')
                    found[port].append(address)
    return {str(port): addresses for port, addresses in found.items()}


def listen_lines(cfg, port, tls=False):
    suffix = ' ssl' if tls else ''
    addresses = cfg.get('nginx_addresses', {}).get(str(port), [])
    lines = ['    listen ' + str(port) + suffix + ';']
    lines.extend('    listen ' + address + ':' + str(port) + suffix + ';' for address in addresses)
    return '\n'.join(lines)


def probe_acme(cfg, probe, report, attempts=12):
    """Wait for new workers; probe the public listener and loopback independently."""
    domain = cfg['domain']
    url = 'http://' + domain + '/.well-known/acme-challenge/' + probe.name
    report['acme_probe'] = []
    for attempt in range(attempts):
        results = []
        for address in dict.fromkeys((cfg['expected_ipv4'], '127.0.0.1')):
            args = ['curl', '--silent', '--show-error', '--noproxy', '*',
                    '--connect-timeout', '2', '--max-time', '4',
                    '--resolve', domain + ':80:' + address]
            try:
                content = run([*args, '--fail', url], timeout=6)
                if content == 'NearMarket-ACME':
                    report['acme_probe'] = results + [{'address': address, 'verified': True}]
                    report['acme_verified_address'] = address
                    return
                results.append({'address': address, 'error': 'Wrong response body'})
            except DeploymentError:
                try:
                    status = run([*args, '--output', '/dev/null', '--write-out', '%{http_code}', url], timeout=6).strip()
                except DeploymentError:
                    status = 'unreachable'
                results.append({'address': address, 'http_status': status if re.fullmatch('[0-9]{3}', status) else 'unreachable'})
        report['acme_probe'] = results
        if attempt + 1 < attempts:
            time.sleep(1)
    details = ', '.join(r['address'] + '=' + r.get('http_status', r.get('error', 'failed')) for r in report['acme_probe'])
    raise DeploymentError('ACME HTTP routing failed after reload retries (' + details + '). Check the managed vhost and /var/log/nginx/error.log; no certificate was requested.')


def nginx_text(cfg, tls):
    domain, port = cfg['domain'], cfg['port']
    cert = Path('/etc/letsencrypt/live') / ('nearmarket-' + domain)
    common = f'''        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
'''
    text = MARK + '''limit_req_zone $binary_remote_addr zone=nearmarket_auth:10m rate=10r/m;
server {
''' + listen_lines(cfg, 80) + '''
    server_name ''' + domain + ''';
    location ^~ /.well-known/acme-challenge/ {
        root /var/lib/nearmarket-acme;
        try_files $uri =404;
    }
    location / { ''' + ('return 301 https://' + domain + '$request_uri;' if tls else 'return 503;') + ''' }
}
'''
    if not tls:
        return text
    text += f'''server {{
{listen_lines(cfg, 443, True)}
    server_name {domain};
    ssl_certificate {cert}/fullchain.pem;
    ssl_certificate_key {cert}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 3m;
    add_header X-NearMarket-Deployment "{cfg['commit']}" always;
    limit_req_status 429;
'''
    for path in ('/api/login', '/api/signup', '/api/orders/pickup'):
        text += '    location = ' + path + ' {\n        limit_req zone=nearmarket_auth burst=5 nodelay;\n' + common + '    }\n'
    return text + '    location / {\n' + common + '    }\n}\n'


def reload_nginx(target):
    run(['/usr/sbin/nginx', '-t'])
    dump = run(['/usr/sbin/nginx', '-T'])
    if str(target) not in dump and str(NGINX_ENABLED / target.name) not in dump:
        raise DeploymentError('Nginx does not include the managed site; no main config was changed')
    run(['systemctl', 'reload', 'nginx.service'])


def health(cfg, https=False, public=False):
    domain = cfg['domain']
    base = 'https://' + domain if https else 'http://127.0.0.1:' + str(cfg['port'])
    args = ['curl', '--fail', '--silent', '--show-error', '--noproxy', '*', '--connect-timeout', '5', '--max-time', '15']
    if https and not public:
        args += ['--resolve', domain + ':443:127.0.0.1']
    payload = json.loads(run([*args, base + '/api/health'], timeout=20))
    if payload.get('status') != 'ok' or payload.get('application') != 'nearmarket' or payload.get('release') != cfg['commit']:
        raise DeploymentError('Health endpoint is not the expected NearMarket release')
    if https:
        page = run([*args, base + '/'], timeout=20)
        if 'NearMarket' not in page or '/app.js' not in page:
            raise DeploymentError('Website does not contain the expected NearMarket page')


def panel_snapshot(cfg, target):
    parent = Path('/var/lib/olamidepanel')
    if not parent.is_dir():
        raise DeploymentError('Olamidepanel data directory is missing')
    try:
        gid = grp.getgrnam('olamidepanel').gr_gid
    except KeyError:
        raise DeploymentError('Olamidepanel service group is missing')
    path = parent / 'hosted-domains.json'
    with (parent / '.nearmarket-hosting.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = json.loads(path.read_text()) if path.exists() else {'domains': []}
        if not isinstance(data, dict) or not isinstance(data.get('domains'), list):
            raise DeploymentError('Existing panel hosting snapshot is malformed; left unchanged')
        rows = [row for row in data['domains'] if isinstance(row, dict) and row.get('domain') != cfg['domain']]
        now = int(time.time())
        rows.append({'domain': cfg['domain'], 'status': 'https_ready', 'deployment_status': 'running',
                     'checked_at': now, 'deployment_checked_at': now, 'configuration': str(target),
                     'backend': 'http://127.0.0.1:' + str(cfg['port']),
                     'repo': 'https://github.com/olamidebello/nearmarket.git', 'commit': cfg['commit']})
        data.update(updated_at=now, domains=rows)
        atomic(path, json.dumps(data, indent=2) + '\n', 0o640)
        os.chown(path, 0, gid)


def deploy(cfg, report):
    validate(cfg)
    domain = cfg['domain']
    target = NGINX_AVAILABLE / ('nearmarket-' + domain + '.conf')
    link = NGINX_ENABLED / target.name
    if not active('nginx.service'):
        raise DeploymentError('Existing shared Nginx must be running')
    dump = run(['/usr/sbin/nginx', '-T'])
    check_nginx(domain, target, link, dump)
    cfg['nginx_addresses'] = listener_policy(cfg, dump)
    report['nginx_addresses'] = cfg['nginx_addresses']
    check_port(cfg['port'])
    report['dns'] = check_dns(domain, cfg['expected_ipv4'])
    if cfg.get('publish_panel_inventory', True):
        if not Path('/var/lib/olamidepanel').is_dir():
            raise DeploymentError('Olamidepanel data directory missing; use publish_panel_inventory=false only for a standalone host')
    source = BASE / 'source'
    actual = run(['git', '-C', source, 'rev-parse', 'HEAD']).strip()
    if actual != cfg['commit']:
        raise DeploymentError('Source changed after Ansible checkout; rerun deployment')
    release = export_release(source, cfg['commit'])
    if cfg.get('run_tests', True):
        # Tests use their own disposable database. They never use the production service environment.
        run(['/usr/bin/python3', '-B', '-m', 'unittest', 'discover', '-s', str(release / 'tests'), '-q'], timeout=120)
    current = BASE / 'current'
    if current.exists() and not current.is_symlink():
        raise DeploymentError('Current application path is not a managed release symlink')
    previous_release = current.resolve() if current.is_symlink() else None
    if previous_release and (previous_release.parent != BASE / 'releases' or not previous_release.exists()):
        raise DeploymentError('Previous release is outside managed releases or missing')
    for path in (UNIT, ENV):
        if path.is_symlink():
            raise DeploymentError('Unexpected symlink at ' + str(path))
    if UNIT.exists() and not UNIT.read_text().startswith(MARK):
        raise DeploymentError('Existing nearmarket.service is not managed by this deployment')
    previous = {p: p.read_bytes() if p.exists() else None for p in (UNIT, ENV, target)}
    old_link = os.readlink(link) if link.is_symlink() else None
    was_active = active('nearmarket.service')
    was_enabled = subprocess.run(['systemctl', 'is-enabled', '--quiet', 'nearmarket.service'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    backup = BACKUPS / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + str(time.time_ns()))
    backup.mkdir(mode=0o700)
    report['backup'] = str(backup)
    report['changed'] = (previous_release != release or previous[UNIT] != unit_text().encode() or previous[ENV] != environment(cfg).encode() or previous[target] != nginx_text(cfg, True).encode() or not was_active)
    for path, payload in previous.items():
        if payload is not None:
            atomic(backup / path.name, payload, 0o600)
    atomic(backup / 'state.json', json.dumps({'release': str(previous_release) if previous_release else None, 'enabled_link': old_link, 'service_active': was_active, 'service_enabled': was_enabled}), 0o600)
    try:
        report['source_or_config_changed'] = report['changed']
        report['changed'] = True  # Every deployment takes a backup and restarts this application.
        report['stage'] = 'application'
        # Stop only this application before backing up its database and switching releases.
        if was_active:
            run(['systemctl', 'stop', 'nearmarket.service'])
        database = DATA / 'market.db'
        if database.exists():
            with contextlib.closing(sqlite3.connect(database)) as src, contextlib.closing(sqlite3.connect(backup / 'market.db')) as dst:
                src.backup(dst)
            (backup / 'market.db').chmod(0o600)
        switch(release)
        atomic(ENV, environment(cfg), 0o600)
        atomic(UNIT, unit_text())
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', 'nearmarket.service'])
        for attempt in range(15):
            try:
                health(cfg)
                break
            except (DeploymentError, ValueError):
                if attempt == 14:
                    raise
                time.sleep(1)
        report['backend_verified'] = True
        report['stage'] = 'https'
        cert = Path('/etc/letsencrypt/live') / ('nearmarket-' + domain)
        tls_exists = (cert / 'fullchain.pem').exists() and (cert / 'privkey.pem').exists()
        atomic(target, nginx_text(cfg, tls_exists))
        if not link.is_symlink():
            link.symlink_to(target)
        reload_nginx(target)
        # HTTP serves ACME only until TLS succeeds. Existing shared Nginx is never stopped.
        challenge_dir = ACME / '.well-known/acme-challenge'
        challenge_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        (ACME / '.well-known').chmod(0o755)
        challenge_dir.chmod(0o755)
        probe = challenge_dir / ('nearmarket-' + str(time.time_ns()))
        atomic(probe, 'NearMarket-ACME')
        report['stage'] = 'acme_http_routing'
        try:
            probe_acme(cfg, probe, report)
        finally:
            probe.unlink(missing_ok=True)
        report['stage'] = 'certificate_issuance'
        run(['certbot', 'certonly', '--webroot', '--webroot-path', ACME,
             '--non-interactive', '--agree-tos', '--email', cfg['email'],
             '--cert-name', 'nearmarket-' + domain, '--keep-until-expiring', '-d', domain], timeout=360)
        atomic(target, nginx_text(cfg, True))
        reload_nginx(target)
        report['stage'] = 'local_https_verification'
        for attempt in range(12):
            try:
                health(cfg, https=True)
                break
            except (DeploymentError, ValueError):
                if attempt == 11:raise
                time.sleep(1)
        report['local_https_verified'] = True
        report['stage'] = 'public_https_verification'
        health(cfg, https=True, public=True)
        report['public_https_verified'] = True
        hook = Path('/etc/letsencrypt/renewal-hooks/deploy/nearmarket-nginx')
        hook.parent.mkdir(parents=True, exist_ok=True)
        atomic(hook, '#!/bin/sh\nset -eu\n/usr/sbin/nginx -t\n/bin/systemctl reload nginx.service\n', 0o755)
        run(['systemctl', 'enable', '--now', 'certbot.timer'])
    except Exception:
        report['rollback'] = 'attempting'
        try:
            # Data is retained: restoring a DB automatically could erase writes or payment callbacks.
            subprocess.run(['systemctl', 'stop', 'nearmarket.service'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
            for path, payload in previous.items():
                if payload is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic(path, payload, 0o600 if path == ENV else 0o644)
            if old_link is None:
                link.unlink(missing_ok=True)
            if previous_release:
                switch(previous_release)
            else:
                current.unlink(missing_ok=True)
            run(['systemctl', 'daemon-reload'])
            if not was_enabled:
                subprocess.run(['systemctl', 'disable', 'nearmarket.service'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            if was_active and previous_release and previous[UNIT]:
                run(['systemctl', 'start', 'nearmarket.service'])
            run(['/usr/sbin/nginx', '-t'])
            run(['systemctl', 'reload', 'nginx.service'])
            report['rollback'] = 'configuration_restored_data_retained'
        except Exception:
            report['rollback'] = 'needs_operator_attention'
        raise
    # Inventory errors must not roll back a verified live application.
    report['stage'] = 'panel_inventory'
    if cfg.get('publish_panel_inventory', True):
        panel_snapshot(cfg, target)
        report['panel_inventory'] = 'updated'
    else:
        report['panel_inventory'] = 'disabled_by_configuration'
    report.update(status='deployed', stage='complete', url='https://' + domain,
                  commit=cfg['commit'], port=cfg['port'], changed=report['changed'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run through Ansible with become: true')
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    report = {'status': 'failed', 'stage': 'preflight', 'changed': False,
              'report': str(STATE / 'report.json'), 'checked_at': int(time.time())}
    with (STATE / 'deploy.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({'status': 'busy', 'changed': False, 'error': 'Another NearMarket deployment is running'}))
            return 1
        try:
            cfg = json.loads(Path(args.config).read_text())
            report['domain'] = cfg.get('domain')
            deploy(cfg, report)
        except Exception as exc:
            report['error'] = str(exc) if isinstance(exc, DeploymentError) else type(exc).__name__
        atomic(STATE / 'report.json', json.dumps(report, indent=2) + '\n', 0o600)
    print(json.dumps(report))
    return 0 if report['status'] == 'deployed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
