#!/usr/bin/env python3
"""Prompt locally for Stripe credentials; never accepts secrets as CLI arguments."""
import argparse
import fcntl
import getpass
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SECRET_FILE = Path('/etc/nearmarket/secrets.env')


def render(previous, tenant, secret, webhook, allow_live=False):
    if not isinstance(tenant, int) or not 1 <= tenant <= 1000000000:
        raise ValueError('Invalid tenant ID')
    if not re.fullmatch(r'sk_(?:test|live)_[A-Za-z0-9]{8,512}', secret):
        raise ValueError('Enter a valid Stripe test or live secret key')
    if not re.fullmatch(r'whsec_[A-Za-z0-9]{8,512}', webhook):
        raise ValueError('Enter the endpoint signing secret beginning with whsec_')
    if secret.startswith('sk_live_') and not allow_live:
        raise ValueError('Use a test key, or explicitly pass --enable-live for live checkout')
    updates = {f'NEARMARKET_T{tenant}_STRIPE_SECRET': secret,
               f'NEARMARKET_T{tenant}_STRIPE_WEBHOOK_SECRET': webhook}
    if allow_live:
        updates['NEARMARKET_ALLOW_LIVE_PAYMENTS'] = '1'
    lines = []
    for line in previous.splitlines():
        name = line.partition('=')[0].strip()
        if name not in updates:
            lines.append(line)
    lines += [name + '=' + value for name, value in updates.items()]
    return '\n'.join(lines) + '\n'


def save(path, text):
    if path.is_symlink():
        raise ValueError('Refusing to replace a symlink')
    fd, temp = tempfile.mkstemp(prefix='.stripe-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tenant', type=int, default=1)
    parser.add_argument('--enable-live', action='store_true', help='Allow configured live gateways globally; enable Stripe separately in tenant settings')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root on the NearMarket server')
    if not sys.stdin.isatty():
        raise SystemExit('Use an interactive terminal so credentials can be entered without echo')
    if not (Path('/opt/nearmarket/current') / 'app.py').is_file():
        raise SystemExit('Deploy NearMarket first')
    if not SECRET_FILE.parent.is_dir():
        raise SystemExit('NearMarket configuration directory is missing')
    os.umask(0o077)
    with (SECRET_FILE.parent / '.stripe-setup.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if SECRET_FILE.is_symlink():
            raise SystemExit('Secrets path must not be a symlink')
        previous = SECRET_FILE.read_text() if SECRET_FILE.exists() else ''
        secret = getpass.getpass('Replacement Stripe secret key (hidden): ').strip()
        webhook = getpass.getpass('Replacement webhook signing secret (hidden): ').strip()
        try:
            content = render(previous, args.tenant, secret, webhook, args.enable_live)
        except ValueError as exc:
            raise SystemExit(str(exc))
        save(SECRET_FILE, content)
        result = subprocess.run(['systemctl', 'restart', 'nearmarket.service'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode:
            save(SECRET_FILE, previous)
            subprocess.run(['systemctl', 'restart', 'nearmarket.service'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            raise SystemExit('Service restart failed; previous environment restored. Inspect service logs locally.')
    print('Stripe settings saved in the protected server environment. No credentials were displayed.')
    print(f'Enable payments and Stripe for tenant #{args.tenant} in Marketplace admin → Settings.')
    print(f'Webhook URL: https://nearmarket.africandroid.world/api/webhooks/stripe/{args.tenant}')
    if args.enable_live:
        print('The global live-payment gate is enabled for all configured live gateways.')
    print('Provider credentials and webhook delivery still require verification in Stripe.')


if __name__ == '__main__':
    main()
