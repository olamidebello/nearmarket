#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 0 ]] || { echo 'Run as root on the NearMarket server.' >&2; exit 2; }
[[ -f /opt/nearmarket/current/app.py ]] || { echo 'Deploy NearMarket first.' >&2; exit 2; }
ADMIN_EMAIL=${1:-}
if [[ -z "$ADMIN_EMAIL" ]]; then
  read -r -p 'Email of your existing NearMarket account: ' ADMIN_EMAIL
fi
[[ "$ADMIN_EMAIL" == *@*.* && "$ADMIN_EMAIL" != *$'\n'* ]] || { echo 'Enter your registered account email.' >&2; exit 2; }
runuser -u nearmarket -- env NEARMARKET_DATA=/var/lib/nearmarket \
  /usr/bin/python3 -B /opt/nearmarket/current/app.py --promote-admin "$ADMIN_EMAIL"
echo 'Sign in and open https://nearmarket.africandroid.world/admin/api-keys'
