#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
usage() {
  cat <<'TXT'
Usage: sudo bash scripts/deploy-olamidepanel.sh --domain DOMAIN --email EMAIL --ipv4 SERVER_IP [--port 18361] [--ref main]
Run on the Debian Olamidepanel server. The domain must already resolve exclusively to this server's IPv4 address, without AAAA records.
Install prerequisites first: apt-get update && apt-get install -y git ansible-core
Remote deployment: ansible-playbook -i ansible/olamidepanel.example.ini ansible/deploy-olamidepanel.yml -e @/root/nearmarket-settings.yml
TXT
}
DOMAIN='' CERT_EMAIL='' SERVER_IPV4='' APP_PORT=18361 REVISION=main
while (($#)); do
  case "$1" in
    --domain|--email|--ipv4|--port|--ref)
      (($# >= 2)) || { usage >&2; exit 2; }
      case "$1" in
        --domain) DOMAIN=$2;; --email) CERT_EMAIL=$2;; --ipv4) SERVER_IPV4=$2;; --port) APP_PORT=$2;; --ref) REVISION=$2;;
      esac
      shift 2;;
    -h|--help) usage; exit 0;;
    *) usage >&2; exit 2;;
  esac
done
[[ -n "$DOMAIN" && -n "$CERT_EMAIL" && -n "$SERVER_IPV4" ]] || { usage >&2; exit 2; }
[[ $EUID == 0 ]] || { echo 'Run this script with sudo or as root on the panel server.' >&2; exit 2; }
command -v ansible-playbook >/dev/null || { echo 'Install ansible-core first.' >&2; exit 2; }
SCRIPT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
POLICY_FILE=$(mktemp /run/nearmarket-deploy-vars.XXXXXX)
trap 'rm -f -- "$POLICY_FILE"' EXIT
python3 - "$DOMAIN" "$CERT_EMAIL" "$SERVER_IPV4" "$APP_PORT" "$REVISION" > "$POLICY_FILE" <<'PY'
import json,sys
print(json.dumps(dict(zip(('nearmarket_domain','nearmarket_email','nearmarket_expected_ipv4','nearmarket_port','nearmarket_ref'),sys.argv[1:]))))
PY
ansible-playbook -i localhost, -c local "$SCRIPT_ROOT/ansible/deploy-olamidepanel.yml" -e "@$POLICY_FILE"
