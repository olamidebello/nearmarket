# Deploy NearMarket on an existing Olamidepanel server

This playbook adds NearMarket as its own unprivileged service and dedicated Nginx site. It uses the existing Debian Nginx instance; it does not reinstall Olamidepanel, alter panel accounts/MySQL, stop shared Nginx, remove other sites, kill conflicting processes, change DNS or change firewall rules. The optional panel registration updates its read-only hosting inventory, not a hosting-account ownership record.

## Before running

- Debian 12 or newer with systemd and an existing active, valid Nginx installation using `/etc/nginx/sites-enabled`.
- A dedicated lowercase domain. Both `1.1.1.1` and `8.8.8.8` must resolve its A records exclusively to the target IPv4 address, with no AAAA records. Cloudflare/CDN proxy addresses do not meet this direct-origin deployment policy.
- Public ports 80 and 443 must already reach this server. HTTP-01 needs port 80; the application port stays on loopback.
- The chosen hostname must not already be explicitly configured by another Nginx site. A panel wildcard may coexist; the specific NearMarket hostname takes precedence. Existing exact-host configurations are never overwritten automatically.
- Root/sudo access. There are no embedded SSH passwords, provider keys or default admin passwords.

No NearMarket production domain has been selected for you. Replace `YOUR_DOMAIN` below with the domain you own and have pointed at the panel host. Replace the example IP if the server differs.

## Run directly on the Olamidepanel server

```bash
apt-get update
apt-get install -y git ansible-core
git clone https://github.com/olamidebello/nearmarket.git /root/nearmarket-deploy
cd /root/nearmarket-deploy
bash scripts/deploy-olamidepanel.sh \
  --domain YOUR_DOMAIN \
  --email YOUR_CERTIFICATE_EMAIL \
  --ipv4 154.16.170.86
```

The wrapper invokes `ansible-playbook -i localhost, -c local` and passes validated non-secret settings in a temporary root-only file. It removes that file on exit. The standard backend port is `18361`; add `--port 18362` if another service already uses it. `--ref main` accepts a branch, tag or commit. The playbook resolves and checks the exact commit it deploys.

For later updates:

```bash
cd /root/nearmarket-deploy
git pull --ff-only
bash scripts/deploy-olamidepanel.sh --domain YOUR_DOMAIN --email YOUR_CERTIFICATE_EMAIL --ipv4 154.16.170.86
```

Each successful run pulls the requested revision, runs tests, takes a backup and restarts only NearMarket. Run one deployment at a time; the deployment worker also has an exclusive lock. Scheduled application updates are not enabled. Certbot certificate renewal is enabled.

## Run from an Ansible control machine

Copy `ansible/olamidepanel.example.ini` and `ansible/olamidepanel.example.yml` to private operator-controlled paths, change the host/domain/email/IP and use an existing SSH key or `--ask-pass`:

```bash
ansible-playbook -i /secure/olamidepanel.ini ansible/deploy-olamidepanel.yml \
  -e @/secure/nearmarket-settings.yml
```

Use `--ask-become-pass` for a non-root sudo account. Host-key verification remains enabled. Do not put SSH passwords or payment secrets in Git. To run without publishing to the Olamidepanel inventory, explicitly set `nearmarket_publish_panel_inventory: false`. Check mode is intentionally rejected because DNS/ACME/service transactions cannot be reliably simulated; `--syntax-check` is supported.

## What deployment does

1. Verifies the existing Nginx configuration and service before installing application prerequisites.
2. Pulls the repository into `/opt/nearmarket/source` without discarding local edits.
3. Checks exact-host routing conflicts, backend port ownership and public DNS before stopping any application.
4. Exports an immutable commit release under `/opt/nearmarket/releases/COMMIT`; unsafe archive paths and symlinks are rejected. Candidate tests use disposable databases.
5. Stops only `nearmarket.service`, backs up the persistent database and old configuration to `/var/backups/nearmarket/TIMESTAMP`, then switches `/opt/nearmarket/current`.
6. Installs a root-owned systemd unit running as `nearmarket`, with a read-only application filesystem and write access only to its own data directory. Runtime data remains at `/var/lib/nearmarket` across releases.
7. Checks the loopback application identity/release. It creates only `nearmarket-DOMAIN.conf` and its enabled symlink. The shared Nginx main configuration is not rewritten. HTTP serves ACME only until HTTPS is ready.
8. Obtains/renews an isolated `nearmarket-DOMAIN` certificate using Certbot webroot. It validates Nginx before reload, waits for the new workers using bounded routing retries, then verifies local SNI/TLS and public HTTPS against the expected NearMarket release. Certificate validation is never bypassed.
9. Enables certificate renewal with an Nginx deploy hook. Adds proxy request limits and rate limiting for login, signup and pickup-code submission.
10. Merges the verified domain into `/var/lib/olamidepanel/hosted-domains.json`, preserving unrelated rows. The panel's hosted-domain view can display the backend, commit, configuration and verified status. This does not grant a panel customer ownership of the domain or configure an authenticated panel API integration.

Nginx rewrite/hosting automation elsewhere must not be configured to manage the same exact hostname. The generated site joins existing loopback/public-IP listener groups only when those groups already exist, preserving their other virtual hosts. ACME probes try the server IPv4 and loopback separately and record HTTP status codes without capturing response bodies.

The preflight stops on a duplicate; migrate that site deliberately rather than running competing deployers. Changing NearMarket's domain also requires an explicit vhost migration; the script will not leave two conflicting NearMarket rate-limit zones loaded.

## Inspect actual outcome

```bash
cat /var/lib/nearmarket-deploy/report.json
systemctl status nearmarket.service --no-pager
journalctl -u nearmarket.service -n 80 --no-pager
nginx -t
```

Only `status: deployed` plus the verified URL is a completed deployment. `stage: panel_inventory` with an error means the application may already be serving verified HTTPS but panel registration failed; fix the inventory file/group and rerun. DNS conflicts, blocked ACME, public routing errors and occupied ports produce failures rather than simulated success. Certbot details are in `/var/log/letsencrypt/letsencrypt.log`.

## Admin and gateway setup

Create your NearMarket account through the HTTPS website, then promote that existing account:

```bash
sudo -u nearmarket env NEARMARKET_DATA=/var/lib/nearmarket \
  python3 /opt/nearmarket/current/app.py --promote-admin YOUR_ACCOUNT_EMAIL
```

Alternatively, run `bash scripts/enable-superadmin.sh` from the deployment checkout; it prompts for your registered email. Then sign in at `https://nearmarket.africandroid.world/admin/api-keys`. Only accounts with the server-verified `superadmin` role can use the controls.

Gateway secrets are never accepted in the playbook command line. Add them locally with a secure editor to `/etc/nearmarket/secrets.env` (root-only, `0600`) and restart:

```bash
sudoedit /etc/nearmarket/secrets.env
systemctl restart nearmarket.service
```

Existing secrets are preserved on every deployment. See the root README for tenant-specific Stripe/Paystack environment names and webhook paths. Live payments remain disabled unless explicitly enabled after provider sandbox verification. Deployment does not create payment accounts, API secrets, active checkout integrations or seller payouts.

## Backups and rollback

Backups contain the previous service unit, non-secret runtime configuration, Nginx vhost, release/link state and a consistent SQLite backup. Protect and copy them off-server. Gateway secrets remain in the separate root-only environment file; back that up privately as well.

If application/TLS verification fails after the switch, the worker attempts to restore the previous release, unit, runtime settings and vhost. It never automatically restores the database: doing so could erase purchases, messages or webhook events received during verification. A previous application may be incompatible with a new schema, so read `rollback` in the report and inspect its logs. Use the private database backup for an operator-reviewed restore only after stopping the app and accounting for any newer writes. A first-install failure leaves no running NearMarket service or new active vhost.

The playbook retains old releases/backups and does not prune data. Initial migration from an unrelated NearMarket installation/path is not automatic. Existing old data must be transferred into `/var/lib/nearmarket` with the service stopped before first deployment. The current standard-library application server remains suitable for a controlled pilot; this script does not turn it into a high-volume production stack.

## Authoring verification

Application and deployment safety tests, Python compilation, shell syntax and Ansible syntax were checked. Deployment tests cover conflicting DNS/ports, unsafe archives, file permissions, wrong application identity, and a failed-candidate rollback preserving application data. The playbook has not been executed on the live Olamidepanel host; real SSH, DNS, ACME, systemd and public HTTPS still require a server run.

## Recovering from the first HTTPS deployment failure

If the old report shows `backend_verified: true`, `stage: https` and `curl (exit 22)`, the backend and DNS passed but the old script did not record which web check failed. Pull this update and rerun the same production playbook. The update retries ACME/TLS checks after Nginx reload and accommodates existing address-specific listener groups. It does not disable HTTPS verification or remove other sites.

If it still fails, the report now distinguishes `acme_http_routing`, `certificate_issuance`, `local_https_verification` and `public_https_verification`. Inspect the recorded `acme_probe` address/status results and `/var/log/nginx/error.log` for a persistent routing or filesystem-permission problem. No DNS edit is needed when both reported resolvers already show the correct IPv4 and no AAAA.
