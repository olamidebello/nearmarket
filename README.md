# NearMarket
Your neighborhood. Your marketplace.

Local flea marketplace with accounts, photo listings, radius search, favorites, offers, private messaging, seller edits, reports, and a super admin GUI.

## Run
Python 3.11+; no dependencies.

```sh
python3 app.py
```
Open http://127.0.0.1:8080. Create your account, then run on the server:

```sh
python3 app.py --promote-admin you@example.com
```
Open your account menu → Super admin dashboard. Manage users, suspend accounts, grant roles, moderate listings, resolve reports, provision/revoke API keys, and inspect audit logs. Self-demotion/suspension is blocked.

## API provisioning
Create a named key in the admin GUI with read/write scopes and a 1–365 day expiry. Copy the secret immediately; only its hash persists. Send `Authorization: Bearer <secret>` over HTTPS.

- `GET /api/v1/listings`: requires `listings:read`; returns up to 100 available listings.
- `POST /api/v1/listings`: requires `listings:write`. JSON: `seller` (active account ID), `title`, `description`, `price` (major currency units), `currency`, `category`, `condition`, `area`, `lat`, `lon`, optional `image` (JPEG/PNG/WebP base64 data URL). Response prices use integer minor units.

Write keys can create listings for any active seller. Keep them on trusted servers. Revocation and expiry are checked on each call. This provisions NearMarket API keys, not third-party provider credentials.

## Deployment and limits
Environment: `HOST=127.0.0.1`, `PORT=8080`, `NEARMARKET_DATA=./data`. Database/photos persist in SQLite; use SQLite backup tools. Run behind a TLS reverse proxy with `COOKIE_SECURE=1`; keep the application port private. Configure proxy authentication rate limits, 3 MB request size limit, logs and process supervision before public access. The standard-library server is for development/a controlled pilot; production server architecture is needed for high-volume use.

GPS requires HTTPS or localhost. Manual location accepts coordinates; address lookup is not configured. Listing coordinates round to two decimals. Photos are limited to 2 MB. Browse caps at 1,000 listings; pagination/object storage remain future scaling work.

No payments, escrow, delivery, email verification, password reset, identity verification, notifications, or pickup codes are implemented. Buyers/sellers arrange pickup/payment themselves. No demo accounts or inventory are created.

## Checks
```sh
python3 -m unittest discover -s tests -v
node --check static/app.js
```
