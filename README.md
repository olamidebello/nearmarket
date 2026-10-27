# NearMarket
**Your neighborhood. Your marketplace.**

Local flea marketplace with accounts, photo listings, radius search, favorites, offers, private messages, seller controls, reports, multiple marketplaces, tenant administration, hosted checkout, order issues and pickup confirmation.

## Run
Python 3.11+, no third-party dependencies.

```sh
python3 app.py
```
Open http://127.0.0.1:8080. Create an account, then enable the first super admin from the server:

```sh
python3 app.py --promote-admin you@example.com
```
Account → Super admin dashboard. No default credentials, inventory, provider accounts or live payments are created.

## Administrator GUI
Tabs: overview, users, listings, reports, keys, tenants and audit. Suspend users, grant/revoke global roles, moderate listings, resolve reports, and inspect recent administrative activity. Self-demotion and self-suspension are blocked. Paid/pending listings cannot be reopened through moderation or seller edits.

Keys: provision, rename, edit read/write scopes, bind a marketplace and optional seller, set 1–365 day expiration, set 1–10,000 requests/minute, rotate secrets, revoke keys, inspect authorized-request counts/last use, and enable/disable the external API globally. Secrets display once and only SHA-256 digests persist. Rotation invalidates the previous secret immediately; quota usage stays with the key.

## Multiple tenants
Use Marketplace admin or Super admin → Tenants → marketplace control center. Super admins create marketplaces for an existing registered owner, set public/private access, quotas and gateway switches, and suspend/reactivate marketplaces. Tenant admins manage their own members, local administrator roles, reports, name, visibility and listings. Tenant admins cannot manage global users, keys, credentials, quotas or gateway activation.

Choose a marketplace from the header. Public marketplaces allow self-join; private marketplaces require an administrator to add your registered email. All signed-in accounts can participate in the default community. Accounts are global, but marketplace listings, conversations, reports, orders and API keys are tenant scoped. Global super admins retain cross-tenant oversight.

Clients select a marketplace with `X-Tenant-ID` (default `1`). It is an input, never an authorization grant. Keys must match that tenant and write keys must name a tenant member; an optional seller restriction limits impersonation further. Server-side authorization checks apply even if clients manipulate the header or listing IDs. Existing data migrates into tenant 1 automatically. This is shared-database isolation, not separate databases or custom-domain hosting.

## Integration API
Send `Authorization: Bearer YOUR_KEY` and `X-Tenant-ID: TENANT_ID` over HTTPS.

- `GET /api/v1/listings`: `listings:read`, up to 100 available tenant listings.
- `POST /api/v1/listings`: `listings:write`. JSON: `seller` (active tenant member ID; optional for seller-bound keys), `title`, `description`, `price` (major units), `currency`, `category`, `condition`, `area`, `lat`, `lon`, optional `image` (JPEG/PNG/WebP data URL). Returned prices are integer minor units.

Write keys may act for any active tenant seller unless bound to one seller. Keep keys on trusted servers. Expiration, revocation, scopes, tenant, seller restrictions and minute quotas are enforced. The integration API switch leaves browser marketplace/admin endpoints available. Request counters measure requests authorized by key/scope, not total failed authentication attempts.

## Stripe and Paystack hosted checkout
Gateways are implemented but **not configured or live-tested**. Use provider sandbox credentials first. Each tenant uses its own merchant account credentials. Set these in the server environment, never source control or browser code:

```text
NEARMARKET_PUBLIC_URL=https://your-market-domain.example
NEARMARKET_T1_STRIPE_SECRET=<Stripe test secret>
NEARMARKET_T1_STRIPE_WEBHOOK_SECRET=<Stripe endpoint signing secret>
NEARMARKET_T1_PAYSTACK_SECRET=<Paystack test secret>
COOKIE_SECURE=1
```

Replace `T1` with the tenant ID, e.g. `T2`. Configure that tenant's webhook URLs in the gateway dashboards:

- Stripe: `/api/webhooks/stripe/1`; subscribe to `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `checkout.session.expired`.
- Paystack: `/api/webhooks/paystack/1`; process `charge.success`.

Enable payments and selected gateways in tenant settings. The GUI reports credentials configured/missing, mode and readiness without exposing secrets. Stripe requires both server and webhook secrets. Paystack uses its server secret for API calls and HMAC-SHA512 webhook validation. Live-key activation additionally requires `NEARMARKET_ALLOW_LIVE_PAYMENTS=1` on the server. No bank/card data passes through this application.

Sellers must opt in per listing. Buyers choose a ready gateway. Amount/currency are loaded from the listing, never trusted from browser input. Checkout reserves the item atomically, preventing duplicate purchases. Provider webhooks verify raw signatures, tenant, reference, amount/currency and duplicate delivery before marking paid. Browser return URLs never mark an order paid. Stripe expiration releases pending inventory. Paystack checkout currently supports NGN; Stripe currency availability depends on the merchant account.

**Settlement model:** charges settle into the tenant merchant account. The tenant is responsible for seller settlement and gateway refunds. Automatic connected seller onboarding/payouts, split commissions, escrow, taxes, refunds and chargeback synchronization are not implemented. Do not advertise these capabilities. Use an appropriate merchant operating model before activating live collection.

Payment network failures may leave a pending reservation if the provider outcome is uncertain. Verify/reconcile these in the gateway dashboard and database before releasing inventory. Automatic reconciliation and Paystack reservation expiry are not implemented; this limits unattended use. Orders have no automatic cancellation button that could accidentally release an item after payment.

Buyer order history shows payment status and a pickup code after confirmed payment. The seller confirms handover using the buyer's code; codes are withheld from seller/admin order responses unless that admin is the buyer. Buyers may open an order issue; tenant admins record resolutions. This records a support workflow and does not perform a gateway refund.

Primary implementation references:
- https://docs.stripe.com/api/checkout/sessions/create
- https://docs.stripe.com/webhooks/signature
- https://paystack.com/docs/payments/accept-payments/
- https://paystack.com/docs/payments/webhooks/

## Operations and current limits
`HOST=127.0.0.1`, `PORT=8080`, `NEARMARKET_DATA=./data`. Back up the SQLite database using SQLite backup tooling. Run behind TLS with secure cookies and private application ports. Configure reverse-proxy authentication rate limiting, 3 MB request size limits, process supervision and logs. The standard-library HTTP server is for development and a controlled pilot; a production server architecture is needed before high-volume use.

Browser GPS requires HTTPS or localhost. Manual location accepts neighborhood coordinates; address geocoding is not configured. Coordinates round to two decimals. Photos are at most 2 MB. Browse caps at 1,000 listings per tenant; administration/orders show recent records. Pagination, object storage, email verification/reset, notifications, identity verification, advanced fraud controls and full production deployment remain future work. Generated branding images are separate deliverables and are not yet embedded into the website.

## Verification
```sh
python3 -m unittest discover -s tests -v
node --check static/app.js
```
Tests cover tenant isolation, membership/admin restrictions, API scopes, rotation, revocation, rate limits, API shutdown, gateway adapter payloads, signature tampering, incorrect amounts, repeated payment events, reservation locking, order visibility, pickup and issue permissions, and repeatable migrations. Provider calls are mocked; live provider accounts and browser layout are not verified. GitHub Actions runs these checks on push/PR.
