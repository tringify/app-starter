# Tringify app starter

A Tringify app as a TypeScript [Cloudflare Worker](https://developers.cloudflare.com/workers/):

- the install redirect, which confirms the install and returns the merchant to the admin,
- an admin page that opens inside the Tringify admin through App Bridge,
- a webhook endpoint that verifies signatures and keeps each store's access token,
- calls to the Store API with that token.

Cloudflare Workers are one way to host an app. Any server that can receive
HTTPS requests works; this starter shows the pieces every app needs.

## Start

```sh
tringify app create --name "My app" --type standard --distribution private
tringify app init --app <app-id>
cd <app-slug>
npm install
npm run db:migrate:local
npm run dev
```

`tringify app init` downloads this starter, writes the app's configuration to
`tringify.app.json`, sets the app ID and client ID in `wrangler.jsonc` and creates
`.dev.vars` with a fresh `TOKEN_ENCRYPTION_KEY`. Add two secrets to
`.dev.vars`; each is shown once, when it is issued:

| Variable | Where it comes from |
| --- | --- |
| `TRINGIFY_CLIENT_SECRET` | the output of `tringify app create` |
| `TRINGIFY_WEBHOOK_SECRET` | the output of `tringify app webhook rotate-key` |

Without the CLI, copy `.dev.vars.example` to `.dev.vars` and fill in every value,
and set `TRINGIFY_APP_ID` and `TRINGIFY_CLIENT_ID` in `wrangler.jsonc`.

## What is where

| File | Purpose |
| --- | --- |
| `src/index.ts` | Routes: `GET /oauth/callback`, `POST /webhooks`, `/api/*` for the admin page, everything else from `public/`. |
| `src/oauth.ts` | The install redirect: exchanges the one-time code to confirm the store, then sends the merchant to the app in the admin. |
| `src/webhooks.ts` | Verifies `X-Tringify-Signature`, handles each event once by its `event_id`, stores the access token from `app.installed` and `app.token_rotated`, forgets it on `app.uninstalled`, and handles the mandatory privacy events (see below). |
| `src/store-api.ts` | Checks App Bridge session tokens against the Store API `/context` and calls the Store API with a store's token. |
| `src/crypto.ts` | Encrypts stored access tokens. |
| `public/` | The admin page. `app.js` gets a session token from App Bridge and calls `/api/overview`. |
| `migrations/` | The D1 schema. |
| `tringify.app.json` | The app's configuration: scopes, webhook URL, admin URL, events and the rest. |

The example page lists five products, so it needs the `read_products` scope.
Add it to `store_scopes` in `tringify.app.json`, or change the example.

## Configure the app

Deploy once to get the Worker's URL, then set it in `tringify.app.json`:

```json
"embed_type": "embedded",
"admin_ui_url": "https://<worker>.<account>.workers.dev/",
"redirect_uris": ["https://<worker>.<account>.workers.dev/oauth/callback"],
"webhook_url": "https://<worker>.<account>.workers.dev/webhooks",
"store_scopes": ["read_products"]
```

```sh
tringify app config push        # shows the changes, then replaces the draft
tringify app webhook test       # sends a signed app.test webhook
tringify app install-link --store <store>.mytringify.com
```

An app whose scopes can read customer data (`read_customers`, `read_orders`,
or a write scope that includes them) must have a `webhook_url`: create, save,
`config push` and release refuse it otherwise. A marketplace submit also sends
a signed `app.test` to it and needs a 2xx answer.

`config push` changes only the draft. A private app installs the draft from an
install link, and `tringify app release --store <id>` sends later drafts to stores
that installed it. A marketplace app releases versions (`tringify app release
--bump minor`), which reach stores once approved and published.

## Privacy events

Three webhook events are mandatory. They cannot be unsubscribed and arrive at
`webhook_url` even while webhooks are switched off. `src/webhooks.ts` handles
each one; extend the handlers when your app stores data of its own.

| Event | Sent to | What to do |
| --- | --- | --- |
| `app.customer_data_request` | Installed apps that can read customer data | A shopper asked the store for a copy of their personal data. Send the store what your app holds about them before `privacy_request.due_at`. |
| `app.customer_redact` | Installed apps that can read customer data | The store erased a shopper at their request. Delete what your app holds about them, unless the law requires you to keep it. |
| `app.store_redact` | Every app, 48 hours after a store uninstalls it unless it is installed again first, and at once when the store is deleted | Delete everything your app keeps for the store. The starter deletes the store's installation row. |

The customer events carry `privacy_request` (`id`, `reference`, `created_at`,
`due_at`) and `customer` (`id`, empty for a shopper without an account, and
`email`): match your records on both. `app.store_redact` carries
`installation_id` and `uninstalled_at`. Like every event, a retry repeats the
`event_id`, so each is handled once.

## Deploy

```sh
npx wrangler d1 create <app-slug>          # paste the id into wrangler.jsonc
npx wrangler secret put TRINGIFY_CLIENT_SECRET
npx wrangler secret put TRINGIFY_WEBHOOK_SECRET
openssl rand -base64 32 | npx wrangler secret put TOKEN_ENCRYPTION_KEY
npm run deploy                              # applies migrations, then deploys
```

Use a production `TOKEN_ENCRYPTION_KEY` that differs from the one in `.dev.vars`.
Changing it later makes stored tokens unreadable; stores then need to reinstall.

### Rotate the webhook secret

For 72 hours after `tringify app webhook rotate-key`, the platform signs each
delivery with both the new and the previous key, sending one `v1=` value per key
in `X-Tringify-Signature`. The app accepts a delivery when any configured secret
matches any `v1`. To rotate without dropping deliveries, keep the old secret as
`TRINGIFY_WEBHOOK_SECRET_PREVIOUS` while you deploy the new one:

```sh
npx wrangler secret put TRINGIFY_WEBHOOK_SECRET_PREVIOUS   # the current secret
npx wrangler secret put TRINGIFY_WEBHOOK_SECRET            # the new secret
npx wrangler secret delete TRINGIFY_WEBHOOK_SECRET_PREVIOUS  # after the overlap ends
```

`TRINGIFY_WEBHOOK_SECRET_PREVIOUS` is optional; leave it unset otherwise.

## Check

```sh
npm run check   # TypeScript
npm test        # signature and encryption tests (Node 22.18 or newer)
```

## Documentation

- [Build an app](https://dev-docs.tringify.com/apps)
- [Admin App Bridge](https://dev-docs.tringify.com/apps/admin-app-bridge/getting-started)
- [Webhooks](https://dev-docs.tringify.com/apps/apps/webhooks)
- [Store API](https://dev-docs.tringify.com/store-api)
