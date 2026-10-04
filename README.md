# Tringify app starter

A Tringify app as a TypeScript [Cloudflare Worker](https://developers.cloudflare.com/workers/):

- an admin page that opens inside the Tringify admin through App Bridge,
- a webhook endpoint that verifies signatures and keeps each store's access token,
- calls to the Store API with that token.

Cloudflare Workers are one way to host an app. Any server that can receive
HTTPS requests works; this starter shows the pieces every app needs.

## Start

Create the app in the [Developer Portal](https://dev.tringify.com) first, then:

```sh
tringify app init --app <app-id>
cd <app-slug>
npm install
npm run db:migrate:local
npm run dev
```

`tringify app init` downloads this starter, writes the app's configuration to
`tringify.app.json`, sets the app ID in `wrangler.jsonc` and creates `.dev.vars`
with a fresh `TOKEN_ENCRYPTION_KEY`. Copy your webhook signing secret into
`.dev.vars` as `TRINGIFY_WEBHOOK_SECRET`. The Developer Portal shows it when you
generate or rotate it: **Apps > your app > Webhooks > Signing Key**.

Without the CLI, copy `.dev.vars.example` to `.dev.vars` and fill in both values,
and set `TRINGIFY_APP_ID` in `wrangler.jsonc`.

## What is where

| File | Purpose |
| --- | --- |
| `src/index.ts` | Routes: `POST /webhooks`, `/api/*` for the admin page, everything else from `public/`. |
| `src/webhooks.ts` | Verifies `X-Tringify-Signature`, handles each event once, stores the access token from `app.installed` and `app.token_rotated`, forgets it on `app.uninstalled`. |
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
"webhook_url": "https://<worker>.<account>.workers.dev/webhooks",
"store_scopes": ["read_products"]
```

```sh
tringify app config push        # shows the changes, then replaces the draft
tringify app webhook test       # sends a signed app.test webhook
tringify app release --bump minor
```

`config push` changes only the draft. Stores get it when you release a version
and it is published (`tringify app versions`, `tringify app publish <version>`).

## Deploy

```sh
npx wrangler d1 create <app-slug>          # paste the id into wrangler.jsonc
npx wrangler secret put TRINGIFY_WEBHOOK_SECRET
openssl rand -base64 32 | npx wrangler secret put TOKEN_ENCRYPTION_KEY
npm run deploy                              # applies migrations, then deploys
```

Use a production `TOKEN_ENCRYPTION_KEY` that differs from the one in `.dev.vars`.
Changing it later makes stored tokens unreadable; stores then need to reinstall.

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
