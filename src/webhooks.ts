import { encrypt } from "./crypto.ts";
import { apiError, json, type Env } from "./env.ts";

// Deliveries older than this are refused, so a captured request cannot be
// replayed later.
const maxAgeSeconds = 300;

export interface Delivery {
  event: string;
  event_id: string;
  delivery_id: string;
  store_id: string;
  app_id?: string;
  timestamp: string;
  data: Record<string, unknown>;
}

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function equal(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// A header with more pairs than this is refused unread.
const maxSignaturePairs = 8;

export interface SignatureHeader {
  timestamp: string;
  signatures: string[];
}

// parseSignatureHeader reads X-Tringify-Signature: t=<unix seconds>,v1=<hex>[,v1=<hex>...].
// While the platform rotates its signing key it sends one v1 per active key.
// Unknown keys are future schemes and are skipped. Returns null when the
// header is malformed.
export function parseSignatureHeader(header: string): SignatureHeader | null {
  const pairs = header.split(",");
  if (pairs.length > maxSignaturePairs) return null;
  let timestamp: string | undefined;
  const signatures: string[] = [];
  for (const pair of pairs) {
    const separator = pair.indexOf("=");
    if (separator < 0) return null;
    const name = pair.slice(0, separator).trim();
    const value = pair.slice(separator + 1).trim();
    if (!name) return null;
    if (name === "t") {
      if (timestamp !== undefined || !/^\d+$/.test(value)) return null;
      timestamp = value;
    } else if (name === "v1") {
      if (!/^[0-9a-f]{64}$/.test(value)) return null;
      signatures.push(value);
    }
  }
  if (timestamp === undefined || signatures.length === 0) return null;
  return { timestamp, signatures };
}

// verifySignature checks X-Tringify-Signature: each v1 is the hex
// HMAC-SHA256 of "<t>.<raw body>" keyed with a webhook signing secret. The
// delivery is accepted when any configured secret matches any v1, so the app
// keeps working whether it deploys a new secret before or after the platform
// switches to it.
export async function verifySignature(header: string, body: string, secrets: string | readonly (string | undefined)[], now = Date.now()): Promise<boolean> {
  const parsed = parseSignatureHeader(header);
  const keys = (typeof secrets === "string" ? [secrets] : secrets).filter((secret): secret is string => !!secret);
  if (!parsed || keys.length === 0) return false;
  if (Math.abs(now / 1000 - Number(parsed.timestamp)) > maxAgeSeconds) return false;
  const message = new TextEncoder().encode(`${parsed.timestamp}.${body}`);
  let valid = false;
  for (const secret of keys) {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const expected = hex(await crypto.subtle.sign("HMAC", key, message));
    // Compare against every candidate, never stopping at the first match.
    for (const signature of parsed.signatures) valid = equal(expected, signature) || valid;
  }
  return valid;
}

// webhookSecrets lists the secrets a delivery may be signed with: the
// current one and, while rotating, the one it replaces.
export function webhookSecrets(env: Pick<Env, "TRINGIFY_WEBHOOK_SECRET" | "TRINGIFY_WEBHOOK_SECRET_PREVIOUS">): string[] {
  return [env.TRINGIFY_WEBHOOK_SECRET, env.TRINGIFY_WEBHOOK_SECRET_PREVIOUS].filter((secret): secret is string => !!secret);
}

export async function handleWebhook(request: Request, env: Env): Promise<Response> {
  const body = await request.text();
  if (!(await verifySignature(request.headers.get("x-tringify-signature") ?? "", body, webhookSecrets(env)))) {
    return apiError(401, "INVALID_SIGNATURE", "The webhook signature is not valid.");
  }
  const delivery = JSON.parse(body) as Delivery;
  if (delivery.app_id && delivery.app_id !== env.TRINGIFY_APP_ID) {
    return apiError(400, "WRONG_APP", "The webhook is for another app.");
  }
  if (!delivery.event_id) return apiError(400, "MISSING_EVENT_ID", "The webhook has no event ID.");
  // Each event is handled once, however many times it is delivered.
  const first = await env.DB.prepare("INSERT OR IGNORE INTO handled_events (event_id, handled_at) VALUES (?, ?)")
    .bind(delivery.event_id, new Date().toISOString())
    .run();
  if (first.meta.changes === 0) return json({ received: true, duplicate: true });

  try {
    await handleEvent(delivery, env);
  } catch (error) {
    // Let the delivery be retried.
    await env.DB.prepare("DELETE FROM handled_events WHERE event_id = ?").bind(delivery.event_id).run();
    throw error;
  }
  return json({ received: true });
}

async function handleEvent(delivery: Delivery, env: Env): Promise<void> {
  const data = delivery.data;
  switch (delivery.event) {
    case "app.installed":
    case "app.token_rotated": {
      const issuedAt = isoTime(delivery.event === "app.installed" ? data.installed_at : data.rotated_at);
      await saveToken(env, delivery.store_id, String(data.access_token), (data.scopes as string[] | undefined) ?? [], issuedAt);
      return;
    }
    case "app.uninstalled": {
      // The token stops working at uninstall; forget it. An uninstall older
      // than the stored token (the store reinstalled since) changes nothing.
      const uninstalledAt = isoTime(data.uninstalled_at);
      await env.DB.prepare(
        `UPDATE installations SET access_token_ciphertext = '', uninstalled_at = ?1
         WHERE store_id = ?2 AND token_issued_at <= ?1`,
      )
        .bind(uninstalledAt, delivery.store_id)
        .run();
      return;
    }
    // The three privacy events are mandatory: every app gets app.store_redact,
    // and an app whose scopes can read customer data (read_customers,
    // read_orders, or a write scope implying them) gets the two customer
    // events. They arrive even while webhooks are switched off, and cannot be
    // unsubscribed.
    case "app.store_redact": {
      // 48 hours after an uninstall, unless the store installed the app again
      // first, and at once when the store is deleted: delete everything the
      // app keeps for the store. Here that is the installation row; add your
      // own tables. A store that reinstalled after this uninstall keeps its data.
      const uninstalledAt = isoTime(data.uninstalled_at);
      await env.DB.prepare(
        `DELETE FROM installations
         WHERE store_id = ?1 AND NOT (uninstalled_at IS NULL AND installed_at > ?2)`,
      )
        .bind(delivery.store_id, uninstalledAt)
        .run();
      return;
    }
    case "app.customer_data_request": {
      // A shopper asked the store for a copy of their personal data. Send the
      // store what your app holds about them before privacy_request.due_at.
      // Find it by customer.id (empty for a shopper without an account) and by
      // customer.email. This starter keeps nothing about shoppers.
      const { customer, request } = privacyRequest(data);
      console.log(`Privacy request ${request.reference} (copy of data, due ${request.due_at}) for store ${delivery.store_id}, customer ${customer.id || "without an account"}: no shopper data is kept.`);
      return;
    }
    case "app.customer_redact": {
      // The store erased a shopper at their request. Delete what your app
      // holds about them, matching customer.id and customer.email, unless the
      // law requires you to keep it. This starter keeps nothing about shoppers.
      const { customer, request } = privacyRequest(data);
      console.log(`Privacy request ${request.reference} (erasure) for store ${delivery.store_id}, customer ${customer.id || "without an account"}: no shopper data is kept.`);
      return;
    }
    case "app.test":
      console.log("Received the test webhook.");
      return;
    default:
      // Events you subscribe to in tringify.app.json arrive here.
      console.log(`Received ${delivery.event} for store ${delivery.store_id}.`);
  }
}

// privacyRequest reads the body of app.customer_data_request and
// app.customer_redact.
function privacyRequest(data: Record<string, unknown>): { customer: { id: string; email: string }; request: { id: string; reference: string; due_at: string } } {
  const customer = (data.customer ?? {}) as { id?: unknown; email?: unknown };
  const request = (data.privacy_request ?? {}) as { id?: unknown; reference?: unknown; due_at?: unknown };
  return {
    customer: { id: String(customer.id ?? ""), email: String(customer.email ?? "") },
    request: { id: String(request.id ?? ""), reference: String(request.reference ?? ""), due_at: String(request.due_at ?? "") },
  };
}

// isoTime normalizes a timestamp to one fixed-width UTC form, so stored
// times compare correctly as text.
function isoTime(value: unknown): string {
  const ms = Date.parse(String(value));
  if (Number.isNaN(ms)) throw new Error(`Not a timestamp: ${String(value)}`);
  return new Date(ms).toISOString();
}

async function saveToken(env: Env, storeID: string, token: string, scopes: string[], issuedAt: string): Promise<void> {
  if (!token) throw new Error("The delivery carries no access token.");
  const ciphertext = await encrypt(token, env.TOKEN_ENCRYPTION_KEY);
  // A late retry of an older delivery never replaces a newer token.
  await env.DB.prepare(
    `INSERT INTO installations (store_id, access_token_ciphertext, scopes, token_issued_at, installed_at)
     VALUES (?1, ?2, ?3, ?4, ?4)
     ON CONFLICT (store_id) DO UPDATE SET
       access_token_ciphertext = excluded.access_token_ciphertext,
       scopes = excluded.scopes,
       token_issued_at = excluded.token_issued_at,
       installed_at = CASE WHEN installations.uninstalled_at IS NULL THEN installations.installed_at ELSE excluded.installed_at END,
       uninstalled_at = NULL
     WHERE excluded.token_issued_at > installations.token_issued_at
       AND (installations.uninstalled_at IS NULL OR installations.uninstalled_at < excluded.token_issued_at)`,
  )
    .bind(storeID, ciphertext, scopes.join(","), issuedAt)
    .run();
}
