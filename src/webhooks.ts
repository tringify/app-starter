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

// verifySignature checks X-Tringify-Signature: t=<unix seconds>,v1=<hex
// HMAC-SHA256 of "<t>.<raw body>" keyed with the webhook signing secret>.
export async function verifySignature(header: string, body: string, secret: string, now = Date.now()): Promise<boolean> {
  const match = /^t=(\d{10}),v1=([0-9a-f]{64})$/.exec(header);
  if (!match || !secret) return false;
  if (Math.abs(now / 1000 - Number(match[1])) > maxAgeSeconds) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expected = hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${match[1]}.${body}`)));
  return equal(expected, match[2]);
}

export async function handleWebhook(request: Request, env: Env): Promise<Response> {
  const body = await request.text();
  if (!(await verifySignature(request.headers.get("x-tringify-signature") ?? "", body, env.TRINGIFY_WEBHOOK_SECRET))) {
    return apiError(401, "INVALID_SIGNATURE", "The webhook signature is not valid.");
  }
  const delivery = JSON.parse(body) as Delivery;
  if (delivery.app_id && delivery.app_id !== env.TRINGIFY_APP_ID) {
    return apiError(400, "WRONG_APP", "The webhook is for another app.");
  }
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
    case "app.test":
      console.log("Received the test webhook.");
      return;
    default:
      // Events you subscribe to in tringify.app.json arrive here.
      console.log(`Received ${delivery.event} for store ${delivery.store_id}.`);
  }
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
