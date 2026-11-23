import { decrypt } from "./crypto.ts";
import type { Env } from "./env.ts";

export class StoreAPIError extends Error {
  // retryAfter is the wait in seconds the Store API asked for on a 429.
  constructor(readonly status: number, message: string, readonly retryAfter = 0) {
    super(message);
  }
}

async function call(env: Env, token: string, path: string, init: RequestInit = {}): Promise<any> {
  const response = await fetch(env.TRINGIFY_STORE_API + path, {
    ...init,
    headers: { authorization: `Bearer ${token}`, accept: "application/json", ...(init.body ? { "content-type": "application/json" } : {}) },
  });
  const body = (await response.json().catch(() => ({}))) as { success?: boolean; data?: unknown; message?: string; error?: { message?: string } };
  if (!response.ok || body.success === false) {
    console.error(`Store API ${init.method ?? "GET"} ${path} answered HTTP ${response.status}: ${JSON.stringify(body).slice(0, 500)}`);
    throw new StoreAPIError(
      response.status,
      body.error?.message ?? body.message ?? `Store API answered HTTP ${response.status}`,
      Number(response.headers.get("retry-after")) || 0,
    );
  }
  return body.data;
}

export interface SessionContext {
  store_id: string;
  app_id: string;
  token_type: string;
  store_currency: string;
  store_timezone: string;
  primary_domain: string;
  scopes: string[];
}

// sessionContext asks the Store API who an App Bridge session token belongs
// to. Only a token for this app is accepted, so another app's session cannot
// act on your data.
export async function sessionContext(env: Env, sessionToken: string): Promise<SessionContext | null> {
  try {
    const context = (await call(env, sessionToken, "/context")) as SessionContext;
    if (context.token_type !== "app" || context.app_id !== env.TRINGIFY_APP_ID || !context.store_id) return null;
    return context;
  } catch (error) {
    if (error instanceof StoreAPIError && (error.status === 401 || error.status === 403)) return null;
    throw error;
  }
}

// storeAPI calls the Store API with the token the store's installation
// received.
export async function storeAPI(env: Env, storeID: string, path: string, init?: RequestInit): Promise<any> {
  const row = await env.DB.prepare(
    "SELECT access_token_ciphertext FROM installations WHERE store_id = ? AND uninstalled_at IS NULL AND access_token_ciphertext != ''",
  )
    .bind(storeID)
    .first<{ access_token_ciphertext: string }>();
  if (!row) throw new StoreAPIError(409, "The app has no access token for this store yet. Reinstall the app.");
  return call(env, await decrypt(row.access_token_ciphertext, env.TOKEN_ENCRYPTION_KEY), path, init);
}
