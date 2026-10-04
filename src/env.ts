export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  TRINGIFY_APP_ID: string;
  TRINGIFY_CLIENT_ID: string;
  TRINGIFY_CLIENT_SECRET: string;
  TRINGIFY_OAUTH_TOKEN_URL: string;
  TRINGIFY_ADMIN_URL: string;
  TRINGIFY_STORE_API: string;
  TRINGIFY_WEBHOOK_SECRET: string;
  TOKEN_ENCRYPTION_KEY: string;
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

export function apiError(status: number, code: string, message: string): Response {
  return json({ error: { code, message } }, status);
}
