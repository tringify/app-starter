import type { Env } from "./env.ts";

// After a store approves the install, Tringify sends the merchant to your
// redirect URI with a one-time `code`. Exchanging it confirms the install is
// for this app and names the store; the merchant then goes back to the app
// inside the Tringify admin. The Store API token the app keeps arrives
// separately, in the app.installed webhook.
export async function handleOAuthCallback(url: URL, env: Env): Promise<Response> {
  const code = url.searchParams.get("code");
  if (!code) return new Response("The authorization code is missing.", { status: 400 });

  const response = await fetch(env.TRINGIFY_OAUTH_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      client_id: env.TRINGIFY_CLIENT_ID,
      client_secret: env.TRINGIFY_CLIENT_SECRET,
      code,
      // Must match the redirect URI the code was issued for.
      redirect_uri: `${url.origin}${url.pathname}`,
    }),
  });
  const body = (await response.json().catch(() => ({}))) as {
    success?: boolean;
    data?: { app_id?: string; store_id?: string };
    message?: string;
  };
  if (!response.ok || body.success !== true || body.data?.app_id !== env.TRINGIFY_APP_ID || !body.data.store_id) {
    return new Response(body.message ?? "The install could not be confirmed.", { status: 502 });
  }
  const admin = new URL(`/dashboard/${body.data.store_id}/apps/${env.TRINGIFY_APP_ID}`, env.TRINGIFY_ADMIN_URL);
  return Response.redirect(admin.toString(), 302);
}
