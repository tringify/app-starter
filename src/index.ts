import { apiError, json, type Env } from "./env.ts";
import { sessionContext, storeAPI, StoreAPIError } from "./store-api.ts";
import { handleOAuthCallback } from "./oauth.ts";
import { handleWebhook } from "./webhooks.ts";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/webhooks" && request.method === "POST") return handleWebhook(request, env);
    if (url.pathname === "/oauth/callback" && request.method === "GET") return handleOAuthCallback(url, env);
    if (url.pathname.startsWith("/api/")) return handleAPI(request, env, url);
    // Everything else is the admin page in public/.
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;

// The admin page calls these with an App Bridge session token.
async function handleAPI(request: Request, env: Env, url: URL): Promise<Response> {
  const authorization = request.headers.get("authorization") ?? "";
  if (!authorization.startsWith("Bearer ")) return apiError(401, "UNAUTHORIZED", "A session token is required.");
  try {
    const session = await sessionContext(env, authorization.slice("Bearer ".length));
    if (!session) return apiError(401, "UNAUTHORIZED", "The session is not valid for this app.");

    if (url.pathname === "/api/overview" && request.method === "GET") {
      // An example Store API read with the installation's token. Change the
      // path and the read_products scope in tringify.app.json together.
      const { products } = (await storeAPI(env, session.store_id, "/products?limit=5")) as { products: { title: string }[] };
      return json({
        store: { domain: session.primary_domain, currency: session.store_currency },
        products: products.map((product) => ({ title: product.title })),
      });
    }
  } catch (error) {
    // The Store API limits each app per store, development stores most
    // tightly. Pass a 429 and its Retry-After on so the page can wait.
    if (error instanceof StoreAPIError && error.status === 429) {
      const response = apiError(429, "RATE_LIMITED", error.message);
      response.headers.set("retry-after", String(Math.max(1, error.retryAfter)));
      return response;
    }
    if (error instanceof StoreAPIError) return apiError(error.status === 409 ? 409 : 502, "STORE_API", error.message);
    throw error;
  }
  return apiError(404, "NOT_FOUND", "Not found.");
}
