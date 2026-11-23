// Runs inside the Tringify admin. App Bridge gives the page a short-lived
// session token; the Worker checks it with the Store API before answering.
const bridge = TringifyBridge.init();

async function api(path) {
  for (let attempt = 0; ; attempt++) {
    // Ask only for the scopes this page needs; each must be in your app's
    // store_scopes.
    const session = await bridge.getSessionToken({ scopes: ["read_products"] });
    const response = await fetch(path, { headers: { authorization: `Bearer ${session.token}` } });
    // Rate limited: wait as long as Retry-After says, a few times at most.
    if (response.status === 429 && attempt < 4) {
      await new Promise((resolve) => setTimeout(resolve, Math.max(1, Number(response.headers.get("retry-after")) || 2) * 1000));
      continue;
    }
    return read(response);
  }
}

async function read(response) {
  const body = await response.json();
  if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
  return body;
}

async function start() {
  await bridge.ready();
  try {
    const { store, products } = await api("/api/overview");
    document.getElementById("store").textContent = `${store.domain} · ${store.currency}`;
    const list = document.getElementById("products");
    for (const product of products) {
      const item = document.createElement("li");
      item.textContent = product.title;
      list.append(item);
    }
    if (products.length === 0) list.textContent = "No products yet.";
  } catch (error) {
    document.getElementById("store").textContent = "";
    bridge.toast(error.message, "error");
  }
}

start();
