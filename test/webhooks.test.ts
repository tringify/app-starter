import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import { verifySignature } from "../src/webhooks.ts";

const secret = "whsec_test";
const body = JSON.stringify({ event: "app.test", event_id: "e1", data: {} });

function sign(timestamp: number, payload = body, key = secret): string {
  const mac = createHmac("sha256", key).update(`${timestamp}.${payload}`).digest("hex");
  return `t=${timestamp},v1=${mac}`;
}

test("accepts a delivery signed with the secret", async () => {
  const now = 1_790_000_000_000;
  assert.equal(await verifySignature(sign(now / 1000), body, secret, now), true);
});

test("refuses a changed body, a wrong secret and an old delivery", async () => {
  const now = 1_790_000_000_000;
  assert.equal(await verifySignature(sign(now / 1000), body + " ", secret, now), false);
  assert.equal(await verifySignature(sign(now / 1000, body, "other"), body, secret, now), false);
  assert.equal(await verifySignature(sign(now / 1000 - 301), body, secret, now), false);
  assert.equal(await verifySignature("v1=abc", body, secret, now), false);
  assert.equal(await verifySignature(sign(now / 1000), body, "", now), false);
});
