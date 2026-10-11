import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import { parseSignatureHeader, verifySignature, webhookSecrets } from "../src/webhooks.ts";

const secret = "whsec_test";
const body = JSON.stringify({ event: "app.test", event_id: "e1", data: {} });

function mac(timestamp: number, payload = body, key = secret): string {
  return createHmac("sha256", key).update(`${timestamp}.${payload}`).digest("hex");
}

function sign(timestamp: number, payload = body, key = secret): string {
  return `t=${timestamp},v1=${mac(timestamp, payload, key)}`;
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

test("accepts a rotation header when either v1 is valid", async () => {
  const now = 1_790_000_000_000;
  const t = now / 1000;
  const valid = mac(t);
  const other = mac(t, body, "whsec_other");
  assert.equal(await verifySignature(`t=${t},v1=${valid},v1=${other}`, body, secret, now), true);
  assert.equal(await verifySignature(`t=${t},v1=${other},v1=${valid}`, body, secret, now), true);
  assert.equal(await verifySignature(`t=${t}, v1=${other} , v1=${valid}`, body, secret, now), true);
});

test("refuses a rotation header when neither v1 is valid", async () => {
  const now = 1_790_000_000_000;
  const t = now / 1000;
  const header = `t=${t},v1=${mac(t, body, "whsec_a")},v1=${mac(t, body, "whsec_b")}`;
  assert.equal(await verifySignature(header, body, secret, now), false);
});

test("ignores unknown keys and refuses malformed headers", async () => {
  const now = 1_790_000_000_000;
  const t = now / 1000;
  const valid = mac(t);
  assert.equal(await verifySignature(`t=${t},v0=abc,v1=${valid},v2=future`, body, secret, now), true);
  assert.equal(await verifySignature(`v1=${valid},t=${t}`, body, secret, now), true);
  // No t, a second t, a t that is not an integer, no v1.
  assert.equal(await verifySignature(`v1=${valid}`, body, secret, now), false);
  assert.equal(await verifySignature(`t=${t},t=${t},v1=${valid}`, body, secret, now), false);
  assert.equal(await verifySignature(`t=${t}.5,v1=${valid}`, body, secret, now), false);
  assert.equal(await verifySignature(`t=abc,v1=${valid}`, body, secret, now), false);
  assert.equal(await verifySignature(`t=${t}`, body, secret, now), false);
  assert.equal(await verifySignature(`t=${t},v2=${valid}`, body, secret, now), false);
  // Any v1 that is not 64 lowercase hex characters, even next to a valid one.
  assert.equal(await verifySignature(`t=${t},v1=${valid.toUpperCase()}`, body, secret, now), false);
  assert.equal(await verifySignature(`t=${t},v1=${valid},v1=abc`, body, secret, now), false);
  assert.equal(await verifySignature(`t=${t},v1=${valid},v1=`, body, secret, now), false);
  // A pair without "=", an empty pair, and more than 8 pairs.
  assert.equal(await verifySignature(`t=${t},v1=${valid},junk`, body, secret, now), false);
  assert.equal(await verifySignature(`t=${t},,v1=${valid}`, body, secret, now), false);
  assert.equal(await verifySignature(`t=${t},v1=${valid}` + ",x=1".repeat(7), body, secret, now), false);
  assert.equal(await verifySignature(`t=${t},v1=${valid}` + ",x=1".repeat(6), body, secret, now), true);
  assert.equal(await verifySignature("", body, secret, now), false);
});

test("parses every v1 and keeps t as sent", () => {
  assert.deepEqual(parseSignatureHeader(` t=1790000000 ,v1=${"a".repeat(64)},v1=${"b".repeat(64)}`), {
    timestamp: "1790000000",
    signatures: ["a".repeat(64), "b".repeat(64)],
  });
  assert.equal(parseSignatureHeader("t=1790000000"), null);
});

test("refuses an old or future timestamp even with several v1", async () => {
  const now = 1_790_000_000_000;
  const t = now / 1000;
  for (const at of [t - 301, t + 301]) {
    assert.equal(await verifySignature(`t=${at},v1=${mac(at, body, "whsec_other")},v1=${mac(at)}`, body, secret, now), false);
  }
  assert.equal(await verifySignature(sign(t - 300), body, secret, now), true);
});

test("accepts deliveries signed with the previous secret while it is configured", async () => {
  const now = 1_790_000_000_000;
  const t = now / 1000;
  const env = { TRINGIFY_WEBHOOK_SECRET: "whsec_new", TRINGIFY_WEBHOOK_SECRET_PREVIOUS: secret };
  assert.deepEqual(webhookSecrets(env), ["whsec_new", secret]);
  // The platform still signs with the old key only, or with both.
  assert.equal(await verifySignature(sign(t), body, webhookSecrets(env), now), true);
  assert.equal(await verifySignature(`t=${t},v1=${mac(t, body, "whsec_new")},v1=${mac(t)}`, body, webhookSecrets(env), now), true);
  assert.equal(await verifySignature(sign(t, body, "whsec_new"), body, webhookSecrets(env), now), true);
  assert.equal(await verifySignature(sign(t, body, "whsec_other"), body, webhookSecrets(env), now), false);
  // Without the previous secret, only the current one counts.
  assert.deepEqual(webhookSecrets({ TRINGIFY_WEBHOOK_SECRET: "whsec_new" }), ["whsec_new"]);
  assert.equal(await verifySignature(sign(t), body, webhookSecrets({ TRINGIFY_WEBHOOK_SECRET: "whsec_new" }), now), false);
  assert.equal(await verifySignature(sign(t), body, [], now), false);
});
