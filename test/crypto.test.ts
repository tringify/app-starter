import assert from "node:assert/strict";
import test from "node:test";
import { decrypt, encrypt } from "../src/crypto.ts";

const key = Buffer.alloc(32, 7).toString("base64");

test("a token survives encryption and is not stored in the clear", async () => {
  const sealed = await encrypt("tpat_secret", key);
  assert.ok(!sealed.includes("tpat_secret"));
  assert.equal(await decrypt(sealed, key), "tpat_secret");
  assert.notEqual(await encrypt("tpat_secret", key), sealed);
});

test("a key of the wrong length is refused", async () => {
  await assert.rejects(encrypt("x", Buffer.alloc(16).toString("base64")), /32 bytes/);
});
