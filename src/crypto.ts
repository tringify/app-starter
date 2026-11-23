// Store access tokens are encrypted at rest with AES-GCM.

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function key(secret: string): Promise<CryptoKey> {
  const raw = base64ToBytes(secret);
  if (raw.length !== 32) throw new Error("TOKEN_ENCRYPTION_KEY must be 32 bytes, base64-encoded");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encrypt(plaintext: string, secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await key(secret), new TextEncoder().encode(plaintext));
  return `${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(sealed))}`;
}

export async function decrypt(ciphertext: string, secret: string): Promise<string> {
  const [iv, sealed] = ciphertext.split(".");
  const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToBytes(iv) }, await key(secret), base64ToBytes(sealed));
  return new TextDecoder().decode(opened);
}
