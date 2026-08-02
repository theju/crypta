import { asArrayBuffer, randomBytes, utf8 } from "./encoding.js";

export const PBKDF2_ITERATIONS = 1_200_000;
export const MIN_PBKDF2_ITERATIONS = 600_000;
export const MAX_PBKDF2_ITERATIONS = 5_000_000;
export const SALT_BYTES = 16;
export const KEY_BYTES = 32;
export const GCM_NONCE_BYTES = 12;

function subtle() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable. Open Crypta in a secure browser context.");
  }
  return globalThis.crypto.subtle;
}

export async function deriveMasterWrappingKey(password, salt, iterations = PBKDF2_ITERATIONS) {
  if (typeof password !== "string" || password.length < 1 || password.length > 4096) {
    throw new Error("The master password is invalid.");
  }
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
    throw new Error("The PBKDF2 salt is invalid.");
  }
  if (!Number.isInteger(iterations) || iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
    throw new Error("The PBKDF2 work factor is outside the supported range.");
  }

  const passwordBytes = utf8(password);
  try {
    const material = await subtle().importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
    return await subtle().deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  } finally {
    passwordBytes.fill(0);
  }
}

export async function derivePasskeyWrappingKey(prfOutput, vaultId) {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length !== KEY_BYTES) {
    throw new Error("The passkey did not provide a valid PRF output.");
  }
  const material = await subtle().importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
  return subtle().deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: utf8(vaultId),
      info: utf8("crypta-passkey-wrap-v1")
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function importVaultKey(rawKey) {
  if (!(rawKey instanceof Uint8Array) || rawKey.length !== KEY_BYTES) {
    throw new Error("The vault key is invalid.");
  }
  return subtle().importKey("raw", rawKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export function generateVaultKey() {
  return randomBytes(KEY_BYTES);
}

export async function encryptAesGcm(key, plaintext, additionalData, iv = randomBytes(GCM_NONCE_BYTES)) {
  const ciphertext = await subtle().encrypt(
    { name: "AES-GCM", iv, additionalData: utf8(additionalData), tagLength: 128 },
    key,
    plaintext
  );
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

export async function decryptAesGcm(key, ciphertext, iv, additionalData) {
  try {
    const plaintext = await subtle().decrypt(
      { name: "AES-GCM", iv, additionalData: utf8(additionalData), tagLength: 128 },
      key,
      ciphertext
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new Error("The vault could not be authenticated. The password may be incorrect or the file may be damaged.");
  }
}

export async function wrapVaultKey(rawVaultKey, wrappingKey, additionalData) {
  return encryptAesGcm(wrappingKey, asArrayBuffer(rawVaultKey), additionalData);
}

export async function unwrapVaultKey(wrappedKey, iv, wrappingKey, additionalData) {
  const rawKey = await decryptAesGcm(wrappingKey, wrappedKey, iv, additionalData);
  if (rawKey.length !== KEY_BYTES) {
    rawKey.fill(0);
    throw new Error("The wrapped vault key has an invalid length.");
  }
  return rawKey;
}

export function wipe(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}
