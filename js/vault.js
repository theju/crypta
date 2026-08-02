import {
  GCM_NONCE_BYTES,
  KEY_BYTES,
  MAX_PBKDF2_ITERATIONS,
  MIN_PBKDF2_ITERATIONS,
  PBKDF2_ITERATIONS,
  SALT_BYTES,
  decryptAesGcm,
  deriveMasterWrappingKey,
  derivePasskeyWrappingKey,
  encryptAesGcm,
  generateVaultKey,
  importVaultKey,
  unwrapVaultKey,
  wipe,
  wrapVaultKey
} from "./crypto.js";
import { decodeUtf8, fromBase64Url, newId, randomBytes, toBase64Url, utf8 } from "./encoding.js";

export const FORMAT = "crypta-vault";
export const FORMAT_VERSION = 1;
export const MIME_TYPE = "application/vnd.crypta.vault+json";
export const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_ENTRIES = 10_000;
const MAX_PASSKEYS = 16;

function exactKeys(value, keys, context) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${context} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${context} has an unsupported structure.`);
  }
}

function boundedString(value, name, maximum, allowEmpty = true) {
  if (typeof value !== "string" || value.length > maximum || (!allowEmpty && value.length === 0)) {
    throw new Error(`${name} is invalid.`);
  }
}

function validDate(value, name) {
  boundedString(value, name, 40, false);
  if (!Number.isFinite(Date.parse(value))) throw new Error(`${name} is invalid.`);
}

function validateWrap(wrap, context, expectedCiphertextLength = KEY_BYTES + 16) {
  exactKeys(wrap, ["algorithm", "iv", "ciphertext"], context);
  if (wrap.algorithm !== "AES-256-GCM") throw new Error(`${context} uses an unsupported algorithm.`);
  fromBase64Url(wrap.iv, GCM_NONCE_BYTES);
  const ciphertext = fromBase64Url(wrap.ciphertext);
  if (expectedCiphertextLength !== null && ciphertext.length !== expectedCiphertextLength) {
    throw new Error(`${context} has an invalid ciphertext length.`);
  }
  if (ciphertext.length > MAX_FILE_BYTES) throw new Error(`${context} is too large.`);
}

export function validateEnvelope(envelope) {
  exactKeys(envelope, ["format", "version", "vaultId", "master", "passkeys", "payload"], "Vault envelope");
  if (envelope.format !== FORMAT || envelope.version !== FORMAT_VERSION) throw new Error("This vault format is not supported.");
  boundedString(envelope.vaultId, "Vault ID", 64, false);
  if (!/^[0-9a-f]{8}-[0-9a-f-]{27}$/iu.test(envelope.vaultId)) throw new Error("The vault ID is invalid.");

  exactKeys(envelope.master, ["kdf", "wrap"], "Master wrapper");
  exactKeys(envelope.master.kdf, ["name", "hash", "iterations", "salt"], "KDF configuration");
  const kdf = envelope.master.kdf;
  if (kdf.name !== "PBKDF2" || kdf.hash !== "SHA-256") throw new Error("The vault KDF is not supported.");
  if (!Number.isInteger(kdf.iterations) || kdf.iterations < MIN_PBKDF2_ITERATIONS || kdf.iterations > MAX_PBKDF2_ITERATIONS) {
    throw new Error("The vault PBKDF2 work factor is outside the supported range.");
  }
  fromBase64Url(kdf.salt, SALT_BYTES);
  validateWrap(envelope.master.wrap, "Master key wrapper");

  if (!Array.isArray(envelope.passkeys) || envelope.passkeys.length > MAX_PASSKEYS) throw new Error("The passkey list is invalid.");
  const ids = new Set();
  const credentials = new Set();
  for (const passkey of envelope.passkeys) {
    exactKeys(passkey, ["id", "credentialId", "prfInput", "wrap"], "Passkey wrapper");
    boundedString(passkey.id, "Passkey ID", 64, false);
    if (ids.has(passkey.id)) throw new Error("The vault contains a duplicate passkey ID.");
    ids.add(passkey.id);
    const credential = fromBase64Url(passkey.credentialId);
    if (credential.length < 16 || credential.length > 1023) throw new Error("A passkey credential ID has an invalid length.");
    if (credentials.has(passkey.credentialId)) throw new Error("The vault contains a duplicate passkey credential.");
    credentials.add(passkey.credentialId);
    fromBase64Url(passkey.prfInput, 32);
    validateWrap(passkey.wrap, "Passkey key wrapper");
  }

  validateWrap(envelope.payload, "Vault payload", null);
  if (fromBase64Url(envelope.payload.ciphertext).length < 17) throw new Error("The vault payload is empty.");
  return envelope;
}

function validateEntry(entry) {
  exactKeys(entry, ["id", "title", "url", "username", "password", "notes", "createdAt", "updatedAt"], "Credential entry");
  boundedString(entry.id, "Entry ID", 64, false);
  boundedString(entry.title, "Entry title", 200, false);
  boundedString(entry.url, "Entry URL", 2048);
  boundedString(entry.username, "Entry username", 500);
  boundedString(entry.password, "Entry password", 4096);
  boundedString(entry.notes, "Entry notes", 20_000);
  validDate(entry.createdAt, "Entry creation date");
  validDate(entry.updatedAt, "Entry update date");
}

export function validatePayload(payload, envelope) {
  exactKeys(payload, ["revision", "createdAt", "updatedAt", "entries", "passkeys"], "Vault payload");
  if (!Number.isSafeInteger(payload.revision) || payload.revision < 0) throw new Error("The vault revision is invalid.");
  validDate(payload.createdAt, "Vault creation date");
  validDate(payload.updatedAt, "Vault update date");
  if (!Array.isArray(payload.entries) || payload.entries.length > MAX_ENTRIES) throw new Error("The vault entry list is invalid.");
  const entryIds = new Set();
  for (const entry of payload.entries) {
    validateEntry(entry);
    if (entryIds.has(entry.id)) throw new Error("The vault contains duplicate entry IDs.");
    entryIds.add(entry.id);
  }
  if (!Array.isArray(payload.passkeys) || payload.passkeys.length !== envelope.passkeys.length) {
    throw new Error("The encrypted passkey metadata does not match the envelope.");
  }
  const wrapperIds = new Set(envelope.passkeys.map(item => item.id));
  for (const passkey of payload.passkeys) {
    exactKeys(passkey, ["id", "label", "createdAt"], "Passkey metadata");
    boundedString(passkey.id, "Passkey ID", 64, false);
    boundedString(passkey.label, "Passkey label", 80, false);
    validDate(passkey.createdAt, "Passkey creation date");
    if (!wrapperIds.delete(passkey.id)) throw new Error("The encrypted passkey metadata is inconsistent.");
  }
  if (wrapperIds.size) throw new Error("The encrypted passkey metadata is incomplete.");
  return payload;
}

function masterAad(envelope) {
  const { name, hash, iterations, salt } = envelope.master.kdf;
  return JSON.stringify([FORMAT, FORMAT_VERSION, envelope.vaultId, "master", name, hash, iterations, salt]);
}

function passkeyAad(envelope, passkey) {
  return JSON.stringify([FORMAT, FORMAT_VERSION, envelope.vaultId, "passkey", passkey.id, passkey.credentialId, passkey.prfInput]);
}

function payloadAad(envelope) {
  return JSON.stringify([FORMAT, FORMAT_VERSION, envelope.vaultId, "payload"]);
}

function encodedEncryption(result) {
  return { algorithm: "AES-256-GCM", iv: toBase64Url(result.iv), ciphertext: toBase64Url(result.ciphertext) };
}

async function encryptPayload(envelope, payload, rawVaultKey) {
  const key = await importVaultKey(rawVaultKey);
  const plaintext = utf8(JSON.stringify(payload));
  try {
    envelope.payload = encodedEncryption(await encryptAesGcm(key, plaintext, payloadAad(envelope)));
  } finally {
    plaintext.fill(0);
  }
}

async function decryptPayload(envelope, rawVaultKey) {
  const key = await importVaultKey(rawVaultKey);
  const plaintext = await decryptAesGcm(
    key,
    fromBase64Url(envelope.payload.ciphertext),
    fromBase64Url(envelope.payload.iv, GCM_NONCE_BYTES),
    payloadAad(envelope)
  );
  try {
    return validatePayload(JSON.parse(decodeUtf8(plaintext)), envelope);
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("The decrypted vault payload is malformed.");
    throw error;
  } finally {
    plaintext.fill(0);
  }
}

async function createMasterWrapper(envelope, password, rawVaultKey, iterations = PBKDF2_ITERATIONS) {
  const salt = randomBytes(SALT_BYTES);
  envelope.master = {
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations, salt: toBase64Url(salt) },
    wrap: null
  };
  const key = await deriveMasterWrappingKey(password, salt, iterations);
  envelope.master.wrap = encodedEncryption(await wrapVaultKey(rawVaultKey, key, masterAad(envelope)));
}

export async function createVault(password) {
  const now = new Date().toISOString();
  const envelope = { format: FORMAT, version: FORMAT_VERSION, vaultId: newId(), master: null, passkeys: [], payload: null };
  const rawVaultKey = generateVaultKey();
  const payload = { revision: 0, createdAt: now, updatedAt: now, entries: [], passkeys: [] };
  await createMasterWrapper(envelope, password, rawVaultKey);
  await encryptPayload(envelope, payload, rawVaultKey);
  return { envelope, payload, rawVaultKey, dirty: true };
}

export async function unlockWithPassword(envelope, password) {
  validateEnvelope(envelope);
  const kdf = envelope.master.kdf;
  const wrappingKey = await deriveMasterWrappingKey(password, fromBase64Url(kdf.salt, SALT_BYTES), kdf.iterations);
  const rawVaultKey = await unwrapVaultKey(
    fromBase64Url(envelope.master.wrap.ciphertext),
    fromBase64Url(envelope.master.wrap.iv, GCM_NONCE_BYTES),
    wrappingKey,
    masterAad(envelope)
  );
  try {
    const payload = await decryptPayload(envelope, rawVaultKey);
    return { envelope, payload, rawVaultKey, dirty: false };
  } catch (error) {
    wipe(rawVaultKey);
    throw error;
  }
}

export async function unlockWithPasskey(envelope, passkeyId, prfOutput) {
  validateEnvelope(envelope);
  const passkey = envelope.passkeys.find(item => item.id === passkeyId);
  if (!passkey) throw new Error("The selected passkey is not enrolled for this vault.");
  const wrappingKey = await derivePasskeyWrappingKey(prfOutput, envelope.vaultId);
  const rawVaultKey = await unwrapVaultKey(
    fromBase64Url(passkey.wrap.ciphertext),
    fromBase64Url(passkey.wrap.iv, GCM_NONCE_BYTES),
    wrappingKey,
    passkeyAad(envelope, passkey)
  );
  try {
    const payload = await decryptPayload(envelope, rawVaultKey);
    return { envelope, payload, rawVaultKey, dirty: false };
  } catch (error) {
    wipe(rawVaultKey);
    throw error;
  }
}

export async function verifyMasterPassword(session, password) {
  const kdf = session.envelope.master.kdf;
  const key = await deriveMasterWrappingKey(password, fromBase64Url(kdf.salt, SALT_BYTES), kdf.iterations);
  const candidate = await unwrapVaultKey(
    fromBase64Url(session.envelope.master.wrap.ciphertext),
    fromBase64Url(session.envelope.master.wrap.iv, GCM_NONCE_BYTES),
    key,
    masterAad(session.envelope)
  );
  let mismatch = candidate.length !== session.rawVaultKey.length;
  for (let index = 0; index < candidate.length && index < session.rawVaultKey.length; index++) mismatch ||= candidate[index] !== session.rawVaultKey[index];
  wipe(candidate);
  if (mismatch) throw new Error("The master password is incorrect.");
}

export async function addPasskey(session, descriptor, prfOutput, label) {
  if (session.envelope.passkeys.length >= MAX_PASSKEYS) throw new Error("This vault already has the maximum number of passkeys.");
  if (session.envelope.passkeys.some(item => item.credentialId === descriptor.credentialId)) throw new Error("This passkey is already enrolled.");
  boundedString(label, "Passkey label", 80, false);
  const passkey = { id: newId(), credentialId: descriptor.credentialId, prfInput: descriptor.prfInput, wrap: null };
  const wrappingKey = await derivePasskeyWrappingKey(prfOutput, session.envelope.vaultId);
  passkey.wrap = encodedEncryption(await wrapVaultKey(session.rawVaultKey, wrappingKey, passkeyAad(session.envelope, passkey)));
  session.envelope.passkeys.push(passkey);
  session.payload.passkeys.push({ id: passkey.id, label, createdAt: new Date().toISOString() });
  session.dirty = true;
  return passkey.id;
}

export async function rotateVaultAccess(session, currentPassword, newPassword, refreshedPasskey = null) {
  await verifyMasterPassword(session, currentPassword);
  const newVaultKey = generateVaultKey();
  const previousPasskeyMetadata = new Map(session.payload.passkeys.map(item => [item.id, item]));
  const nextEnvelope = structuredClone(session.envelope);
  const nextPayload = structuredClone(session.payload);
  nextEnvelope.passkeys = [];
  nextPayload.passkeys = [];
  try {
    await createMasterWrapper(nextEnvelope, newPassword, newVaultKey);

    if (refreshedPasskey) {
      const oldMetadata = previousPasskeyMetadata.get(refreshedPasskey.id);
      if (oldMetadata) {
        const passkey = {
          id: refreshedPasskey.id,
          credentialId: refreshedPasskey.credentialId,
          prfInput: refreshedPasskey.prfInput,
          wrap: null
        };
        const key = await derivePasskeyWrappingKey(refreshedPasskey.prfOutput, nextEnvelope.vaultId);
        passkey.wrap = encodedEncryption(await wrapVaultKey(newVaultKey, key, passkeyAad(nextEnvelope, passkey)));
        nextEnvelope.passkeys.push(passkey);
        nextPayload.passkeys.push(oldMetadata);
      }
    }

    await encryptPayload(nextEnvelope, nextPayload, newVaultKey);
    validateEnvelope(nextEnvelope);
    validatePayload(nextPayload, nextEnvelope);
  } catch (error) {
    wipe(newVaultKey);
    throw error;
  }

  wipe(session.rawVaultKey);
  session.envelope = nextEnvelope;
  session.payload = nextPayload;
  session.rawVaultKey = newVaultKey;
  session.dirty = true;
}

export async function sealForExport(session) {
  const nextEnvelope = structuredClone(session.envelope);
  const nextPayload = structuredClone(session.payload);
  nextPayload.revision += 1;
  nextPayload.updatedAt = new Date().toISOString();
  await encryptPayload(nextEnvelope, nextPayload, session.rawVaultKey);
  validateEnvelope(nextEnvelope);
  validatePayload(nextPayload, nextEnvelope);
  session.envelope = nextEnvelope;
  session.payload = nextPayload;
  session.dirty = false;
  return JSON.stringify(nextEnvelope, null, 2) + "\n";
}

export function parseVaultFile(text) {
  if (typeof text !== "string" || utf8(text).length > MAX_FILE_BYTES) throw new Error("The selected vault file is too large.");
  let envelope;
  try {
    envelope = JSON.parse(text);
  } catch {
    throw new Error("The selected file is not valid JSON.");
  }
  return validateEnvelope(envelope);
}

export function closeSession(session) {
  if (session?.rawVaultKey) wipe(session.rawVaultKey);
}
