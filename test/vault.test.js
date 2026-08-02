import test from "node:test";
import assert from "node:assert/strict";

import { addPasskey, createVault, parseVaultFile, rotateVaultAccess, sealForExport, unlockWithPasskey, unlockWithPassword, validateEnvelope } from "../js/vault.js";
import { randomBytes, toBase64Url } from "../js/encoding.js";

const PASSWORD = "correct horse battery staple";

test("vault lifecycle authenticates password, payload, and passkey wrappers", async () => {
  const session = await createVault(PASSWORD);
  session.payload.entries.push({
    id: crypto.randomUUID(),
    title: "Example",
    url: "https://example.com",
    username: "alice@example.com",
    password: "a secret",
    notes: "test entry",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  session.dirty = true;

  const prfOutput = randomBytes(32);
  const descriptor = { credentialId: toBase64Url(randomBytes(32)), prfInput: toBase64Url(randomBytes(32)) };
  const passkeyId = await addPasskey(session, descriptor, prfOutput, "Test passkey");
  const serialized = await sealForExport(session);
  const envelope = parseVaultFile(serialized);
  const firstPayloadNonce = envelope.payload.iv;

  session.payload.entries[0].notes = "changed";
  session.dirty = true;
  const nextEnvelope = parseVaultFile(await sealForExport(session));
  assert.notEqual(nextEnvelope.payload.iv, firstPayloadNonce, "each payload encryption needs a fresh nonce");

  const passwordSession = await unlockWithPassword(nextEnvelope, PASSWORD);
  assert.equal(passwordSession.payload.entries[0].password, "a secret");
  assert.equal(passwordSession.payload.revision, 2);

  const passkeySession = await unlockWithPasskey(nextEnvelope, passkeyId, prfOutput);
  assert.equal(passkeySession.payload.entries[0].username, "alice@example.com");

  await assert.rejects(unlockWithPassword(nextEnvelope, "definitely incorrect"), /could not be authenticated/u);

  const tampered = structuredClone(nextEnvelope);
  const ciphertext = tampered.payload.ciphertext;
  tampered.payload.ciphertext = `${ciphertext.slice(0, -1)}${ciphertext.endsWith("A") ? "B" : "A"}`;
  await assert.rejects(unlockWithPassword(tampered, PASSWORD), /could not be authenticated/u);
});

test("master password changes rotate the vault key and invalidate stale access", async () => {
  const session = await createVault(PASSWORD);
  const oldKey = Uint8Array.from(session.rawVaultKey);
  await rotateVaultAccess(session, PASSWORD, "a newer and much stronger master password", null);
  assert.notDeepEqual(session.rawVaultKey, oldKey);
  assert.equal(session.envelope.passkeys.length, 0);

  const serialized = await sealForExport(session);
  const envelope = parseVaultFile(serialized);
  await assert.rejects(unlockWithPassword(envelope, PASSWORD), /could not be authenticated/u);
  const unlocked = await unlockWithPassword(envelope, "a newer and much stronger master password");
  assert.equal(unlocked.payload.revision, 1);
});

test("schema rejects unsafe KDF work factors and unknown fields", async () => {
  const session = await createVault(PASSWORD);
  const unsafe = structuredClone(session.envelope);
  unsafe.master.kdf.iterations = 1;
  assert.throws(() => validateEnvelope(unsafe), /outside the supported range/u);

  const unknown = structuredClone(session.envelope);
  unknown.debug = true;
  assert.throws(() => validateEnvelope(unknown), /unsupported structure/u);
});
