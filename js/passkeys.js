import { asArrayBuffer, fromBase64Url, randomBytes, toBase64Url } from "./encoding.js";

const TIMEOUT = 120_000;

export function passkeysAvailable() {
  return Boolean(
    globalThis.isSecureContext &&
    globalThis.PublicKeyCredential &&
    navigator.credentials?.create &&
    navigator.credentials?.get
  );
}

function requirePasskeys() {
  if (!passkeysAvailable()) {
    throw new Error("Passkeys require a supported browser and a secure HTTPS or localhost origin.");
  }
}

function assertionOptions(wrappers) {
  const evalByCredential = {};
  for (const wrapper of wrappers) {
    evalByCredential[wrapper.credentialId] = {
      first: asArrayBuffer(fromBase64Url(wrapper.prfInput, 32))
    };
  }
  return {
    challenge: asArrayBuffer(randomBytes(32)),
    allowCredentials: wrappers.map(wrapper => ({
      type: "public-key",
      id: asArrayBuffer(fromBase64Url(wrapper.credentialId))
    })),
    userVerification: "required",
    timeout: TIMEOUT,
    extensions: { prf: { evalByCredential } }
  };
}

function readPrfResult(credential) {
  const result = credential.getClientExtensionResults?.().prf?.results?.first;
  if (!result) throw new Error("This browser or passkey provider did not return a WebAuthn PRF result.");
  const output = new Uint8Array(result);
  if (output.length !== 32) throw new Error("The passkey returned an invalid PRF result.");
  return output;
}

export async function requestPasskeyPrf(wrappers) {
  requirePasskeys();
  if (!Array.isArray(wrappers) || wrappers.length === 0) throw new Error("This vault has no enrolled passkeys.");
  let credential;
  try {
    credential = await navigator.credentials.get({ publicKey: assertionOptions(wrappers) });
  } catch (error) {
    if (error?.name === "NotAllowedError") throw new Error("Passkey verification was cancelled or timed out.");
    throw new Error(`Passkey verification failed: ${error?.message || "unknown error"}`);
  }
  if (!credential) throw new Error("No passkey was selected.");
  const credentialId = toBase64Url(new Uint8Array(credential.rawId));
  const wrapper = wrappers.find(item => item.credentialId === credentialId);
  if (!wrapper) throw new Error("The selected passkey is not enrolled in this vault.");
  return { wrapper, prfOutput: readPrfResult(credential) };
}

export async function createPasskey(vaultId, existingWrappers = []) {
  requirePasskeys();
  const prfInput = randomBytes(32);
  const creationOptions = {
    challenge: asArrayBuffer(randomBytes(32)),
    rp: { name: "Crypta" },
    user: {
      id: asArrayBuffer(randomBytes(32)),
      name: `vault-${vaultId.slice(0, 8)}`,
      displayName: "Crypta vault"
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 }
    ],
    timeout: TIMEOUT,
    attestation: "none",
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required"
    },
    excludeCredentials: existingWrappers.map(wrapper => ({
      type: "public-key",
      id: asArrayBuffer(fromBase64Url(wrapper.credentialId))
    })),
    extensions: { prf: { eval: { first: asArrayBuffer(prfInput) } } }
  };

  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey: creationOptions });
  } catch (error) {
    if (error?.name === "NotAllowedError") throw new Error("Passkey creation was cancelled or timed out.");
    if (error?.name === "InvalidStateError") throw new Error("That passkey is already enrolled.");
    throw new Error(`Passkey creation failed: ${error?.message || "unknown error"}`);
  }
  if (!credential) throw new Error("The browser did not create a passkey.");
  const registrationResult = credential.getClientExtensionResults?.().prf;
  if (!registrationResult?.enabled) {
    throw new Error("The new passkey does not support WebAuthn PRF and cannot unlock an encrypted vault.");
  }

  const descriptor = {
    credentialId: toBase64Url(new Uint8Array(credential.rawId)),
    prfInput: toBase64Url(prfInput)
  };
  const verified = await requestPasskeyPrf([{ id: "pending", ...descriptor }]);
  return { descriptor, prfOutput: verified.prfOutput };
}
