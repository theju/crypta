import { wipe } from "./crypto.js";
import { addPasskey, closeSession, createVault, parseVaultFile, rotateVaultAccess, sealForExport, unlockWithPasskey, unlockWithPassword, verifyMasterPassword, MIME_TYPE, MAX_FILE_BYTES } from "./vault.js";
import { createPasskey, passkeysAvailable, requestPasskeyPrf } from "./passkeys.js";
import { newId } from "./encoding.js";

if (globalThis.top === globalThis.self) document.body.classList.remove("framing-protected");

const $ = selector => document.querySelector(selector);
const views = [$("#welcome-view"), $("#unlock-view"), $("#vault-view")];
const state = {
  pendingEnvelope: null,
  pendingFileName: "",
  session: null,
  inactivityTimer: null,
  toastTimer: null
};

function showView(view) {
  for (const item of views) item.hidden = item !== view;
  $("#vault-actions").hidden = view !== $("#vault-view");
}

function showToast(message, duration = 5000) {
  const toast = $("#toast");
  clearTimeout(state.toastTimer);
  toast.textContent = message;
  toast.hidden = false;
  state.toastTimer = setTimeout(() => { toast.hidden = true; }, duration);
}

function errorMessage(error) {
  console.error(error);
  showToast(error?.message || "Something went wrong.", 7000);
}

async function busy(message, operation) {
  $("#busy-message").textContent = message;
  $("#busy").hidden = false;
  try {
    await new Promise(resolve => requestAnimationFrame(resolve));
    return await operation();
  } finally {
    $("#busy").hidden = true;
  }
}

function markDirty() {
  state.session.dirty = true;
  updateVaultStatus();
}

function updateVaultStatus() {
  if (!state.session) return;
  const count = state.session.payload.entries.length;
  $("#vault-status").textContent = `${count} ${count === 1 ? "entry" : "entries"} · revision ${state.session.payload.revision}${state.session.dirty ? " · not exported" : ""}`;
  $("#export-button").textContent = state.session.dirty ? "Export changes" : "Export vault";
}

function lastRevision(vaultId) {
  const value = Number.parseInt(localStorage.getItem(`crypta:last-revision:${vaultId}`) || "0", 10);
  return Number.isSafeInteger(value) ? value : 0;
}

function rememberRevision(vaultId, revision) {
  localStorage.setItem(`crypta:last-revision:${vaultId}`, String(revision));
}

function finishUnlock(session) {
  state.session = session;
  // Keep the last sealed envelope separate from in-memory edits so locking can
  // safely return to it without retaining plaintext or half-written wrappers.
  state.pendingEnvelope = structuredClone(session.envelope);
  const seen = lastRevision(session.envelope.vaultId);
  if (session.payload.revision < seen) {
    showToast(`Warning: this is revision ${session.payload.revision}, but this browser previously opened revision ${seen}.`, 10000);
  } else {
    rememberRevision(session.envelope.vaultId, session.payload.revision);
  }
  $("#unlock-password").value = "";
  $("#search-input").value = "";
  showView($("#vault-view"));
  renderEntries();
  renderSecurity();
  resetInactivityTimer();
}

function configureUnlock(envelope, fileName) {
  state.pendingEnvelope = envelope;
  state.pendingFileName = fileName;
  $("#unlock-file-name").textContent = fileName;
  const canUsePasskeys = envelope.passkeys.length > 0 && passkeysAvailable();
  $("#passkey-unlock-button").hidden = !canUsePasskeys;
  $("#unlock-divider").hidden = !canUsePasskeys;
  showView($("#unlock-view"));
  $("#unlock-password").focus();
}

async function openFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) throw new Error("The selected vault file is larger than 10 MiB.");
  const envelope = parseVaultFile(await file.text());
  configureUnlock(envelope, file.name);
}

function textElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function copyButton(label, value) {
  const button = textElement("button", "button quiet", label);
  button.type = "button";
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(value);
      showToast(`${label.replace("Copy ", "")} copied. Clipboard history may retain it.`);
    } catch (error) {
      errorMessage(error?.name === "NotAllowedError" ? new Error("Clipboard access was denied.") : error);
    }
  });
  return button;
}

function renderEntries() {
  const list = $("#entry-list");
  list.replaceChildren();
  const query = $("#search-input").value.trim().toLocaleLowerCase();
  const entries = state.session.payload.entries
    .filter(entry => [entry.title, entry.url, entry.username].some(value => value.toLocaleLowerCase().includes(query)))
    .sort((left, right) => left.title.localeCompare(right.title));

  for (const entry of entries) {
    const card = document.createElement("article");
    card.className = "entry-card";
    const summary = document.createElement("div");
    summary.append(textElement("h2", "", entry.title));
    summary.append(textElement("p", "", entry.username || entry.url || "No username or website"));
    const controls = document.createElement("div");
    controls.className = "entry-controls";
    if (entry.username) controls.append(copyButton("Copy username", entry.username));
    if (entry.password) controls.append(copyButton("Copy password", entry.password));
    const edit = textElement("button", "button quiet", "Edit");
    edit.type = "button";
    edit.addEventListener("click", () => openEntryDialog(entry));
    controls.append(edit);
    card.append(summary, controls);
    list.append(card);
  }
  $("#empty-state").hidden = state.session.payload.entries.length !== 0 || query !== "";
  updateVaultStatus();
}

function openEntryDialog(entry = null) {
  $("#entry-form").reset();
  $("#entry-id").value = entry?.id || "";
  $("#entry-dialog-title").textContent = entry ? "Edit entry" : "Add entry";
  $("#delete-entry").hidden = !entry;
  if (entry) {
    $("#entry-title").value = entry.title;
    $("#entry-url").value = entry.url;
    $("#entry-username").value = entry.username;
    $("#entry-password").value = entry.password;
    $("#entry-notes").value = entry.notes;
  }
  $("#entry-dialog").showModal();
  $("#entry-title").focus();
}

function renderSecurity() {
  if (!state.session) return;
  const list = $("#passkey-list");
  list.replaceChildren();
  for (const passkey of state.session.payload.passkeys) {
    const row = document.createElement("div");
    row.className = "passkey-item";
    row.append(textElement("strong", "", passkey.label));
    row.append(textElement("span", "muted", new Date(passkey.createdAt).toLocaleDateString()));
    list.append(row);
  }
  $("#reset-passkeys-button").hidden = state.session.envelope.passkeys.length === 0;
  $("#add-passkey-button").disabled = !passkeysAvailable();
  $("#passkey-support").textContent = passkeysAvailable()
    ? "This browser can request passkeys. The selected provider must also support WebAuthn PRF."
    : "Passkeys are unavailable here. Use HTTPS or localhost with a compatible browser.";
}

function resetInactivityTimer() {
  clearTimeout(state.inactivityTimer);
  if (!state.session) return;
  state.inactivityTimer = setTimeout(() => lockVault(true), 10 * 60 * 1000);
}

function lockVault(automatic = false) {
  if (!state.session) return;
  if (!automatic && state.session.dirty && !confirm("Locking now will discard changes that have not been exported. Continue?")) return;
  const discarded = state.session.dirty;
  closeSession(state.session);
  state.session = null;
  clearTimeout(state.inactivityTimer);
  if (state.pendingEnvelope) configureUnlock(state.pendingEnvelope, state.pendingFileName);
  else showView($("#welcome-view"));
  if (automatic) showToast(discarded ? "Vault locked after inactivity; unexported changes were discarded." : "Vault locked after inactivity.", 8000);
}

function randomPassword(length = 24) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";
  const limit = 256 - (256 % alphabet.length);
  let password = "";
  while (password.length < length) {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    for (const value of bytes) {
      if (value < limit && password.length < length) password += alphabet[value % alphabet.length];
    }
    bytes.fill(0);
  }
  return password;
}

function openPasswordDialog(purpose) {
  $("#password-form").reset();
  $("#password-purpose").value = purpose;
  const changing = purpose === "change-password";
  const adding = purpose === "add-passkey";
  $("#password-dialog-title").textContent = changing ? "Change master password" : adding ? "Add a passkey" : "Remove passkeys";
  $("#new-password-fields").hidden = !changing;
  $("#new-password").required = changing;
  $("#new-password-confirm").required = changing;
  $("#passkey-label-row").hidden = !adding;
  $("#passkey-label").hidden = !adding;
  $("#passkey-label").required = adding;
  if (adding) $("#passkey-label").value = "Personal passkey";
  $("#password-dialog").showModal();
  $("#current-password").focus();
}

async function exportVault() {
  const contents = await busy("Encrypting export…", () => sealForExport(state.session));
  const blob = new Blob([contents], { type: MIME_TYPE });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "crypta-vault.crypta";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  state.pendingEnvelope = structuredClone(state.session.envelope);
  state.pendingFileName = "crypta-vault.crypta";
  rememberRevision(state.session.envelope.vaultId, state.session.payload.revision);
  updateVaultStatus();
  showToast("Encrypted vault exported. Replace the older cloud copy with this file.", 8000);
}

$("#open-file").addEventListener("change", event => {
  busy("Reading encrypted vault…", () => openFile(event.target.files[0])).catch(errorMessage);
  event.target.value = "";
});

const dropZone = $("#drop-zone");
for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, event => { event.preventDefault(); dropZone.classList.add("dragging"); });
}
for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, event => { event.preventDefault(); dropZone.classList.remove("dragging"); });
}
dropZone.addEventListener("drop", event => busy("Reading encrypted vault…", () => openFile(event.dataTransfer.files[0])).catch(errorMessage));
dropZone.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") $("#open-file").click(); });

$("#create-button").addEventListener("click", () => $("#create-dialog").showModal());
$("#create-form").addEventListener("submit", event => {
  event.preventDefault();
  const password = $("#create-password").value;
  if (password !== $("#confirm-password").value) return errorMessage(new Error("The master passwords do not match."));
  if (password.length < 12) return errorMessage(new Error("Use a master password of at least 12 characters; a long multi-word passphrase is better."));
  busy("Deriving your encryption key…", async () => {
    const session = await createVault(password);
    $("#create-form").reset();
    $("#create-dialog").close();
    state.pendingEnvelope = session.envelope;
    state.pendingFileName = "crypta-vault.crypta";
    finishUnlock(session);
    showToast("Vault created. Add credentials, then export your encrypted file.", 8000);
  }).catch(errorMessage);
});

$("#back-button").addEventListener("click", () => {
  state.pendingEnvelope = null;
  state.pendingFileName = "";
  showView($("#welcome-view"));
});

$("#unlock-form").addEventListener("submit", event => {
  event.preventDefault();
  const password = $("#unlock-password").value;
  busy("Unlocking with PBKDF2…", async () => finishUnlock(await unlockWithPassword(state.pendingEnvelope, password))).catch(errorMessage);
});

$("#passkey-unlock-button").addEventListener("click", () => {
  busy("Waiting for your passkey…", async () => {
    const result = await requestPasskeyPrf(state.pendingEnvelope.passkeys);
    try {
      finishUnlock(await unlockWithPasskey(state.pendingEnvelope, result.wrapper.id, result.prfOutput));
    } finally {
      wipe(result.prfOutput);
    }
  }).catch(errorMessage);
});

$("#search-input").addEventListener("input", renderEntries);
$("#add-entry-button").addEventListener("click", () => openEntryDialog());
$("#entry-form").addEventListener("submit", event => {
  event.preventDefault();
  const id = $("#entry-id").value;
  const existing = state.session.payload.entries.find(entry => entry.id === id);
  const now = new Date().toISOString();
  const entry = {
    id: existing?.id || newId(),
    title: $("#entry-title").value.trim(),
    url: $("#entry-url").value.trim(),
    username: $("#entry-username").value,
    password: $("#entry-password").value,
    notes: $("#entry-notes").value,
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };
  if (existing) Object.assign(existing, entry);
  else state.session.payload.entries.push(entry);
  markDirty();
  $("#entry-dialog").close();
  renderEntries();
});

$("#delete-entry").addEventListener("click", () => {
  const id = $("#entry-id").value;
  if (!confirm("Delete this credential from the current vault?")) return;
  state.session.payload.entries = state.session.payload.entries.filter(entry => entry.id !== id);
  markDirty();
  $("#entry-dialog").close();
  renderEntries();
});

$("#generate-password").addEventListener("click", () => {
  const password = randomPassword();
  $("#entry-password").type = "text";
  $("#entry-password").value = password;
  showToast("Generated a 24-character password.");
});

$("#export-button").addEventListener("click", () => exportVault().catch(errorMessage));
$("#lock-button").addEventListener("click", () => lockVault(false));
$("#settings-button").addEventListener("click", () => { renderSecurity(); $("#security-dialog").showModal(); });
$("#add-passkey-button").addEventListener("click", () => openPasswordDialog("add-passkey"));
$("#change-password-button").addEventListener("click", () => openPasswordDialog("change-password"));
$("#reset-passkeys-button").addEventListener("click", () => {
  if (confirm("This rotates the vault key and removes every passkey. Other devices will need the master password. Continue?")) openPasswordDialog("reset-passkeys");
});

$("#password-form").addEventListener("submit", event => {
  event.preventDefault();
  const purpose = $("#password-purpose").value;
  const currentPassword = $("#current-password").value;
  busy(purpose === "add-passkey" ? "Creating and verifying passkey…" : "Rotating vault encryption…", async () => {
    if (purpose === "add-passkey") {
      await verifyMasterPassword(state.session, currentPassword);
      const created = await createPasskey(state.session.envelope.vaultId, state.session.envelope.passkeys);
      try {
        await addPasskey(state.session, created.descriptor, created.prfOutput, $("#passkey-label").value.trim());
      } finally {
        wipe(created.prfOutput);
      }
      showToast("Passkey added. Export the vault to keep this enrollment.", 7000);
    } else if (purpose === "reset-passkeys") {
      await rotateVaultAccess(state.session, currentPassword, currentPassword, null);
      showToast("All passkeys removed and the vault key rotated. Export the vault now.", 8000);
    } else {
      const nextPassword = $("#new-password").value;
      if (nextPassword.length < 12) throw new Error("The new master password must contain at least 12 characters.");
      if (nextPassword !== $("#new-password-confirm").value) throw new Error("The new master passwords do not match.");
      let refreshed = null;
      if (state.session.envelope.passkeys.length) {
        try {
          const result = await requestPasskeyPrf(state.session.envelope.passkeys);
          refreshed = { ...result.wrapper, prfOutput: result.prfOutput };
        } catch (error) {
          if (!confirm(`${error.message}\n\nContinue and remove all existing passkey wrappers?`)) throw error;
        }
      }
      try {
        await rotateVaultAccess(state.session, currentPassword, nextPassword, refreshed);
      } finally {
        if (refreshed) wipe(refreshed.prfOutput);
      }
      showToast("Master password and vault key changed. Export the vault now.", 8000);
    }
    $("#password-form").reset();
    $("#password-dialog").close();
    renderSecurity();
    updateVaultStatus();
  }).catch(errorMessage);
});

document.querySelectorAll(".close-dialog").forEach(button => button.addEventListener("click", () => button.closest("dialog").close()));
for (const eventName of ["pointerdown", "keydown"]) document.addEventListener(eventName, resetInactivityTimer, { passive: true });
window.addEventListener("beforeunload", event => {
  if (state.session?.dirty) {
    event.preventDefault();
    event.returnValue = "";
  }
});

if ("serviceWorker" in navigator && globalThis.isSecureContext) {
  navigator.serviceWorker.register("./service-worker.js").catch(error => console.warn("Service worker registration failed", error));
}

showView($("#welcome-view"));
