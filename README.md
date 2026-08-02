# Crypta

Crypta is a dependency-free, file-based password vault. It is a static PWA made from HTML, CSS, and JavaScript; there is no application server, database, account, analytics, or network sync.

Credentials are encrypted in the browser and exported as a `.crypta` file. Put that file in Dropbox, Google Drive, iCloud Drive, Syncthing, or any other storage you trust to synchronize opaque encrypted data.

## Disclaimer

The current Crypta v2 codebase is completely AI-generated. It has not undergone an independent security audit; review and test it carefully before trusting it with sensitive credentials.

## Run locally

Crypta requires a secure browser context for Web Crypto, service workers, clipboard access, and passkeys. `localhost` is considered secure by browsers:

```sh
npm run serve
```

Then open <http://localhost:8000>. The `npm` command only invokes Python's static file server; the application has no npm dependencies or build step.

Run the dependency-free test suite with:

```sh
npm test
```

## Vault encryption

1. Crypta generates a random 256-bit vault key.
2. PBKDF2-HMAC-SHA-256 derives a wrapping key from the master password, a random 128-bit salt, and 1,200,000 iterations.
3. AES-256-GCM encrypts the vault key with that wrapping key.
4. A separate AES-256-GCM operation encrypts the complete vault payload with the random vault key.
5. Every encryption uses a fresh random 96-bit nonce and authenticates the vault identity and format metadata.

The file contains the salt, work factor, nonces, encrypted vault key, optional passkey wrappers, and encrypted payload. It contains neither the master password nor a password verifier.

PBKDF2 is used because it is available in native Web Crypto across modern browsers without adding a dependency. It is less resistant to GPU guessing than Argon2id, so use a long, unique multi-word master password.

## Passkeys

Passkeys are optional convenience unlock methods. Crypta uses the WebAuthn PRF extension—not the passkey signature itself—to derive a key that encrypts another copy of the vault key.

- A passkey must support PRF and pass a second assertion before Crypta enrolls it.
- A synced passkey can work on another device when its provider and browser reproduce the PRF output.
- Another provider/device can be enrolled after unlocking once with the master password.
- The master password is always the portable fallback.
- Changing the master password or removing passkeys rotates the vault key. Wrappers that cannot be refreshed are removed.
- Passkeys are bound to the production relying-party domain, so deploy Crypta on a stable HTTPS hostname.

Passkey PRF support still varies among browsers, operating systems, authenticators, and credential providers. Password unlock remains available everywhere Web Crypto is supported.

## File workflow

1. Select the latest `.crypta` file.
2. Unlock it with the master password or an enrolled passkey.
3. Make changes in memory.
4. Export `crypta-vault.crypta` and replace the older cloud copy.

Crypta warns about revisions older than the latest one seen by that browser. This is not complete rollback protection: a new browser has no trusted external revision counter, and simultaneous edits on multiple devices can still create conflicts.

## Deployment security

The application origin is part of the trust boundary: JavaScript served by a compromised host can capture an unlocked vault. Serve only reviewed, pinned release artifacts over HTTPS. The repository bundles no third-party runtime code.

Configure the static host to send these headers in addition to the in-document CSP:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

Do not add third-party scripts, fonts, analytics, tag managers, or CDN-hosted cryptographic code.

## Security boundaries

- Anyone with the file can make unlimited offline master-password guesses.
- Malware, hostile extensions, keyloggers, screenshots, developer tools, or compromised browser code can read an unlocked vault.
- Clipboard history may retain copied credentials.
- Cloud storage exposes filenames, file sizes, timestamps, old versions, trash, and conflict copies.
- Old exported files remain unlockable with their old password or passkey.
- AES-GCM detects corruption but cannot recover damaged or deleted data.
- There is no password or account recovery.

Keep versioned encrypted backups and test that they unlock.

## License

MIT
