# 🚀 stellar-crypto
### Core End-to-End Encryption SDK for the Stellar Ecosystem
**Zero-Knowledge. Fast. Auditable. Open Source.**

`stellar-crypto` is the official cryptographic core used across the **Stellar Security** ecosystem — powering encrypted storage, key-wrapping, secure sync, vault creation, and cross-platform AES-GCM operations.

This package provides:

- 🔐 **Vault creation** using PBKDF2-SHA256 (210k iterations)
- 🧩 **EAK (Encrypted Access Key) extraction** for login flows
- 🗝️ **Master Key wrapping/unwrapping** using AES-GCM
- 📦 **Server bundle encoding** (IV || ciphertext)
- 📚 **Typed interfaces** for KDF params, vault headers, bundles
- ✨ **No dependencies** — pure WebCrypto

All crypto happens **client-side**.  
Stellar servers never see plaintext notes or master keys.  
**Stellar ID is optional** — cryptography works independently.

---

## 🔧 Installation

```bash
npm install stellar-crypto
```

or (if using a scoped package):

```bash
npm install @stellarsecurity/stellar-crypto
```

---

## 📦 Quick Start

### 1. Create a vault (new user)

```ts
import { createVault, exportServerBundleFromHeader } from 'stellar-crypto';

const { header, mkRaw } = await createVault("mypassword");

// Send this to your backend:
const bundle = exportServerBundleFromHeader(header);
```

### 2. Login using EAK from server

```ts
import { extractPlainEAK } from 'stellar-crypto';

const { eakB64, eakBytes } = await extractPlainEAK(password, serverBundle);

// eakBytes = 32-byte master key for local encryption/decryption
```

### 3. Encrypt / decrypt notes

```ts
import { encryptTextWithMK, decryptTextWithMK } from 'stellar-crypto';

const blob = await encryptTextWithMK(eakBytes, "Hello world");

// later:
const text = await decryptTextWithMK(eakBytes, blob);
```

---

## 📁 Server Bundle Format

The backend stores:

```json
{
  "crypto_version": "v1",
  "kdf_params": {
    "algo": "PBKDF2",
    "hash": "SHA-256",
    "iters": 210000
  },
  "kdf_salt": "base64",
  "eak": "base64(IV || ciphertext)"
}
```

This allows:
- stateless server operations
- deterministic login flows
- end-to-end encryption without key disclosure

---

## 🛡️ Security Model

- AES‑256‑GCM used for all encryption
- PBKDF2-SHA256 with high iteration count
- All secret material left **only in RAM**
- No plaintext keys are ever sent to the backend
- Optional app-lock layer (Argon2 or PBKDF2) can wrap bundles locally

**Stellar servers cannot decrypt user data. Period.**

---

## 🧪 Browser Compatibility

Uses native WebCrypto:

- Chrome
- Firefox
- Safari
- Edge
- Android WebView
- iOS WKWebView

No polyfills required.

---

## 🏗️ Roadmap

- Argon2id KDF (WebAssembly)
- ECDH key exchange (Secure sharing)
- Multi-device key rotation
- Attachment encryption

---

## 📝 License

MIT — do whatever you want, just don’t break security.

---

## 🧑‍💻 About Stellar Security
Swiss-based security company building open-source, zero-knowledge privacy tools.

https://stellarsecurity.com
