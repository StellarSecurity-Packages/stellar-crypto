import { VaultHeaderV1, ServerBundle, CipherBlobV1 } from './types';
import { b64encode, b64decode, concat } from './b64';

const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * Create a new vault:
 * - Derive PK from password via PBKDF2-SHA256
 * - Generate random 32-byte MK
 * - Wrap MK with PK using AES-GCM
 * Returns header (to store) + MK bytes (to use immediately)
 */
export async function createVault(
  password: string,
  iters = 210_000
): Promise<{ header: VaultHeaderV1; mkRaw: Uint8Array }> {
  if (!password || password.length < 6) {
    throw new Error('Weak password');
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  const passKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iters, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  const mkRaw = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, passKey, mkRaw);

  const header: VaultHeaderV1 = {
    v: 1,
    kdf: {
      algo: 'PBKDF2',
      hash: 'SHA-256',
      iters,
      salt_b64: b64encode(salt),
    },
    mk_wrapped_b64: b64encode(wrapped),
    mk_iv_b64: b64encode(iv),
    created_at: Date.now(),
    rotated_at: null,
  };

  return { header, mkRaw };
}

/**
 * Build DB/server-compatible bundle from a VaultHeader.
 */
export function exportServerBundleFromHeader(header: VaultHeaderV1): ServerBundle {
  const iv = new Uint8Array(b64decode(header.mk_iv_b64));
  const ct = new Uint8Array(b64decode(header.mk_wrapped_b64));
  const packed = concat(iv, ct);

  return {
    crypto_version: 'v1',
    kdf_params: {
      algo: header.kdf.algo,
      hash: header.kdf.hash,
      iters: header.kdf.iters,
    },
    kdf_salt: header.kdf.salt_b64,
    eak: b64encode(packed),
  };
}

/**
 * Derive plaintext EAK (MK) from a server bundle using the user's password.
 */
export async function extractPlainEAK(
  userPassword: string,
  serverBundle: ServerBundle
): Promise<{ eakB64: string; eakBytes: Uint8Array; cryptoVersion: string }> {
  if (!userPassword) throw new Error('Password missing');
  if (!serverBundle?.kdf_params?.iters || !serverBundle?.kdf_salt || !serverBundle?.eak) {
    throw new Error('Bundle missing required fields');
  }

  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(userPassword), 'PBKDF2', false, ['deriveKey']);
  const pk = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: new Uint8Array(b64decode(serverBundle.kdf_salt)),
      iterations: serverBundle.kdf_params.iters,
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const blob = new Uint8Array(b64decode(serverBundle.eak));
  if (blob.length < 13) throw new Error('Invalid EAK blob');

  const iv = blob.slice(0, 12);
  const ct = blob.slice(12);

  const eakBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, pk, ct);
  const eakBytes = new Uint8Array(eakBuf);
  const eakB64 = b64encode(eakBytes);

  return { eakB64, eakBytes, cryptoVersion: serverBundle.crypto_version };
}

/**
 * Encrypt a UTF-8 string with a raw 32-byte MK using AES-GCM.
 */
export async function encryptTextWithMK(
  mkRaw: Uint8Array,
  plain: string,
  aad?: string
): Promise<CipherBlobV1> {
  if (mkRaw.length !== 32) {
    throw new Error('MK must be 32 bytes');
  }
  const mk = await crypto.subtle.importKey('raw', mkRaw, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ad = aad ? enc.encode(aad) : undefined;

  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: ad },
    mk,
    enc.encode(plain)
  );

  return {
    v: 1,
    iv_b64: b64encode(iv),
    ct_b64: b64encode(ct),
    aad_b64: ad ? b64encode(ad) : undefined,
  };
}

/**
 * Decrypt a CipherBlobV1 back to UTF-8 using the raw 32-byte MK.
 */
export async function decryptTextWithMK(
  mkRaw: Uint8Array,
  blob: CipherBlobV1
): Promise<string> {
  if (mkRaw.length !== 32) {
    throw new Error('MK must be 32 bytes');
  }
  if (blob.v !== 1) {
    throw new Error('Unsupported blob version');
  }

  const mk = await crypto.subtle.importKey('raw', mkRaw, 'AES-GCM', false, ['decrypt']);
  const iv = new Uint8Array(b64decode(blob.iv_b64));
  const ad = blob.aad_b64 ? new Uint8Array(b64decode(blob.aad_b64)) : undefined;
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: ad },
    mk,
    b64decode(blob.ct_b64)
  );

  return dec.decode(pt);
}
