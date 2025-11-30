export type AlgoPBKDF2 = 'PBKDF2';
export type HashSHA256 = 'SHA-256';

export interface KdfParamsPBKDF2 {
  algo: AlgoPBKDF2;
  hash: HashSHA256;
  iters: number;
  salt_b64?: string;
}

export interface VaultHeaderV1 {
  v: 1;
  kdf: KdfParamsPBKDF2 & { salt_b64: string };
  mk_wrapped_b64: string;
  mk_iv_b64: string;
  created_at: number;
  rotated_at?: number | null;
}

export type ServerBundle = {
  crypto_version: 'v1';
  kdf_params: KdfParamsPBKDF2;
  kdf_salt: string; // base64
  eak: string;      // base64(IV || ciphertext+tag)
};

export interface CipherBlobV1 {
  v: 1;
  iv_b64: string;
  ct_b64: string;
  aad_b64?: string;
}
