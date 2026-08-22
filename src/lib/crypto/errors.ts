/**
 * Typed, non-leaky crypto errors.
 *
 * `code` is safe to branch on in the UI; `message` is safe to render to users.
 * Nothing here ever embeds key material, ciphertext or stack detail.
 */
export type CryptoErrorCode =
  | "WEB_CRYPTO_UNAVAILABLE"
  | "EMPTY_SECRET"
  | "SECRET_TOO_LARGE"
  | "PASSPHRASE_TOO_SHORT"
  | "PASSPHRASE_TOO_LONG"
  | "INVALID_LINK"
  | "PASSPHRASE_REQUIRED"
  | "DECRYPT_FAILED";

const MESSAGES: Record<CryptoErrorCode, string> = {
  WEB_CRYPTO_UNAVAILABLE:
    "Your browser did not expose the Web Crypto API. VaporVault must be served over HTTPS (or localhost).",
  EMPTY_SECRET: "Enter a secret before creating a link.",
  SECRET_TOO_LARGE: "That secret is too large. The limit is 10 KB.",
  PASSPHRASE_TOO_SHORT: "Use a passphrase of at least 8 characters.",
  PASSPHRASE_TOO_LONG: "That passphrase is too long.",
  INVALID_LINK: "This link is incomplete. The decryption key is missing from the URL.",
  PASSPHRASE_REQUIRED: "This secret is protected by a passphrase.",
  DECRYPT_FAILED: "Could not decrypt this secret. The link or passphrase is incorrect.",
};

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode) {
    super(MESSAGES[code]);
    this.name = "CryptoError";
    this.code = code;
  }
}

export function isCryptoError(error: unknown): error is CryptoError {
  return error instanceof CryptoError;
}
