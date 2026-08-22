/**
 * Protocol constants shared by the browser (encryption) and the server (validation).
 *
 * These values are part of the on-the-wire contract. Changing any of them requires
 * bumping `PROTOCOL_VERSION`, because old links must keep decrypting with old rules.
 */

/** Version tag embedded in the URL fragment and in the stored envelope. */
export const PROTOCOL_VERSION = 1;

/** Fragment prefix, e.g. `#v1.<key>`. */
export const FRAGMENT_PREFIX = `v${PROTOCOL_VERSION}`;

/** Marker appended to the fragment when the secret is additionally passphrase-protected. */
export const FRAGMENT_PASSPHRASE_FLAG = "p";

/* ------------------------------------------------------------------------- */
/* Cryptography (all algorithm parameters are pinned by PROTOCOL_VERSION)     */
/* ------------------------------------------------------------------------- */

export const AES_KEY_BITS = 256;
export const AES_KEY_BYTES = AES_KEY_BITS / 8;
/** AES-GCM nonce. 96 bits is the only size with an unmodified counter block. */
export const AES_IV_BYTES = 12;
/** AES-GCM authentication tag length. */
export const AES_TAG_BITS = 128;
export const AES_TAG_BYTES = AES_TAG_BITS / 8;
/** Salt for HKDF and (when a passphrase is used) PBKDF2. */
export const KDF_SALT_BYTES = 16;
/**
 * PBKDF2 work factor. Pinned by protocol version so a malicious server cannot
 * hand the browser an absurd iteration count and hang the tab.
 */
export const PBKDF2_ITERATIONS = 600_000;
export const HKDF_INFO = `vaporvault.v${PROTOCOL_VERSION}.content-key`;

/* ------------------------------------------------------------------------- */
/* Size limits                                                               */
/* ------------------------------------------------------------------------- */

/** Hard cap on the plaintext secret. */
export const MAX_PLAINTEXT_BYTES = 10 * 1024;
/** Ciphertext is plaintext plus the GCM tag. */
export const MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + AES_TAG_BYTES;

/** Unpadded base64url length required to encode `bytes` bytes. */
export function base64UrlLength(bytes: number): number {
  return Math.ceil((bytes * 4) / 3);
}

export const CIPHERTEXT_B64_MAX_LENGTH = base64UrlLength(MAX_CIPHERTEXT_BYTES);
export const IV_B64_LENGTH = base64UrlLength(AES_IV_BYTES);
export const SALT_B64_LENGTH = base64UrlLength(KDF_SALT_BYTES);
export const KEY_B64_LENGTH = base64UrlLength(AES_KEY_BYTES);

/** Upper bound for the serialised envelope we are willing to persist. */
export const MAX_STORED_ENVELOPE_BYTES = 16 * 1024;
/** Upper bound for any request body we will read off the socket. */
export const MAX_REQUEST_BODY_BYTES = 20 * 1024;

/** Passphrase bounds. Lower bound is advisory UX, upper bound prevents KDF abuse. */
export const MIN_PASSPHRASE_LENGTH = 8;
export const MAX_PASSPHRASE_LENGTH = 256;

/* ------------------------------------------------------------------------- */
/* Identifiers and lifetimes                                                 */
/* ------------------------------------------------------------------------- */

/** 128 bits of entropy: enumeration of secret ids is not feasible. */
export const SECRET_ID_BYTES = 16;
export const SECRET_ID_LENGTH = base64UrlLength(SECRET_ID_BYTES);

export const MIN_TTL_SECONDS = 60;
/** Product requirement: nothing outlives 24 hours. */
export const MAX_TTL_SECONDS = 24 * 60 * 60;
export const DEFAULT_TTL_SECONDS = 60 * 60;

export const TTL_CHOICES: ReadonlyArray<{ label: string; seconds: number }> = [
  { label: "5 minutes", seconds: 5 * 60 },
  { label: "1 hour", seconds: 60 * 60 },
  { label: "12 hours", seconds: 12 * 60 * 60 },
  { label: "24 hours", seconds: 24 * 60 * 60 },
];

/* ------------------------------------------------------------------------- */
/* Redis key namespace                                                       */
/* ------------------------------------------------------------------------- */

export const REDIS_SECRET_PREFIX = "vv:s:";
export const REDIS_RATELIMIT_PREFIX = "vv:rl:";
