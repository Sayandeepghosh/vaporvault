import { z } from "zod";

import {
  AES_KEY_BYTES,
  AES_IV_BYTES,
  AES_TAG_BYTES,
  CIPHERTEXT_B64_MAX_LENGTH,
  FRAGMENT_PASSPHRASE_FLAG,
  FRAGMENT_PREFIX,
  KDF_SALT_BYTES,
  KEY_B64_LENGTH,
  PROTOCOL_VERSION,
  base64UrlLength,
} from "@/lib/constants";
import {
  fromBase64Url,
  isBase64Url,
  toBase64Url,
  utf8Encode,
  type Bytes,
} from "@/lib/crypto/encoding";
import { CryptoError } from "@/lib/crypto/errors";
import { parseJsonSafely } from "@/lib/safe-json";

/**
 * The only thing the server ever stores.
 *
 * Deliberately minimal: it carries no algorithm negotiation and no "is a passphrase
 * required" flag. Algorithms are pinned by `v`, and the passphrase flag lives in the
 * URL fragment (which never reaches the server), so the backend cannot be used as an
 * oracle for how a secret is protected.
 */
export interface SecretEnvelope {
  /** Protocol version. Pins cipher, KDF and work factors. */
  readonly v: typeof PROTOCOL_VERSION;
  /** base64url, 16 bytes. Salt for HKDF and, when used, PBKDF2. */
  readonly salt: string;
  /** base64url, 12 bytes. AES-GCM nonce. */
  readonly iv: string;
  /** base64url. AES-GCM ciphertext with the 16-byte tag appended. */
  readonly ct: string;
}

const exactBase64Url = (bytes: number) =>
  z
    .string()
    .length(base64UrlLength(bytes))
    .refine((value) => isBase64Url(value), { message: "malformed" });

/** Smallest legal ciphertext: one plaintext byte plus the GCM tag. */
const CIPHERTEXT_B64_MIN_LENGTH = base64UrlLength(AES_TAG_BYTES + 1);

/**
 * Strict schema. Unknown keys are rejected so a caller cannot smuggle extra data
 * into Redis, and every field is length-bounded before any decoding happens.
 */
export const secretEnvelopeSchema = z.strictObject({
  v: z.literal(PROTOCOL_VERSION),
  salt: exactBase64Url(KDF_SALT_BYTES),
  iv: exactBase64Url(AES_IV_BYTES),
  ct: z
    .string()
    .min(CIPHERTEXT_B64_MIN_LENGTH)
    .max(CIPHERTEXT_B64_MAX_LENGTH)
    .refine((value) => isBase64Url(value), { message: "malformed" }),
});

export type ParsedEnvelope = z.infer<typeof secretEnvelopeSchema>;

/**
 * Re-serialise from validated fields only. Guarantees the value written to Redis is
 * canonical and contains nothing the schema did not approve.
 */
export function serialiseEnvelope(envelope: SecretEnvelope): string {
  return JSON.stringify({
    v: envelope.v,
    salt: envelope.salt,
    iv: envelope.iv,
    ct: envelope.ct,
  });
}

/** Parse a stored envelope. Returns `null` for anything unexpected; never throws. */
export function deserialiseEnvelope(raw: string): SecretEnvelope | null {
  let candidate: unknown;
  try {
    candidate = parseJsonSafely(raw);
  } catch {
    return null;
  }
  const result = secretEnvelopeSchema.safeParse(candidate);
  return result.success ? result.data : null;
}

/* ------------------------------------------------------------------------- */
/* URL fragment                                                              */
/* ------------------------------------------------------------------------- */

export interface LinkFragment {
  /** Raw 32-byte link key. Never leaves the browser. */
  readonly linkKey: Bytes;
  /** Whether a passphrase must be mixed in to derive the content key. */
  readonly requiresPassphrase: boolean;
}

/** `v1.<43 chars>` plus an optional `.p`, so a generous ceiling catches junk early. */
const MAX_FRAGMENT_LENGTH = 128;

/** Build the `#...` fragment. Returned without the leading `#`. */
export function serialiseFragment(linkKey: Uint8Array, requiresPassphrase: boolean): string {
  if (linkKey.byteLength !== AES_KEY_BYTES) {
    throw new CryptoError("INVALID_LINK");
  }
  const parts = [FRAGMENT_PREFIX, toBase64Url(linkKey)];
  if (requiresPassphrase) parts.push(FRAGMENT_PASSPHRASE_FLAG);
  return parts.join(".");
}

/**
 * Strictly parse a fragment. Accepts an optional leading `#` and, as a concession to
 * clients that percent-encode URLs, one round of `decodeURIComponent`.
 *
 * @throws CryptoError `INVALID_LINK`
 */
export function parseFragment(raw: string): LinkFragment {
  // Total over any input: callers pass `window.location.hash`, and this must raise the
  // documented CryptoError rather than leaking a raw TypeError from `startsWith`.
  if (typeof raw !== "string") throw new CryptoError("INVALID_LINK");

  const attempt = (value: string): LinkFragment | null => {
    if (value.length === 0 || value.length > MAX_FRAGMENT_LENGTH) return null;

    const parts = value.split(".");
    if (parts.length < 2 || parts.length > 3) return null;
    if (parts[0] !== FRAGMENT_PREFIX) return null;
    if (parts[1].length !== KEY_B64_LENGTH) return null;
    if (parts.length === 3 && parts[2] !== FRAGMENT_PASSPHRASE_FLAG) return null;

    let linkKey: Bytes;
    try {
      linkKey = fromBase64Url(parts[1]);
    } catch {
      return null;
    }
    if (linkKey.byteLength !== AES_KEY_BYTES) return null;

    return { linkKey, requiresPassphrase: parts.length === 3 };
  };

  const normalised = raw.startsWith("#") ? raw.slice(1) : raw;

  const direct = attempt(normalised);
  if (direct) return direct;

  if (normalised.includes("%")) {
    try {
      const decoded = attempt(decodeURIComponent(normalised));
      if (decoded) return decoded;
    } catch {
      /* fall through to the generic error */
    }
  }

  throw new CryptoError("INVALID_LINK");
}

/**
 * Additional authenticated data.
 *
 * Binds the protocol version and the passphrase flag to the ciphertext, so neither
 * can be altered in transit (or by a hostile server) without the AEAD failing.
 */
export function buildAad(requiresPassphrase: boolean): Bytes {
  const flag = requiresPassphrase ? FRAGMENT_PASSPHRASE_FLAG : "n";
  return utf8Encode(`vaporvault.v${PROTOCOL_VERSION}.${flag}`);
}
