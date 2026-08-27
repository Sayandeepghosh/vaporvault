/**
 * The zero-knowledge core. Runs exclusively in the browser.
 *
 * Scheme (protocol v1)
 * --------------------
 *   linkKey    = 32 random bytes, transported only in the URL fragment
 *   salt       = 16 random bytes, stored server-side (public)
 *   passMat    = PBKDF2-SHA256(NFKC(passphrase), salt, 600_000) -> 32 bytes  [optional]
 *   ikm        = linkKey || passMat        (or just linkKey when no passphrase)
 *   contentKey = HKDF-SHA256(ikm, salt, info = "vaporvault.v1.content-key") -> 32 bytes
 *   ciphertext = AES-256-GCM(contentKey, iv = 12 random bytes, plaintext, aad)
 *   aad        = "vaporvault.v1.p" | "vaporvault.v1.n"
 *
 * The server receives only { v, salt, iv, ct }. Without the fragment (and the
 * passphrase, when set) that material is computationally useless.
 *
 * Algorithm parameters are pinned by the protocol version rather than transmitted,
 * which removes an entire class of downgrade and KDF-flooding attacks.
 */

import {
  AES_IV_BYTES,
  AES_KEY_BITS,
  AES_KEY_BYTES,
  AES_TAG_BITS,
  CIPHERTEXT_B64_MAX_LENGTH,
  HKDF_INFO,
  KDF_SALT_BYTES,
  MAX_PASSPHRASE_LENGTH,
  MAX_PLAINTEXT_BYTES,
  MIN_PASSPHRASE_LENGTH,
  PBKDF2_ITERATIONS,
  PROTOCOL_VERSION,
} from "@/lib/constants";
import {
  concatBytes,
  fromBase64Url,
  toBase64Url,
  utf8Decode,
  utf8Encode,
  zeroize,
  type Bytes,
} from "@/lib/crypto/encoding";
import {
  buildAad,
  parseFragment,
  serialiseFragment,
  type LinkFragment,
  type SecretEnvelope,
} from "@/lib/crypto/envelope";
import { CryptoError } from "@/lib/crypto/errors";

/** Web Crypto is only exposed in secure contexts; surface that clearly. */
function requireWebCrypto(): Crypto {
  const provider = globalThis.crypto;
  if (!provider || !provider.subtle || typeof provider.getRandomValues !== "function") {
    throw new CryptoError("WEB_CRYPTO_UNAVAILABLE");
  }
  return provider;
}

function randomBytes(length: number): Bytes {
  return requireWebCrypto().getRandomValues(new Uint8Array(length));
}

/**
 * Normalise a passphrase, then bound it.
 *
 * Order matters. NFKC both contracts and expands — three Hangul jamo (9 UTF-16 units)
 * collapse to one syllable each, and U+FDFA expands to 18 characters — so bounds measured
 * on the raw input do not constrain what actually reaches PBKDF2. Measuring the normalised
 * form in code points means the limits apply to the value being hashed, and that the same
 * effective passphrase is accepted or rejected consistently however it was typed.
 *
 * Returns `undefined` when no passphrase was supplied.
 */
function normalisePassphrase(
  passphrase: string | undefined,
  enforceMinimum: boolean,
): string | undefined {
  if (passphrase === undefined || passphrase.length === 0) return undefined;

  const normalised = passphrase.normalize("NFKC");
  const codePoints = [...normalised].length;

  if (codePoints > MAX_PASSPHRASE_LENGTH) throw new CryptoError("PASSPHRASE_TOO_LONG");
  if (enforceMinimum && codePoints < MIN_PASSPHRASE_LENGTH) {
    throw new CryptoError("PASSPHRASE_TOO_SHORT");
  }

  return normalised;
}

/**
 * Derive the AES-GCM content key.
 *
 * The returned `CryptoKey` is non-extractable, so once derived the raw bytes are not
 * reachable from JavaScript. All intermediate buffers are scrubbed.
 */
async function deriveContentKey(
  linkKey: Bytes,
  salt: Bytes,
  /** Already NFKC-normalised and length-checked by `normalisePassphrase`. */
  passphrase: string | undefined,
): Promise<CryptoKey> {
  const { subtle } = requireWebCrypto();

  let passBytes: Bytes | undefined;
  let passMaterial: Bytes | undefined;
  let ikm: Bytes | undefined;

  try {
    if (passphrase !== undefined) {
      // Held in a tracked local so the UTF-8 copy of the passphrase is scrubbed too.
      passBytes = utf8Encode(passphrase);
      const passphraseKey = await subtle.importKey("raw", passBytes, "PBKDF2", false, [
        "deriveBits",
      ]);
      const derived = await subtle.deriveBits(
        { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
        passphraseKey,
        AES_KEY_BITS,
      );
      passMaterial = new Uint8Array(derived);
      ikm = concatBytes(linkKey, passMaterial);
    } else {
      // Copy so that scrubbing `ikm` never clobbers the caller's link key.
      ikm = Uint8Array.from(linkKey);
    }

    const hkdfKey = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);

    return await subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: utf8Encode(HKDF_INFO) },
      hkdfKey,
      { name: "AES-GCM", length: AES_KEY_BITS },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    zeroize(passBytes, passMaterial, ikm);
  }
}

export interface EncryptSecretInput {
  plaintext: string;
  /** When present, the recipient needs both the link and this passphrase. */
  passphrase?: string;
}

export interface EncryptSecretResult {
  /** Safe to send to the server. */
  envelope: SecretEnvelope;
  /** URL fragment, without the leading `#`. Must never be sent to the server. */
  fragment: string;
}

export async function encryptSecret({
  plaintext,
  passphrase,
}: EncryptSecretInput): Promise<EncryptSecretResult> {
  // Guard the type explicitly: `TextEncoder.encode` coerces anything, so without this a
  // non-string would be silently encrypted as `"null"` or `"[object Object]"`.
  if (typeof plaintext !== "string") throw new CryptoError("EMPTY_SECRET");

  const normalisedPassphrase = normalisePassphrase(passphrase, true);
  const usePassphrase = normalisedPassphrase !== undefined;

  const { subtle } = requireWebCrypto();

  const linkKey = randomBytes(AES_KEY_BYTES);
  const salt = randomBytes(KDF_SALT_BYTES);
  const iv = randomBytes(AES_IV_BYTES);
  /**
   * Encoded exactly once, then measured.
   *
   * Reading `plaintext` twice — once to measure, once to encrypt — left a second copy of
   * the secret in memory that nothing scrubbed, and made the size cap a check-then-use
   * race against any value whose string conversion changes between the two reads.
   */
  let payload: Bytes | undefined;

  try {
    payload = utf8Encode(plaintext);
    if (payload.byteLength === 0) throw new CryptoError("EMPTY_SECRET");
    if (payload.byteLength > MAX_PLAINTEXT_BYTES) throw new CryptoError("SECRET_TOO_LARGE");

    const contentKey = await deriveContentKey(linkKey, salt, normalisedPassphrase);

    const ciphertext = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: buildAad(usePassphrase),
        tagLength: AES_TAG_BITS,
      },
      contentKey,
      payload,
    );

    return {
      envelope: {
        v: PROTOCOL_VERSION,
        salt: toBase64Url(salt),
        iv: toBase64Url(iv),
        ct: toBase64Url(new Uint8Array(ciphertext)),
      },
      fragment: serialiseFragment(linkKey, usePassphrase),
    };
  } finally {
    zeroize(linkKey, payload);
  }
}

export interface DecryptSecretInput {
  envelope: SecretEnvelope;
  /** Raw `location.hash` (with or without `#`) or an already-parsed fragment. */
  fragment: string | LinkFragment;
  passphrase?: string;
}

export async function decryptSecret({
  envelope,
  fragment,
  passphrase,
}: DecryptSecretInput): Promise<string> {
  const parsed = typeof fragment === "string" ? parseFragment(fragment) : fragment;
  // We own the buffer only when we parsed it ourselves; a caller-supplied fragment stays
  // the caller's to manage.
  const ownsLinkKey = typeof fragment === "string";

  if (parsed.requiresPassphrase && (passphrase === undefined || passphrase.length === 0)) {
    throw new CryptoError("PASSPHRASE_REQUIRED");
  }
  const normalisedPassphrase = normalisePassphrase(passphrase, false);

  if (envelope.v !== PROTOCOL_VERSION) throw new CryptoError("DECRYPT_FAILED");
  if (parsed.linkKey.byteLength !== AES_KEY_BYTES) throw new CryptoError("DECRYPT_FAILED");
  // Bound the ciphertext before decoding it, so this module is safe even when it is not
  // sitting behind the response schema that normally enforces the same limit.
  if (envelope.ct.length > CIPHERTEXT_B64_MAX_LENGTH) throw new CryptoError("DECRYPT_FAILED");

  const { subtle } = requireWebCrypto();

  let salt: Bytes;
  let iv: Bytes;
  let ciphertext: Bytes;
  try {
    salt = fromBase64Url(envelope.salt);
    iv = fromBase64Url(envelope.iv);
    ciphertext = fromBase64Url(envelope.ct);
  } catch {
    throw new CryptoError("DECRYPT_FAILED");
  }
  if (salt.byteLength !== KDF_SALT_BYTES || iv.byteLength !== AES_IV_BYTES) {
    throw new CryptoError("DECRYPT_FAILED");
  }

  let plaintextBytes: Bytes | undefined;
  try {
    const contentKey = await deriveContentKey(
      parsed.linkKey,
      salt,
      parsed.requiresPassphrase ? normalisedPassphrase : undefined,
    );

    const decrypted = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: buildAad(parsed.requiresPassphrase),
        tagLength: AES_TAG_BITS,
      },
      contentKey,
      ciphertext,
    );

    plaintextBytes = new Uint8Array(decrypted);
    // Strict UTF-8: authenticated bytes that are not valid text mean something is wrong.
    return utf8Decode(plaintextBytes);
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    // Never surface the underlying WebCrypto/OperationError detail.
    throw new CryptoError("DECRYPT_FAILED");
  } finally {
    zeroize(plaintextBytes, ownsLinkKey ? parsed.linkKey : undefined);
  }
}
