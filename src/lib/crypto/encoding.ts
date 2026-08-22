/**
 * Isomorphic, dependency-free binary/text codecs.
 *
 * Hand-rolled rather than using `atob`/`Buffer` because we need
 *   - identical behaviour in the browser, the Node runtime and the Edge runtime;
 *   - *strict* decoding: `atob` tolerates whitespace and non-canonical trailing
 *     bits, which makes ciphertext malleable at the encoding layer.
 */

/**
 * Byte buffers that are explicitly `ArrayBuffer`-backed.
 *
 * `Uint8Array` on its own widens to `Uint8Array<ArrayBufferLike>`, which the Web Crypto
 * typings reject because a `SharedArrayBuffer` view is not a valid `BufferSource`. Naming
 * the concrete type keeps every crypto call site free of casts.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const DECODE_TABLE: Int16Array = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i += 1) {
    table[ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

export class EncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncodingError";
  }
}

/** Encode bytes as unpadded base64url (RFC 4648 §5). */
export function toBase64Url(bytes: Uint8Array): string {
  let out = "";
  let i = 0;

  for (; i + 2 < bytes.length; i += 3) {
    const triple = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      ALPHABET[(triple >> 18) & 63] +
      ALPHABET[(triple >> 12) & 63] +
      ALPHABET[(triple >> 6) & 63] +
      ALPHABET[triple & 63];
  }

  const remaining = bytes.length - i;
  if (remaining === 1) {
    const chunk = bytes[i] << 16;
    out += ALPHABET[(chunk >> 18) & 63] + ALPHABET[(chunk >> 12) & 63];
  } else if (remaining === 2) {
    const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += ALPHABET[(chunk >> 18) & 63] + ALPHABET[(chunk >> 12) & 63] + ALPHABET[(chunk >> 6) & 63];
  }

  return out;
}

/**
 * Decode unpadded base64url. Rejects padding, whitespace, unknown characters and
 * non-canonical encodings (trailing bits that are not zero).
 */
export function fromBase64Url(value: string): Bytes {
  const length = value.length;
  if (length % 4 === 1) {
    throw new EncodingError("invalid base64url length");
  }

  const fullGroups = Math.floor(length / 4);
  const remainder = length - fullGroups * 4;
  const outputLength = fullGroups * 3 + (remainder === 2 ? 1 : remainder === 3 ? 2 : 0);
  const out = new Uint8Array(outputLength);

  let outIndex = 0;
  let inIndex = 0;

  const sextet = (index: number): number => {
    const code = value.charCodeAt(index);
    const mapped = code < 128 ? DECODE_TABLE[code] : -1;
    if (mapped < 0) {
      throw new EncodingError("invalid base64url character");
    }
    return mapped;
  };

  for (let group = 0; group < fullGroups; group += 1) {
    const a = sextet(inIndex);
    const b = sextet(inIndex + 1);
    const c = sextet(inIndex + 2);
    const d = sextet(inIndex + 3);
    inIndex += 4;
    out[outIndex] = (a << 2) | (b >> 4);
    out[outIndex + 1] = ((b & 15) << 4) | (c >> 2);
    out[outIndex + 2] = ((c & 3) << 6) | d;
    outIndex += 3;
  }

  if (remainder === 2) {
    const a = sextet(inIndex);
    const b = sextet(inIndex + 1);
    if ((b & 15) !== 0) {
      throw new EncodingError("non-canonical base64url encoding");
    }
    out[outIndex] = (a << 2) | (b >> 4);
  } else if (remainder === 3) {
    const a = sextet(inIndex);
    const b = sextet(inIndex + 1);
    const c = sextet(inIndex + 2);
    if ((c & 3) !== 0) {
      throw new EncodingError("non-canonical base64url encoding");
    }
    out[outIndex] = (a << 2) | (b >> 4);
    out[outIndex + 1] = ((b & 15) << 4) | (c >> 2);
  }

  return out;
}

/** True when `value` is a syntactically valid unpadded base64url string of `length` chars. */
export function isBase64Url(value: string, expectedLength?: number): boolean {
  if (expectedLength !== undefined && value.length !== expectedLength) return false;
  try {
    fromBase64Url(value);
    return true;
  } catch {
    return false;
  }
}

const textEncoder = new TextEncoder();
/** Strict decoder: throws on malformed UTF-8 instead of emitting U+FFFD. */
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8Encode(value: string): Bytes {
  return textEncoder.encode(value);
}

export function utf8Decode(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

export function utf8ByteLength(value: string): number {
  return textEncoder.encode(value).byteLength;
}

export function concatBytes(...chunks: ReadonlyArray<Uint8Array>): Bytes {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/**
 * Best-effort scrub of key material. JavaScript cannot guarantee that copies made
 * by the engine are erased, but overwriting the buffers we control shortens the
 * window in which raw keys sit in a heap snapshot or core dump.
 */
export function zeroize(...buffers: ReadonlyArray<Uint8Array | undefined>): void {
  for (const buffer of buffers) {
    buffer?.fill(0);
  }
}
