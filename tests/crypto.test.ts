import { describe, expect, it } from "vitest";

import { AES_KEY_BYTES, MAX_PLAINTEXT_BYTES } from "@/lib/constants";
import { fromBase64Url, isBase64Url, toBase64Url } from "@/lib/crypto/encoding";
import {
  buildAad,
  deserialiseEnvelope,
  parseFragment,
  secretEnvelopeSchema,
  serialiseEnvelope,
  serialiseFragment,
} from "@/lib/crypto/envelope";
import { CryptoError } from "@/lib/crypto/errors";
import { decryptSecret, encryptSecret } from "@/lib/crypto/secret-crypto";

describe("base64url codec", () => {
  it("round-trips every byte value", () => {
    const bytes = new Uint8Array(256).map((_, index) => index);
    expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
  });

  it("round-trips every remainder length", () => {
    for (let length = 0; length <= 8; length += 1) {
      const bytes = new Uint8Array(length).fill(0xab);
      expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
    }
  });

  it("never emits padding or non-url-safe characters", () => {
    const encoded = toBase64Url(new Uint8Array([251, 255, 191, 254, 0]));
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it("rejects padding, whitespace and out-of-alphabet characters", () => {
    for (const bad of ["QQ==", "QQ ", "Q Q", "QQ\n", "a+b/", "aaaaa!"]) {
      expect(() => fromBase64Url(bad)).toThrow();
      expect(isBase64Url(bad)).toBe(false);
    }
  });

  it("rejects impossible lengths and non-canonical trailing bits", () => {
    expect(() => fromBase64Url("A")).toThrow();
    // "AB": the low 4 bits of 'B' are dropped, so only "AA" is canonical for that byte.
    expect(() => fromBase64Url("AB")).toThrow();
    expect(() => fromBase64Url("AAB")).toThrow();
    expect(fromBase64Url("AA")).toEqual(new Uint8Array([0]));
  });
});

describe("URL fragment", () => {
  const key = new Uint8Array(AES_KEY_BYTES).fill(7);

  it("round-trips with and without the passphrase flag", () => {
    expect(parseFragment(serialiseFragment(key, false))).toEqual({
      linkKey: key,
      requiresPassphrase: false,
    });
    expect(parseFragment(serialiseFragment(key, true))).toEqual({
      linkKey: key,
      requiresPassphrase: true,
    });
  });

  it("accepts a leading hash and percent-encoded input", () => {
    const fragment = serialiseFragment(key, true);
    expect(parseFragment(`#${fragment}`).requiresPassphrase).toBe(true);
    expect(parseFragment(encodeURIComponent(fragment)).requiresPassphrase).toBe(true);
  });

  it("rejects malformed fragments instead of guessing", () => {
    const valid = serialiseFragment(key, false);
    const cases = [
      "",
      "#",
      "v2." + toBase64Url(key),
      valid.slice(0, -1), // truncated key
      `${valid}.x`, // unknown flag
      `${valid}.p.p`, // too many parts
      `v1.${"!".repeat(43)}`,
      "v1." + toBase64Url(new Uint8Array(16)), // key too short
      "x".repeat(200),
    ];
    for (const candidate of cases) {
      expect(() => parseFragment(candidate), candidate).toThrowError(CryptoError);
    }
  });

  it("binds the passphrase flag into the AAD", () => {
    expect(buildAad(true)).not.toEqual(buildAad(false));
  });
});

describe("envelope schema", () => {
  async function sampleEnvelope() {
    const { envelope } = await encryptSecret({ plaintext: "hello" });
    return envelope;
  }

  it("accepts a freshly produced envelope and re-serialises canonically", async () => {
    const envelope = await sampleEnvelope();
    expect(secretEnvelopeSchema.safeParse(envelope).success).toBe(true);
    expect(deserialiseEnvelope(serialiseEnvelope(envelope))).toEqual(envelope);
  });

  it("strips anything not in the schema", async () => {
    const envelope = await sampleEnvelope();
    const polluted = { ...envelope, extra: "x".repeat(1000) };
    // Unknown keys are rejected outright rather than silently dropped.
    expect(secretEnvelopeSchema.safeParse(polluted).success).toBe(false);
    expect(serialiseEnvelope(polluted)).not.toContain("extra");
  });

  it("rejects wrong versions, wrong lengths and oversized ciphertext", async () => {
    const envelope = await sampleEnvelope();
    const bad = [
      { ...envelope, v: 2 },
      { ...envelope, iv: envelope.iv.slice(0, -1) },
      { ...envelope, salt: `${envelope.salt}A` },
      { ...envelope, ct: "A" },
      { ...envelope, ct: "A".repeat(20_000) },
      { ...envelope, ct: "!!!!!!!!!!!!!!!!!!!!!!!!" },
    ];
    for (const candidate of bad) {
      expect(secretEnvelopeSchema.safeParse(candidate).success).toBe(false);
    }
  });

  it("treats unparsable stored values as absent rather than throwing", () => {
    for (const raw of ["", "not json", "null", "[]", '{"v":1}', '{"v":1,"salt":"a"}']) {
      expect(deserialiseEnvelope(raw)).toBeNull();
    }
  });
});

describe("encrypt / decrypt", () => {
  it("round-trips without a passphrase", async () => {
    const plaintext = "correct horse battery staple";
    const { envelope, fragment } = await encryptSecret({ plaintext });
    await expect(decryptSecret({ envelope, fragment })).resolves.toBe(plaintext);
  });

  it("round-trips unicode, newlines and NUL bytes", async () => {
    const plaintext = "línea 1\nlínea 2\t🔐 \u0000 end";
    const { envelope, fragment } = await encryptSecret({ plaintext });
    await expect(decryptSecret({ envelope, fragment })).resolves.toBe(plaintext);
  });

  it("round-trips with a passphrase and marks the fragment", async () => {
    const plaintext = "s3cret";
    const passphrase = "a-long-enough-passphrase";
    const { envelope, fragment } = await encryptSecret({ plaintext, passphrase });

    expect(fragment.endsWith(".p")).toBe(true);
    await expect(decryptSecret({ envelope, fragment, passphrase })).resolves.toBe(plaintext);
  });

  it("never puts the key or the plaintext in the envelope", async () => {
    const plaintext = "canary-value-do-not-leak";
    const { envelope, fragment } = await encryptSecret({ plaintext });
    const serialised = serialiseEnvelope(envelope);

    expect(serialised).not.toContain(plaintext);
    // The 43-char link key must appear nowhere in what the server receives.
    expect(serialised).not.toContain(fragment.split(".")[1]);
    expect(Object.keys(envelope).sort()).toEqual(["ct", "iv", "salt", "v"]);
  });

  it("produces a fresh salt, iv and key for identical plaintext", async () => {
    const a = await encryptSecret({ plaintext: "same" });
    const b = await encryptSecret({ plaintext: "same" });
    expect(a.envelope.iv).not.toBe(b.envelope.iv);
    expect(a.envelope.salt).not.toBe(b.envelope.salt);
    expect(a.envelope.ct).not.toBe(b.envelope.ct);
    expect(a.fragment).not.toBe(b.fragment);
  });

  it("fails closed on a wrong passphrase", async () => {
    const { envelope, fragment } = await encryptSecret({
      plaintext: "top secret",
      passphrase: "the-right-passphrase",
    });
    await expect(
      decryptSecret({ envelope, fragment, passphrase: "the-wrong-passphrase" }),
    ).rejects.toMatchObject({ code: "DECRYPT_FAILED" });
  });

  it("requires the passphrase when the fragment demands one", async () => {
    const { envelope, fragment } = await encryptSecret({
      plaintext: "top secret",
      passphrase: "the-right-passphrase",
    });
    await expect(decryptSecret({ envelope, fragment })).rejects.toMatchObject({
      code: "PASSPHRASE_REQUIRED",
    });
  });

  it("fails when the passphrase flag is stripped from the link", async () => {
    const passphrase = "the-right-passphrase";
    const { envelope, fragment } = await encryptSecret({ plaintext: "x", passphrase });
    const downgraded = fragment.replace(/\.p$/, "");

    await expect(decryptSecret({ envelope, fragment: downgraded })).rejects.toMatchObject({
      code: "DECRYPT_FAILED",
    });
  });

  it("rejects a tampered ciphertext, iv or salt", async () => {
    const { envelope, fragment } = await encryptSecret({ plaintext: "integrity matters" });

    const flip = (value: string) => {
      const bytes = fromBase64Url(value);
      bytes[0] ^= 0x01;
      return toBase64Url(bytes);
    };

    for (const mutated of [
      { ...envelope, ct: flip(envelope.ct) },
      { ...envelope, iv: flip(envelope.iv) },
      { ...envelope, salt: flip(envelope.salt) },
    ]) {
      await expect(decryptSecret({ envelope: mutated, fragment })).rejects.toMatchObject({
        code: "DECRYPT_FAILED",
      });
    }
  });

  it("rejects a truncated ciphertext (dropped auth tag)", async () => {
    const { envelope, fragment } = await encryptSecret({ plaintext: "integrity matters" });
    const bytes = fromBase64Url(envelope.ct);
    const truncated = toBase64Url(bytes.slice(0, bytes.length - 4));

    await expect(
      decryptSecret({ envelope: { ...envelope, ct: truncated }, fragment }),
    ).rejects.toMatchObject({ code: "DECRYPT_FAILED" });
  });

  it("cannot be decrypted with a different link key", async () => {
    const first = await encryptSecret({ plaintext: "one" });
    const second = await encryptSecret({ plaintext: "two" });

    await expect(
      decryptSecret({ envelope: first.envelope, fragment: second.fragment }),
    ).rejects.toMatchObject({ code: "DECRYPT_FAILED" });
  });

  it("enforces the payload ceiling and rejects empty input", async () => {
    await expect(encryptSecret({ plaintext: "" })).rejects.toMatchObject({
      code: "EMPTY_SECRET",
    });
    await expect(
      encryptSecret({ plaintext: "a".repeat(MAX_PLAINTEXT_BYTES + 1) }),
    ).rejects.toMatchObject({ code: "SECRET_TOO_LARGE" });
  });

  it("counts the limit in bytes, not characters", async () => {
    // A 4-byte emoji: 2600 of them is 10 400 bytes but only 5200 UTF-16 code units.
    await expect(encryptSecret({ plaintext: "🔐".repeat(2600) })).rejects.toMatchObject({
      code: "SECRET_TOO_LARGE",
    });
    const atLimit = "a".repeat(MAX_PLAINTEXT_BYTES);
    const { envelope, fragment } = await encryptSecret({ plaintext: atLimit });
    await expect(decryptSecret({ envelope, fragment })).resolves.toBe(atLimit);
  });

  it("rejects a too-short passphrase at creation time", async () => {
    await expect(encryptSecret({ plaintext: "x", passphrase: "short" })).rejects.toMatchObject({
      code: "PASSPHRASE_TOO_SHORT",
    });
  });

  it("normalises the passphrase so equivalent unicode still decrypts", async () => {
    // NFD "é" vs NFC "é": different bytes, same user-visible passphrase.
        const nfd = "cafe\u0301-passphrase";
    const nfc = "caf\u00e9-passphrase";
    expect(nfd).not.toBe(nfc);

    const { envelope, fragment } = await encryptSecret({ plaintext: "x", passphrase: nfd });
    await expect(decryptSecret({ envelope, fragment, passphrase: nfc })).resolves.toBe("x");
  });
});
