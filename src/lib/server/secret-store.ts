import "server-only";

import { createHmac, randomBytes } from "node:crypto";

import {
  MAX_STORED_ENVELOPE_BYTES,
  MAX_TTL_SECONDS,
  MIN_TTL_SECONDS,
  REDIS_SECRET_PREFIX,
  SECRET_ID_BYTES,
} from "@/lib/constants";
import { toBase64Url, utf8ByteLength } from "@/lib/crypto/encoding";
import { isSecretId } from "@/lib/secret-id";
import {
  deserialiseEnvelope,
  secretEnvelopeSchema,
  serialiseEnvelope,
  type SecretEnvelope,
} from "@/lib/crypto/envelope";
import { getServerConfig } from "@/lib/server/config";
import { logger } from "@/lib/server/logger";
import { getSecretsRedis, type SecretsRedis } from "@/lib/server/redis";

export class SecretStoreError extends Error {
  constructor(
    message: string,
    readonly code: "id_collision" | "invalid_envelope" | "invalid_ttl" | "too_large",
  ) {
    super(message);
    this.name = "SecretStoreError";
  }
}

function generateSecretId(): string {
  return toBase64Url(new Uint8Array(randomBytes(SECRET_ID_BYTES)));
}

/**
 * Map a public secret id onto its Redis key via a keyed hash.
 *
 * A stolen Redis snapshot therefore cannot be turned back into shareable URLs, and the
 * id in a URL cannot be used to probe the keyspace of another deployment. The ciphertext
 * is useless without the fragment either way; this is defence in depth.
 */
function redisKeyFor(id: string): string {
  const digest = createHmac("sha256", getServerConfig().secretIdKey).update(id).digest();
  return REDIS_SECRET_PREFIX + toBase64Url(new Uint8Array(digest));
}

export interface CreateSecretInput {
  envelope: SecretEnvelope;
  ttlSeconds: number;
  redis?: SecretsRedis;
}

export interface CreateSecretResult {
  id: string;
  /** ISO 8601. Advisory only: Redis owns the authoritative expiry. */
  expiresAt: string;
}

export async function createSecret({
  envelope,
  ttlSeconds,
  redis = getSecretsRedis(),
}: CreateSecretInput): Promise<CreateSecretResult> {
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < MIN_TTL_SECONDS || ttlSeconds > MAX_TTL_SECONDS) {
    throw new SecretStoreError("ttl out of range", "invalid_ttl");
  }

  // Re-validate at the storage boundary. Routes validate too, but the store must not
  // depend on its callers to be correct.
  const validated = secretEnvelopeSchema.safeParse(envelope);
  if (!validated.success) {
    throw new SecretStoreError("envelope rejected", "invalid_envelope");
  }

  const payload = serialiseEnvelope(validated.data);
  if (utf8ByteLength(payload) > MAX_STORED_ENVELOPE_BYTES) {
    throw new SecretStoreError("envelope too large", "too_large");
  }

  // 128-bit ids: a collision is not realistically reachable, but never overwrite a
  // live secret if one occurs.
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const id = generateSecretId();
    const stored = await redis.setIfAbsent(redisKeyFor(id), payload, ttlSeconds);
    if (stored) {
      return {
        id,
        expiresAt: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
      };
    }
  }

  throw new SecretStoreError("could not allocate a secret id", "id_collision");
}

export interface ConsumeSecretInput {
  id: string;
  redis?: SecretsRedis;
}

/**
 * Atomically read and destroy a secret.
 *
 * `GETDEL` is a single Redis command, so two concurrent readers cannot both receive the
 * envelope: exactly one gets the value, everyone else gets `null`. Returns `null` for
 * malformed ids, expired secrets, already-read secrets and unparsable payloads alike, so
 * callers cannot distinguish those cases.
 */
export async function consumeSecret({
  id,
  redis = getSecretsRedis(),
}: ConsumeSecretInput): Promise<SecretEnvelope | null> {
  if (!isSecretId(id)) return null;

  const raw = await redis.getAndDelete(redisKeyFor(id));
  if (raw === null) return null;

  const envelope = deserialiseEnvelope(raw);
  if (!envelope) {
    // Already destroyed by the GETDEL above; nothing to roll back.
    logger.warn("store.unparsable_envelope");
    return null;
  }
  return envelope;
}
