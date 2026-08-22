import { z } from "zod";

import { MAX_TTL_SECONDS, MIN_TTL_SECONDS, SECRET_ID_LENGTH } from "@/lib/constants";
import { secretEnvelopeSchema } from "@/lib/crypto/envelope";

/**
 * Wire contract shared by the browser client and the route handlers, so the two cannot
 * drift apart. Nothing here is server-only, and nothing here can carry plaintext.
 */

export const createSecretRequestSchema = z.strictObject({
  envelope: secretEnvelopeSchema,
  ttlSeconds: z.number().int().min(MIN_TTL_SECONDS).max(MAX_TTL_SECONDS),
});

export type CreateSecretRequest = z.infer<typeof createSecretRequestSchema>;

export const createSecretResponseSchema = z.strictObject({
  id: z.string().length(SECRET_ID_LENGTH),
  expiresAt: z.string(),
});

export type CreateSecretResponse = z.infer<typeof createSecretResponseSchema>;

export const revealSecretResponseSchema = z.strictObject({
  envelope: secretEnvelopeSchema,
});

export type RevealSecretResponse = z.infer<typeof revealSecretResponseSchema>;

export const apiErrorSchema = z.object({
  error: z.string(),
  message: z.string(),
});
