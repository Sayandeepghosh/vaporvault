import { SECRET_ID_BYTES, SECRET_ID_LENGTH } from "@/lib/constants";
import { fromBase64Url } from "@/lib/crypto/encoding";

/**
 * Syntactic validation for a secret id, shared by the browser and the server.
 *
 * Kept out of the server-only store module so the reveal page can reject junk ids without
 * pulling the Redis client into the render path.
 */
export function isSecretId(value: string): boolean {
  if (typeof value !== "string" || value.length !== SECRET_ID_LENGTH) return false;
  try {
    return fromBase64Url(value).byteLength === SECRET_ID_BYTES;
  } catch {
    return false;
  }
}
