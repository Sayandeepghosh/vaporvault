/**
 * Map API error codes onto user-facing copy *on the client*.
 *
 * The server's message text is deliberately ignored. Rendering a server-supplied string
 * would make the UI a reflection point for whatever the backend (or anything
 * impersonating it) returns; keeping the copy local removes that path entirely and keeps
 * the wording consistent.
 */

const MESSAGES: Record<string, string> = {
  invalid_request: "That request was rejected. Please try again.",
  unsupported_media_type: "That request was rejected. Please try again.",
  payload_too_large: "That secret is too large. The limit is 10 KB.",
  forbidden: "That request was blocked. Reload the page and try again.",
  not_found: "Secret not found or already destroyed.",
  method_not_allowed: "That request was rejected. Please try again.",
  rate_limited: "Too many requests. Wait a moment and try again.",
  service_unavailable: "VaporVault is temporarily unavailable. Try again shortly.",
  internal_error: "Something went wrong. Please try again.",
};

const FALLBACK = "Something went wrong. Please try again.";

/** Read a response's error code and translate it. Never throws. */
export async function describeApiFailure(response: Response): Promise<string> {
  if (response.status === 429) return MESSAGES.rate_limited;
  if (response.status === 404) return MESSAGES.not_found;
  if (response.status === 413) return MESSAGES.payload_too_large;

  try {
    const body: unknown = await response.json();
    if (
      typeof body === "object" &&
      body !== null &&
      "error" in body &&
      typeof (body as { error: unknown }).error === "string"
    ) {
      return MESSAGES[(body as { error: string }).error] ?? FALLBACK;
    }
  } catch {
    /* fall through */
  }
  return FALLBACK;
}

export const NETWORK_FAILURE_MESSAGE =
  "Could not reach VaporVault. Check your connection and try again.";
