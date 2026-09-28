/**
 * PKCE (RFC 7636), S256 only.
 *
 * Used where a one-time code crosses from a browser back into an app — the
 * mobile "other sign-in options" flow opens a browser auth session, and the
 * code that comes back through `app://auth?code=…` travels through a custom
 * URL scheme any other app on the device can register. PKCE makes that code
 * useless to whoever intercepts it: redeeming it needs the verifier, which
 * never left the app that started the flow.
 *
 * **`plain` is deliberately not offered.** With `plain` the challenge IS the
 * verifier, so anyone who saw the authorisation request can redeem the code —
 * the one attacker PKCE exists to stop. RFC 7636 §4.2 keeps it only for
 * clients that cannot hash, and every client here can.
 */

import { createHash, timingSafeEqual } from "node:crypto";

import { AuthError } from "./errors.js";

/**
 * RFC 7636 §4.1: 43–128 characters of the unreserved set.
 *
 * Enforced rather than hashed-whatever-arrives: a short verifier is a guessable
 * one, and a server that accepts `"a"` has quietly turned PKCE into a
 * one-character password.
 */
const VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;

/** A SHA-256 digest in unpadded base64url is always exactly 43 characters. */
const S256_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

function isValidVerifier(verifier: unknown): verifier is string {
  return typeof verifier === "string" && VERIFIER.test(verifier);
}

/**
 * `BASE64URL(SHA256(ASCII(verifier)))`, per RFC 7636 §4.2.
 *
 * Throws {@link AuthError} on a verifier outside the RFC. The message does not
 * repeat the input — a verifier is a secret until the exchange completes.
 */
export function pkceChallengeS256(verifier: string): string {
  if (!isValidVerifier(verifier)) {
    throw new AuthError("PKCE verifier must be 43-128 characters of [A-Za-z0-9-._~].");
  }
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

/**
 * Does `verifier` hash to `challenge`?
 *
 * Returns false — never throws — for a malformed verifier or challenge, so a
 * route can answer every failure with the same generic 400.
 *
 * Constant-time over the digest. The challenge is not secret, but the
 * comparison is between a stored value and one an attacker chooses, and `===`
 * on that shape is the habit that eventually gets applied where it matters.
 */
export function verifyPkceS256(verifier: string, challenge: string): boolean {
  if (!isValidVerifier(verifier)) return false;
  if (typeof challenge !== "string" || !S256_CHALLENGE.test(challenge)) return false;

  const expected = Buffer.from(pkceChallengeS256(verifier), "ascii");
  const presented = Buffer.from(challenge, "ascii");
  // Both are 43 bytes once the regex has passed; checked anyway, because
  // timingSafeEqual throws on a length mismatch and a throw here would be an
  // uncaught 500 instead of a clean refusal.
  if (expected.length !== presented.length) return false;
  return timingSafeEqual(expected, presented);
}
