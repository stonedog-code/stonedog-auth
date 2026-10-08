/**
 * The short manual code beside a "connect a phone" QR — the accessible
 * alternative to scanning, `ABCD-EFGH`.
 *
 * ## The shape is the phone's, not ours
 *
 * `@stonedogcode/mobile-auth` defines it (`normaliseManualCode`,
 * `formatManualCode`): 8 characters of Crockford base32 (no I, L, O or U),
 * shown as two groups of four. Typing is forgiving — case, spaces and hyphens
 * are ignored, and I/L read as 1 and O as 0 — so a code read aloud or copied by
 * hand still resolves. {@link normaliseManualCode} below is the same rule on
 * the server, and the unit suite pins the two packages against each other on
 * the cases that matter.
 *
 * ## Derived, not stored
 *
 * The code is NOT a second random secret with its own column. It is the first
 * 40 bits of an HMAC, under a key the host supplies, of the ticket's digest —
 * which the row already holds. So there is nothing new at rest (a dumped
 * ticket table yields digests, and without the key those yield no code; a
 * bare hash of a 40-bit code would be reversible in seconds by anyone who
 * could read the table), and the code is single-use and dies with the ticket
 * for free, because redeeming it performs the SAME transition the QR does.
 *
 * At 40 bits it is short by design, so it is only safe with what the host must
 * also do: a tight attempt budget on the route that redeems it, and
 * confirmation on the signed-in website before anything is issued.
 */

import { createHmac } from "node:crypto";

import { AuthError, MisconfiguredError } from "./errors.js";
import { hashToken, tokenHashEquals } from "./tokens.js";

/** Crockford base32: digits and letters without I, L, O, U. */
export const MANUAL_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export const MANUAL_CODE_LENGTH = 8;
/** 8 symbols × 5 bits. */
export const MANUAL_CODE_BITS = MANUAL_CODE_LENGTH * 5;

const MIN_KEY_BYTES = 16;

/**
 * Derive the manual-code key from a host secret and a purpose label —
 * `HMAC-SHA256(secret, label)` — so this HMAC can never be confused with any
 * other use of that secret. Rotating the secret invalidates only codes already
 * on screen, which live about two minutes.
 *
 * Throws {@link MisconfiguredError} on an empty secret rather than deriving a
 * key from nothing: a code computed under an empty key looks exactly like a
 * real one and protects nothing.
 */
export function manualCodeKeyFrom(secret: string, label: string): Uint8Array {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new MisconfiguredError("The manual-code secret is empty.");
  }
  if (typeof label !== "string" || label.length === 0) {
    throw new MisconfiguredError("The manual-code key label is empty.");
  }
  return new Uint8Array(createHmac("sha256", secret).update(label, "utf8").digest());
}

/**
 * The canonical code (`ABCDEFGH`) for a ticket, from the digest the row holds.
 *
 * Throws {@link MisconfiguredError} on a key shorter than 128 bits; a short key
 * is one the first person to read the table can brute-force.
 */
export function manualCodeForTicketHash(ticketHash: string, key: Uint8Array): string {
  if (!(key instanceof Uint8Array) || key.length < MIN_KEY_BYTES) {
    throw new MisconfiguredError("The manual-code key must be at least 16 bytes.");
  }
  if (typeof ticketHash !== "string" || ticketHash.length === 0) {
    throw new AuthError("A ticket digest is required to derive a manual code.");
  }
  const mac = createHmac("sha256", key).update(ticketHash, "utf8").digest();
  // First 40 bits, five at a time, most significant first.
  let bits = 0n;
  for (let i = 0; i < 5; i++) bits = (bits << 8n) | BigInt(mac[i] ?? 0);
  let out = "";
  for (let i = MANUAL_CODE_LENGTH - 1; i >= 0; i--) {
    out += MANUAL_CODE_ALPHABET[Number((bits >> BigInt(i * 5)) & 31n)];
  }
  return out;
}

/**
 * What a person typed, as a canonical code, or `null` if it cannot be one.
 * The same rule as `@stonedogcode/mobile-auth`'s `normaliseManualCode`.
 */
export function normaliseManualCode(input: unknown): string | null {
  if (typeof input !== "string" || input.length > 32) return null;
  const cleaned = input
    .toUpperCase()
    .replace(/[\s-]+/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
  if (cleaned.length !== MANUAL_CODE_LENGTH) return null;
  for (const ch of cleaned) if (!MANUAL_CODE_ALPHABET.includes(ch)) return null;
  return cleaned;
}

/** Display form, `ABCD-EFGH`. Throws {@link AuthError} on anything that is not a code. */
export function formatManualCode(canonical: string): string {
  const code = normaliseManualCode(canonical);
  if (code === null) throw new AuthError("Not a manual code.");
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

/**
 * Equality of two canonical codes, in constant time: both are hashed and the
 * digests compared with the same primitive the ticket and nonce use, so how
 * much of a guess matched cannot be read off the response time.
 */
export function manualCodesEqual(a: string, b: string): boolean {
  return tokenHashEquals(hashToken(a), hashToken(b));
}
