/**
 * Recovery codes — the way back in when a second factor is lost.
 *
 * Ten single-use codes, shown once at enrolment, stored only as hashes. The
 * rules, all of which the tests assert:
 *
 *  1. **CSPRNG, unbiased.** Each character is `randomInt(0, 32)`, not a byte
 *     modulo 32 — the same reasoning as `generateNumericCode`.
 *  2. **Only the hash is stored.** A dumped table yields no working codes.
 *  3. **Issuing replaces every previous code.** A regenerate that appended
 *     would leave the old sheet — the one the user is regenerating *because*
 *     they think it leaked — valid forever.
 *  4. **Single use.** `consume` is the store's atomic conditional mark, so two
 *     simultaneous submissions of one code cannot both succeed.
 *  5. **Forgiving on input, strict on meaning.** Case, hyphens and spaces are
 *     ignored, and the visually ambiguous letters are folded onto the digits
 *     they are mistaken for, because these are typed by hand off a piece of
 *     paper by someone who is already locked out. Nothing else is tolerated.
 *
 * ## A recovery code is never the only secret
 *
 * See `mayAuthenticateWith` and `createSignInTickets`: the host lets a code
 * replace ONE step (the TOTP after a password, or the passkey + PIN after an
 * emailed code), never the whole sign-in. This module verifies the code; the
 * ticket enforces what else must have happened first.
 */

import { randomInt } from "node:crypto";

import { MisconfiguredError } from "./errors.js";
import { hashToken } from "./tokens.js";
import { systemClock, type AuditSink, type Clock } from "./types.js";

/**
 * Crockford's base32 alphabet, lowercase: digits and letters with `i`, `l`,
 * `o` and `u` removed. The first three are the ones people misread as `1`, `1`
 * and `0`; `u` is dropped so no code can spell the obvious obscenities.
 */
const ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";

/** 10 characters × 5 bits = 50 bits per code. Grouped 4-4-2 for reading aloud. */
const CODE_CHARS = 10;

const NORMALISED = /^[0-9abcdefghjkmnpqrstvwxyz]{10}$/;

/**
 * The storage this needs.
 *
 * `consume` has the same contract as `TokenStore.claim`: **one atomic
 * conditional write** — `UPDATE … SET used_at = now() WHERE user_id = $1 AND
 * code_hash = $2 AND used_at IS NULL` — returning whether it matched. A
 * read-then-write implementation satisfies the types and lets one code sign in
 * twice.
 *
 * It must also match on `subjectId`. The hash alone is not scoped to a person,
 * so a store that looked up by hash only would accept one user's code for
 * another's account.
 */
export interface RecoveryCodeStore {
  /** Delete (or mark used) every existing code for the subject, then insert these. */
  replaceAll(subjectId: string, hashes: string[]): Promise<void>;
  /** Atomically mark one unused code used. True only if exactly that happened. */
  consume(subjectId: string, hash: string): Promise<boolean>;
  /** How many unused codes the subject has left. */
  remaining(subjectId: string): Promise<number>;
}

function generateRecoveryCode(): string {
  let raw = "";
  for (let i = 0; i < CODE_CHARS; i += 1) raw += ALPHABET[randomInt(0, ALPHABET.length)];
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8)}`;
}

/**
 * Case-, hyphen- and space-insensitive, with Crockford's ambiguity folding.
 * Returns null for anything that is not then exactly ten alphabet characters.
 */
function normalise(code: unknown): string | null {
  if (typeof code !== "string" || code.length > 64) return null;
  const folded = code
    .toLowerCase()
    .replace(/[\s-]/g, "")
    .replace(/[il]/g, "1")
    .replace(/o/g, "0");
  return NORMALISED.test(folded) ? folded : null;
}

/**
 * The stored form. The package's existing token hash (SHA-256, hex), applied
 * to the NORMALISED code, so every spelling a person might type hashes the same.
 *
 * A fast hash is adequate here for the same reason it is for tokens: the code
 * carries 50 bits of CSPRNG output, which is not a guess space a slow KDF
 * meaningfully defends, and the host's attempt limiter is what bounds online
 * guessing.
 */
function hashRecoveryCode(normalised: string): string {
  return hashToken(normalised);
}

export function createRecoveryCodes(opts: {
  store: RecoveryCodeStore;
  count?: number;
  audit?: AuditSink;
  clock?: Clock;
}): {
  issue(subjectId: string): Promise<string[]>;
  consume(subjectId: string, code: string): Promise<boolean>;
  remaining(subjectId: string): Promise<number>;
} {
  const count = opts.count ?? 10;
  if (!Number.isInteger(count) || count < 1 || count > 100) {
    throw new MisconfiguredError("createRecoveryCodes count must be an integer from 1 to 100.");
  }
  const clock = opts.clock ?? systemClock;
  const { store, audit } = opts;

  return {
    /**
     * Mint a fresh set and REPLACE every previous code. Returns plaintext
     * formatted `xxxx-xxxx-xx`: show it once, never store it, never log it.
     */
    async issue(subjectId) {
      const codes = new Set<string>();
      // A duplicate inside one batch at 50 bits is astronomically unlikely, and
      // would silently leave the user one code short. The loop costs nothing.
      while (codes.size < count) codes.add(generateRecoveryCode());
      const plaintext = [...codes];

      await store.replaceAll(
        subjectId,
        plaintext.map((code) => hashRecoveryCode(normalise(code) as string)),
      );
      await audit?.record({
        type: "recovery.issued",
        factor: "recovery-code",
        subjectId,
        at: clock.now(),
        detail: { count },
      });
      return plaintext;
    },

    /**
     * Spend one code. False for a wrong, malformed, already-used or other
     * subject's code — one answer for all of them, per `FactorResult`'s rule.
     *
     * The comparison is the store's indexed equality on a SHA-256 digest of a
     * CSPRNG value, the same as `TokenStore.claim`: a timing difference there
     * reveals something about a digest, which reveals nothing usable about any
     * code. No plaintext comparison ever happens, in constant time or otherwise.
     */
    async consume(subjectId, code) {
      const normalised = normalise(code);
      const ok = normalised !== null && (await store.consume(subjectId, hashRecoveryCode(normalised)));
      await audit?.record({
        type: ok ? "recovery.used" : "factor.rejected",
        factor: "recovery-code",
        subjectId,
        at: clock.now(),
      });
      return ok;
    },

    async remaining(subjectId) {
      return store.remaining(subjectId);
    },
  };
}
