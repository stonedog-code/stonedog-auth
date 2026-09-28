/**
 * The emailed 6-digit code as a sign-in factor — `email_code`, the
 * accessibility alternative to clicking a magic link.
 *
 * A thin layer over `createTokenIssuer` (kind `"email-code"`) and
 * `generateNumericCode`, so single-use, invalidate-on-reissue, the resend
 * cooldown and the one-reason failure all come from the code that already
 * enforces them for links. What this adds is the two things a SHORT code needs
 * and a 256-bit link does not:
 *
 *  1. **An attempt limit.** A million possibilities is a guessable space. Pass
 *     a limiter (keyed by subject, as the PIN is) and every wrong or malformed
 *     code counts against it.
 *  2. **A subject-bound hash.** The token store looks up by hash. For a random
 *     link that is unique; for a 6-digit code it is not — with enough users,
 *     two will hold the same six digits at once, and a hash of the digits alone
 *     would let one user's attempt find and SPEND the other's code. So the
 *     stored hash is of `subjectId:code`. The person still types six digits;
 *     only the database row is scoped.
 *
 * Same assurance as a magic link — control of the inbox. Not MFA.
 */

import { generateNumericCode, type TokenIssuer } from "./tokens.js";
import type { AttemptLimiter } from "./lockout.js";
import { LockedOutError } from "./errors.js";
import { systemClock, type AuditSink, type Clock, type FactorResult } from "./types.js";

const KIND = "email-code";
const DIGITS = 6;
const CODE = /^[0-9]{6}$/;

function bind(subjectId: string, code: string): string {
  return `${subjectId}:${code}`;
}

export function createEmailCodeFactor(opts: {
  issuer: TokenIssuer;
  limiter?: AttemptLimiter;
  audit?: AuditSink;
  /** Stamps audit events only; expiry is the issuer's clock. Not in the contract; additive. */
  clock?: Clock;
}): {
  issue(subjectId: string): Promise<{ code: string; expiresAt: Date }>;
  verify(subjectId: string, code: string): Promise<FactorResult>;
} {
  const { issuer, limiter, audit } = opts;
  const clock = opts.clock ?? systemClock;

  return {
    /**
     * Mint a code for `subjectId` and invalidate any outstanding one. Email
     * `code`; never store or log it. Throws `ResendTooSoonError` inside the
     * issuer's cooldown.
     */
    async issue(subjectId) {
      const code = generateNumericCode(DIGITS);
      const { expiresAt } = await issuer.issue(subjectId, KIND, { mint: () => bind(subjectId, code) });
      await audit?.record({ type: "token.issued", factor: "emailed-token", subjectId, at: clock.now() });
      return { code, expiresAt };
    },

    /**
     * Throws {@link LockedOutError} when the limiter refuses, before the code
     * is even looked at — the same shape as the PIN factor, so a route can send
     * `Retry-After`. Otherwise one `{ ok: false }` for wrong, expired, used and
     * malformed alike.
     */
    async verify(subjectId, code) {
      try {
        await limiter?.assertAllowed(subjectId);
      } catch (error) {
        if (error instanceof LockedOutError) {
          await audit?.record({ type: "factor.locked-out", factor: "emailed-token", subjectId, at: clock.now() });
        }
        throw error;
      }

      // Malformed input is still an attempt: not counting it would be a free
      // probe, and trimming it would accept inputs the code never was.
      const result =
        typeof code === "string" && CODE.test(code)
          ? await issuer.consume(bind(subjectId, code), KIND)
          : ({ ok: false } as const);

      // The issuer's own subject check is implicit in the bound hash; this is
      // the belt to that brace, and costs a string compare.
      const ok = result.ok && result.subjectId === subjectId;

      if (!ok) {
        await limiter?.recordFailure(subjectId);
        await audit?.record({ type: "factor.rejected", factor: "emailed-token", subjectId, at: clock.now() });
        return { ok: false };
      }
      await limiter?.recordSuccess(subjectId);
      await audit?.record({ type: "factor.verified", factor: "emailed-token", subjectId, at: clock.now() });
      return { ok: true };
    },
  };
}
