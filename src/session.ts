/**
 * Revoking every session but this one — the primitive four apps were each
 * about to get wrong in the same way.
 *
 * Copyright (C) 2026 StoneDogCode L.L.C. All rights reserved.
 *
 * ## The failure this exists to prevent, measured in production code
 *
 * "Changing your password signs you out everywhere else" is normally built by
 * stamping a revocation instant on the user and refusing any token issued
 * before it. The obvious value to compare against is the JWT's own `iat`, and
 * it is the wrong one.
 *
 * `iat` is REGENERATED every time the token is re-minted, and a session token
 * is re-minted far more often than people expect — NextAuth re-issues it on
 * every `GET /api/auth/session`, which its own React client calls on window
 * focus and on a refetch interval. So a revoked device that merely sits there
 * with a tab open asks for its session, receives a token bearing a fresh `iat`,
 * and is silently un-revoked. Nobody has to attack anything; the framework's
 * default client behaviour is the whole exploit path.
 *
 * Measured end to end in optima-cloud-saas with a control: the device is at
 * `/login` before the call and back at `/entities` after it.
 *
 * ## The fix, in one sentence
 *
 * **Compare the revocation instant against when the session was ESTABLISHED,
 * not against when its current token was issued.** Establishment happens once,
 * at a real authentication; issuance happens continually. A re-mint cannot
 * launder a revocation it is required to carry forward unchanged.
 *
 * ## Why this is a package and not four copies
 *
 * Every application in this fleet has the same shape — a token, a re-mint path
 * it does not fully control, and a column recording when sessions were cut —
 * and the defect is not visible from any one of those pieces. It lives in the
 * seam. A primitive that names `establishedAt` as distinct from `issuedAt`
 * makes the distinction impossible to miss at the call site, which is the only
 * place it has ever been missed.
 *
 * This module is deliberately framework-agnostic: no NextAuth, no cookies, no
 * I/O. It takes numbers and dates and returns a decision, so the same rule can
 * be applied by a JWT callback, a middleware, or a server component.
 */

import type { Clock } from "./types.js";

/**
 * The claim name carrying the establishment instant.
 *
 * Exported so consumers agree on it rather than each inventing a spelling —
 * two apps disagreeing here would be two apps whose tokens are not portable,
 * and the symptom would be a session that is valid in one code path and
 * revoked in another.
 *
 * Deliberately not `iat`, `auth_time` or any registered claim: `iat` is the
 * value this module exists to stop people using, and a registered name invites
 * a framework to helpfully rewrite it.
 */
export const SESSION_ESTABLISHED_CLAIM = "sdcEstablishedAt" as const;

/** A token payload carrying, or about to carry, the establishment instant. */
export interface SessionClaims {
  [SESSION_ESTABLISHED_CLAIM]?: unknown;
}

/**
 * Stamp a newly ESTABLISHED session — a real authentication, and nothing else.
 *
 * Call this where a person proved who they are: a completed sign-in, or a
 * deliberate re-establishment such as the acting user's own session after they
 * changed their password. **Do not call it on a re-mint**, which is the entire
 * point — see `carrySessionEstablishment`.
 */
export function establishSession(clock: Clock = { now: () => new Date() }): number {
  return Math.floor(clock.now().getTime() / 1000);
}

/**
 * Copy the establishment instant forward onto a re-minted token.
 *
 * Returns the value the new token must carry. A re-mint that loses this claim
 * is a re-mint that resets the session's age, which is the bug — so an absent
 * previous value is NOT quietly replaced with "now". It comes back `null`, and
 * `isSessionCurrent` treats `null` as *not provably current*, so the session is
 * refused rather than silently renewed.
 *
 * That is the fail-closed direction, and it is the one that matters: the
 * failure mode of being too strict is somebody signs in again, and the failure
 * mode of being too lax is a revoked session that never dies.
 */
export function carrySessionEstablishment(previous: SessionClaims | null | undefined): number | null {
  const raw = previous?.[SESSION_ESTABLISHED_CLAIM];
  return typeof raw === "number" && Number.isFinite(raw) && raw >= 0 ? Math.floor(raw) : null;
}

/**
 * May a session established at `establishedAt` still be honoured?
 *
 * @param establishedAt seconds since epoch, from `SESSION_ESTABLISHED_CLAIM`.
 *   **Never the token's `iat`** — passing `iat` here reintroduces exactly the
 *   defect this module exists to remove, and the types cannot stop you, so the
 *   name is the warning.
 * @param revokedBefore the user's revocation instant, or `null`/`undefined`
 *   when they have never revoked anything — which is most accounts.
 *
 * ## Second granularity, and why `>=` rather than `>`
 *
 * A claim is whole seconds while a revocation instant carries milliseconds, so
 * the comparison floors the latter. A session established in the same second as
 * the revocation therefore survives. That is intentional and is what lets the
 * person who just changed their password stay signed in when their own session
 * is re-established in the same instant. The cost is a sub-second window that
 * nobody can aim at.
 *
 * ## It FAILS CLOSED on anything it cannot read
 *
 * A missing, non-finite or negative claim cannot be shown to post-date a
 * revocation, so once a revocation exists the session is refused. `null` on
 * `revokedBefore` means "never revoked" and is honest — an account that has
 * never cut a session should not be paying for this check.
 */
export function isSessionCurrent(
  establishedAt: number | null | undefined,
  revokedBefore: Date | null | undefined,
): boolean {
  if (!revokedBefore) return true;
  if (typeof establishedAt !== "number" || !Number.isFinite(establishedAt)) return false;
  return establishedAt >= Math.floor(revokedBefore.getTime() / 1000);
}
