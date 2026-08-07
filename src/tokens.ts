/**
 * Emailed single-use tokens — magic links, email verification, password reset,
 * and short numeric codes.
 *
 * All of them are one mechanism with a different `kind`, so they share one
 * implementation. Two copies of "spend this exactly once" is two places for a
 * replay bug to live, and the password-reset copy is the one that matters.
 *
 * The rules, all of which the tests assert:
 *
 *  1. The raw token is returned to the caller **once**, at issue, and is never
 *     persisted — only its SHA-256 is. A dumped database yields no working
 *     links.
 *  2. Consumption is a **conditional update**, not read-then-write. Two
 *     concurrent clicks must race in the database and exactly one must win.
 *  3. Issuing a token of a kind **invalidates the outstanding ones** of that
 *     kind, or every reset email ever sent to an address stays live until it
 *     expires.
 *  4. Every failure reports the same reason.
 */

import { createHash, randomBytes, randomInt, timingSafeEqual } from "node:crypto";

import { ResendTooSoonError } from "./errors";
import { systemClock, type Clock } from "./types";

/**
 * Host-defined. A string rather than a union so an application can add its own
 * kind — "device-approval", "invite" — without this package releasing.
 */
export type TokenKind = string;

/** 256 bits of CSPRNG, URL-safe. Guessing is not a strategy against this. */
export function generateToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * A short numeric code, for when a link cannot be clicked — an emailed second
 * factor, or a device with no browser.
 *
 * `randomInt` rather than `randomBytes % 10`, which is biased toward low
 * digits. The bias is small and it is exactly the kind of small that survives
 * review forever.
 *
 * **A 6-digit code has a million possibilities**, so it is only a credential
 * when paired with an attempt limit and a short expiry. Treat it like a PIN.
 */
export function generateNumericCode(digits = 6): string {
  let code = "";
  for (let i = 0; i < digits; i += 1) code += String(randomInt(0, 10));
  return code;
}

/**
 * SHA-256, hex. Fast-hashed on purpose.
 *
 * A slow KDF defends a low-entropy secret. A 32-byte random token has no guess
 * space to slow an attacker down in, and lookup is an exact match on an indexed
 * column — which a slow hash would make impossible without a table scan.
 *
 * A **numeric code is different** and the host must not rely on this alone:
 * pair it with the attempt limiter.
 */
export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Compare two digests without leaking where they diverge.
 *
 * Lookup is by unique index, so this is belt-and-braces rather than the primary
 * defence — but `===` on a secret-derived value is exactly the habit that
 * eventually gets applied somewhere it does matter.
 */
export function tokenHashEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/** One issued token, as the host stores it. */
export interface StoredToken {
  subjectId: string;
  kind: TokenKind;
  tokenHash: string;
  expiresAt: Date;
  createdAt: Date;
  consumedAt?: Date | null;
}

/**
 * The storage this needs.
 *
 * Written as three narrow operations rather than as a Prisma model, so a host
 * on any store can implement it. `claim` is the interesting one and its
 * contract is strict — see below.
 */
export interface TokenStore {
  /** Mark every unconsumed token of this kind for this subject as consumed. */
  invalidateOutstanding(subjectId: string, kind: TokenKind, at: Date): Promise<void>;

  insert(token: StoredToken): Promise<void>;

  /** The most recent token of this kind, consumed or not, for the cooldown. */
  findMostRecent(subjectId: string, kind: TokenKind): Promise<StoredToken | null>;

  /**
   * **Atomically** mark the matching token consumed and return it.
   *
   * Must be a single conditional write — the equivalent of an `UPDATE … WHERE
   * token_hash = $1 AND kind = $2 AND consumed_at IS NULL AND expires_at > $3`
   * — and must return null when it matched nothing.
   *
   * A read-then-write implementation satisfies the types and breaks rule 2:
   * two simultaneous clicks on a reset link would both succeed. If your store
   * cannot express a conditional update, use a transaction with the row locked;
   * do not check first and then write.
   */
  claim(tokenHash: string, kind: TokenKind, now: Date): Promise<StoredToken | null>;
}

export interface TokenPolicy {
  /** How long a token of each kind stays valid, in minutes. */
  ttlMinutes: Record<TokenKind, number>;
  /** Minimum gap between two sends of the same kind to the same subject. */
  resendCooldownSeconds: number;
}

/**
 * Verification is generous and reset is short, deliberately.
 *
 * People sign up, get distracted, and come back after lunch; forcing a resend
 * there is friction with no attacker benefit, because possession of the link
 * only proves what sign-up already claimed. A reset link is a live credential
 * and a magic link *is* the sign-in, so both are short.
 */
export const defaultTokenPolicy: TokenPolicy = {
  ttlMinutes: {
    "email-verification": 24 * 60,
    "password-reset": 60,
    "magic-link": 15,
    "email-code": 10,
  },
  resendCooldownSeconds: 60,
};

export interface IssuedToken {
  /** Send this. Never store it, never log it. */
  token: string;
  expiresAt: Date;
}

export interface IssueOptions {
  /** Generate the secret. Override for numeric codes, or in a test. */
  mint?: () => string;
  /** Skip the cooldown — for a token issued as part of sign-up itself. */
  enforceCooldown?: boolean;
}

export interface TokenIssuer {
  issue(subjectId: string, kind: TokenKind, options?: IssueOptions): Promise<IssuedToken>;
  consume(token: string, kind: TokenKind): Promise<ConsumeResult>;
}

export type ConsumeResult =
  | { ok: true; subjectId: string }
  /** One reason for every failure, so nothing distinguishes them to a caller. */
  | { ok: false; reason: "invalid-or-expired" };

export interface TokenIssuerOptions {
  store: TokenStore;
  policy?: TokenPolicy;
  clock?: Clock;
  /** Applied to a token's TTL when its kind is not in the policy. */
  fallbackTtlMinutes?: number;
}

export function createTokenIssuer(options: TokenIssuerOptions): TokenIssuer {
  const policy = options.policy ?? defaultTokenPolicy;
  const clock = options.clock ?? systemClock;
  const fallbackTtl = options.fallbackTtlMinutes ?? 15;
  const { store } = options;

  return {
    async issue(subjectId, kind, issueOptions = {}) {
      const now = clock.now();
      const mint = issueOptions.mint ?? generateToken;

      if (issueOptions.enforceCooldown !== false) {
        const recent = await store.findMostRecent(subjectId, kind);
        if (recent) {
          const elapsed = (now.getTime() - recent.createdAt.getTime()) / 1000;
          if (elapsed < policy.resendCooldownSeconds) {
            throw new ResendTooSoonError(Math.ceil(policy.resendCooldownSeconds - elapsed));
          }
        }
      }

      // Burn the outstanding ones FIRST. If the insert below fails the subject
      // has no live token and must ask again — annoying, and strictly safer
      // than the other ordering, which leaves two live tokens when the
      // invalidation is what failed.
      await store.invalidateOutstanding(subjectId, kind, now);

      const token = mint();
      const ttl = policy.ttlMinutes[kind] ?? fallbackTtl;
      const expiresAt = new Date(now.getTime() + ttl * 60_000);

      await store.insert({
        subjectId,
        kind,
        tokenHash: hashToken(token),
        expiresAt,
        // Stamped from the SAME clock as `expiresAt`, rather than left to a
        // column default. Otherwise createdAt comes from the database and
        // expiresAt from the application, and the cooldown compares two clocks
        // that differ by however much they drift — which shows up as a resend
        // that refuses for a minute and one second, or lets a second through
        // immediately, depending on which way it went.
        createdAt: now,
      });

      return { token, expiresAt };
    },

    async consume(token, kind) {
      const now = clock.now();
      const claimed = await store.claim(hashToken(token), kind, now);
      if (!claimed) return { ok: false, reason: "invalid-or-expired" };
      return { ok: true, subjectId: claimed.subjectId };
    },
  };
}
