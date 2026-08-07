/**
 * Attempt limiting and lockout.
 *
 * The policy lives here; the counter lives in the host's store. That split is
 * the whole design: an in-memory counter is per-process, and every one of these
 * applications runs behind a load balancer, so a limit that counts in memory is
 * a limit multiplied by the number of containers — and it resets on deploy,
 * which is a thing an attacker can trigger by waiting.
 */

import { LockedOutError } from "./errors";
import { systemClock, type Clock } from "./types";

export interface LockoutPolicy {
  /** Failures before the subject is locked out. */
  maxFailures: number;
  /** How long a lockout lasts. */
  lockoutSeconds: number;
  /**
   * How long a failure counts toward the total.
   *
   * Without a window the counter is cumulative for the life of the account, so
   * a person who mistypes twice a year is eventually locked out permanently by
   * their own history.
   */
  windowSeconds: number;
}

/** Five in fifteen minutes, locked for fifteen. */
export const defaultLockoutPolicy: LockoutPolicy = {
  maxFailures: 5,
  lockoutSeconds: 15 * 60,
  windowSeconds: 15 * 60,
};

/**
 * Stricter, for a numeric PIN.
 *
 * A 6-digit PIN is a million guesses; at five per fifteen minutes an attacker
 * needs centuries, which is the point. Do not raise this to be helpful.
 */
export const pinLockoutPolicy: LockoutPolicy = {
  maxFailures: 5,
  lockoutSeconds: 30 * 60,
  windowSeconds: 60 * 60,
};

/** One subject's attempt record, as the host stores it. */
export interface AttemptRecord {
  failures: number;
  /** When the first failure in the current window happened. */
  windowStartedAt: Date;
  /** Set while locked out; cleared on success. */
  lockedUntil?: Date | null;
}

/**
 * The state this needs, reached through the host's own storage.
 *
 * `load` returning null means "no failures on record", which is the common
 * case and must not be an error.
 */
export interface AttemptStore {
  load(subjectId: string): Promise<AttemptRecord | null>;
  save(subjectId: string, record: AttemptRecord): Promise<void>;
  clear(subjectId: string): Promise<void>;
}

export interface AttemptLimiter {
  /** Throws {@link LockedOutError} if the subject may not attempt right now. */
  assertAllowed(subjectId: string): Promise<void>;
  recordFailure(subjectId: string): Promise<void>;
  recordSuccess(subjectId: string): Promise<void>;
}

export interface AttemptLimiterOptions {
  store: AttemptStore;
  policy?: LockoutPolicy;
  clock?: Clock;
}

export function createAttemptLimiter(options: AttemptLimiterOptions): AttemptLimiter {
  const policy = options.policy ?? defaultLockoutPolicy;
  const clock = options.clock ?? systemClock;
  const { store } = options;

  return {
    async assertAllowed(subjectId) {
      const record = await store.load(subjectId);
      if (!record?.lockedUntil) return;

      const now = clock.now();
      const remainingMs = record.lockedUntil.getTime() - now.getTime();
      if (remainingMs <= 0) return;

      throw new LockedOutError(Math.ceil(remainingMs / 1000));
    },

    async recordFailure(subjectId) {
      const now = clock.now();
      const existing = await store.load(subjectId);

      // A failure outside the window starts a fresh count rather than adding to
      // a stale one.
      const windowExpired =
        existing !== null &&
        now.getTime() - existing.windowStartedAt.getTime() > policy.windowSeconds * 1000;

      const failures = existing === null || windowExpired ? 1 : existing.failures + 1;
      const windowStartedAt = existing === null || windowExpired ? now : existing.windowStartedAt;

      const record: AttemptRecord = { failures, windowStartedAt };
      if (failures >= policy.maxFailures) {
        record.lockedUntil = new Date(now.getTime() + policy.lockoutSeconds * 1000);
      }

      await store.save(subjectId, record);
    },

    async recordSuccess(subjectId) {
      // Cleared entirely rather than decremented. A successful sign-in is
      // evidence the person is who they say they are, and leaving a partial
      // count behind means a legitimate user who mistyped four times then
      // succeeded is one typo away from a lockout for the rest of the window.
      await store.clear(subjectId);
    },
  };
}

/**
 * An in-memory {@link AttemptStore}.
 *
 * **For tests and single-process development only.** It is exported because
 * the alternative is every consumer writing the same twenty lines badly, and
 * named so that it cannot be adopted in production by accident. Behind more
 * than one container it counts per-process, which multiplies every limit by
 * the replica count and resets them on deploy.
 */
export function createInMemoryAttemptStore(): AttemptStore {
  const records = new Map<string, AttemptRecord>();
  return {
    load: async (subjectId) => records.get(subjectId) ?? null,
    save: async (subjectId, record) => {
      records.set(subjectId, record);
    },
    clear: async (subjectId) => {
      records.delete(subjectId);
    },
  };
}
