/**
 * PINs — a short numeric secret, hashed the same way and gated differently.
 *
 * A PIN is not a short password, and treating it as one is the mistake this
 * module exists to prevent. A 6-digit PIN has a million possibilities; a slow
 * KDF buys nothing against that, because an attacker who can guess online does
 * not care what the hash costs, and an attacker with the database can exhaust
 * the space regardless of the work factor.
 *
 * **So the only real defence is a strict attempt limit**, and a PIN factor
 * without one is a four-hour brute force wearing the costume of a credential.
 * `createPinFactor` therefore requires an attempt limiter and refuses to be
 * built without one — the one place in this package where a dependency is
 * mandatory rather than optional.
 */

import { MisconfiguredError, WeakSecretError } from "./errors";
import type { AttemptLimiter } from "./lockout";
import { ARGON2ID_PARAMS, type Argon2Binding, type Argon2Params, type FactorResult } from "./types";

export const DEFAULT_PIN_LENGTH = 6;

/** Digits only. A "PIN" that accepts letters is a password with a bad name. */
const DIGITS_ONLY = /^[0-9]+$/;

export interface PinPolicy {
  minLength: number;
  maxLength: number;
  /**
   * Reject sequences and repeats — `000000`, `123456`, `654321`.
   *
   * On by default. These are a large share of real PIN choices, and they are
   * the first few thousand guesses of any attack, so allowing them makes the
   * attempt limit far less protective than its number suggests.
   */
  rejectTrivial: boolean;
}

export const defaultPinPolicy: PinPolicy = {
  minLength: 4,
  maxLength: 12,
  rejectTrivial: true,
};

function isTrivial(pin: string): boolean {
  if (/^(\d)\1*$/.test(pin)) return true;

  const codes = [...pin].map((c) => c.charCodeAt(0));
  const ascending = codes.every((c, i) => i === 0 || c === (codes[i - 1] ?? 0) + 1);
  const descending = codes.every((c, i) => i === 0 || c === (codes[i - 1] ?? 0) - 1);
  return ascending || descending;
}

/** Throws {@link WeakSecretError}. Never echoes the PIN into the message. */
export function assertPinAcceptable(pin: string, policy: PinPolicy = defaultPinPolicy): void {
  if (!DIGITS_ONLY.test(pin)) {
    throw new WeakSecretError("not-numeric", "PIN must contain digits only.");
  }
  if (pin.length < policy.minLength) {
    throw new WeakSecretError("too-short", `PIN must be at least ${policy.minLength} digits.`);
  }
  if (pin.length > policy.maxLength) {
    throw new WeakSecretError("too-long", `PIN must be at most ${policy.maxLength} digits.`);
  }
  if (policy.rejectTrivial && isTrivial(pin)) {
    throw new WeakSecretError("not-numeric", "Choose a PIN that is not a repeat or a sequence.");
  }
}

export interface PinFactorOptions {
  argon2: Argon2Binding;
  /**
   * Required, not optional. See the note at the top of this file: a PIN
   * without an attempt limit is not a credential.
   */
  limiter: AttemptLimiter;
  policy?: PinPolicy;
  params?: Argon2Params;
}

export interface PinFactor {
  hash(pin: string): Promise<string>;
  /**
   * Consumes an attempt against the limiter whether or not the PIN is right.
   *
   * Throws {@link LockedOutError} when the subject is already locked out —
   * thrown rather than returned as `ok: false`, because a caller must be able
   * to tell "wrong" from "stop asking" in order to send `Retry-After`, and a
   * lockout is not a secret: the attacker causing it already knows.
   */
  verify(
    subjectId: string,
    storedHash: string | null | undefined,
    pin: string,
  ): Promise<FactorResult>;
}

export function createPinFactor(options: PinFactorOptions): PinFactor {
  if (!options.argon2) {
    throw new MisconfiguredError(
      "createPinFactor requires an argon2 binding; import one of the adapter entry points.",
    );
  }
  if (!options.limiter) {
    throw new MisconfiguredError(
      "createPinFactor requires an attempt limiter. A PIN's search space is small enough that " +
        "the attempt limit is its only meaningful defence.",
    );
  }

  const policy = options.policy ?? defaultPinPolicy;
  const params = options.params ?? ARGON2ID_PARAMS;
  const { argon2, limiter } = options;

  return {
    async hash(pin) {
      assertPinAcceptable(pin, policy);
      return argon2.hash(pin, params);
    },

    async verify(subjectId, storedHash, pin) {
      // Throws LockedOutError before any work is done, so a locked-out subject
      // costs an attacker a database read rather than an Argon2 hash.
      await limiter.assertAllowed(subjectId);

      if (!storedHash || !DIGITS_ONLY.test(pin) || pin.length > policy.maxLength) {
        // Still counts as an attempt. Not counting malformed input would give
        // an attacker a free probe for whether an account has a PIN at all.
        await limiter.recordFailure(subjectId);
        return { ok: false };
      }

      let matched = false;
      try {
        matched = await argon2.verify(storedHash, pin);
      } catch {
        matched = false;
      }

      if (!matched) {
        await limiter.recordFailure(subjectId);
        return { ok: false };
      }

      await limiter.recordSuccess(subjectId);
      return { ok: true };
    },
  };
}
