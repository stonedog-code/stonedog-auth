/**
 * Errors this package throws.
 *
 * Every one of them is safe to let reach a user, because none of them carries
 * a secret, an identifier, or a reason that distinguishes one failure from
 * another. That is a deliberate constraint rather than an accident of style:
 * an auth library is written while debugging, which is exactly when internal
 * detail is closest to hand and most likely to end up in a message that ships.
 */

/** Base class, so a host can catch everything from this package at once. */
export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthError";
  }
}

export type WeakSecretReason = "too-short" | "too-long" | "not-numeric";

/**
 * A password or PIN the policy refuses.
 *
 * Never carries the input. A validation error that echoes the rejected secret
 * puts it in a log, a stack trace, and an error-reporting service, which is a
 * longer and less controlled life than the secret was ever meant to have.
 */
export class WeakSecretError extends AuthError {
  constructor(
    readonly reason: WeakSecretReason,
    message: string,
  ) {
    super(message);
    this.name = "WeakSecretError";
  }
}

/**
 * A resend asked for sooner than the cooldown allows.
 *
 * Carries `retryAfterSeconds` because a caller needs it for a `Retry-After`
 * header, and it discloses nothing — the cooldown is a published constant.
 */
export class ResendTooSoonError extends AuthError {
  constructor(readonly retryAfterSeconds: number) {
    super("A message was sent recently. Try again shortly.");
    this.name = "ResendTooSoonError";
  }
}

/** An attempt refused because the subject is locked out. */
export class LockedOutError extends AuthError {
  constructor(readonly retryAfterSeconds: number) {
    super("Too many attempts. Try again later.");
    this.name = "LockedOutError";
  }
}

/**
 * A factor was used before its dependency was supplied.
 *
 * Thrown at configuration time, not during a request — a missing Argon2 binding
 * should stop the process starting rather than fail the first sign-in.
 */
export class MisconfiguredError extends AuthError {
  constructor(message: string) {
    super(message);
    this.name = "MisconfiguredError";
  }
}
