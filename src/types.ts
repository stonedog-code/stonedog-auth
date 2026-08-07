/**
 * The contracts every factor in this package is written against.
 *
 * Two rules govern what may appear here:
 *
 *  1. **No storage.** This package owns no schema and issues no migration. Any
 *     state a factor needs is reached through a port the host implements, so
 *     adopting one factor never means a migration in four repositories at once.
 *  2. **No transport.** Nothing here knows about HTTP, cookies, or a framework.
 *     A factor that needed a `Request` could not be tested without one, and
 *     could not be used from a background job at all.
 */

/** The factors this package can verify. Hosts opt into the ones they want. */
export type FactorKind = "password" | "pin" | "totp" | "webauthn" | "emailed-token";

/**
 * Who is being authenticated, as far as this package is concerned.
 *
 * Deliberately thin. It carries an opaque id and nothing else — no email, no
 * name, no roles. A subject that carried an email would make every factor a
 * place an email address could be logged, and roles belong to authorisation,
 * which is a different package and a different question.
 */
export interface Subject {
  /** Opaque to this package. The host's own user identifier. */
  id: string;
}

/**
 * The result of verifying one factor.
 *
 * `ok: false` carries no reason on purpose. "No such account", "wrong
 * password" and "account not yet verified" must be indistinguishable to a
 * caller, because a caller that can distinguish them will eventually surface
 * the difference and turn the sign-in form into an account enumerator.
 *
 * A host that needs to *log* the distinction has the audit event for it, which
 * goes to the host's own sink and not to the person signing in.
 */
export type FactorResult =
  | {
      ok: true;
      /**
       * Set when the stored credential should be re-written with current
       * parameters. Only the caller can do it: this package never has the
       * plaintext and the store at the same time by accident.
       */
      needsRehash?: boolean;
    }
  | { ok: false };

/**
 * A clock, injectable.
 *
 * Every expiry, cooldown and lockout in this package takes one. Tests then
 * assert the arithmetic without sleeping, and — more importantly — a caller
 * inside a transaction can stamp every row it writes from a single instant.
 * Two clocks in one flow is how a cooldown ends up off by the drift between
 * the application and the database.
 */
export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

/**
 * An Argon2 implementation, supplied by the host.
 *
 * **This package deliberately bundles no Argon2 binding.** Which one works is
 * decided by the runtime image, not by preference: a node-gyp binding needs a
 * build toolchain that an Alpine image does not carry, and a prebuilt binding
 * needs a platform tarball that must exist for the target. Two applications
 * here already differ for exactly that reason.
 *
 * They interoperate regardless, because both emit and accept the standard PHC
 * string (`$argon2id$v=19$m=…`). A hash written by one verifies under the
 * other, so adopting this package never invalidates an existing password
 * column — which is the difference between a migration and a mass password
 * reset.
 *
 * Adapters for both bindings ship as separate entry points.
 */
export interface Argon2Binding {
  hash(plain: string, params: Argon2Params): Promise<string>;
  /** Must return false — never throw — for a malformed or foreign digest. */
  verify(digest: string, plain: string): Promise<boolean>;
}

/**
 * The work factor, pinned rather than left to the binding's defaults.
 *
 * A default is not a control. An auditor asks to see the work factor, and a
 * dependency upgrade can change a default with nothing failing anywhere.
 *
 * Deliberately not readable from an environment variable. A work factor that
 * config can lower is a work factor an attacker who reaches config can lower,
 * and the only caller who ever wanted that knob was a test suite — which
 * injects a fake binding instead.
 */
export interface Argon2Params {
  /** 2 = Argon2id. The only value this package uses. */
  algorithm: 2;
  memoryCost: number;
  timeCost: number;
  parallelism: number;
}

/**
 * OWASP's second Argon2id profile (19 MiB, t=2, p=1).
 *
 * Matches what the applications adopting this package already run, so their
 * existing hashes need no rewrite.
 */
export const ARGON2ID_PARAMS: Argon2Params = {
  algorithm: 2,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

/**
 * One thing worth telling the host's audit log about.
 *
 * A shared shape so four products describe a failed sign-in the same way —
 * which is what makes "show me every lockout this week" a question that can be
 * asked once rather than four times.
 *
 * **It carries no secret and no email.** `subjectId` is the host's opaque id;
 * everything else is an enum or a count. If a field here could ever hold a
 * credential, the shape is wrong.
 */
export interface AuthEvent {
  type:
    | "factor.verified"
    | "factor.rejected"
    | "factor.locked-out"
    | "token.issued"
    | "token.consumed"
    | "token.rejected";
  factor: FactorKind;
  /** Absent when the attempt named an account that does not exist. */
  subjectId?: string;
  at: Date;
  /**
   * Free-form, host-defined, and **never** a credential. Typed as unknown
   * rather than string so a host cannot casually interpolate a secret into it
   * and have it type-check.
   */
  detail?: Record<string, number | boolean | string>;
}

/** Where audit events go. A host that wants none supplies nothing. */
export interface AuditSink {
  record(event: AuthEvent): void | Promise<void>;
}
