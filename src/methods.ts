/**
 * Sign-in METHODS — which combination of factors an account signs in with,
 * and the rule that stops an account being signed into with less than it chose.
 *
 * A factor (password, TOTP, passkey…) answers "is this secret right?". A method
 * answers a different question: "which secrets does THIS account require, in
 * what order, and may a sign-in by some other route stand in for them?" That
 * second question is where the downgrade bug lives. Every product that offers
 * "use a passkey instead of a magic link" and still leaves the magic-link
 * endpoint open for that account has built an MFA screen with a single-factor
 * door beside it. Nothing in the factors can see that; it lives in the seam
 * between them, so it gets one function here that every door calls.
 *
 * Pure data and arithmetic. No storage, no clock, no transport.
 */

/** The four ways an account may sign in. `magic_link` is every host's default. */
export type AuthMethod = "magic_link" | "email_code" | "password_totp" | "passkey_pin";

/**
 * One factor step inside a sign-in, as a string a host can store in a ticket.
 *
 * Not exported as a named type — the contract spells the union out inline on
 * `requiredSteps`, and a second name for the same set is a second place for
 * the two to drift.
 */
type SignInStep = "email-link" | "email-code" | "password" | "totp" | "webauthn" | "pin";

/** Every method, in ascending assurance. Frozen so a consumer cannot push to it. */
export const AUTH_METHODS: readonly AuthMethod[] = Object.freeze([
  "magic_link",
  "email_code",
  "password_totp",
  "passkey_pin",
] as const);

/**
 * How much a successful sign-in by this method proves.
 *
 *  - **1** — control of the inbox, and nothing else. `email_code` is the SAME
 *    assurance as `magic_link`: it is an accessibility alternative for people
 *    who cannot click a link on the device they are signing in on, not a
 *    second factor. Calling it MFA would be the kind of claim an auditor is
 *    right to strike.
 *  - **2** — two independent factors, neither of which is the inbox.
 *
 * A number rather than a label so comparisons are arithmetic and cannot be
 * got wrong by a string compare.
 */
export function methodAssurance(m: AuthMethod): 1 | 2 {
  switch (m) {
    case "magic_link":
    case "email_code":
      return 1;
    case "password_totp":
    case "passkey_pin":
      return 2;
    default:
      // Unreachable under the types. At runtime (a string from a database
      // column) an unknown method is treated as the HIGHEST assurance, so that
      // `mayAuthenticateWith` refuses every assurance-1 route into it rather
      // than quietly letting a magic link through. Failing toward "sign-in
      // refused" is recoverable; failing toward "sign-in allowed" is not.
      return 2;
  }
}

/** True when moving from `from` to `to` lowers what a sign-in proves. */
export function isDowngrade(from: AuthMethod, to: AuthMethod): boolean {
  return methodAssurance(to) < methodAssurance(from);
}

const STEPS: Record<AuthMethod, readonly SignInStep[]> = Object.freeze({
  magic_link: Object.freeze(["email-link"] as const),
  email_code: Object.freeze(["email-code"] as const),
  password_totp: Object.freeze(["password", "totp"] as const),
  passkey_pin: Object.freeze(["webauthn", "pin"] as const),
});

/**
 * Which factors a sign-in with `m` must complete, in order.
 *
 * Order is part of the contract, not a presentation detail. `createSignInTickets`
 * refuses a step presented out of this order, so a client cannot submit the
 * TOTP before the password and have the server treat "password" as optional.
 *
 * An unknown method (a bad database value) yields an empty list — which no
 * ticket can ever complete, so the sign-in fails closed.
 */
export function requiredSteps(
  m: AuthMethod,
): readonly ("email-link" | "email-code" | "password" | "totp" | "webauthn" | "pin")[] {
  return STEPS[m] ?? [];
}

/**
 * Whether a sign-in by `used` may establish a session for a user whose method
 * is `enrolled`. **Every door that can create a session must ask this** — the
 * magic-link route, the email-code route, any legacy provider, the mobile
 * exchange. One door that forgets is the whole account's assurance.
 *
 * The rule:
 *
 *  - A route of **equal or higher** assurance is allowed. `magic_link` and
 *    `email_code` users may use either (both are assurance 1); an assurance-2
 *    user may use either assurance-2 method.
 *  - A route of **lower** assurance is refused. A `password_totp` or
 *    `passkey_pin` account cannot be entered with a magic link or an emailed
 *    code — that is the downgrade this module exists to stop.
 *  - `"recovery"` is allowed **only** for an assurance-2 account. An
 *    assurance-1 account has nothing a recovery code could stand in for; its
 *    recovery IS the inbox.
 *
 * ## What `"recovery"` does NOT mean here, and what the host must enforce
 *
 * This function answers "may a recovery sign-in exist for this account", not
 * "is this recovery sign-in complete". **A recovery code is never the only
 * secret.** The host must have the recovery code replace exactly ONE step and
 * complete the other:
 *
 *  - `password_totp` — the password step must already be done; the recovery
 *    code replaces only the TOTP.
 *  - `passkey_pin` — an emailed code must be verified first; the recovery code
 *    then replaces the passkey + PIN pair.
 *
 * `createSignInTickets` enforces exactly those two paths (a ticket fresh from
 * `start` never accepts a recovery code), so a host that routes recovery
 * through a ticket gets this for free. A host that calls this function and then
 * establishes a session on a recovery code alone has rebuilt single-factor
 * sign-in with a longer password.
 *
 * Unknown `enrolled` values are treated as assurance 2 (see `methodAssurance`),
 * so a corrupt column refuses the low-assurance routes rather than opening them.
 */
export function mayAuthenticateWith(enrolled: AuthMethod, used: AuthMethod | "recovery"): boolean {
  if (used === "recovery") return methodAssurance(enrolled) === 2;
  if (!AUTH_METHODS.includes(used)) return false;
  return methodAssurance(used) >= methodAssurance(enrolled);
}

/**
 * A credential an account holds: the factor it satisfies, and the host's id
 * for it. `device-key` is the on-device fingerprint key
 * (`@stonedogcode/mobile-auth`); it satisfies NO step of any method, because
 * it is a convenience layered on top of the method the user chose, never a
 * way in by itself.
 */
export type CredentialFactor = "password" | "totp" | "webauthn" | "pin" | "device-key";

export interface CredentialRecord {
  id: string;
  kind: CredentialFactor;
}

export type RemovalVerdict =
  | { ok: true }
  | { ok: false; reason: "last-way-in" | "not-found" | "unknown-method" };

const STEP_NEEDS: Partial<Record<string, CredentialFactor>> = Object.freeze({
  password: "password",
  totp: "totp",
  webauthn: "webauthn",
  pin: "pin",
});

/**
 * May the credential `removingId` be removed from an account whose method is
 * `method` and whose credentials are `credentials`?
 *
 * Refuses when, after removal, some step of `requiredSteps(method)` would have
 * no credential left to satisfy it — the last passkey of a `passkey_pin`
 * account, the TOTP of a `password_totp` account. The `email-link` and
 * `email-code` steps need no credential (their way in is the inbox), so an
 * assurance-1 account may remove anything. Removing a `device-key` is always
 * allowed: it satisfies no step, so it can never be the last way in.
 *
 * **Call it before every removal, and treat a refusal as final.** The server
 * refuses removing the last way in; it does not offer to change the method
 * instead — that is a separate, step-up-gated decision. An unknown method (a
 * bad column value) refuses, in keeping with `methodAssurance`: failing
 * toward "cannot remove" is recoverable, failing toward "removed" is not.
 */
export function canRemoveCredential(
  method: AuthMethod,
  credentials: readonly CredentialRecord[],
  removingId: string,
): RemovalVerdict {
  if (!AUTH_METHODS.includes(method)) return { ok: false, reason: "unknown-method" };
  if (!credentials.some((c) => c.id === removingId)) return { ok: false, reason: "not-found" };
  const remaining = credentials.filter((c) => c.id !== removingId);
  for (const step of requiredSteps(method)) {
    const needs = STEP_NEEDS[step];
    if (needs === undefined) continue;
    if (!remaining.some((c) => c.kind === needs)) return { ok: false, reason: "last-way-in" };
  }
  return { ok: true };
}
