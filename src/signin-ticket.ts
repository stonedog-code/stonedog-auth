/**
 * Sign-in tickets — carrying a half-finished sign-in from one step to the next
 * without issuing a session.
 *
 * A two-step sign-in has a gap: the password was right, the TOTP has not been
 * asked for yet, and the server must remember "this browser proved step one
 * for this account" without handing out anything that works as a session. The
 * tempting shortcuts are all bugs:
 *
 *  - a cookie saying `passwordOk=1` is forgeable, and replayable forever;
 *  - a session with an `mfaPending` flag is a session, and every route that
 *    forgets to check the flag is a single-factor sign-in;
 *  - a ticket that is reused across steps lets a client submit step two twice,
 *    or step one again after step two, and the server cannot tell.
 *
 * So a ticket here is:
 *
 *  1. **Random and hashed at rest.** 256 bits from `generateToken`; only its
 *     SHA-256 reaches the store. A dumped ticket table completes nothing.
 *  2. **Single-use per step.** `advance` TAKES the stored ticket (get + delete,
 *     atomically — see the store contract) and issues a new one. A ticket that
 *     has been advanced once is dead, whether the step it was advanced with was
 *     right or wrong.
 *  3. **Bound to the method's step ORDER.** The only step a ticket accepts is
 *     the next one in `requiredSteps(method)` — or the next one on that
 *     method's single recovery path, below. A skipped, repeated or out-of-order
 *     step returns null and the ticket is spent.
 *  4. **Short-lived.** Five minutes per step by default.
 *
 * ## The recovery paths (Amendment A — "recovery is never one secret")
 *
 * Besides `requiredSteps`, exactly two alternative orders are accepted, and a
 * recovery code is the LAST step of both:
 *
 * | method          | primary path          | recovery path                   |
 * |-----------------|-----------------------|---------------------------------|
 * | `password_totp` | `password`, `totp`    | `password`, `recovery-code`     |
 * | `passkey_pin`   | `webauthn`, `pin`     | `email-code`, `recovery-code`   |
 *
 * So a ticket fresh from `start` can never be advanced with `"recovery-code"`:
 * the code only ever replaces the missing factor after the other one has been
 * proved. Assurance-1 methods have no recovery path at all — their recovery is
 * the inbox.
 *
 * `advance` does not tell the host WHICH path completed; the host knows, because
 * it chose the `step` string. When it passed `"recovery-code"` it must treat
 * the result as a recovery sign-in (notify the user, revoke other sessions,
 * send them to re-enrol) — see the README.
 *
 * ## What `start`'s `completedStep` means
 *
 * The step the host has just verified. Two shapes are accepted:
 *
 *  - **A factor step** (`"password"`, `"webauthn"`, `"email-code"` …) — it must
 *    be the first step of one of the method's paths, and is recorded as done.
 *  - **Anything else** (`"email"`, `"identified"`) — an identification marker:
 *    "we know which account this is, no factor has been proved yet". Nothing is
 *    recorded, and the ticket's next step is the first factor.
 *
 * That second rule fails in the safe direction on purpose: a typo in a factor
 * name records NO progress, so the sign-in demands more, never less.
 */

import { AuthError } from "./errors.js";
import { requiredSteps, type AuthMethod } from "./methods.js";
import { generateToken, hashToken } from "./tokens.js";
import { systemClock, type Clock } from "./types.js";

/** One ticket, as the host stores it. `hash` is the primary key. */
export interface StoredTicket {
  hash: string;
  subjectId: string;
  method: AuthMethod;
  /** Factor steps completed so far, in order. */
  completed: string[];
  expiresAt: Date;
}

/**
 * The storage this needs.
 *
 * `take` must be **get + delete, atomically** — `DELETE … WHERE hash = $1
 * RETURNING *`. A read-then-delete implementation lets two concurrent requests
 * advance the same ticket and both receive a successor, which forks one
 * half-finished sign-in into two.
 */
export interface SignInTicketStore {
  put(t: StoredTicket): Promise<void>;
  take(hash: string): Promise<StoredTicket | null>;
}

const FACTOR_STEPS: ReadonlySet<string> = new Set([
  "email-link",
  "email-code",
  "password",
  "totp",
  "webauthn",
  "pin",
  "recovery-code",
]);

/** The accepted orders for a method: its required steps, plus its recovery path if it has one. */
function pathsFor(method: AuthMethod): readonly (readonly string[])[] {
  const primary = requiredSteps(method);
  switch (method) {
    case "password_totp":
      return [primary, ["password", "recovery-code"]];
    case "passkey_pin":
      return [primary, ["email-code", "recovery-code"]];
    default:
      return [primary];
  }
}

function isPrefixOf(prefix: readonly string[], path: readonly string[]): boolean {
  if (prefix.length > path.length) return false;
  return prefix.every((step, i) => path[i] === step);
}

export function createSignInTickets(opts: {
  store: SignInTicketStore;
  ttlMinutes?: number;
  clock?: Clock;
}): {
  start(subjectId: string, method: AuthMethod, completedStep: string): Promise<{ ticket: string }>;
  advance(
    ticket: string,
    step: string,
  ): Promise<{ ticket: string; subjectId: string; method: AuthMethod; done: boolean } | null>;
  peek(ticket: string): Promise<{ subjectId: string; method: AuthMethod; completed: readonly string[] } | null>;
} {
  const ttlMs = (opts.ttlMinutes ?? 5) * 60_000;
  const clock = opts.clock ?? systemClock;
  const { store } = opts;

  async function mint(subjectId: string, method: AuthMethod, completed: string[]): Promise<string> {
    const ticket = generateToken();
    await store.put({
      hash: hashToken(ticket),
      subjectId,
      method,
      completed,
      // Fresh per step. Total lifetime is bounded by the path length (two
      // steps) times the TTL, and a user reading a code off a phone should not
      // be racing the time they spent typing a password.
      expiresAt: new Date(clock.now().getTime() + ttlMs),
    });
    return ticket;
  }

  /** Take (and thereby spend) a live ticket, or null. An expired one is still deleted. */
  async function takeLive(ticket: string): Promise<StoredTicket | null> {
    if (typeof ticket !== "string" || ticket.length === 0 || ticket.length > 256) return null;
    const stored = await store.take(hashToken(ticket));
    if (!stored) return null;
    // Checked here rather than in the store so an expired ticket is also
    // DELETED by the take, not left for a cleanup job to notice.
    if (stored.expiresAt.getTime() <= clock.now().getTime()) return null;
    return stored;
  }

  return {
    /**
     * Open a ticket for `subjectId` after its first check. See the file header
     * for what `completedStep` may be. Throws {@link AuthError} when a factor
     * step is named that does not begin any of the method's paths — that is a
     * host bug, and silently accepting it would record progress that is not.
     */
    async start(subjectId, method, completedStep) {
      const paths = pathsFor(method);
      if (paths.every((p) => p.length === 0)) {
        throw new AuthError("Unknown sign-in method.");
      }
      let completed: string[] = [];
      if (FACTOR_STEPS.has(completedStep)) {
        if (!paths.some((p) => p[0] === completedStep)) {
          throw new AuthError("That step does not begin this sign-in method.");
        }
        completed = [completedStep];
      }
      return { ticket: await mint(subjectId, method, completed) };
    },

    /**
     * Record that `step` has just been verified, spending `ticket`.
     *
     * Returns a NEW ticket (the old one is dead) and `done: true` when the
     * steps now form a complete path. Returns null — with the old ticket still
     * spent — when the ticket is unknown, expired, already used, or when `step`
     * is not the next step on any of the method's paths.
     *
     * **Call it only AFTER the factor has verified.** `advance` records that a
     * step happened; it cannot check the secret. To learn which subject to
     * verify against first, use `peek`.
     */
    async advance(ticket, step) {
      const stored = await takeLive(ticket);
      if (!stored) return null;

      const completed = [...stored.completed, step];
      const paths = pathsFor(stored.method);
      if (!paths.some((p) => isPrefixOf(completed, p))) return null;
      const done = paths.some((p) => p.length === completed.length && isPrefixOf(completed, p));

      return {
        ticket: await mint(stored.subjectId, stored.method, completed),
        subjectId: stored.subjectId,
        method: stored.method,
        done,
      };
    },

    /**
     * Read a ticket WITHOUT advancing it: which subject and method, and what
     * is already done — so a host can verify the next factor against the right
     * account before calling `advance`.
     *
     * Implemented on the two-operation store port as take-then-put-back with
     * the ORIGINAL expiry. A concurrent `advance` racing a peek sees no ticket
     * and returns null, which fails closed; the peek does not extend a ticket's
     * life.
     *
     * Not in the original contract; added because `advance` consumes, and a
     * host that had to call it before knowing whose password to check would
     * have either burned the ticket on every typo or — worse — handed the
     * successor ticket back after a failed check.
     */
    async peek(ticket) {
      const stored = await takeLive(ticket);
      if (!stored) return null;
      await store.put(stored);
      return { subjectId: stored.subjectId, method: stored.method, completed: [...stored.completed] };
    },
  };
}
