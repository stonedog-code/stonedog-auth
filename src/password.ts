/**
 * Passwords: policy, hashing, verification, and rehash-on-login.
 *
 * Nothing in this file logs, returns, or stringifies a password. A thrown
 * error from here must not carry the input — see {@link assertAcceptable}.
 */

import { MisconfiguredError, WeakSecretError } from "./errors";
import { ARGON2ID_PARAMS, type Argon2Binding, type Argon2Params, type FactorResult } from "./types";

/**
 * Length only, no composition rules.
 *
 * NIST SP 800-63B dropped the character-class requirements because they push
 * people toward `Passw0rd!` and away from length, which is the property that
 * actually resists an offline attack.
 */
export const MIN_PASSWORD_LENGTH = 12;

/**
 * Argon2 reads the input as bytes, so a megabyte-long "password" is a cheap
 * way to make one unauthenticated request burn a lot of CPU. Far above any
 * real passphrase.
 */
export const MAX_PASSWORD_LENGTH = 256;

export interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  /**
   * Asked whether a password is known-breached. Supplied by the host, because
   * the answer needs a corpus this package will not ship and may need a network
   * call this package must not make.
   *
   * Return `true` to reject. Anything that throws is treated as *not* breached:
   * a breach-list outage must not become a sign-up outage.
   */
  isBreached?: (password: string) => Promise<boolean> | boolean;
}

export const defaultPasswordPolicy: PasswordPolicy = {
  minLength: MIN_PASSWORD_LENGTH,
  maxLength: MAX_PASSWORD_LENGTH,
};

/**
 * Throws {@link WeakSecretError}. Never echoes the password into the message.
 *
 * Length is checked before anything expensive, so an oversized input is
 * rejected without being hashed or sent to a breach service.
 */
export function assertAcceptable(
  password: string,
  policy: PasswordPolicy = defaultPasswordPolicy,
): void {
  if (password.length < policy.minLength) {
    throw new WeakSecretError(
      "too-short",
      `Password must be at least ${policy.minLength} characters.`,
    );
  }
  if (password.length > policy.maxLength) {
    throw new WeakSecretError(
      "too-long",
      `Password must be at most ${policy.maxLength} characters.`,
    );
  }
}

export interface PasswordFactorOptions {
  argon2: Argon2Binding;
  policy?: PasswordPolicy;
  /** Override only to match an existing column written with other parameters. */
  params?: Argon2Params;
}

export interface PasswordFactor {
  /** Validates against the policy, then hashes. Throws on a weak password. */
  hash(password: string): Promise<string>;
  /**
   * Never throws for a bad input, a missing hash, or a corrupt one.
   *
   * `storedHash` is nullable because a subject may legitimately have no
   * password — passkey-only, or magic-link-only. Returning `ok: false` there is
   * the entire point: this shape has, in more than one codebase, treated "no
   * hash" as "nothing to check" and let the sign-in through.
   */
  verify(storedHash: string | null | undefined, password: string): Promise<FactorResult>;
  /** True when `storedHash` was written with weaker parameters than current. */
  needsRehash(storedHash: string): boolean;
}

/**
 * Parse the parameters out of a PHC string (`$argon2id$v=19$m=19456,t=2,p=1$…`).
 *
 * **The parameters are read BY NAME, in any order**, and that is not defensive
 * programming — the two Argon2 bindings this package supports genuinely
 * disagree:
 *
 *   argon2          $argon2id$v=19$m=19456,p=1,t=2$…
 *   @node-rs/argon2 $argon2id$v=19$m=19456,t=2,p=1$…
 *
 * A positional regex matches one and returns null for the other, which reads as
 * "not an Argon2 hash" and makes `needsRehash` true for every password written
 * by the other binding. The visible effect is an application that silently
 * rewrites its entire password column on first sign-in after adopting this
 * package — a lot of writes, and a lot of alarm, for no reason.
 *
 * Found by the integration tier, which runs both bindings for real. No unit
 * test with a fake could have seen it.
 *
 * Returns null for anything that is not an Argon2id digest, which the caller
 * treats as "needs rehashing" — a bcrypt or scrypt hash from a previous life
 * genuinely does.
 */
function parsePhc(
  digest: string,
): { memoryCost: number; timeCost: number; parallelism: number } | null {
  const match = /^\$argon2id\$v=\d+\$([^$]+)\$/.exec(digest);
  const params = match?.[1];
  if (params === undefined) return null;

  const found = new Map<string, number>();
  for (const pair of params.split(",")) {
    const [key, value] = pair.split("=");
    if (key === undefined || value === undefined || !/^\d+$/.test(value)) return null;
    found.set(key, Number(value));
  }

  const memoryCost = found.get("m");
  const timeCost = found.get("t");
  const parallelism = found.get("p");
  if (memoryCost === undefined || timeCost === undefined || parallelism === undefined) return null;

  return { memoryCost, timeCost, parallelism };
}

export function createPasswordFactor(options: PasswordFactorOptions): PasswordFactor {
  if (!options.argon2) {
    // At construction, not at first sign-in. A missing binding should stop the
    // process starting rather than surface as an authentication outage.
    throw new MisconfiguredError(
      "createPasswordFactor requires an argon2 binding; import one of the adapter entry points.",
    );
  }

  const policy = options.policy ?? defaultPasswordPolicy;
  const params = options.params ?? ARGON2ID_PARAMS;
  const { argon2 } = options;

  return {
    async hash(password) {
      assertAcceptable(password, policy);
      if (policy.isBreached) {
        let breached = false;
        try {
          breached = await policy.isBreached(password);
        } catch {
          // A breach-list outage must not become a sign-up outage. Failing
          // open here is the deliberate choice: the alternative refuses every
          // registration whenever a third party is down, and the password is
          // still subject to every other control.
          breached = false;
        }
        if (breached) {
          throw new WeakSecretError(
            "too-short",
            "That password has appeared in a data breach. Choose another.",
          );
        }
      }
      return argon2.hash(password, params);
    },

    async verify(storedHash, password) {
      if (!storedHash) return { ok: false };
      // Bounds first: an empty or oversized candidate cannot match anything,
      // and checking here means an attacker cannot make us hash a megabyte.
      if (password.length === 0 || password.length > policy.maxLength) return { ok: false };

      let matched = false;
      try {
        matched = await argon2.verify(storedHash, password);
      } catch {
        // A truncated column, or a digest written by some other algorithm,
        // denies access rather than throwing. A 500 here would distinguish a
        // corrupt row from a wrong password, which tells an attacker the
        // account exists.
        return { ok: false };
      }

      if (!matched) return { ok: false };
      const stale = this.needsRehash(storedHash);
      return stale ? { ok: true, needsRehash: true } : { ok: true };
    },

    needsRehash(storedHash) {
      const found = parsePhc(storedHash);
      if (!found) return true;
      return (
        found.memoryCost < params.memoryCost ||
        found.timeCost < params.timeCost ||
        found.parallelism !== params.parallelism
      );
    },
  };
}
