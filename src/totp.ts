/**
 * TOTP (RFC 6238) over HOTP (RFC 4226), on `node:crypto` alone.
 *
 * Implemented rather than depended on because it is ~60 lines of HMAC and
 * base32, and every TOTP dependency in this space carries a much larger
 * surface than the algorithm needs. The parts that are actually easy to get
 * wrong are not the arithmetic:
 *
 *  - **Replay.** RFC 6238 §5.2 is explicit that a code must be accepted once.
 *    A verifier without single-use enforcement lets anyone who reads the code
 *    over someone's shoulder use it too, for the rest of the step. This module
 *    takes a store and enforces it; `verifyTotpCode` is the raw check and is
 *    exported separately so it is obvious which one you are using.
 *  - **Drift.** A window of ±1 step is the usual advice. Each extra step
 *    multiplies the guess space an attacker gets per attempt, so this does not
 *    default higher.
 *  - **Comparison.** Constant-time, always.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32, no padding — what authenticator apps expect. */
export function toBase32(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

export function fromBase32(encoded: string): Buffer {
  // Case-insensitive, and padding and spaces are tolerated: people retype these
  // by hand off a screen, and refusing "JBSW Y3DP" helps nobody.
  const cleaned = encoded.toUpperCase().replace(/[\s=]/g, "");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error("Invalid base32 character in TOTP secret.");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/**
 * A new secret, base32-encoded.
 *
 * 20 bytes (160 bits) — RFC 4226 §4 R6's recommended length, and what every
 * authenticator app assumes.
 */
export function generateTotpSecret(): string {
  return toBase32(randomBytes(20));
}

export interface TotpParams {
  /** Seconds per step. 30 is universal; changing it breaks most apps. */
  stepSeconds: number;
  digits: number;
  algorithm: "sha1" | "sha256" | "sha512";
}

/**
 * SHA-1 is the default and that is correct here, uncomfortable as it looks.
 *
 * HMAC-SHA-1 is not affected by the collision attacks that retired SHA-1 for
 * signatures, and it is what authenticator apps overwhelmingly implement —
 * Google Authenticator ignores the algorithm parameter in the provisioning URI
 * entirely. Choosing SHA-256 here produces codes a user's app cannot generate,
 * which presents as "TOTP is broken" rather than as a configuration mismatch.
 */
export const defaultTotpParams: TotpParams = {
  stepSeconds: 30,
  digits: 6,
  algorithm: "sha1",
};

function hotp(secret: Buffer, counter: number, params: TotpParams): string {
  const buffer = Buffer.alloc(8);
  // The counter is 64-bit. Written as two 32-bit halves because a bitwise shift
  // in JavaScript truncates to 32 bits, which would silently break in 2038 and
  // pass every test written before then.
  buffer.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buffer.writeUInt32BE(counter >>> 0, 4);

  const digest = createHmac(params.algorithm, secret).update(buffer).digest();
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const binary =
    (((digest[offset] ?? 0) & 0x7f) << 24) |
    (((digest[offset + 1] ?? 0) & 0xff) << 16) |
    (((digest[offset + 2] ?? 0) & 0xff) << 8) |
    ((digest[offset + 3] ?? 0) & 0xff);

  return String(binary % 10 ** params.digits).padStart(params.digits, "0");
}

/** The code for a given instant. Exported for tests and for showing a preview. */
export function totpCodeAt(
  secret: string,
  at: Date,
  params: TotpParams = defaultTotpParams,
): string {
  const counter = Math.floor(at.getTime() / 1000 / params.stepSeconds);
  return hotp(fromBase32(secret), counter, params);
}

function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * The raw check: is this code valid for this secret, within the drift window?
 *
 * **No replay protection.** Use {@link createTotpFactor} unless you are
 * implementing that yourself — this is exported so that choice is visible in
 * the call site rather than hidden in a default.
 *
 * Returns the matched step so a caller enforcing single-use knows what to
 * record.
 */
export function verifyTotpCode(
  secret: string,
  code: string,
  options: { at?: Date; window?: number; params?: TotpParams } = {},
): { ok: true; step: number } | { ok: false } {
  const params = options.params ?? defaultTotpParams;
  const at = options.at ?? new Date();
  const window = options.window ?? 1;

  if (!/^[0-9]+$/.test(code) || code.length !== params.digits) return { ok: false };

  const current = Math.floor(at.getTime() / 1000 / params.stepSeconds);
  const key = fromBase32(secret);

  // Every candidate step is checked, with no early return, so the time taken
  // does not reveal which step matched — or how near a wrong guess was.
  let matchedStep: number | null = null;
  for (let offset = -window; offset <= window; offset += 1) {
    const step = current + offset;
    if (constantTimeEquals(hotp(key, step, params), code) && matchedStep === null) {
      matchedStep = step;
    }
  }

  return matchedStep === null ? { ok: false } : { ok: true, step: matchedStep };
}

/**
 * Records which step a subject last spent, so a code cannot be replayed.
 *
 * The host stores it because this package stores nothing — and because the
 * value must be shared across every process that can verify, or a replay
 * simply goes to another container.
 */
export interface TotpReplayStore {
  /** The last step this subject successfully used, or null. */
  lastUsedStep(subjectId: string): Promise<number | null>;
  recordUsedStep(subjectId: string, step: number): Promise<void>;
}

export interface TotpFactorOptions {
  store: TotpReplayStore;
  params?: TotpParams;
  /** Steps of drift accepted either side. Defaults to 1. Raising it is a cost. */
  window?: number;
  clock?: { now(): Date };
}

export interface TotpFactor {
  verify(
    subjectId: string,
    secret: string,
    code: string,
  ): Promise<{ ok: true } | { ok: false }>;
}

export function createTotpFactor(options: TotpFactorOptions): TotpFactor {
  const params = options.params ?? defaultTotpParams;
  const window = options.window ?? 1;
  const clock = options.clock ?? { now: () => new Date() };
  const { store } = options;

  return {
    async verify(subjectId, secret, code) {
      const result = verifyTotpCode(secret, code, { at: clock.now(), window, params });
      if (!result.ok) return { ok: false };

      // `<=`, not `===`. Rejecting only an exact repeat still accepts an EARLIER
      // step within the drift window, so a code captured one step ago replays
      // successfully after a newer one has been used.
      const lastUsed = await store.lastUsedStep(subjectId);
      if (lastUsed !== null && result.step <= lastUsed) return { ok: false };

      await store.recordUsedStep(subjectId, result.step);
      return { ok: true };
    },
  };
}

export interface ProvisioningUriOptions {
  /** Shown in the authenticator app as the account. Usually an email. */
  account: string;
  /** Shown as the site. Keep it stable — changing it looks like a new account. */
  issuer: string;
  params?: TotpParams;
}

/**
 * The `otpauth://` URI an authenticator app scans.
 *
 * `issuer` appears twice — in the label prefix and as a parameter — because
 * apps disagree about which they read, and supplying only one produces entries
 * labelled with a bare email address and no clue which site they belong to.
 */
export function totpProvisioningUri(secret: string, options: ProvisioningUriOptions): string {
  const params = options.params ?? defaultTotpParams;
  const label = `${encodeURIComponent(options.issuer)}:${encodeURIComponent(options.account)}`;
  const query = new URLSearchParams({
    secret,
    issuer: options.issuer,
    algorithm: params.algorithm.toUpperCase(),
    digits: String(params.digits),
    period: String(params.stepSeconds),
  });
  return `otpauth://totp/${label}?${query.toString()}`;
}
