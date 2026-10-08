/**
 * The server half of the on-device key.
 *
 * The phone (`@stonedogcode/mobile-auth/device-key`) holds a P-256 key that
 * never leaves it, unlocked by the fingerprint, and answers a challenge with
 * ECDSA over SHA-256, DER-encoded, standard base64. This module is everything
 * the server does with that: parse the public key it was handed at enrolment
 * (P-256 and nothing else), issue and spend single-use challenges, and verify
 * a signature over the challenge IT stored.
 *
 * ## Consume first, verify second
 *
 * `claim` spends the challenge before anything looks at the signature, and the
 * signature is verified over the STORED challenge the claim returned — never
 * over one the client sent back. The defect this closes (hopper-web NEH-1899)
 * was a route that verified a client-supplied challenge: a captured signature
 * then replayed forever, because the thing it signed was whatever the client
 * said it was. A challenge is 256 random bits, so nobody can spend one they do
 * not hold; the only cost of consume-first is that a phone whose signature
 * fails asks for another.
 *
 * Like `webauthn.ts`, this module verifies nothing more exotic than one
 * signature primitive, with `node:crypto`. The whole package assumes Node
 * (`engines`), and a consumer that needs this on an edge runtime needs a
 * different package, not a polyfill.
 */

import { createPublicKey, createVerify, generateKeyPairSync, randomBytes } from "node:crypto";

import { MisconfiguredError } from "./errors.js";
import { systemClock, type Clock } from "./types.js";

export type DeviceKeyChallengeKind = "signin" | "enrol";

/** One issued challenge, as the host stores it. `challenge` is the primary key. */
export interface StoredDeviceKeyChallenge {
  challenge: string;
  subjectId: string;
  kind: DeviceKeyChallengeKind;
  expiresAt: Date;
}

/**
 * The storage this needs. `claim` must be **delete + return, atomically** —
 * `DELETE … WHERE challenge = $1 AND kind = $2 RETURNING *` — and must return
 * null when it matched nothing. The same requirement, for the same reason, as
 * `ChallengeStore.claim` and `TokenStore.claim`.
 */
export interface DeviceKeyChallengeStore {
  insert(challenge: StoredDeviceKeyChallenge): Promise<void>;
  claim(challenge: string, kind: DeviceKeyChallengeKind): Promise<StoredDeviceKeyChallenge | null>;
}

export interface DeviceKeyChallengeOptions {
  store: DeviceKeyChallengeStore;
  /** Two minutes: a fingerprint prompt and a retry, not a coffee. */
  ttlSeconds?: number;
  clock?: Clock;
  /**
   * A short label the challenge begins with (`<prefix>.<random>`), so a
   * challenge of this host's can never be mistaken for another host's or for a
   * WebAuthn challenge. Letters, digits, `.`, `-`, `_`; up to 32 characters.
   */
  prefix?: string;
}

export interface DeviceKeyChallenges {
  /** Issue a challenge for `subjectId`. Send it; never log it. */
  issue(subjectId: string, kind: DeviceKeyChallengeKind): Promise<string>;
  /**
   * Spend a challenge. Returns whose it was, or null for one that is unknown,
   * expired, already spent, of the other kind, or not shaped like a challenge
   * at all. An expired challenge is still deleted by the claim.
   */
  claim(challenge: string, kind: DeviceKeyChallengeKind): Promise<{ subjectId: string } | null>;
  /**
   * A challenge of the real shape that was never stored. For the path where
   * the key id named nothing: the client receives something indistinguishable
   * from a real challenge, and whatever it signs can never be claimed.
   */
  unstored(): string;
}

const PREFIX = /^[A-Za-z0-9._-]{1,32}$/;
/** Opaque printable ASCII, 16–1024 — the shape `signDeviceChallenge` accepts. */
const CHALLENGE = /^[\x21-\x7e]{16,1024}$/;
const PEM_MAX = 1024;
/** A DER-encoded P-256 signature is 70–72 bytes; base64 of that is 96 chars. Bounded loosely. */
const SIGNATURE = /^[A-Za-z0-9+/]{60,120}={0,2}$/;

export function createDeviceKeyChallenges(options: DeviceKeyChallengeOptions): DeviceKeyChallenges {
  const ttlSeconds = options.ttlSeconds ?? 120;
  const clock = options.clock ?? systemClock;
  const prefix = options.prefix ?? "device-key";
  if (!PREFIX.test(prefix)) {
    throw new MisconfiguredError("The device-key challenge prefix must be 1–32 characters of [A-Za-z0-9._-].");
  }
  const { store } = options;

  const mint = () => `${prefix}.${randomBytes(32).toString("base64url")}`;

  return {
    async issue(subjectId, kind) {
      const challenge = mint();
      await store.insert({
        challenge,
        subjectId,
        kind,
        expiresAt: new Date(clock.now().getTime() + ttlSeconds * 1000),
      });
      return challenge;
    },

    async claim(challenge, kind) {
      if (typeof challenge !== "string" || !CHALLENGE.test(challenge)) return null;
      const stored = await store.claim(challenge, kind);
      if (!stored) return null;
      if (stored.kind !== kind) return null;
      // Checked here rather than in the store's WHERE so an expired challenge
      // is still DELETED by the claim, not left for a cleanup job to notice.
      if (stored.expiresAt.getTime() <= clock.now().getTime()) return null;
      return { subjectId: stored.subjectId };
    },

    unstored: mint,
  };
}

/**
 * Parse and check a submitted public key: a P-256 (`prime256v1`)
 * SubjectPublicKeyInfo in PEM, nothing else. Returns the normalised PEM — the
 * form to store and later verify with — or null. Never throws.
 *
 * P-256 only, because that is what the phone generates and because a verifier
 * that accepts "any EC key" accepts a curve nobody reviewed.
 */
export function parseDeviceKeyPem(input: unknown): string | null {
  if (typeof input !== "string" || input.length > PEM_MAX || !input.includes("BEGIN PUBLIC KEY")) return null;
  try {
    const key = createPublicKey(input);
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") return null;
    return key.export({ type: "spki", format: "pem" }).toString();
  } catch {
    return null;
  }
}

/**
 * Verify the phone's signature over `challenge` — the challenge `claim`
 * returned, never one the client supplied. Never throws: a malformed
 * signature, a foreign key and a wrong signature all answer false, so a route
 * can give every refusal the same status.
 */
export function verifyDeviceKeySignature(publicKeyPem: string, challenge: string, signature: unknown): boolean {
  if (typeof publicKeyPem !== "string" || typeof challenge !== "string") return false;
  if (typeof signature !== "string" || !SIGNATURE.test(signature)) return false;
  try {
    const verifier = createVerify("SHA256");
    verifier.update(challenge, "ascii");
    return verifier.verify(publicKeyPem, signature, "base64");
  } catch {
    return false;
  }
}

/**
 * A verifier for the MISS path. When the key id names nothing, or names a key
 * that is not the challenge's subject's, a host that wants the refusal to cost
 * the same as a real check calls this with the same arguments: it runs a real
 * ECDSA verification against a per-process throwaway key, which can never
 * succeed. One verification is well under a millisecond, so this is a timing
 * equaliser, not an expense; the host still rate-limits the presenter.
 */
export function createDecoyVerifier(): (challenge: string, signature: unknown) => false {
  const decoyPem = generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    .publicKey.export({ type: "spki", format: "pem" })
    .toString();
  return (challenge, signature) => {
    verifyDeviceKeySignature(decoyPem, challenge, signature);
    return false;
  };
}
