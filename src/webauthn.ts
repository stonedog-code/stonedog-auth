/**
 * WebAuthn — the challenge lifecycle, and nothing else.
 *
 * **This module does not verify WebAuthn signatures and never will.** Parsing
 * attestation objects, validating certificate chains and checking COSE
 * signatures is a large, adversarial surface with a real library behind it;
 * a second-best reimplementation here would be the single most dangerous file
 * in this package.
 *
 * What it does own is the part that libraries leave to the caller and that
 * callers get wrong: a challenge must be **random, stored server-side, bound to
 * one subject, short-lived, and spent exactly once**. Every one of those is a
 * property of *storage and time*, which is precisely what a verification
 * library cannot enforce for you.
 *
 * So: this issues and claims challenges, and hands the ceremony to a verifier
 * the host supplies — `@simplewebauthn/server` in every application here.
 */

import { randomBytes } from "node:crypto";

import { systemClock, type Clock } from "./types";

export type CeremonyKind = "registration" | "authentication";

/** Base64url, which is what the WebAuthn API expects on the wire. */
export function generateChallenge(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export interface StoredChallenge {
  challenge: string;
  subjectId: string;
  kind: CeremonyKind;
  expiresAt: Date;
}

export interface ChallengeStore {
  insert(challenge: StoredChallenge): Promise<void>;
  /**
   * **Atomically** delete and return the challenge, or return null.
   *
   * Single-use is the whole point, so this must be a conditional delete or a
   * locked read — the same requirement, for the same reason, as `TokenStore.claim`.
   */
  claim(challenge: string, kind: CeremonyKind): Promise<StoredChallenge | null>;
}

export interface WebAuthnOptions {
  store: ChallengeStore;
  /**
   * How long a challenge lives. Ninety seconds is enough for a user to find a
   * key or a fingerprint and short enough that a captured challenge is stale
   * before it is useful.
   */
  ttlSeconds?: number;
  clock?: Clock;
}

export interface WebAuthnChallenges {
  issue(subjectId: string, kind: CeremonyKind): Promise<string>;
  /**
   * Spend a challenge, checking it belongs to this subject.
   *
   * The subject check is not redundant with the random value. Without it, a
   * challenge issued to one account can be presented in another's ceremony —
   * and since the challenge is public by the time the browser has it, the only
   * thing binding it to a person is this comparison.
   */
  claim(
    challenge: string,
    kind: CeremonyKind,
    subjectId: string,
  ): Promise<{ ok: true } | { ok: false }>;
}

export function createWebAuthnChallenges(options: WebAuthnOptions): WebAuthnChallenges {
  const ttlSeconds = options.ttlSeconds ?? 90;
  const clock = options.clock ?? systemClock;
  const { store } = options;

  return {
    async issue(subjectId, kind) {
      const challenge = generateChallenge();
      await store.insert({
        challenge,
        subjectId,
        kind,
        expiresAt: new Date(clock.now().getTime() + ttlSeconds * 1000),
      });
      return challenge;
    },

    async claim(challenge, kind, subjectId) {
      const stored = await store.claim(challenge, kind);
      if (!stored) return { ok: false };
      // Expiry is checked here rather than in the store's WHERE clause so that
      // an expired challenge is still *deleted* by the claim — leaving it
      // behind would let it be retried until a cleanup job noticed.
      if (stored.expiresAt.getTime() <= clock.now().getTime()) return { ok: false };
      if (stored.subjectId !== subjectId) return { ok: false };
      return { ok: true };
    },
  };
}
