import {
  createWebAuthnChallenges,
  generateChallenge,
  type ChallengeStore,
  type StoredChallenge,
} from "../webauthn";
import type { Clock } from "../types";

/** Implements `claim` as one atomic delete-and-return, as the contract requires. */
function fakeStore(): ChallengeStore & { rows: Map<string, StoredChallenge> } {
  const rows = new Map<string, StoredChallenge>();
  return {
    rows,
    async insert(challenge) {
      rows.set(`${challenge.kind}:${challenge.challenge}`, challenge);
    },
    async claim(challenge, kind) {
      const key = `${kind}:${challenge}`;
      const found = rows.get(key);
      if (!found) return null;
      rows.delete(key);
      return found;
    },
  };
}

function fixedClock(start: Date): Clock & { advance(seconds: number): void } {
  let current = start;
  return {
    now: () => current,
    advance: (seconds) => {
      current = new Date(current.getTime() + seconds * 1000);
    },
  };
}

describe("challenge generation", () => {
  it("is base64url and does not repeat", () => {
    const seen = new Set(Array.from({ length: 500 }, () => generateChallenge()));
    expect(seen.size).toBe(500);
    for (const challenge of seen) expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe("the challenge lifecycle", () => {
  const start = new Date("2026-08-07T12:00:00Z");

  it("issues a challenge that can be claimed once", async () => {
    const store = fakeStore();
    const challenges = createWebAuthnChallenges({ store, clock: fixedClock(start) });

    const challenge = await challenges.issue("user-1", "authentication");
    await expect(challenges.claim(challenge, "authentication", "user-1")).resolves.toEqual({
      ok: true,
    });
    await expect(challenges.claim(challenge, "authentication", "user-1")).resolves.toEqual({
      ok: false,
    });
  });

  it("REFUSES a challenge presented for a different subject", async () => {
    // Not redundant with the randomness: the challenge is public by the time
    // the browser has it, so this comparison is the only thing binding it to a
    // person. Without it, a challenge issued to one account can be replayed
    // into another's ceremony.
    const store = fakeStore();
    const challenges = createWebAuthnChallenges({ store, clock: fixedClock(start) });

    const challenge = await challenges.issue("user-1", "authentication");
    await expect(challenges.claim(challenge, "authentication", "user-2")).resolves.toEqual({
      ok: false,
    });
  });

  it("SPENDS a challenge even when the subject check fails", async () => {
    // Otherwise a wrong-subject attempt leaves the challenge live and an
    // attacker simply retries it against every account id they can think of.
    const store = fakeStore();
    const challenges = createWebAuthnChallenges({ store, clock: fixedClock(start) });

    const challenge = await challenges.issue("user-1", "authentication");
    await challenges.claim(challenge, "authentication", "user-2");
    await expect(challenges.claim(challenge, "authentication", "user-1")).resolves.toEqual({
      ok: false,
    });
  });

  it("refuses a registration challenge presented in an authentication ceremony", async () => {
    const store = fakeStore();
    const challenges = createWebAuthnChallenges({ store, clock: fixedClock(start) });

    const challenge = await challenges.issue("user-1", "registration");
    await expect(challenges.claim(challenge, "authentication", "user-1")).resolves.toEqual({
      ok: false,
    });
  });

  it("refuses an expired challenge", async () => {
    const store = fakeStore();
    const clock = fixedClock(start);
    const challenges = createWebAuthnChallenges({ store, clock, ttlSeconds: 90 });

    const challenge = await challenges.issue("user-1", "authentication");
    clock.advance(91);
    await expect(challenges.claim(challenge, "authentication", "user-1")).resolves.toEqual({
      ok: false,
    });
  });

  it("DELETES an expired challenge rather than leaving it to a cleanup job", async () => {
    // Expiry is checked after the claim, not in the store's WHERE clause, so an
    // expired challenge is still removed. Leaving it behind lets it be retried
    // until something else notices.
    const store = fakeStore();
    const clock = fixedClock(start);
    const challenges = createWebAuthnChallenges({ store, clock, ttlSeconds: 90 });

    await challenges.issue("user-1", "authentication");
    clock.advance(91);
    const challenge = [...store.rows.values()][0]?.challenge ?? "";
    await challenges.claim(challenge, "authentication", "user-1");

    expect(store.rows.size).toBe(0);
  });

  it("refuses a challenge that was never issued", async () => {
    const store = fakeStore();
    const challenges = createWebAuthnChallenges({ store, clock: fixedClock(start) });
    await expect(
      challenges.claim(generateChallenge(), "authentication", "user-1"),
    ).resolves.toEqual({ ok: false });
  });
});
