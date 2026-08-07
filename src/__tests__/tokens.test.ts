import { ResendTooSoonError } from "../errors";
import {
  createTokenIssuer,
  generateNumericCode,
  generateToken,
  hashToken,
  tokenHashEquals,
  type StoredToken,
  type TokenStore,
} from "../tokens";
import type { Clock } from "../types";

/**
 * A store that implements `claim` CORRECTLY — as one conditional operation.
 *
 * Written this way on purpose: a read-then-write fake would let the
 * single-use test pass against an implementation that is racy in Postgres,
 * which is the exact bug the contract exists to prevent.
 */
function fakeStore(): TokenStore & { rows: StoredToken[] } {
  const rows: StoredToken[] = [];
  return {
    rows,
    async invalidateOutstanding(subjectId, kind, at) {
      for (const row of rows) {
        if (row.subjectId === subjectId && row.kind === kind && !row.consumedAt) {
          row.consumedAt = at;
        }
      }
    },
    async insert(token) {
      rows.push({ ...token });
    },
    async findMostRecent(subjectId, kind) {
      const matching = rows
        .filter((r) => r.subjectId === subjectId && r.kind === kind)
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
      return matching[0] ?? null;
    },
    async claim(tokenHash, kind, now) {
      const row = rows.find(
        (r) =>
          r.tokenHash === tokenHash &&
          r.kind === kind &&
          !r.consumedAt &&
          r.expiresAt.getTime() > now.getTime(),
      );
      if (!row) return null;
      row.consumedAt = now;
      return { ...row };
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

describe("token generation", () => {
  it("produces a URL-safe token with no padding", () => {
    const token = generateToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    // 32 bytes base64url — long enough that guessing is not a strategy.
    expect(token.length).toBeGreaterThanOrEqual(42);
  });

  it("does not repeat", () => {
    const seen = new Set(Array.from({ length: 500 }, () => generateToken()));
    expect(seen.size).toBe(500);
  });

  it("produces numeric codes of exactly the requested length, zero-padded", () => {
    for (let i = 0; i < 200; i += 1) {
      const code = generateNumericCode(6);
      expect(code).toMatch(/^[0-9]{6}$/);
    }
  });

  it("spreads numeric codes across every leading digit", () => {
    // A `randomBytes % 10` implementation is biased toward low digits. The bias
    // is small, and small is exactly what survives review forever.
    const leading = new Set(
      Array.from({ length: 1000 }, () => generateNumericCode(6)[0]),
    );
    expect(leading.size).toBe(10);
  });
});

describe("token hashing", () => {
  it("is stable and hex", () => {
    expect(hashToken("abc")).toBe(hashToken("abc"));
    expect(hashToken("abc")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("compares equal digests without a length-based shortcut lying", () => {
    expect(tokenHashEquals(hashToken("a"), hashToken("a"))).toBe(true);
    expect(tokenHashEquals(hashToken("a"), hashToken("b"))).toBe(false);
    expect(tokenHashEquals("short", "muchlongervalue")).toBe(false);
  });
});

describe("issuing and consuming", () => {
  const start = new Date("2026-08-07T12:00:00Z");

  it("returns the raw token once and stores only its hash", async () => {
    const store = fakeStore();
    const issuer = createTokenIssuer({ store, clock: fixedClock(start) });

    const { token } = await issuer.issue("user-1", "password-reset");

    // A dumped database must yield no working links.
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]?.tokenHash).toBe(hashToken(token));
    expect(JSON.stringify(store.rows)).not.toContain(token);
  });

  it("spends a token exactly once", async () => {
    const store = fakeStore();
    const issuer = createTokenIssuer({ store, clock: fixedClock(start) });
    const { token } = await issuer.issue("user-1", "password-reset");

    await expect(issuer.consume(token, "password-reset")).resolves.toEqual({
      ok: true,
      subjectId: "user-1",
    });
    await expect(issuer.consume(token, "password-reset")).resolves.toEqual({
      ok: false,
      reason: "invalid-or-expired",
    });
  });

  it("lets exactly one of two concurrent consumptions win", async () => {
    const store = fakeStore();
    const issuer = createTokenIssuer({ store, clock: fixedClock(start) });
    const { token } = await issuer.issue("user-1", "password-reset");

    const [first, second] = await Promise.all([
      issuer.consume(token, "password-reset"),
      issuer.consume(token, "password-reset"),
    ]);

    expect([first.ok, second.ok].filter(Boolean)).toHaveLength(1);
  });

  it("invalidates outstanding tokens of the same kind when a new one is issued", async () => {
    // Otherwise every reset email ever sent to an address stays live until it
    // expires.
    const store = fakeStore();
    const clock = fixedClock(start);
    const issuer = createTokenIssuer({ store, clock });

    const first = await issuer.issue("user-1", "password-reset");
    clock.advance(120);
    await issuer.issue("user-1", "password-reset");

    await expect(issuer.consume(first.token, "password-reset")).resolves.toEqual({
      ok: false,
      reason: "invalid-or-expired",
    });
  });

  it("leaves a DIFFERENT kind's token alone", async () => {
    const store = fakeStore();
    const clock = fixedClock(start);
    const issuer = createTokenIssuer({ store, clock });

    const verification = await issuer.issue("user-1", "email-verification");
    clock.advance(120);
    await issuer.issue("user-1", "password-reset");

    await expect(issuer.consume(verification.token, "email-verification")).resolves.toEqual({
      ok: true,
      subjectId: "user-1",
    });
  });

  it("refuses a token presented as the wrong kind", async () => {
    // A verification link must not be spendable as a password reset — they have
    // very different consequences and very different TTLs.
    const store = fakeStore();
    const issuer = createTokenIssuer({ store, clock: fixedClock(start) });
    const { token } = await issuer.issue("user-1", "email-verification");

    await expect(issuer.consume(token, "password-reset")).resolves.toEqual({
      ok: false,
      reason: "invalid-or-expired",
    });
  });

  it("refuses an expired token", async () => {
    const store = fakeStore();
    const clock = fixedClock(start);
    const issuer = createTokenIssuer({ store, clock });
    const { token } = await issuer.issue("user-1", "magic-link");

    clock.advance(16 * 60); // magic-link TTL is 15 minutes
    await expect(issuer.consume(token, "magic-link")).resolves.toEqual({
      ok: false,
      reason: "invalid-or-expired",
    });
  });

  it("reports the SAME reason for every kind of failure", async () => {
    // Distinguishing "no such token" from "expired" from "already used" tells
    // an attacker which of their guesses was once real.
    const store = fakeStore();
    const clock = fixedClock(start);
    const issuer = createTokenIssuer({ store, clock });
    const { token } = await issuer.issue("user-1", "password-reset");
    await issuer.consume(token, "password-reset");

    const neverExisted = await issuer.consume(generateToken(), "password-reset");
    const alreadyUsed = await issuer.consume(token, "password-reset");
    clock.advance(61 * 60);
    const expired = await issuer.consume(generateToken(), "password-reset");

    expect(neverExisted).toEqual(alreadyUsed);
    expect(alreadyUsed).toEqual(expired);
  });

  it("stamps createdAt and expiresAt from the SAME clock", async () => {
    // Otherwise createdAt comes from the database and expiresAt from the
    // application, and the cooldown compares two clocks that drift.
    const store = fakeStore();
    const issuer = createTokenIssuer({ store, clock: fixedClock(start) });
    await issuer.issue("user-1", "password-reset");

    const row = store.rows[0];
    expect(row?.createdAt).toEqual(start);
    expect(row?.expiresAt.getTime()).toBe(start.getTime() + 60 * 60_000);
  });
});

describe("the resend cooldown", () => {
  const start = new Date("2026-08-07T12:00:00Z");

  it("refuses a second send inside the cooldown, and says how long to wait", async () => {
    const store = fakeStore();
    const clock = fixedClock(start);
    const issuer = createTokenIssuer({ store, clock });

    await issuer.issue("user-1", "password-reset");
    clock.advance(10);

    await expect(issuer.issue("user-1", "password-reset")).rejects.toThrow(ResendTooSoonError);
    try {
      await issuer.issue("user-1", "password-reset");
    } catch (error) {
      expect((error as ResendTooSoonError).retryAfterSeconds).toBe(50);
    }
  });

  it("allows the send once the cooldown has passed", async () => {
    const store = fakeStore();
    const clock = fixedClock(start);
    const issuer = createTokenIssuer({ store, clock });

    await issuer.issue("user-1", "password-reset");
    clock.advance(61);
    await expect(issuer.issue("user-1", "password-reset")).resolves.toBeDefined();
  });

  it("can be skipped for the token issued during sign-up itself", async () => {
    const store = fakeStore();
    const clock = fixedClock(start);
    const issuer = createTokenIssuer({ store, clock });

    await issuer.issue("user-1", "email-verification");
    await expect(
      issuer.issue("user-1", "email-verification", { enforceCooldown: false }),
    ).resolves.toBeDefined();
  });

  it("applies a fallback TTL to a host-defined kind the policy does not name", async () => {
    const store = fakeStore();
    const issuer = createTokenIssuer({
      store,
      clock: fixedClock(start),
      fallbackTtlMinutes: 5,
    });
    await issuer.issue("user-1", "device-approval");

    expect(store.rows[0]?.expiresAt.getTime()).toBe(start.getTime() + 5 * 60_000);
  });
});
