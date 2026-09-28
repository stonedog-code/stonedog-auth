import { LockedOutError } from "../errors.js";
import { createEmailCodeFactor } from "../email-code.js";
import { createAttemptLimiter, createInMemoryAttemptStore } from "../lockout.js";
import { createTokenIssuer, hashToken, type StoredToken, type TokenStore } from "../tokens.js";
import type { AuthEvent, Clock } from "../types.js";

/** Same correct-claim fake as the token tests: one conditional operation. */
function fakeStore(): TokenStore & { rows: StoredToken[] } {
  const rows: StoredToken[] = [];
  return {
    rows,
    async invalidateOutstanding(subjectId, kind, at) {
      for (const row of rows) {
        if (row.subjectId === subjectId && row.kind === kind && !row.consumedAt) row.consumedAt = at;
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
        (r) => r.tokenHash === tokenHash && r.kind === kind && !r.consumedAt && r.expiresAt.getTime() > now.getTime(),
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

function setup(withLimiter = true) {
  const store = fakeStore();
  const clock = fixedClock(new Date("2026-09-28T12:00:00Z"));
  const events: AuthEvent[] = [];
  const issuer = createTokenIssuer({ store, clock });
  const limiter = createAttemptLimiter({ store: createInMemoryAttemptStore(), clock });
  const factor = createEmailCodeFactor({
    issuer,
    ...(withLimiter ? { limiter } : {}),
    audit: { record: (e) => void events.push(e) },
    clock,
  });
  return { store, clock, events, factor };
}

describe("email code factor", () => {
  it("issues a 6-digit code valid for ten minutes (the issuer's email-code TTL)", async () => {
    const { factor, clock } = setup();
    const { code, expiresAt } = await factor.issue("u1");
    expect(code).toMatch(/^[0-9]{6}$/);
    expect(expiresAt.getTime()).toBe(clock.now().getTime() + 10 * 60_000);
  });

  it("accepts the right code once, then never again", async () => {
    const { factor } = setup();
    const { code } = await factor.issue("u1");
    expect(await factor.verify("u1", code)).toEqual({ ok: true });
    expect(await factor.verify("u1", code)).toEqual({ ok: false });
  });

  it("stores a hash bound to the subject — never the code, never the bare code's hash", async () => {
    const { factor, store } = setup();
    const { code } = await factor.issue("u1");
    const [row] = store.rows;
    expect(row?.kind).toBe("email-code");
    expect(row?.tokenHash).toBe(hashToken(`u1:${code}`));
    expect(row?.tokenHash).not.toBe(hashToken(code));
    expect(JSON.stringify(store.rows)).not.toContain(code);
  });

  it("refuses one subject's code for another, and does not spend it", async () => {
    const { factor } = setup();
    const { code } = await factor.issue("u1");
    expect(await factor.verify("u2", code)).toEqual({ ok: false });
    expect(await factor.verify("u1", code)).toEqual({ ok: true });
  });

  it("refuses an expired code", async () => {
    const { factor, clock } = setup();
    const { code } = await factor.issue("u1");
    clock.advance(10 * 60);
    expect(await factor.verify("u1", code)).toEqual({ ok: false });
  });

  it("invalidates the previous code when a new one is issued", async () => {
    const { factor, clock } = setup();
    const { code: first } = await factor.issue("u1");
    clock.advance(61);
    const { code: second } = await factor.issue("u1");
    if (first !== second) expect(await factor.verify("u1", first)).toEqual({ ok: false });
    expect(await factor.verify("u1", second)).toEqual({ ok: true });
  });

  it.each(["12345", "1234567", "12a456", " 123456", ""])(
    "treats malformed input %p as a failed attempt",
    async (input) => {
      const { factor, events } = setup();
      await factor.issue("u1");
      expect(await factor.verify("u1", input)).toEqual({ ok: false });
      expect(events.at(-1)?.type).toBe("factor.rejected");
    },
  );

  it("locks out after five failures and throws LockedOutError before looking at the code", async () => {
    const { factor, events } = setup();
    const { code } = await factor.issue("u1");
    for (let i = 0; i < 5; i += 1) await factor.verify("u1", "000000" === code ? "111111" : "000000");
    await expect(factor.verify("u1", code)).rejects.toBeInstanceOf(LockedOutError);
    expect(events.at(-1)?.type).toBe("factor.locked-out");
  });

  it("refuses a claim the issuer reports for a DIFFERENT subject (backstop to the bound hash)", async () => {
    // Unreachable with the real issuer, because the hash is subject-bound. This
    // stands in for a host TokenStore whose claim ignores the hash scoping.
    const factor = createEmailCodeFactor({
      issuer: {
        issue: async () => ({ token: "x", expiresAt: new Date() }),
        consume: async () => ({ ok: true, subjectId: "u2" }),
      },
    });
    expect(await factor.verify("u1", "123456")).toEqual({ ok: false });
  });

  it("works without a limiter (the host limits elsewhere)", async () => {
    const { factor } = setup(false);
    const { code } = await factor.issue("u1");
    expect(await factor.verify("u1", code)).toEqual({ ok: true });
  });

  it("rethrows a non-lockout limiter error without auditing a lockout", async () => {
    const events: AuthEvent[] = [];
    const factor = createEmailCodeFactor({
      issuer: createTokenIssuer({ store: fakeStore() }),
      limiter: {
        assertAllowed: async () => {
          throw new Error("store down");
        },
        recordFailure: async () => undefined,
        recordSuccess: async () => undefined,
      },
      audit: { record: (e) => void events.push(e) },
    });
    await expect(factor.verify("u1", "123456")).rejects.toThrow("store down");
    expect(events).toEqual([]);
  });

  it("audits issue, success and failure without ever carrying the code", async () => {
    const { factor, events } = setup();
    const { code } = await factor.issue("u1");
    await factor.verify("u1", "999999" === code ? "888888" : "999999");
    await factor.verify("u1", code);
    expect(events.map((e) => e.type)).toEqual(["token.issued", "factor.rejected", "factor.verified"]);
    expect(events.every((e) => e.factor === "emailed-token")).toBe(true);
    expect(JSON.stringify(events)).not.toContain(code);
  });
});
