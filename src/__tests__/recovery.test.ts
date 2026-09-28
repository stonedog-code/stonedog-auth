import { MisconfiguredError } from "../errors.js";
import { createRecoveryCodes, type RecoveryCodeStore } from "../recovery.js";
import { hashToken } from "../tokens.js";
import type { AuthEvent, Clock } from "../types.js";

interface Row {
  subjectId: string;
  hash: string;
  used: boolean;
}

/**
 * A store implementing the contract CORRECTLY: `consume` is one conditional
 * mark scoped by subject, and `replaceAll` leaves nothing of the old set.
 */
function fakeStore(): RecoveryCodeStore & { rows: Row[] } {
  let rows: Row[] = [];
  return {
    get rows() {
      return rows;
    },
    async replaceAll(subjectId, hashes) {
      rows = rows.filter((r) => r.subjectId !== subjectId);
      for (const hash of hashes) rows.push({ subjectId, hash, used: false });
    },
    async consume(subjectId, hash) {
      const row = rows.find((r) => r.subjectId === subjectId && r.hash === hash && !r.used);
      if (!row) return false;
      row.used = true;
      return true;
    },
    async remaining(subjectId) {
      return rows.filter((r) => r.subjectId === subjectId && !r.used).length;
    },
  };
}

const clock: Clock = { now: () => new Date("2026-09-28T12:00:00Z") };

function audited() {
  const events: AuthEvent[] = [];
  return { events, sink: { record: (e: AuthEvent) => void events.push(e) } };
}

describe("recovery codes — issuing", () => {
  it("issues ten codes in the xxxx-xxxx-xx unambiguous base32 format", async () => {
    const codes = await createRecoveryCodes({ store: fakeStore() }).issue("u1");
    expect(codes).toHaveLength(10);
    for (const code of codes) {
      // No i, l, o, u — the characters people misread or that spell words.
      expect(code).toMatch(/^[0-9abcdefghjkmnpqrstvwxyz]{4}-[0-9abcdefghjkmnpqrstvwxyz]{4}-[0-9abcdefghjkmnpqrstvwxyz]{2}$/);
    }
    expect(new Set(codes).size).toBe(10);
  });

  it("honours a custom count and refuses a silly one at construction", async () => {
    expect(await createRecoveryCodes({ store: fakeStore(), count: 3 }).issue("u1")).toHaveLength(3);
    for (const count of [0, -1, 1.5, 101, Number.NaN]) {
      expect(() => createRecoveryCodes({ store: fakeStore(), count })).toThrow(MisconfiguredError);
    }
  });

  it("stores only hashes — never a plaintext code", async () => {
    const store = fakeStore();
    const codes = await createRecoveryCodes({ store }).issue("u1");
    const stored = store.rows.map((r) => r.hash);
    for (const code of codes) {
      expect(stored).not.toContain(code);
      expect(stored).not.toContain(code.replace(/-/g, ""));
      expect(stored).toContain(hashToken(code.replace(/-/g, "")));
    }
  });

  it("is not predictable across many draws (every alphabet character appears)", async () => {
    const recovery = createRecoveryCodes({ store: fakeStore(), count: 100 });
    const chars = new Set((await recovery.issue("u1")).join("").replace(/-/g, ""));
    expect(chars.size).toBe(32);
  });

  it("REPLACES every previous code when issued again", async () => {
    const store = fakeStore();
    const recovery = createRecoveryCodes({ store });
    const first = await recovery.issue("u1");
    await recovery.issue("u1");
    // The sheet being regenerated is the one the user thinks leaked.
    for (const code of first) expect(await recovery.consume("u1", code)).toBe(false);
    expect(await recovery.remaining("u1")).toBe(10);
  });

  it("audits the issue with a count and no code", async () => {
    const { events, sink } = audited();
    const codes = await createRecoveryCodes({ store: fakeStore(), audit: sink, clock }).issue("u1");
    expect(events).toEqual([
      { type: "recovery.issued", factor: "recovery-code", subjectId: "u1", at: clock.now(), detail: { count: 10 } },
    ]);
    const serialised = JSON.stringify(events);
    for (const code of codes) expect(serialised).not.toContain(code.slice(0, 4));
  });
});

describe("recovery codes — consuming", () => {
  it("accepts a code once, and never again (single use)", async () => {
    const recovery = createRecoveryCodes({ store: fakeStore() });
    const [code] = await recovery.issue("u1");
    expect(await recovery.consume("u1", code as string)).toBe(true);
    expect(await recovery.consume("u1", code as string)).toBe(false);
    expect(await recovery.remaining("u1")).toBe(9);
  });

  it("is case-, hyphen- and space-insensitive, and folds i/l/o", async () => {
    const recovery = createRecoveryCodes({ store: fakeStore(), count: 4 });
    const codes = (await recovery.issue("u1")) as [string, string, string, string];
    expect(await recovery.consume("u1", codes[0].toUpperCase())).toBe(true);
    expect(await recovery.consume("u1", codes[1].replace(/-/g, ""))).toBe(true);
    expect(await recovery.consume("u1", ` ${codes[2].replace(/-/g, " ")} `)).toBe(true);
    // Typed off paper: a 1 read as l, a 0 read as O.
    const misread = codes[3].replace(/1/g, "l").replace(/0/g, "O");
    expect(await recovery.consume("u1", misread)).toBe(true);
  });

  it("refuses another subject's code", async () => {
    const store = fakeStore();
    const recovery = createRecoveryCodes({ store });
    const [code] = await recovery.issue("u1");
    await recovery.issue("u2");
    expect(await recovery.consume("u2", code as string)).toBe(false);
    // And the attempt did not spend it for its owner.
    expect(await recovery.consume("u1", code as string)).toBe(true);
  });

  it.each([
    ["too short", "abcd-efgh-j"],
    ["too long", "abcd-efgh-jkm"],
    ["a character outside the alphabet", "abcd-efgh-u1"],
    ["empty", ""],
    ["absurdly long", "a".repeat(10_000)],
  ])("refuses %s without reaching the store", async (_label, code) => {
    const store = fakeStore();
    let calls = 0;
    const real = store.consume.bind(store);
    store.consume = async (subjectId, hash) => {
      calls += 1;
      return real(subjectId, hash);
    };
    const recovery = createRecoveryCodes({ store });
    await recovery.issue("u1");
    expect(await recovery.consume("u1", code)).toBe(false);
    expect(calls).toBe(0);
  });

  it("refuses a non-string without throwing", async () => {
    const recovery = createRecoveryCodes({ store: fakeStore() });
    expect(await recovery.consume("u1", undefined as unknown as string)).toBe(false);
  });

  it("audits use and rejection, never the code", async () => {
    const { events, sink } = audited();
    const recovery = createRecoveryCodes({ store: fakeStore(), audit: sink, clock });
    const [code] = await recovery.issue("u1");
    await recovery.consume("u1", code as string);
    await recovery.consume("u1", code as string);
    expect(events.map((e) => [e.type, e.factor])).toEqual([
      ["recovery.issued", "recovery-code"],
      ["recovery.used", "recovery-code"],
      ["factor.rejected", "recovery-code"],
    ]);
    expect(JSON.stringify(events)).not.toContain((code as string).slice(0, 4));
  });
});
