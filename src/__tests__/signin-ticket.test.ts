import { AuthError } from "../errors.js";
import type { AuthMethod } from "../methods.js";
import { createSignInTickets, type SignInTicketStore, type StoredTicket } from "../signin-ticket.js";
import { hashToken } from "../tokens.js";
import type { Clock } from "../types.js";

/** `take` is get + delete in one step, as the contract demands. */
function fakeStore(): SignInTicketStore & { rows: Map<string, StoredTicket> } {
  const rows = new Map<string, StoredTicket>();
  return {
    rows,
    async put(t) {
      rows.set(t.hash, { ...t, completed: [...t.completed] });
    },
    async take(hash) {
      const row = rows.get(hash) ?? null;
      rows.delete(hash);
      return row;
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

function setup() {
  const store = fakeStore();
  const clock = fixedClock(new Date("2026-09-28T12:00:00Z"));
  return { store, clock, tickets: createSignInTickets({ store, clock }) };
}

describe("sign-in tickets — the primary path", () => {
  it("walks password → totp to done, re-issuing a new ticket at each step", async () => {
    const { tickets } = setup();
    const { ticket: t0 } = await tickets.start("u1", "password_totp", "email");
    const t1 = await tickets.advance(t0, "password");
    expect(t1).toMatchObject({ subjectId: "u1", method: "password_totp", done: false });
    expect(t1?.ticket).not.toBe(t0);
    const t2 = await tickets.advance(t1?.ticket as string, "totp");
    expect(t2).toMatchObject({ subjectId: "u1", method: "password_totp", done: true });
  });

  it("walks webauthn → pin when start already records the first factor", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "passkey_pin", "webauthn");
    expect(await tickets.advance(ticket, "pin")).toMatchObject({ done: true });
  });

  it("stores only the hash of a ticket", async () => {
    const { tickets, store } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    expect([...store.rows.keys()]).toEqual([hashToken(ticket)]);
    expect(JSON.stringify([...store.rows.values()])).not.toContain(ticket);
  });

  it("defaults to a five-minute life per step", async () => {
    const { tickets, store, clock } = setup();
    await tickets.start("u1", "password_totp", "email");
    const [row] = [...store.rows.values()];
    expect(row?.expiresAt.getTime()).toBe(clock.now().getTime() + 5 * 60_000);
  });
});

describe("sign-in tickets — every way to cheat returns null", () => {
  it("refuses a REPLAYED ticket (single use per step)", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    expect(await tickets.advance(ticket, "password")).not.toBeNull();
    expect(await tickets.advance(ticket, "password")).toBeNull();
  });

  it("refuses a SKIPPED step — totp straight from start", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    expect(await tickets.advance(ticket, "totp")).toBeNull();
  });

  it("refuses a REPEATED step — password twice", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    const t1 = await tickets.advance(ticket, "password");
    expect(await tickets.advance(t1?.ticket as string, "password")).toBeNull();
  });

  it("refuses a WRONG-ORDER step — pin before webauthn", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "passkey_pin", "email");
    expect(await tickets.advance(ticket, "pin")).toBeNull();
  });

  it("refuses a step from ANOTHER method", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    expect(await tickets.advance(ticket, "webauthn")).toBeNull();
  });

  it("spends the ticket even when the step was wrong", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    expect(await tickets.advance(ticket, "totp")).toBeNull();
    expect(await tickets.advance(ticket, "password")).toBeNull();
  });

  it("refuses an EXPIRED ticket, and deletes it rather than leaving it", async () => {
    const { tickets, clock, store } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    clock.advance(5 * 60);
    expect(await tickets.advance(ticket, "password")).toBeNull();
    expect(store.rows.size).toBe(0);
  });

  it("accepts a ticket one second before expiry", async () => {
    const { tickets, clock } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    clock.advance(5 * 60 - 1);
    expect(await tickets.advance(ticket, "password")).not.toBeNull();
  });

  it("refuses an unknown, empty or absurd ticket", async () => {
    const { tickets } = setup();
    expect(await tickets.advance("nope", "password")).toBeNull();
    expect(await tickets.advance("", "password")).toBeNull();
    expect(await tickets.advance("x".repeat(1000), "password")).toBeNull();
  });

  it("refuses to advance a completed ticket any further", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "passkey_pin", "webauthn");
    const done = await tickets.advance(ticket, "pin");
    expect(await tickets.advance(done?.ticket as string, "pin")).toBeNull();
  });
});

describe("sign-in tickets — recovery is never one secret (Amendment A)", () => {
  it("password_totp: a recovery code replaces the TOTP after the password", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    const t1 = await tickets.advance(ticket, "password");
    expect(await tickets.advance(t1?.ticket as string, "recovery-code")).toMatchObject({ done: true });
  });

  it("passkey_pin: a recovery code completes only after an emailed code", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "passkey_pin", "email");
    const t1 = await tickets.advance(ticket, "email-code");
    expect(t1).toMatchObject({ done: false });
    expect(await tickets.advance(t1?.ticket as string, "recovery-code")).toMatchObject({ done: true });
  });

  it.each(["password_totp", "passkey_pin"] as const)(
    "%s: a ticket from start alone NEVER accepts a recovery code",
    async (method) => {
      const { tickets } = setup();
      const { ticket } = await tickets.start("u1", method, "email");
      expect(await tickets.advance(ticket, "recovery-code")).toBeNull();
    },
  );

  it("passkey_pin: an emailed code cannot be followed by the PIN (that would drop the passkey)", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "passkey_pin", "email");
    const t1 = await tickets.advance(ticket, "email-code");
    expect(await tickets.advance(t1?.ticket as string, "pin")).toBeNull();
  });

  it("passkey_pin: a recovery code cannot follow the passkey (the email step is the pairing)", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "passkey_pin", "webauthn");
    expect(await tickets.advance(ticket, "recovery-code")).toBeNull();
  });

  it("assurance-1 methods have no recovery path", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "magic_link", "email");
    const t1 = await tickets.advance(ticket, "email-link");
    expect(t1).toMatchObject({ done: true });
    const { ticket: t2 } = await tickets.start("u1", "email_code", "email");
    expect(await tickets.advance(t2, "recovery-code")).toBeNull();
  });
});

describe("sign-in tickets — start", () => {
  it("throws on a factor step that does not begin the method", async () => {
    const { tickets } = setup();
    await expect(tickets.start("u1", "password_totp", "totp")).rejects.toBeInstanceOf(AuthError);
    await expect(tickets.start("u1", "password_totp", "webauthn")).rejects.toBeInstanceOf(AuthError);
    await expect(tickets.start("u1", "password_totp", "recovery-code")).rejects.toBeInstanceOf(AuthError);
  });

  it("throws on an unknown method", async () => {
    const { tickets } = setup();
    await expect(tickets.start("u1", "sms" as AuthMethod, "email")).rejects.toBeInstanceOf(AuthError);
  });

  it("records NO progress for a non-factor marker, including a typo (fails toward more steps)", async () => {
    const { tickets } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "passwrd");
    expect(await tickets.advance(ticket, "totp")).toBeNull();
  });

  it("honours a custom TTL", async () => {
    const store = fakeStore();
    const clock = fixedClock(new Date("2026-09-28T12:00:00Z"));
    const tickets = createSignInTickets({ store, clock, ttlMinutes: 1 });
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    clock.advance(60);
    expect(await tickets.advance(ticket, "password")).toBeNull();
  });
});

describe("sign-in tickets — peek", () => {
  it("reads without spending, and does not extend the expiry", async () => {
    const { tickets, clock, store } = setup();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    const before = [...store.rows.values()][0]?.expiresAt.getTime();
    clock.advance(60);
    expect(await tickets.peek(ticket)).toEqual({ subjectId: "u1", method: "password_totp", completed: [] });
    expect([...store.rows.values()][0]?.expiresAt.getTime()).toBe(before);
    expect(await tickets.advance(ticket, "password")).not.toBeNull();
  });

  it("returns null for an unknown or expired ticket", async () => {
    const { tickets, clock } = setup();
    expect(await tickets.peek("nope")).toBeNull();
    const { ticket } = await tickets.start("u1", "password_totp", "email");
    clock.advance(5 * 60);
    expect(await tickets.peek(ticket)).toBeNull();
  });
});
