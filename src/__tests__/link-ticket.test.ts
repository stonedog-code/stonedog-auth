import { createLinkTickets, LIVE_LINK_STATES, type LinkTicketState } from "../link-ticket.js";
import { manualCodeForTicketHash, manualCodeKeyFrom, normaliseManualCode } from "../manual-code.js";
import { hashToken } from "../tokens.js";
import type { Clock } from "../types.js";
import { fakeLinkStore } from "./link-ticket-store.js";

function fixedClock(start: Date): Clock & { advance(seconds: number): void } {
  let current = start;
  return {
    now: () => current,
    advance: (seconds) => {
      current = new Date(current.getTime() + seconds * 1000);
    },
  };
}

const KEY = manualCodeKeyFrom("test-secret-with-enough-entropy", "test.manual-code.v1");
const META = { model: "Pixel 9", platform: "android", osVersion: "16", appVersion: "0.4.1" };

function setup(opts: { withCode?: boolean; hashEncoding?: "hex" | "base64url"; maxPendingScan?: number } = {}) {
  const store = fakeLinkStore();
  const clock = fixedClock(new Date("2026-10-08T12:00:00Z"));
  const tickets = createLinkTickets({
    store,
    clock,
    ...(opts.withCode === false ? {} : { manualCodeKey: KEY }),
    ...(opts.hashEncoding ? { hashEncoding: opts.hashEncoding } : {}),
    ...(opts.maxPendingScan !== undefined ? { maxPendingScan: opts.maxPendingScan } : {}),
  });
  return { store, clock, tickets };
}

/** The whole happy path up to `confirmed`, returning what each holder got. */
async function toConfirmed(s: ReturnType<typeof setup>, subjectId = "u1") {
  const minted = await s.tickets.mint(subjectId);
  const scanned = await s.tickets.scan({ ticket: minted.ticket }, META);
  if (!scanned) throw new Error("scan failed in setup");
  expect(await s.tickets.confirm(subjectId, minted.id)).toBe(true);
  return { minted, scanned };
}

describe("link tickets — the happy path", () => {
  it("mint → scan → confirm → complete → claimEnrolment, each exactly once", async () => {
    const s = setup();
    const minted = await s.tickets.mint("u1");
    expect(minted.ticket).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(minted.manualCode).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    expect(minted.expiresAt.getTime()).toBe(s.clock.now().getTime() + 120_000);
    expect((await s.tickets.read("u1", minted.id))?.state).toBe("pending");

    const scanned = await s.tickets.scan({ ticket: minted.ticket }, META);
    expect(scanned).toMatchObject({ ticketId: minted.id, subjectId: "u1" });
    expect(scanned?.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const read = await s.tickets.read("u1", minted.id);
    expect(read).toMatchObject({ state: "scanned", meta: META });

    // The phone polls before the website decides: waiting, not invalid.
    expect(await s.tickets.complete({ ticket: minted.ticket }, scanned!.nonce)).toEqual({ ok: false, reason: "waiting" });

    expect(await s.tickets.confirm("u1", minted.id)).toBe(true);
    expect((await s.tickets.read("u1", minted.id))?.state).toBe("confirmed");

    const done = await s.tickets.complete({ ticket: minted.ticket }, scanned!.nonce);
    expect(done).toEqual({ ok: true, ticketId: minted.id, subjectId: "u1" });
    expect((await s.tickets.read("u1", minted.id))?.state).toBe("consumed");

    expect(await s.tickets.claimEnrolment(minted.id, "u1")).toBe(true);
    expect(await s.tickets.claimEnrolment(minted.id, "u1")).toBe(false); // replayed enrolment plants nothing
  });

  it("stores only digests: neither the ticket nor the nonce ever reaches the store", async () => {
    const s = setup();
    const minted = await s.tickets.mint("u1");
    const scanned = await s.tickets.scan({ ticket: minted.ticket });
    const dump = JSON.stringify([...s.store.rows.values()]);
    expect(dump).not.toContain(minted.ticket);
    expect(dump).not.toContain(scanned!.nonce);
    expect(dump).not.toContain(minted.manualCode!.replace("-", ""));
    const row = [...s.store.rows.values()][0]!;
    expect(row.ticketHash).toBe(hashToken(minted.ticket));
    expect(row.nonceHash).toBe(hashToken(scanned!.nonce));
  });

  it("hashes with the configured encoding, so a base64url store keeps its rows", async () => {
    const s = setup({ hashEncoding: "base64url" });
    const minted = await s.tickets.mint("u1");
    expect([...s.store.rows.values()][0]!.ticketHash).toBe(hashToken(minted.ticket, "base64url"));
    expect(await s.tickets.scan({ ticket: minted.ticket })).not.toBeNull();
  });

  it("the phone may name its ticket by row id after a typed code", async () => {
    const s = setup();
    const { minted, scanned } = await toConfirmed(s);
    expect(await s.tickets.complete({ ticketId: minted.id }, scanned.nonce)).toMatchObject({ ok: true });
  });
});

describe("link tickets — every transition is one conditional write", () => {
  it("scan is pending → scanned, once: a second scan of the same ticket is refused", async () => {
    const s = setup();
    const minted = await s.tickets.mint("u1");
    expect(await s.tickets.scan({ ticket: minted.ticket })).not.toBeNull();
    expect(await s.tickets.scan({ ticket: minted.ticket })).toBeNull();
  });

  it("confirm requires scanned: a pending or already-confirmed ticket does not move", async () => {
    const s = setup();
    const minted = await s.tickets.mint("u1");
    expect(await s.tickets.confirm("u1", minted.id)).toBe(false);
    await s.tickets.scan({ ticket: minted.ticket });
    expect(await s.tickets.confirm("u1", minted.id)).toBe(true);
    expect(await s.tickets.confirm("u1", minted.id)).toBe(false);
  });

  it("confirm and cancel are scoped to the owner: another subject cannot move the row", async () => {
    const s = setup();
    const minted = await s.tickets.mint("u1");
    await s.tickets.scan({ ticket: minted.ticket });
    expect(await s.tickets.confirm("u2", minted.id)).toBe(false);
    expect(await s.tickets.cancel("u2", minted.id)).toBe(false);
    expect(await s.tickets.read("u2", minted.id)).toBeNull();
    expect((await s.tickets.read("u1", minted.id))?.state).toBe("scanned");
  });

  it("complete needs the nonce minted at scan — another phone's, or a guess, is invalid", async () => {
    const s = setup();
    const { minted } = await toConfirmed(s);
    const other = "A".repeat(43);
    expect(await s.tickets.complete({ ticket: minted.ticket }, other)).toEqual({ ok: false, reason: "invalid" });
    expect((await s.tickets.read("u1", minted.id))?.state).toBe("confirmed");
  });

  it("complete is confirmed → consumed exactly once: two phones racing on one nonce, one wins", async () => {
    const s = setup();
    const { minted, scanned } = await toConfirmed(s);
    const [a, b] = await Promise.all([
      s.tickets.complete({ ticket: minted.ticket }, scanned.nonce),
      s.tickets.complete({ ticket: minted.ticket }, scanned.nonce),
    ]);
    const wins = [a, b].filter((r) => r.ok);
    expect(wins).toHaveLength(1);
    expect([a, b].find((r) => !r.ok)).toEqual({ ok: false, reason: "invalid" });
    // One row, one consumed transition recorded.
    expect(s.store.updates.filter((u) => u.data.state === "consumed" && u.moved === 1)).toHaveLength(1);
  });

  it("the write decides, not the read: a cancel landing between read and write leaves complete with invalid", async () => {
    const s = setup();
    const { minted, scanned } = await toConfirmed(s);
    // Simulate the race: the website cancels after the phone's read but before its write.
    const original = s.store.updateMany.bind(s.store);
    let intercepted = false;
    s.store.updateMany = async (where, data) => {
      if (!intercepted && data.state === "consumed") {
        intercepted = true;
        await s.tickets.cancel("u1", minted.id);
      }
      return original(where, data);
    };
    expect(await s.tickets.complete({ ticket: minted.ticket }, scanned.nonce)).toEqual({ ok: false, reason: "invalid" });
    expect((await s.tickets.read("u1", minted.id))?.state).toBe("cancelled");
  });

  it("claimEnrolment needs consumed + the owner: a confirmed ticket or another subject cannot claim", async () => {
    const s = setup();
    const { minted, scanned } = await toConfirmed(s);
    expect(await s.tickets.claimEnrolment(minted.id, "u1")).toBe(false);
    await s.tickets.complete({ ticket: minted.ticket }, scanned.nonce);
    expect(await s.tickets.claimEnrolment(minted.id, "u2")).toBe(false);
    expect(await s.tickets.claimEnrolment(minted.id, "u1")).toBe(true);
  });
});

describe("link tickets — expiry", () => {
  it("is set once at mint; after 120 s every transition refuses and the poll reads expired", async () => {
    const s = setup();
    const minted = await s.tickets.mint("u1");
    const scanned = await s.tickets.scan({ ticket: minted.ticket });
    s.clock.advance(120);
    expect((await s.tickets.read("u1", minted.id))?.state).toBe("expired");
    expect(await s.tickets.confirm("u1", minted.id)).toBe(false);
    expect(await s.tickets.complete({ ticket: minted.ticket }, scanned!.nonce)).toEqual({ ok: false, reason: "invalid" });
    // The row keeps its last state; `expired` is a view.
    expect([...s.store.rows.values()][0]!.state).toBe("scanned");
  });

  it("an expired pending ticket cannot be scanned, by QR or by code", async () => {
    const s = setup();
    const minted = await s.tickets.mint("u1");
    s.clock.advance(121);
    expect(await s.tickets.scan({ ticket: minted.ticket })).toBeNull();
    expect(await s.tickets.scan({ manualCode: minted.manualCode! })).toBeNull();
  });

  it("a consumed ticket is not reported expired — only live states are", async () => {
    const s = setup();
    const { minted, scanned } = await toConfirmed(s);
    await s.tickets.complete({ ticket: minted.ticket }, scanned.nonce);
    s.clock.advance(600);
    expect((await s.tickets.read("u1", minted.id))?.state).toBe("consumed");
  });
});

describe("link tickets — cancel, burn, supersede", () => {
  it("mint supersedes every live ticket the subject holds, so only one QR works", async () => {
    const s = setup();
    const first = await s.tickets.mint("u1");
    const second = await s.tickets.mint("u1");
    expect((await s.tickets.read("u1", first.id))?.state).toBe("cancelled");
    expect([...s.store.rows.values()].find((r) => r.id === first.id)?.cancelReason).toBe("superseded");
    expect(await s.tickets.scan({ ticket: first.ticket })).toBeNull();
    expect(await s.tickets.scan({ ticket: second.ticket })).not.toBeNull();
  });

  it("mint does not touch another subject's tickets", async () => {
    const s = setup();
    const theirs = await s.tickets.mint("u2");
    await s.tickets.mint("u1");
    expect((await s.tickets.read("u2", theirs.id))?.state).toBe("pending");
  });

  it("cancel retires any live state with the reason given, and nothing twice", async () => {
    const s = setup();
    for (const state of LIVE_LINK_STATES) {
      const minted = await s.tickets.mint(`u-${state}`);
      if (state !== "pending") await s.tickets.scan({ ticket: minted.ticket });
      if (state === "confirmed") await s.tickets.confirm(`u-${state}`, minted.id);
      expect(await s.tickets.cancel(`u-${state}`, minted.id, "cancelled")).toBe(true);
      expect(await s.tickets.cancel(`u-${state}`, minted.id, "cancelled")).toBe(false);
      expect((await s.tickets.read(`u-${state}`, minted.id))?.state).toBe("cancelled");
    }
  });

  it("burn on sign-out retires every live ticket AND a consumed one whose enrolment is unused", async () => {
    const s = setup();
    const live = await s.tickets.mint("u1");
    await s.tickets.scan({ ticket: live.ticket });
    // A second subject's consumed-but-unenrolled ticket must not be touched.
    const theirs = await toConfirmed(s, "u2");
    await s.tickets.complete({ ticket: theirs.minted.ticket }, theirs.scanned.nonce);
    // u1's own consumed-but-unenrolled — a second mint would supersede `live`,
    // so build it on the fake directly: consumed, enrolledAt null.
    const row = [...s.store.rows.values()].find((r) => r.id === live.id)!;
    const consumedUnenrolled = { ...row, id: "tX", state: "consumed" as LinkTicketState, ticketHash: "x".repeat(64) };
    s.store.rows.set("tX", consumedUnenrolled);
    expect(await s.tickets.burn("u1", "sign_out")).toBe(2);
    expect(s.store.rows.get(live.id)?.state).toBe("cancelled");
    expect(s.store.rows.get("tX")?.state).toBe("cancelled");
    expect(s.store.rows.get(live.id)?.cancelReason).toBe("sign_out");
    expect((await s.tickets.read("u2", theirs.minted.id))?.state).toBe("consumed");
    expect(await s.tickets.burn("u1", "sign_out")).toBe(0);
  });

  it("burn leaves a consumed ticket whose enrolment is already claimed alone", async () => {
    const s = setup();
    const { minted, scanned } = await toConfirmed(s);
    await s.tickets.complete({ ticket: minted.ticket }, scanned.nonce);
    await s.tickets.claimEnrolment(minted.id, "u1");
    expect(await s.tickets.burn("u1", "sign_out")).toBe(0);
    expect((await s.tickets.read("u1", minted.id))?.state).toBe("consumed");
  });

  it("cancelFromPhone needs the nonce, so a pending ticket cannot be cancelled from the phone at all", async () => {
    const s = setup();
    const minted = await s.tickets.mint("u1");
    expect(await s.tickets.cancelFromPhone({ ticket: minted.ticket }, "A".repeat(43))).toBeNull();
    expect((await s.tickets.read("u1", minted.id))?.state).toBe("pending");
    const scanned = await s.tickets.scan({ ticket: minted.ticket });
    expect(await s.tickets.cancelFromPhone({ ticket: minted.ticket }, "A".repeat(43))).toBeNull();
    expect(await s.tickets.cancelFromPhone({ ticketId: minted.id }, scanned!.nonce)).toEqual({ ticketId: minted.id, subjectId: "u1" });
    expect(s.store.rows.get(minted.id)?.cancelReason).toBe("phone_cancelled");
    expect(await s.tickets.cancelFromPhone({ ticketId: minted.id }, scanned!.nonce)).toBeNull();
  });
});

describe("link tickets — the manual code", () => {
  it("is derived from the ticket digest under the key, and redeems the SAME pending → scanned transition", async () => {
    const s = setup();
    const minted = await s.tickets.mint("u1");
    const row = [...s.store.rows.values()][0]!;
    expect(minted.manualCode!.replace("-", "")).toBe(manualCodeForTicketHash(row.ticketHash, KEY));
    const scanned = await s.tickets.scan({ manualCode: minted.manualCode! }, META);
    expect(scanned).toMatchObject({ ticketId: minted.id, subjectId: "u1" });
    // Spent: the QR no longer scans either, because it is the same row.
    expect(await s.tickets.scan({ ticket: minted.ticket })).toBeNull();
    expect(await s.tickets.scan({ manualCode: minted.manualCode! })).toBeNull();
  });

  it("accepts the forgiving spellings a person types", async () => {
    const s = setup();
    const minted = await s.tickets.mint("u1");
    const sloppy = ` ${minted.manualCode!.toLowerCase().replace("-", " ")} `;
    expect(normaliseManualCode(sloppy)).toBe(minted.manualCode!.replace("-", ""));
    expect(await s.tickets.scan({ manualCode: sloppy })).not.toBeNull();
  });

  it("refuses a code that matches no live ticket, and is not a code at all", async () => {
    const s = setup();
    await s.tickets.mint("u1");
    expect(await s.tickets.scan({ manualCode: "ZZZZ-ZZZZ" })).toBeNull();
    expect(await s.tickets.scan({ manualCode: "not a code" })).toBeNull();
    expect(await s.tickets.scan({ manualCode: "" })).toBeNull();
  });

  it("refuses when two live tickets derive the same code — the only answer that cannot connect the wrong account", async () => {
    const s = setup();
    const a = await s.tickets.mint("u1");
    const b = await s.tickets.mint("u2");
    // Force the collision: give u2's row u1's digest.
    s.store.rows.get(b.id)!.ticketHash = s.store.rows.get(a.id)!.ticketHash;
    expect(await s.tickets.scan({ manualCode: a.manualCode! })).toBeNull();
  });

  it("refuses above the pending ceiling rather than scanning without bound", async () => {
    const s = setup({ maxPendingScan: 2 });
    const codes = await Promise.all(["u1", "u2", "u3"].map((u) => s.tickets.mint(u)));
    expect(await s.tickets.scan({ manualCode: codes[0]!.manualCode! })).toBeNull();
    // The QR is unaffected by the ceiling.
    expect(await s.tickets.scan({ ticket: codes[0]!.ticket })).not.toBeNull();
  });

  it("without a key there is no code: mint returns null and typed codes refuse", async () => {
    const s = setup({ withCode: false });
    const minted = await s.tickets.mint("u1");
    expect(minted.manualCode).toBeNull();
    expect(await s.tickets.scan({ manualCode: "ABCD-EFGH" })).toBeNull();
  });
});

describe("link tickets — input shapes", () => {
  it("refuses a ticket or nonce that is not 43 base64url characters without touching the store", async () => {
    const s = setup();
    await s.tickets.mint("u1");
    const before = s.store.updates.length;
    expect(await s.tickets.scan({ ticket: "short" })).toBeNull();
    expect(await s.tickets.scan({ ticket: "A".repeat(44) })).toBeNull();
    expect(await s.tickets.complete({ ticket: "A".repeat(43) }, "bad")).toEqual({ ok: false, reason: "invalid" });
    expect(await s.tickets.complete({ ticketId: "" }, "A".repeat(43))).toEqual({ ok: false, reason: "invalid" });
    expect(s.store.updates.length).toBe(before);
  });

  it("refuses empty ids", async () => {
    const s = setup();
    expect(await s.tickets.read("", "t1")).toBeNull();
    expect(await s.tickets.confirm("u1", "")).toBe(false);
    expect(await s.tickets.cancel("", "t1")).toBe(false);
    expect(await s.tickets.burn("", "sign_out")).toBe(0);
    expect(await s.tickets.claimEnrolment("", "u1")).toBe(false);
    await expect(s.tickets.mint("")).rejects.toThrow(TypeError);
  });

  it("a scan without meta leaves the row's meta null; with meta, stores it as given", async () => {
    const s = setup();
    const a = await s.tickets.mint("u1");
    await s.tickets.scan({ ticket: a.ticket });
    expect((await s.tickets.read("u1", a.id))?.meta).toBeNull();
    const b = await s.tickets.mint("u2");
    await s.tickets.scan({ ticket: b.ticket }, { model: null, platform: "ios" });
    expect((await s.tickets.read("u2", b.id))?.meta).toEqual({ model: null, platform: "ios" });
  });
});
