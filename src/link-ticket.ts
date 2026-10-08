/**
 * The cross-device LINK TICKET — the state machine behind "connect a phone".
 *
 * A signed-in website shows a QR code (or a short manual code). A phone with
 * no session presents it. The website is shown what presented it and confirms
 * or cancels. The phone then collects, once, and the host issues it whatever
 * the connection is for — an enrolment token, a session. Two holders, and a
 * third party's decision between them, so the ticket string stays stable
 * while the row's STATE moves. That is why neither `createSignInTickets`
 * (single-holder; `advance` consumes and re-issues) nor `createTokenIssuer`
 * (`claim` cannot say "confirmed AND this phone's nonce") could carry it.
 *
 * ## The lifecycle, and who moves it
 *
 *   pending ──scan (phone)──▶ scanned ──confirm (website)──▶ confirmed
 *      ──complete (phone)──▶ consumed ──claimEnrolment (host)──▶ consumed, enrolled
 *
 * `cancel` (website), `burn` (website sign-out, or a newer ticket superseding)
 * and `cancelFromPhone` (the phone holding its nonce) move any RETIRABLE row
 * to `cancelled` — retirable being every live state, and `consumed` with no
 * `enrolledAt` yet, so a sign-out after confirmation also kills the enrolment
 * the phone has not used. `expiresAt` is set once at mint and every
 * transition requires it in the future: a ticket is dead 120 s after it was
 * minted whatever state it is in. `expired` is a VIEW the poll derives; the
 * row keeps its last state.
 *
 * ## The one rule everything rests on
 *
 * **Every transition is one conditional update with the FROM state in its
 * where-clause.** Of two concurrent callers exactly one moves the row and the
 * other sees `0`. The server decides from what IT stored — the ticket's
 * digest, the nonce's digest, the state, the expiry — never from anything the
 * client sends back. That is what makes the ticket single-use at every step
 * without a lock, and it is the property the defect this was lifted from
 * (hopper-web NEH-1899) lacked.
 *
 * ## What the host keeps
 *
 * The row, the database, the transaction and RLS context, rate limits,
 * logging, the email for "Connect this phone to <email>?" (the package returns
 * a `subjectId`; `Subject` carries no email on purpose), and the enrolment
 * token it mints when `complete` succeeds. The port below is deliberately
 * dumb: a closed where-clause and a closed patch, each field mapping to one
 * column. The host adds no logic, which is the point — the replay rules
 * cannot drift between consumers because a consumer has nowhere to put them.
 */

import { manualCodeForTicketHash, manualCodesEqual, normaliseManualCode, formatManualCode } from "./manual-code.js";
import { generateToken, hashToken, tokenHashEquals, type TokenHashEncoding } from "./tokens.js";
import { systemClock, type Clock } from "./types.js";

export type LinkTicketState = "pending" | "scanned" | "confirmed" | "consumed" | "cancelled";
/** What the website's poll reports. `expired` is derived; the row keeps its last state. */
export type LinkTicketView = LinkTicketState | "expired";

/** States a ticket can still be moved out of. */
export const LIVE_LINK_STATES: readonly LinkTicketState[] = Object.freeze(["pending", "scanned", "confirmed"] as const);

export type LinkCancelReason = "cancelled" | "sign_out" | "superseded" | "phone_cancelled";

/**
 * Host-opaque details recorded at scan — device model, platform, app version —
 * for the website's "Connect <device>?" screen. The package never interprets
 * it. Stored as the host sees fit (a JSON column, or one column per key); a
 * store on a backend without JSON serialises it itself.
 */
export type LinkTicketMeta = Record<string, string | null>;

/** One ticket, as the host stores it. */
export interface StoredLinkTicket {
  id: string;
  subjectId: string;
  ticketHash: string;
  state: LinkTicketState;
  nonceHash: string | null;
  expiresAt: Date;
  enrolledAt: Date | null;
  meta: LinkTicketMeta | null;
}

/** What `mint` inserts. The host assigns the id. */
export interface NewLinkTicket {
  subjectId: string;
  ticketHash: string;
  state: "pending";
  expiresAt: Date;
  createdAt: Date;
}

/**
 * A closed where-clause. Every present field is an AND-ed equality, except
 * `state` (one value, or any of a list), `expiresAfter` (`expiresAt > value`)
 * and `enrolled` (`enrolledAt IS NOT NULL` / `IS NULL`). The host translates
 * each field to its column and adds nothing.
 *
 * `expiresAfter` is a millisecond `Date`; compare it with whatever precision
 * the column has. A ticket at the exact boundary is refused one way or the
 * other, and a second later it is refused every way.
 */
export interface LinkTicketWhere {
  id?: string;
  ticketHash?: string;
  subjectId?: string;
  nonceHash?: string;
  state?: LinkTicketState | readonly LinkTicketState[];
  expiresAfter?: Date;
  enrolled?: boolean;
}

/** A closed patch. Only present fields change. */
export interface LinkTicketPatch {
  state?: LinkTicketState;
  nonceHash?: string;
  meta?: LinkTicketMeta;
  scannedAt?: Date;
  confirmedAt?: Date;
  consumedAt?: Date;
  cancelledAt?: Date;
  cancelReason?: LinkCancelReason;
  enrolledAt?: Date;
}

/**
 * The storage this needs.
 *
 * `updateMany` must be **one conditional write** — `UPDATE … SET … WHERE
 * <every field of where>` — returning the number of rows it changed. A
 * read-then-write implementation satisfies the types and breaks the one rule
 * above. `findPending` serves the manual code only: the pending, unexpired
 * tickets' digests.
 *
 * `mint` calls `updateMany` (supersede) and then `insert` as two operations.
 * Two mints racing for one subject can leave two pending tickets — both the
 * subject's own, each still single-use — so a host that can wrap the two in a
 * transaction (a store bound to one) should.
 */
export interface LinkTicketStore {
  insert(row: NewLinkTicket): Promise<{ id: string }>;
  findOne(where: LinkTicketWhere): Promise<StoredLinkTicket | null>;
  findPending(now: Date): Promise<ReadonlyArray<{ ticketHash: string }>>;
  updateMany(where: LinkTicketWhere, data: LinkTicketPatch): Promise<number>;
}

export interface LinkTicketOptions {
  store: LinkTicketStore;
  /** From mint, whatever the state. 120 s: long enough to scan and confirm, short enough that a QR left on a screen dies. */
  ttlSeconds?: number;
  clock?: Clock;
  /** Digest encoding for the ticket and nonce hashes. Must match the store's existing rows (see `createTokenIssuer`). */
  hashEncoding?: TokenHashEncoding;
  /**
   * The key the manual code is derived under (`manualCodeKeyFrom`). Without
   * one, `mint` returns no manual code and `scan({ manualCode })` refuses —
   * the QR still works.
   */
  manualCodeKey?: Uint8Array;
  /**
   * `scan({ manualCode })` reads every pending ticket and HMACs each. The pool
   * is bounded by the TTL and by `mint` superseding — at most one live ticket
   * per subject mid-connect — but a host under pressure gets a ceiling rather
   * than an unbounded scan: above it the manual code refuses (null) and the
   * QR is unaffected.
   */
  maxPendingScan?: number;
}

/** How the phone names its ticket: the ticket itself (it scanned the QR), or the row id (it typed the code and never held the ticket). */
export type LinkTicketRef = { ticket: string } | { ticketId: string };

export interface MintedLinkTicket {
  id: string;
  /** Send this to the browser once, as the QR payload. Never store it, never log it. */
  ticket: string;
  /** `ABCD-EFGH`, or null when no `manualCodeKey` was configured. Shown beside the QR; never stored, never logged. */
  manualCode: string | null;
  expiresAt: Date;
}

export interface ScannedLinkTicket {
  ticketId: string;
  subjectId: string;
  /** Hand this to the scanning phone once; it must present it at `complete`. Never store it, never log it. */
  nonce: string;
  expiresAt: Date;
}

export interface LinkTicketStatus {
  id: string;
  state: LinkTicketView;
  meta: LinkTicketMeta | null;
  expiresAt: Date;
}

export type CompleteLinkOutcome =
  | { ok: true; ticketId: string; subjectId: string }
  /** The website has not confirmed yet. The phone keeps polling. */
  | { ok: false; reason: "waiting" }
  /** Unknown, expired, cancelled, consumed, or not this phone's nonce. */
  | { ok: false; reason: "invalid" };

export interface LinkTickets {
  /** The website mints. Every live ticket the subject holds is cancelled as `superseded` first, so only one QR ever works. */
  mint(subjectId: string): Promise<MintedLinkTicket>;
  /**
   * A phone presented the ticket (from the QR) or typed the manual code.
   * `pending → scanned`, exactly once; records `meta`; mints the nonce that
   * phone — and only that phone — needs at `complete`. Null for a ticket or
   * code that is unknown, expired, already scanned, cancelled or consumed.
   * The caller answers all of those identically.
   */
  scan(by: { ticket: string } | { manualCode: string }, meta?: LinkTicketMeta): Promise<ScannedLinkTicket | null>;
  /** The website's poll: its own ticket, with `expired` derived, or null. */
  read(subjectId: string, id: string): Promise<LinkTicketStatus | null>;
  /** The website confirmed the phone it was shown. `scanned → confirmed`, once. */
  confirm(subjectId: string, id: string): Promise<boolean>;
  /** The website cancelled one ticket. Any retirable state → `cancelled`, once. */
  cancel(subjectId: string, id: string, reason?: LinkCancelReason): Promise<boolean>;
  /** Every retirable ticket the subject holds → `cancelled`. Call it on sign-out. Returns how many. */
  burn(subjectId: string, reason: LinkCancelReason): Promise<number>;
  /**
   * The scanning phone collects. `confirmed → consumed`, exactly once, for
   * the phone holding the nonce minted at scan. `waiting` while the website
   * has not decided; `invalid` for everything else.
   */
  complete(ref: LinkTicketRef, nonce: string): Promise<CompleteLinkOutcome>;
  /**
   * The phone backed out. Retires the ticket as the website's Cancel would,
   * authorised by the nonce — so a `pending` row (no phone yet) cannot be
   * touched from here. Returns the ticket this call moved, or null.
   */
  cancelFromPhone(ref: LinkTicketRef, nonce: string): Promise<{ ticketId: string; subjectId: string } | null>;
  /**
   * The enrolment the host issued at `complete` registers ONE thing. Call this
   * before registering; the second call for the same ticket finds `enrolledAt`
   * set and gets false, so a replayed enrolment token plants nothing.
   */
  claimEnrolment(ticketId: string, subjectId: string): Promise<boolean>;
}

/** 32 random bytes as base64url — `generateToken`'s shape, and `parseConnectQr`'s. */
const OPAQUE = /^[A-Za-z0-9_-]{43}$/;
const ID_MAX = 128;

function isOpaque(value: unknown): value is string {
  return typeof value === "string" && OPAQUE.test(value);
}

function isId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= ID_MAX;
}

export function createLinkTickets(options: LinkTicketOptions): LinkTickets {
  const ttlMs = (options.ttlSeconds ?? 120) * 1000;
  const clock = options.clock ?? systemClock;
  const encoding = options.hashEncoding ?? "hex";
  const codeKey = options.manualCodeKey;
  const maxPendingScan = options.maxPendingScan ?? 1000;
  const { store } = options;

  const digest = (secret: string) => hashToken(secret, encoding);

  function refWhere(ref: LinkTicketRef): LinkTicketWhere | null {
    if ("ticket" in ref) return isOpaque(ref.ticket) ? { ticketHash: digest(ref.ticket) } : null;
    return isId(ref.ticketId) ? { id: ref.ticketId } : null;
  }

  function view(state: LinkTicketState, expiresAt: Date, now: Date): LinkTicketView {
    return LIVE_LINK_STATES.includes(state) && expiresAt.getTime() <= now.getTime() ? "expired" : state;
  }

  /** Retire: every live row matching `where`, plus a consumed one whose enrolment is unused. Two disjoint sets, one atomic write each. */
  async function retire(where: LinkTicketWhere, reason: LinkCancelReason, now: Date): Promise<number> {
    const data: LinkTicketPatch = { state: "cancelled", cancelledAt: now, cancelReason: reason };
    const live = await store.updateMany({ ...where, state: LIVE_LINK_STATES }, data);
    const unenrolled = await store.updateMany({ ...where, state: "consumed", enrolled: false }, data);
    return live + unenrolled;
  }

  async function scanByHash(ticketHash: string, meta: LinkTicketMeta | undefined, now: Date): Promise<ScannedLinkTicket | null> {
    const nonce = generateToken();
    const patch: LinkTicketPatch = { state: "scanned", scannedAt: now, nonceHash: digest(nonce) };
    if (meta !== undefined) patch.meta = meta;
    const moved = await store.updateMany({ ticketHash, state: "pending", expiresAfter: now }, patch);
    if (moved !== 1) return null;
    const row = await store.findOne({ ticketHash });
    if (!row) return null;
    return { ticketId: row.id, subjectId: row.subjectId, nonce, expiresAt: row.expiresAt };
  }

  return {
    async mint(subjectId) {
      if (!isId(subjectId)) throw new TypeError("A subject id is required to mint a link ticket.");
      const now = clock.now();
      const ticket = generateToken();
      const ticketHash = digest(ticket);
      const expiresAt = new Date(now.getTime() + ttlMs);
      // Supersede FIRST. If the insert below fails the subject has no live
      // ticket and must press the button again — strictly safer than the
      // other order, which leaves two QR codes working when the supersede is
      // what failed.
      await retire({ subjectId }, "superseded", now);
      const { id } = await store.insert({ subjectId, ticketHash, state: "pending", expiresAt, createdAt: now });
      const manualCode = codeKey ? formatManualCode(manualCodeForTicketHash(ticketHash, codeKey)) : null;
      return { id, ticket, manualCode, expiresAt };
    },

    async scan(by, meta) {
      const now = clock.now();
      if ("ticket" in by) {
        if (!isOpaque(by.ticket)) return null;
        return scanByHash(digest(by.ticket), meta, now);
      }
      if (!codeKey) return null;
      const code = normaliseManualCode(by.manualCode);
      if (code === null) return null;
      const pending = await store.findPending(now);
      if (pending.length > maxPendingScan) return null;
      const hits = pending.filter((row) => manualCodesEqual(manualCodeForTicketHash(row.ticketHash, codeKey), code));
      // Exactly one. Two matches (one in ~10^11 per pair at 40 bits) refuse:
      // that is the only answer that cannot connect the wrong account.
      if (hits.length !== 1) return null;
      return scanByHash(hits[0]!.ticketHash, meta, now);
    },

    async read(subjectId, id) {
      if (!isId(subjectId) || !isId(id)) return null;
      const row = await store.findOne({ id, subjectId });
      if (!row) return null;
      return { id: row.id, state: view(row.state, row.expiresAt, clock.now()), meta: row.meta, expiresAt: row.expiresAt };
    },

    async confirm(subjectId, id) {
      if (!isId(subjectId) || !isId(id)) return false;
      const now = clock.now();
      const moved = await store.updateMany(
        { id, subjectId, state: "scanned", expiresAfter: now },
        { state: "confirmed", confirmedAt: now },
      );
      return moved === 1;
    },

    async cancel(subjectId, id, reason = "cancelled") {
      if (!isId(subjectId) || !isId(id)) return false;
      return (await retire({ id, subjectId }, reason, clock.now())) === 1;
    },

    async burn(subjectId, reason) {
      if (!isId(subjectId)) return 0;
      return retire({ subjectId }, reason, clock.now());
    },

    async complete(ref, nonce) {
      const where = refWhere(ref);
      if (!where || !isOpaque(nonce)) return { ok: false, reason: "invalid" };
      const now = clock.now();
      const nonceHash = digest(nonce);
      const row = await store.findOne(where);
      if (!row || row.nonceHash === null || !tokenHashEquals(row.nonceHash, nonceHash)) return { ok: false, reason: "invalid" };
      if (row.expiresAt.getTime() <= now.getTime()) return { ok: false, reason: "invalid" };
      if (row.state === "scanned") return { ok: false, reason: "waiting" };
      if (row.state !== "confirmed") return { ok: false, reason: "invalid" };
      // The read above only chose the answer; the WRITE decides. Its where
      // repeats every condition, so a concurrent complete, cancel or expiry
      // between the two leaves this caller with 0 and "invalid".
      const moved = await store.updateMany(
        { id: row.id, nonceHash, state: "confirmed", expiresAfter: now },
        { state: "consumed", consumedAt: now },
      );
      if (moved !== 1) return { ok: false, reason: "invalid" };
      return { ok: true, ticketId: row.id, subjectId: row.subjectId };
    },

    async cancelFromPhone(ref, nonce) {
      const where = refWhere(ref);
      if (!where || !isOpaque(nonce)) return null;
      const nonceHash = digest(nonce);
      const row = await store.findOne(where);
      if (!row || row.nonceHash === null || !tokenHashEquals(row.nonceHash, nonceHash)) return null;
      // `nonceHash` in the where: a pending row has none, so it can never match.
      const moved = await retire({ id: row.id, nonceHash }, "phone_cancelled", clock.now());
      if (moved !== 1) return null;
      return { ticketId: row.id, subjectId: row.subjectId };
    },

    async claimEnrolment(ticketId, subjectId) {
      if (!isId(ticketId) || !isId(subjectId)) return false;
      const moved = await store.updateMany(
        { id: ticketId, subjectId, state: "consumed", enrolled: false },
        { enrolledAt: clock.now() },
      );
      return moved === 1;
    },
  };
}
