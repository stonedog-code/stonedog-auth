/**
 * An in-memory `LinkTicketStore` whose `updateMany` is GENUINELY conditional:
 * every field of the where-clause is checked against the row at write time,
 * so a test that races two callers sees exactly one of them move the row.
 * Shared by the link-ticket suites; not a test file itself.
 */
import type {
  LinkTicketPatch,
  LinkTicketStore,
  LinkTicketWhere,
  NewLinkTicket,
  StoredLinkTicket,
} from "../link-ticket.js";

export interface FakeRow extends StoredLinkTicket {
  createdAt: Date;
  cancelReason: string | null;
  scannedAt: Date | null;
  confirmedAt: Date | null;
  consumedAt: Date | null;
  cancelledAt: Date | null;
}

export interface FakeLinkStore extends LinkTicketStore {
  rows: Map<string, FakeRow>;
  updates: Array<{ where: LinkTicketWhere; data: LinkTicketPatch; moved: number }>;
}

export function matches(row: FakeRow, where: LinkTicketWhere): boolean {
  if (where.id !== undefined && row.id !== where.id) return false;
  if (where.ticketHash !== undefined && row.ticketHash !== where.ticketHash) return false;
  if (where.subjectId !== undefined && row.subjectId !== where.subjectId) return false;
  if (where.nonceHash !== undefined && row.nonceHash !== where.nonceHash) return false;
  if (where.state !== undefined) {
    const states = typeof where.state === "string" ? [where.state] : where.state;
    if (!states.includes(row.state)) return false;
  }
  if (where.expiresAfter !== undefined && !(row.expiresAt.getTime() > where.expiresAfter.getTime())) return false;
  if (where.enrolled !== undefined && (row.enrolledAt !== null) !== where.enrolled) return false;
  return true;
}

export function fakeLinkStore(): FakeLinkStore {
  const rows = new Map<string, FakeRow>();
  const updates: FakeLinkStore["updates"] = [];
  let seq = 0;
  return {
    rows,
    updates,
    async insert(row: NewLinkTicket) {
      const id = `t${++seq}`;
      rows.set(id, {
        id,
        subjectId: row.subjectId,
        ticketHash: row.ticketHash,
        state: row.state,
        nonceHash: null,
        expiresAt: row.expiresAt,
        enrolledAt: null,
        meta: null,
        createdAt: row.createdAt,
        cancelReason: null,
        scannedAt: null,
        confirmedAt: null,
        consumedAt: null,
        cancelledAt: null,
      });
      return { id };
    },
    async findOne(where) {
      for (const row of rows.values()) if (matches(row, where)) return { ...row };
      return null;
    },
    async findPending(now) {
      return [...rows.values()]
        .filter((r) => r.state === "pending" && r.expiresAt.getTime() > now.getTime())
        .map((r) => ({ ticketHash: r.ticketHash }));
    },
    async updateMany(where, data) {
      let moved = 0;
      for (const row of rows.values()) {
        if (!matches(row, where)) continue;
        Object.assign(row, data);
        moved += 1;
      }
      updates.push({ where, data, moved });
      return moved;
    },
  };
}
