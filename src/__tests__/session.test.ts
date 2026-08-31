/**
 * Copyright (C) 2026 StoneDogCode L.L.C. All rights reserved.
 *
 * The rule these assertions exist for, stated once: a revocation must be
 * compared against when a session was ESTABLISHED, never against when its
 * current token was ISSUED. The two diverge because tokens are re-minted, and
 * every test below is a way of pinning that divergence.
 */

import {
  carrySessionEstablishment,
  establishSession,
  isSessionCurrent,
  SESSION_ESTABLISHED_CLAIM,
} from "../session.js";
import type { Clock } from "../types.js";

const at = (iso: string): Clock => ({ now: () => new Date(iso) });

describe("isSessionCurrent", () => {
  it("honours every session when nothing has ever been revoked", () => {
    // Most accounts. They should not pay for a check that cannot fire.
    expect(isSessionCurrent(1_700_000_000, null)).toBe(true);
    expect(isSessionCurrent(1_700_000_000, undefined)).toBe(true);
    // …including one whose claim is missing, because there is nothing to
    // compare it against yet.
    expect(isSessionCurrent(null, null)).toBe(true);
  });

  it("refuses a session established BEFORE the revocation", () => {
    const revoked = new Date("2026-08-31T12:00:00.000Z");
    expect(isSessionCurrent(Math.floor(revoked.getTime() / 1000) - 1, revoked)).toBe(false);
  });

  it("honours a session established AFTER the revocation", () => {
    const revoked = new Date("2026-08-31T12:00:00.000Z");
    expect(isSessionCurrent(Math.floor(revoked.getTime() / 1000) + 1, revoked)).toBe(true);
  });

  it("honours one established in the SAME second, which is what keeps the actor signed in", () => {
    /*
      The person who just changed their password re-establishes their own
      session in the same instant the revocation is stamped. Comparing with `>`
      would sign them out of the act they just performed — which reads as the
      change having failed, and is the bug on the other side of this coin.
    */
    const revoked = new Date("2026-08-31T12:00:00.750Z");
    expect(isSessionCurrent(Math.floor(revoked.getTime() / 1000), revoked)).toBe(true);
  });

  it("FAILS CLOSED on a claim it cannot read, once a revocation exists", () => {
    const revoked = new Date("2026-08-31T12:00:00.000Z");
    for (const bad of [null, undefined, NaN, Infinity, -Infinity]) {
      expect(isSessionCurrent(bad as number, revoked)).toBe(false);
    }
  });
});

describe("carrySessionEstablishment — the half that closes the hole", () => {
  it("copies a valid claim forward unchanged", () => {
    // The whole mechanism: a re-mint must inherit this value, not regenerate it.
    expect(carrySessionEstablishment({ [SESSION_ESTABLISHED_CLAIM]: 1_700_000_000 })).toBe(
      1_700_000_000,
    );
  });

  it("returns null rather than 'now' when the claim is absent", () => {
    /*
      The single most important assertion in this file.

      Defaulting a missing claim to the current time is the tempting,
      friendly-looking choice, and it silently reinstates the exact defect: a
      token that lost the claim would come back as freshly established and a
      revoked session would renew itself forever. `null` then fails closed in
      `isSessionCurrent`, so the person signs in again — the cheap failure.
    */
    expect(carrySessionEstablishment({})).toBeNull();
    expect(carrySessionEstablishment(null)).toBeNull();
    expect(carrySessionEstablishment(undefined)).toBeNull();
  });

  it("rejects a claim of the wrong shape rather than coercing it", () => {
    for (const bad of ["1700000000", true, {}, [], NaN, Infinity, -1]) {
      expect(carrySessionEstablishment({ [SESSION_ESTABLISHED_CLAIM]: bad })).toBeNull();
    }
  });

  it("survives repeated re-mints without drifting", () => {
    /*
      A re-mint chain is the production case — NextAuth re-issues on every
      session read, so a token can be re-minted hundreds of times in a day. The
      value must be identical at the end, or the session ages out of its own
      revocation window by accident.
    */
    let claims = { [SESSION_ESTABLISHED_CLAIM]: establishSession(at("2026-08-31T12:00:00.000Z")) };
    const original = claims[SESSION_ESTABLISHED_CLAIM];
    for (let i = 0; i < 200; i += 1) {
      const carried = carrySessionEstablishment(claims);
      expect(carried).not.toBeNull();
      claims = { [SESSION_ESTABLISHED_CLAIM]: carried as number };
    }
    expect(claims[SESSION_ESTABLISHED_CLAIM]).toBe(original);
  });
});

describe("the defect this module exists to prevent", () => {
  it("a re-mint does NOT launder a revocation", () => {
    /*
      The regression test for the live finding. Written as the sequence that
      actually happened in a browser:

        1. a session is established
        2. a password change revokes everything established before now
        3. the revoked device's token is RE-MINTED — new `iat`, same session
        4. it must still be refused

      Step 4 is what fails if anyone compares against the token's issue time.
    */
    const established = establishSession(at("2026-08-31T12:00:00.000Z"));
    const revokedAt = new Date("2026-08-31T12:05:00.000Z");

    expect(isSessionCurrent(established, revokedAt)).toBe(false);

    // The re-mint. A fresh `iat` would be 12:06 — later than the revocation,
    // and it is precisely the value that must NOT be consulted.
    const remintedIat = Math.floor(new Date("2026-08-31T12:06:00.000Z").getTime() / 1000);
    const carried = carrySessionEstablishment({ [SESSION_ESTABLISHED_CLAIM]: established });

    expect(carried).toBe(established);
    expect(isSessionCurrent(carried, revokedAt)).toBe(false);

    // And the proof the distinction is real: consulting the re-minted issue
    // time instead would have let it straight back in.
    expect(isSessionCurrent(remintedIat, revokedAt)).toBe(true);
  });

  it("a genuine re-authentication DOES restore access", () => {
    // The other direction, so the guard is not simply "always refuse". Signing
    // in again establishes a new session, after the revocation.
    const revokedAt = new Date("2026-08-31T12:05:00.000Z");
    const reEstablished = establishSession(at("2026-08-31T12:06:00.000Z"));
    expect(isSessionCurrent(reEstablished, revokedAt)).toBe(true);
  });
});

describe("establishSession", () => {
  it("is whole seconds, matching the granularity of the comparison", () => {
    expect(establishSession(at("2026-08-31T12:00:00.999Z"))).toBe(
      Math.floor(new Date("2026-08-31T12:00:00.999Z").getTime() / 1000),
    );
  });

  it("takes an injected clock, so a test names the instant", () => {
    expect(establishSession(at("2020-01-01T00:00:00.000Z"))).toBe(1_577_836_800);
  });
});
