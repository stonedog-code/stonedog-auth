import {
  createTotpFactor,
  defaultTotpParams,
  fromBase32,
  generateTotpSecret,
  toBase32,
  totpCodeAt,
  totpProvisioningUri,
  verifyTotpCode,
  type TotpReplayStore,
} from "../totp";

/**
 * RFC 4226 Appendix D — the published HOTP test vectors for the ASCII secret
 * "12345678901234567890".
 *
 * Worth having rather than asserting our own output against itself: a test that
 * only checks self-consistency passes happily against an implementation that
 * agrees with nobody else's authenticator app.
 */
const RFC_SECRET = toBase32(Buffer.from("12345678901234567890", "ascii"));
const RFC_HOTP = [
  "755224",
  "287082",
  "359152",
  "969429",
  "338314",
  "254676",
  "287922",
  "162583",
  "399871",
  "520489",
];

function replayStore(): TotpReplayStore & { used: Map<string, number> } {
  const used = new Map<string, number>();
  return {
    used,
    lastUsedStep: async (subjectId) => used.get(subjectId) ?? null,
    recordUsedStep: async (subjectId, step) => {
      used.set(subjectId, step);
    },
  };
}

describe("base32", () => {
  it("round-trips", () => {
    const original = Buffer.from("12345678901234567890", "ascii");
    expect(fromBase32(toBase32(original))).toEqual(original);
  });

  it("tolerates the spacing and padding people retype off a screen", () => {
    const secret = toBase32(Buffer.from("hello world!", "ascii"));
    const mangled = `${secret.toLowerCase().slice(0, 4)} ${secret.toLowerCase().slice(4)}==`;
    expect(fromBase32(mangled)).toEqual(fromBase32(secret));
  });

  it("refuses a character that is not in the alphabet", () => {
    expect(() => fromBase32("ABC1")).toThrow(/base32/i);
  });
});

describe("against the RFC 4226 vectors", () => {
  it("produces the published codes for counters 0-9", () => {
    RFC_HOTP.forEach((expected, counter) => {
      // TOTP counter = floor(unix seconds / step), so a given counter is
      // reproduced by picking the instant that yields it.
      const at = new Date(counter * defaultTotpParams.stepSeconds * 1000);
      expect(totpCodeAt(RFC_SECRET, at)).toBe(expected);
    });
  });
});

describe("verifying a code", () => {
  const at = new Date("2026-08-07T12:00:00Z");
  const secret = generateTotpSecret();

  it("accepts the current code", () => {
    expect(verifyTotpCode(secret, totpCodeAt(secret, at), { at }).ok).toBe(true);
  });

  it("accepts one step either side, for clock drift", () => {
    const before = new Date(at.getTime() - 30_000);
    const after = new Date(at.getTime() + 30_000);
    expect(verifyTotpCode(secret, totpCodeAt(secret, before), { at }).ok).toBe(true);
    expect(verifyTotpCode(secret, totpCodeAt(secret, after), { at }).ok).toBe(true);
  });

  it("refuses two steps away with the default window", () => {
    // Each extra step multiplies the guess space an attacker gets per attempt.
    const stale = new Date(at.getTime() - 90_000);
    expect(verifyTotpCode(secret, totpCodeAt(secret, stale), { at }).ok).toBe(false);
  });

  it("refuses anything that is not the right shape, without hashing", () => {
    expect(verifyTotpCode(secret, "12345", { at }).ok).toBe(false);
    expect(verifyTotpCode(secret, "1234567", { at }).ok).toBe(false);
    expect(verifyTotpCode(secret, "abcdef", { at }).ok).toBe(false);
    expect(verifyTotpCode(secret, "", { at }).ok).toBe(false);
  });

  it("reports which step matched, so single-use can be enforced", () => {
    const result = verifyTotpCode(secret, totpCodeAt(secret, at), { at });
    expect(result.ok && typeof result.step).toBe("number");
  });

  it("handles a counter above 2^32 without truncating", () => {
    // A bitwise shift in JavaScript truncates to 32 bits, which would break
    // silently in 2038 and pass every test written before then.
    const far = new Date(Date.UTC(2200, 0, 1));
    expect(() => totpCodeAt(secret, far)).not.toThrow();
    expect(verifyTotpCode(secret, totpCodeAt(secret, far), { at: far }).ok).toBe(true);
  });
});

describe("replay protection", () => {
  const at = new Date("2026-08-07T12:00:00Z");

  it("accepts a code once and refuses the same code again", () => {
    // RFC 6238 §5.2. Without this, anyone who reads the code over a shoulder
    // can use it too, for the rest of the step.
    const secret = generateTotpSecret();
    const store = replayStore();
    const factor = createTotpFactor({ store, clock: { now: () => at } });
    const code = totpCodeAt(secret, at);

    return factor
      .verify("user-1", secret, code)
      .then((first) => {
        expect(first.ok).toBe(true);
        return factor.verify("user-1", secret, code);
      })
      .then((second) => {
        expect(second.ok).toBe(false);
      });
  });

  it("refuses an EARLIER step once a later one has been spent", async () => {
    // `<=`, not `===`. Rejecting only an exact repeat still accepts a code
    // captured one step ago, which replays successfully after a newer one is
    // used — a subtle hole that an equality check leaves wide open.
    const secret = generateTotpSecret();
    const store = replayStore();
    const factor = createTotpFactor({ store, clock: { now: () => at } });

    const previousStepCode = totpCodeAt(secret, new Date(at.getTime() - 30_000));
    await factor.verify("user-1", secret, totpCodeAt(secret, at));

    await expect(factor.verify("user-1", secret, previousStepCode)).resolves.toEqual({
      ok: false,
    });
  });

  it("tracks replay per subject, not globally", async () => {
    const secret = generateTotpSecret();
    const store = replayStore();
    const factor = createTotpFactor({ store, clock: { now: () => at } });
    const code = totpCodeAt(secret, at);

    await factor.verify("user-1", secret, code);
    // A different person's identical code must still work — they are different
    // secrets in practice, but the store must not be keyed globally.
    await expect(factor.verify("user-2", secret, code)).resolves.toEqual({ ok: true });
  });

  it("does not record a step for a code that failed", async () => {
    const secret = generateTotpSecret();
    const store = replayStore();
    const factor = createTotpFactor({ store, clock: { now: () => at } });

    await factor.verify("user-1", secret, "000000");
    expect(store.used.has("user-1")).toBe(false);
  });
});

describe("the provisioning URI", () => {
  it("names the issuer twice, because apps disagree about which one they read", () => {
    const uri = totpProvisioningUri("JBSWY3DPEHPK3PXP", {
      account: "person@example.com",
      issuer: "Example",
    });
    expect(uri).toContain("otpauth://totp/Example:person%40example.com");
    expect(uri).toContain("issuer=Example");
  });

  it("escapes an issuer containing a colon or a space", () => {
    const uri = totpProvisioningUri("JBSWY3DPEHPK3PXP", {
      account: "a@b.com",
      issuer: "Big Co: Ltd",
    });
    // An unescaped colon in the label breaks the issuer/account split.
    expect(uri).toContain("otpauth://totp/Big%20Co%3A%20Ltd:a%40b.com");
  });

  it("declares the parameters the code was generated with", () => {
    const uri = totpProvisioningUri(generateTotpSecret(), {
      account: "a@b.com",
      issuer: "Example",
    });
    expect(uri).toContain("algorithm=SHA1");
    expect(uri).toContain("digits=6");
    expect(uri).toContain("period=30");
  });
});

describe("generated secrets", () => {
  it("are 160 bits, which is what authenticator apps assume", () => {
    expect(fromBase32(generateTotpSecret())).toHaveLength(20);
  });

  it("do not repeat", () => {
    const seen = new Set(Array.from({ length: 200 }, () => generateTotpSecret()));
    expect(seen.size).toBe(200);
  });
});
