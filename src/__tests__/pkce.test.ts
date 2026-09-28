import { createHash } from "node:crypto";

import { AuthError } from "../errors.js";
import { pkceChallengeS256, verifyPkceS256 } from "../pkce.js";

// RFC 7636 Appendix B's published example — agreement with the RFC, not only
// with ourselves.
const RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("pkceChallengeS256", () => {
  it("matches the RFC 7636 Appendix B vector", () => {
    expect(pkceChallengeS256(RFC_VERIFIER)).toBe(RFC_CHALLENGE);
  });

  it("is base64url SHA-256 of the ASCII verifier", () => {
    const v = "a".repeat(43);
    expect(pkceChallengeS256(v)).toBe(createHash("sha256").update(v).digest("base64url"));
  });

  it.each([
    ["42 chars (too short)", "a".repeat(42)],
    ["129 chars (too long)", "a".repeat(129)],
    ["a reserved character", `${"a".repeat(42)}+`],
    ["a space", `${"a".repeat(42)} `],
    ["empty", ""],
  ])("refuses a verifier with %s, without echoing it", (_label, verifier) => {
    let thrown: unknown;
    try {
      pkceChallengeS256(verifier);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(AuthError);
    if (verifier.length > 0) expect((thrown as Error).message).not.toContain(verifier);
  });

  it("accepts both boundary lengths and the full unreserved set", () => {
    expect(() => pkceChallengeS256("a".repeat(43))).not.toThrow();
    expect(() => pkceChallengeS256("a".repeat(128))).not.toThrow();
    expect(() => pkceChallengeS256(`AZaz09-._~${"x".repeat(33)}`)).not.toThrow();
  });
});

describe("verifyPkceS256", () => {
  it("accepts the matching pair", () => {
    expect(verifyPkceS256(RFC_VERIFIER, RFC_CHALLENGE)).toBe(true);
  });

  it("refuses a different verifier", () => {
    expect(verifyPkceS256(`${RFC_VERIFIER.slice(0, -1)}Y`, RFC_CHALLENGE)).toBe(false);
  });

  it("refuses the plain method — challenge equal to the verifier", () => {
    const v = "b".repeat(43);
    expect(verifyPkceS256(v, v)).toBe(false);
  });

  it("returns false, never throws, on a malformed verifier or challenge", () => {
    expect(verifyPkceS256("short", RFC_CHALLENGE)).toBe(false);
    expect(verifyPkceS256(RFC_VERIFIER, "")).toBe(false);
    expect(verifyPkceS256(RFC_VERIFIER, `${RFC_CHALLENGE}=`)).toBe(false);
    expect(verifyPkceS256(RFC_VERIFIER, RFC_CHALLENGE.slice(1))).toBe(false);
    expect(verifyPkceS256(undefined as unknown as string, RFC_CHALLENGE)).toBe(false);
    expect(verifyPkceS256(RFC_VERIFIER, null as unknown as string)).toBe(false);
  });
});
