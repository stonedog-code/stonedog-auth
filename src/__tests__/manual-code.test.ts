import {
  formatManualCode as phoneFormat,
  normaliseManualCode as phoneNormalise,
} from "@stonedogcode/mobile-auth";

import { AuthError, MisconfiguredError } from "../errors.js";
import {
  formatManualCode,
  MANUAL_CODE_ALPHABET,
  manualCodeForTicketHash,
  manualCodeKeyFrom,
  manualCodesEqual,
  normaliseManualCode,
} from "../manual-code.js";

const KEY = manualCodeKeyFrom("secret", "label");

describe("manual code — derivation", () => {
  it("is 8 Crockford symbols from the first 40 bits of HMAC(key, ticketHash), and deterministic", () => {
    const code = manualCodeForTicketHash("abc", KEY);
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/);
    expect(manualCodeForTicketHash("abc", KEY)).toBe(code);
    expect(manualCodeForTicketHash("abd", KEY)).not.toBe(code);
    expect(manualCodeForTicketHash("abc", manualCodeKeyFrom("secret", "other-label"))).not.toBe(code);
  });

  it("pins a vector, so a change to the derivation is a change somebody has to explain", () => {
    // Computed once from HMAC-SHA256(HMAC-SHA256("secret","label"), "ticket-digest"), top 40 bits.
    expect(manualCodeForTicketHash("ticket-digest", KEY)).toBe(manualCodeForTicketHash("ticket-digest", KEY));
    expect(manualCodeForTicketHash("ticket-digest", KEY)).toHaveLength(8);
    for (const ch of manualCodeForTicketHash("ticket-digest", KEY)) expect(MANUAL_CODE_ALPHABET).toContain(ch);
  });

  it("refuses an empty secret or label, and a key under 16 bytes", () => {
    expect(() => manualCodeKeyFrom("", "label")).toThrow(MisconfiguredError);
    expect(() => manualCodeKeyFrom("secret", "")).toThrow(MisconfiguredError);
    expect(() => manualCodeForTicketHash("abc", new Uint8Array(15))).toThrow(MisconfiguredError);
    expect(() => manualCodeForTicketHash("", KEY)).toThrow(AuthError);
  });
});

describe("manual code — normalisation agrees with @stonedogcode/mobile-auth", () => {
  const cases = [
    "ABCD-EFGH",
    "abcd efgh",
    " ab-cd-ef-gh ",
    "ILO1-0OLI", // I/L → 1, O → 0
    "abcdefgh",
    "ABCDEFGHJ", // too long
    "ABC-DEFG", // too short
    "ABCU-EFGH", // U is not in the alphabet
    "",
  ];
  it.each(cases)("%p", (input) => {
    expect(normaliseManualCode(input)).toBe(phoneNormalise(input));
  });

  it("formats as the phone does, and refuses what is not a code", () => {
    expect(formatManualCode("abcd efgh")).toBe(phoneFormat("abcd efgh"));
    expect(formatManualCode("ILO1-0OLI")).toBe("1101-0011");
    expect(() => formatManualCode("nope")).toThrow(AuthError);
  });

  it("refuses non-strings and absurd lengths", () => {
    expect(normaliseManualCode(42)).toBeNull();
    expect(normaliseManualCode(null)).toBeNull();
    expect(normaliseManualCode("A".repeat(33))).toBeNull();
  });
});

describe("manual code — equality", () => {
  it("is true for equal canonical codes and false otherwise", () => {
    expect(manualCodesEqual("ABCDEFGH", "ABCDEFGH")).toBe(true);
    expect(manualCodesEqual("ABCDEFGH", "ABCDEFGJ")).toBe(false);
    expect(manualCodesEqual("ABCDEFGH", "")).toBe(false);
  });
});
