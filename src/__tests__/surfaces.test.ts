import { AUTH_SURFACES, CREDENTIAL_KINDS, credentialAllowedOn, type AuthSurface, type CredentialKind } from "../surfaces.js";

describe("credentialAllowedOn — the diagonal", () => {
  it("a web credential signs in to web; a verified mobile credential to mobile", () => {
    expect(credentialAllowedOn("web", "web")).toBe(true);
    expect(credentialAllowedOn("mobile", "mobile", { userVerified: true })).toBe(true);
  });

  it("plants each crossing and refuses it", () => {
    expect(credentialAllowedOn("web", "mobile")).toBe(false);
    expect(credentialAllowedOn("web", "mobile", { userVerified: true })).toBe(false);
    expect(credentialAllowedOn("mobile", "web", { userVerified: true })).toBe(false);
    expect(credentialAllowedOn("mobile", "web")).toBe(false);
  });

  it("a mobile credential without user verification is refused on its own surface — absent is not true", () => {
    expect(credentialAllowedOn("mobile", "mobile")).toBe(false);
    expect(credentialAllowedOn("mobile", "mobile", {})).toBe(false);
    expect(credentialAllowedOn("mobile", "mobile", { userVerified: false })).toBe(false);
    expect(credentialAllowedOn("mobile", "mobile", { userVerified: "true" as unknown as boolean })).toBe(false);
  });

  it("a web credential does not need user verification to be asserted here (the WebAuthn verifier owns UV for web)", () => {
    expect(credentialAllowedOn("web", "web", { userVerified: false })).toBe(true);
  });

  it("refuses anything outside the unions — a corrupt column closes the door", () => {
    expect(credentialAllowedOn("primary" as CredentialKind, "web")).toBe(false);
    expect(credentialAllowedOn("web", "api" as AuthSurface)).toBe(false);
    expect(credentialAllowedOn("" as CredentialKind, "" as AuthSurface)).toBe(false);
    expect(credentialAllowedOn(undefined as unknown as CredentialKind, "web")).toBe(false);
  });

  it("is exhaustive over the exported unions: exactly two of four pairs pass", () => {
    let passes = 0;
    for (const kind of CREDENTIAL_KINDS) for (const surface of AUTH_SURFACES) {
      if (credentialAllowedOn(kind, surface, { userVerified: true })) passes += 1;
    }
    expect(passes).toBe(2);
  });
});
