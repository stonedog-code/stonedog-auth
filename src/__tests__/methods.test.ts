import {
  AUTH_METHODS,
  isDowngrade,
  mayAuthenticateWith,
  methodAssurance,
  requiredSteps,
  type AuthMethod,
} from "../methods.js";

describe("method assurance", () => {
  it("ranks the inbox methods at 1 and the two-factor methods at 2", () => {
    expect(methodAssurance("magic_link")).toBe(1);
    // An accessibility alternative, not MFA. Ranking it higher would let an
    // emailed code stand in for a password + TOTP.
    expect(methodAssurance("email_code")).toBe(1);
    expect(methodAssurance("password_totp")).toBe(2);
    expect(methodAssurance("passkey_pin")).toBe(2);
  });

  it("treats an unknown method (a corrupt column) as the HIGHEST assurance", () => {
    // Failing toward "refuse the magic link" is recoverable; the other way is not.
    expect(methodAssurance("sms" as AuthMethod)).toBe(2);
  });

  it("lists every method once, frozen", () => {
    expect([...AUTH_METHODS].sort()).toEqual(
      ["email_code", "magic_link", "passkey_pin", "password_totp"],
    );
    expect(Object.isFrozen(AUTH_METHODS)).toBe(true);
  });
});

describe("isDowngrade", () => {
  it("is true only when assurance falls", () => {
    expect(isDowngrade("password_totp", "magic_link")).toBe(true);
    expect(isDowngrade("passkey_pin", "email_code")).toBe(true);
    expect(isDowngrade("magic_link", "email_code")).toBe(false);
    expect(isDowngrade("password_totp", "passkey_pin")).toBe(false);
    expect(isDowngrade("magic_link", "passkey_pin")).toBe(false);
  });
});

describe("requiredSteps", () => {
  it("names each method's factors in the order they must be completed", () => {
    expect(requiredSteps("magic_link")).toEqual(["email-link"]);
    expect(requiredSteps("email_code")).toEqual(["email-code"]);
    expect(requiredSteps("password_totp")).toEqual(["password", "totp"]);
    expect(requiredSteps("passkey_pin")).toEqual(["webauthn", "pin"]);
  });

  it("returns nothing completable for an unknown method", () => {
    expect(requiredSteps("sms" as AuthMethod)).toEqual([]);
  });
});

describe("mayAuthenticateWith — the no-downgrade rule", () => {
  const every = [...AUTH_METHODS];

  it("refuses every assurance-1 route into an assurance-2 account", () => {
    for (const enrolled of ["password_totp", "passkey_pin"] as const) {
      expect(mayAuthenticateWith(enrolled, "magic_link")).toBe(false);
      expect(mayAuthenticateWith(enrolled, "email_code")).toBe(false);
    }
  });

  it("lets magic_link and email_code users use either (equal assurance)", () => {
    expect(mayAuthenticateWith("magic_link", "email_code")).toBe(true);
    expect(mayAuthenticateWith("email_code", "magic_link")).toBe(true);
  });

  it("allows equal-or-higher for every pair, and nothing else", () => {
    for (const enrolled of every) {
      for (const used of every) {
        expect(mayAuthenticateWith(enrolled, used)).toBe(
          methodAssurance(used) >= methodAssurance(enrolled),
        );
      }
    }
  });

  it("allows recovery only for assurance-2 accounts", () => {
    expect(mayAuthenticateWith("password_totp", "recovery")).toBe(true);
    expect(mayAuthenticateWith("passkey_pin", "recovery")).toBe(true);
    expect(mayAuthenticateWith("magic_link", "recovery")).toBe(false);
    expect(mayAuthenticateWith("email_code", "recovery")).toBe(false);
  });

  it("refuses an unknown route, and refuses the inbox into an unknown enrolment", () => {
    expect(mayAuthenticateWith("magic_link", "sms" as AuthMethod)).toBe(false);
    expect(mayAuthenticateWith("sms" as AuthMethod, "magic_link")).toBe(false);
  });
});
