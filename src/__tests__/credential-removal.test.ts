import { canRemoveCredential, type AuthMethod, type CredentialRecord } from "../methods.js";

const pk = (id: string): CredentialRecord => ({ id, kind: "webauthn" });
const dk = (id: string): CredentialRecord => ({ id, kind: "device-key" });

describe("canRemoveCredential — the last way in", () => {
  it("refuses removing the last passkey of a passkey_pin account", () => {
    expect(canRemoveCredential("passkey_pin", [pk("p1"), { id: "pin", kind: "pin" }], "p1")).toEqual({ ok: false, reason: "last-way-in" });
  });

  it("allows removing a passkey when another remains", () => {
    expect(canRemoveCredential("passkey_pin", [pk("p1"), pk("p2"), { id: "pin", kind: "pin" }], "p1")).toEqual({ ok: true });
  });

  it("refuses removing the TOTP of a password_totp account, allows removing a spare", () => {
    const creds: CredentialRecord[] = [{ id: "pw", kind: "password" }, { id: "t1", kind: "totp" }];
    expect(canRemoveCredential("password_totp", creds, "t1")).toEqual({ ok: false, reason: "last-way-in" });
    expect(canRemoveCredential("password_totp", [...creds, { id: "t2", kind: "totp" }], "t1")).toEqual({ ok: true });
    expect(canRemoveCredential("password_totp", creds, "pw")).toEqual({ ok: false, reason: "last-way-in" });
  });

  it("a device key satisfies no step, so removing the last one is always allowed", () => {
    expect(canRemoveCredential("passkey_pin", [pk("p1"), { id: "pin", kind: "pin" }, dk("d1")], "d1")).toEqual({ ok: true });
    expect(canRemoveCredential("magic_link", [dk("d1")], "d1")).toEqual({ ok: true });
  });

  it("and a device key cannot stand in for the last passkey", () => {
    expect(canRemoveCredential("passkey_pin", [pk("p1"), { id: "pin", kind: "pin" }, dk("d1"), dk("d2")], "p1")).toEqual({
      ok: false,
      reason: "last-way-in",
    });
  });

  it("assurance-1 methods need no credential: their way in is the inbox", () => {
    expect(canRemoveCredential("magic_link", [pk("p1")], "p1")).toEqual({ ok: true });
    expect(canRemoveCredential("email_code", [pk("p1"), dk("d1")], "d1")).toEqual({ ok: true });
  });

  it("refuses an id the account does not hold, and an unknown method", () => {
    expect(canRemoveCredential("passkey_pin", [pk("p1")], "nope")).toEqual({ ok: false, reason: "not-found" });
    expect(canRemoveCredential("sms" as AuthMethod, [pk("p1")], "p1")).toEqual({ ok: false, reason: "unknown-method" });
  });

  it("does not mutate the list it is given", () => {
    const creds = [pk("p1"), pk("p2")];
    canRemoveCredential("passkey_pin", creds, "p1");
    expect(creds).toHaveLength(2);
  });
});
