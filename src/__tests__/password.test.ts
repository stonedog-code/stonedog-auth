import { WeakSecretError } from "../errors";
import {
  assertAcceptable,
  createPasswordFactor,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
} from "../password";
import { ARGON2ID_PARAMS, type Argon2Binding } from "../types";

/**
 * A fake binding: the real Argon2 is deliberately slow, and none of what is
 * asserted here is about the KDF. The integration tier runs the real one.
 *
 * It produces a PHC-shaped string so `needsRehash` has something honest to
 * parse — a fake that returned "hash:pw" would let a parser bug through.
 */
function fakeArgon2(params = ARGON2ID_PARAMS): Argon2Binding {
  return {
    hash: async (plain) =>
      `$argon2id$v=19$m=${params.memoryCost},t=${params.timeCost},p=${params.parallelism}$c2FsdA$${Buffer.from(plain).toString("base64url")}`,
    verify: async (digest, plain) => {
      const encoded = digest.split("$").pop();
      if (encoded === undefined) throw new Error("malformed digest");
      return encoded === Buffer.from(plain).toString("base64url");
    },
  };
}

describe("the password policy", () => {
  it("accepts a password at exactly the minimum length", () => {
    expect(() => assertAcceptable("a".repeat(MIN_PASSWORD_LENGTH))).not.toThrow();
  });

  it("refuses one character short, and says which way it was wrong", () => {
    expect(() => assertAcceptable("a".repeat(MIN_PASSWORD_LENGTH - 1))).toThrow(WeakSecretError);
    try {
      assertAcceptable("short");
    } catch (error) {
      expect((error as WeakSecretError).reason).toBe("too-short");
    }
  });

  it("refuses an oversized password before anything hashes it", () => {
    try {
      assertAcceptable("a".repeat(MAX_PASSWORD_LENGTH + 1));
      throw new Error("should have thrown");
    } catch (error) {
      expect((error as WeakSecretError).reason).toBe("too-long");
    }
  });

  it("never puts the password in the error message", () => {
    // The whole reason WeakSecretError takes a reason rather than the input: an
    // error that echoes the secret puts it in a log, a stack trace, and an
    // error-reporting service.
    const secret = "hunter2-hunter2-hunter2";
    try {
      assertAcceptable(secret.slice(0, 3));
      throw new Error("should have thrown");
    } catch (error) {
      expect((error as Error).message).not.toContain("hun");
    }
  });
});

describe("verifying a password", () => {
  const factor = createPasswordFactor({ argon2: fakeArgon2() });

  it("accepts the right password", async () => {
    const stored = await factor.hash("correct horse battery");
    await expect(factor.verify(stored, "correct horse battery")).resolves.toEqual({ ok: true });
  });

  it("rejects the wrong one", async () => {
    const stored = await factor.hash("correct horse battery");
    await expect(factor.verify(stored, "incorrect horse battery")).resolves.toEqual({ ok: false });
  });

  it("FAILS CLOSED when the subject has no password at all", async () => {
    // A passkey-only or magic-link-only account. This shape has, in more than
    // one codebase, treated "no hash" as "nothing to check" and signed the
    // person in.
    await expect(factor.verify(null, "anything")).resolves.toEqual({ ok: false });
    await expect(factor.verify(undefined, "anything")).resolves.toEqual({ ok: false });
    await expect(factor.verify("", "anything")).resolves.toEqual({ ok: false });
  });

  it("denies rather than throwing on a corrupt stored hash", async () => {
    // A truncated column or a digest from another algorithm. Throwing would
    // 500, and a 500 distinguishes a corrupt row from a wrong password — which
    // tells an attacker the account exists.
    await expect(factor.verify("$argon2id$truncated", "anything")).resolves.toEqual({ ok: false });
    await expect(factor.verify("not-a-hash-at-all", "anything")).resolves.toEqual({ ok: false });
  });

  it("refuses an empty or oversized candidate without hashing it", async () => {
    let calls = 0;
    const counting: Argon2Binding = {
      hash: fakeArgon2().hash,
      verify: async (...args) => {
        calls += 1;
        return fakeArgon2().verify(...args);
      },
    };
    const guarded = createPasswordFactor({ argon2: counting });
    const stored = await guarded.hash("correct horse battery");

    await expect(guarded.verify(stored, "")).resolves.toEqual({ ok: false });
    await expect(
      guarded.verify(stored, "a".repeat(MAX_PASSWORD_LENGTH + 1)),
    ).resolves.toEqual({ ok: false });
    // Neither reached the KDF — otherwise an attacker can make us burn CPU on a
    // megabyte of input per unauthenticated request.
    expect(calls).toBe(0);
  });
});

describe("rehash on login", () => {
  it("asks for a rehash when the stored hash used weaker parameters", async () => {
    const weak = { ...ARGON2ID_PARAMS, memoryCost: 4096 };
    const stored = await fakeArgon2(weak).hash("correct horse battery", weak);

    const factor = createPasswordFactor({ argon2: fakeArgon2(weak) });
    await expect(factor.verify(stored, "correct horse battery")).resolves.toEqual({
      ok: true,
      needsRehash: true,
    });
  });

  it("asks for a rehash for a digest from another algorithm entirely", () => {
    // A bcrypt column from a previous life genuinely does need rehashing, and
    // an unparseable digest must not be reported as current.
    const factor = createPasswordFactor({ argon2: fakeArgon2() });
    expect(factor.needsRehash("$2b$12$abcdefghijklmnopqrstuv")).toBe(true);
    expect(factor.needsRehash("")).toBe(true);
  });

  it("does not ask for a rehash when the parameters already match", async () => {
    const factor = createPasswordFactor({ argon2: fakeArgon2() });
    const stored = await factor.hash("correct horse battery");
    expect(factor.needsRehash(stored)).toBe(false);
  });

  it("reads the parameters BY NAME, whatever order the binding wrote them in", () => {
    // The two supported bindings disagree: `argon2` emits `m,p,t` and
    // `@node-rs/argon2` emits `m,t,p`. A positional parser matches one and
    // reports the other as needing a rehash, which silently rewrites an entire
    // password column on first sign-in after adoption.
    const factor = createPasswordFactor({ argon2: fakeArgon2() });
    const { memoryCost: m, timeCost: t, parallelism: p } = ARGON2ID_PARAMS;

    expect(factor.needsRehash(`$argon2id$v=19$m=${m},t=${t},p=${p}$c2FsdA$aGFzaA`)).toBe(false);
    expect(factor.needsRehash(`$argon2id$v=19$m=${m},p=${p},t=${t}$c2FsdA$aGFzaA`)).toBe(false);
  });

  it("treats a digest with a missing parameter as needing a rehash", () => {
    const factor = createPasswordFactor({ argon2: fakeArgon2() });
    expect(factor.needsRehash("$argon2id$v=19$m=19456,t=2$c2FsdA$aGFzaA")).toBe(true);
    expect(factor.needsRehash("$argon2id$v=19$m=abc,t=2,p=1$c2FsdA$aGFzaA")).toBe(true);
  });

  it("never reports needsRehash on a FAILED verification", async () => {
    // Otherwise the caller has a signal that separates "wrong password on a
    // modern hash" from "wrong password on an old one", which is a fact about
    // the account it should not be able to learn.
    const weak = { ...ARGON2ID_PARAMS, memoryCost: 4096 };
    const factor = createPasswordFactor({ argon2: fakeArgon2(weak) });
    const stored = await fakeArgon2(weak).hash("correct horse battery", weak);

    expect(await factor.verify(stored, "wrong")).toEqual({ ok: false });
  });
});

describe("the breach check", () => {
  it("refuses a breached password", async () => {
    const factor = createPasswordFactor({
      argon2: fakeArgon2(),
      policy: {
        minLength: MIN_PASSWORD_LENGTH,
        maxLength: MAX_PASSWORD_LENGTH,
        isBreached: async () => true,
      },
    });
    await expect(factor.hash("correct horse battery")).rejects.toThrow(WeakSecretError);
  });

  it("FAILS OPEN when the breach service throws", async () => {
    // A breach-list outage must not become a sign-up outage. The password is
    // still subject to every other control.
    const factor = createPasswordFactor({
      argon2: fakeArgon2(),
      policy: {
        minLength: MIN_PASSWORD_LENGTH,
        maxLength: MAX_PASSWORD_LENGTH,
        isBreached: async () => {
          throw new Error("hibp is down");
        },
      },
    });
    await expect(factor.hash("correct horse battery")).resolves.toContain("$argon2id$");
  });

  it("is not consulted for a password the length policy already refused", async () => {
    let consulted = false;
    const factor = createPasswordFactor({
      argon2: fakeArgon2(),
      policy: {
        minLength: MIN_PASSWORD_LENGTH,
        maxLength: MAX_PASSWORD_LENGTH,
        isBreached: () => {
          consulted = true;
          return false;
        },
      },
    });
    await expect(factor.hash("short")).rejects.toThrow(WeakSecretError);
    // Sending a rejected password to a third party is a disclosure with no
    // benefit — the answer could not change the outcome.
    expect(consulted).toBe(false);
  });
});
