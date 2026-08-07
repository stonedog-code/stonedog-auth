import { LockedOutError, MisconfiguredError, WeakSecretError } from "../errors";
import {
  createAttemptLimiter,
  createInMemoryAttemptStore,
  defaultLockoutPolicy,
} from "../lockout";
import { assertPinAcceptable, createPinFactor } from "../pin";
import { ARGON2ID_PARAMS, type Argon2Binding, type Clock } from "../types";

function fixedClock(start: Date): Clock & { advance(seconds: number): void } {
  let current = start;
  return {
    now: () => current,
    advance: (seconds) => {
      current = new Date(current.getTime() + seconds * 1000);
    },
  };
}

const fakeArgon2: Argon2Binding = {
  hash: async (plain) =>
    `$argon2id$v=19$m=${ARGON2ID_PARAMS.memoryCost},t=2,p=1$c2FsdA$${Buffer.from(plain).toString("base64url")}`,
  verify: async (digest, plain) =>
    digest.split("$").pop() === Buffer.from(plain).toString("base64url"),
};

describe("the attempt limiter", () => {
  const start = new Date("2026-08-07T12:00:00Z");

  it("allows attempts below the limit", async () => {
    const clock = fixedClock(start);
    const limiter = createAttemptLimiter({ store: createInMemoryAttemptStore(), clock });

    for (let i = 0; i < defaultLockoutPolicy.maxFailures - 1; i += 1) {
      await limiter.recordFailure("user-1");
      await expect(limiter.assertAllowed("user-1")).resolves.toBeUndefined();
    }
  });

  it("locks out on the nth failure and reports how long to wait", async () => {
    const clock = fixedClock(start);
    const limiter = createAttemptLimiter({ store: createInMemoryAttemptStore(), clock });

    for (let i = 0; i < defaultLockoutPolicy.maxFailures; i += 1) {
      await limiter.recordFailure("user-1");
    }

    await expect(limiter.assertAllowed("user-1")).rejects.toThrow(LockedOutError);
    try {
      await limiter.assertAllowed("user-1");
    } catch (error) {
      expect((error as LockedOutError).retryAfterSeconds).toBe(defaultLockoutPolicy.lockoutSeconds);
    }
  });

  it("lets the subject back in once the lockout expires", async () => {
    const clock = fixedClock(start);
    const limiter = createAttemptLimiter({ store: createInMemoryAttemptStore(), clock });

    for (let i = 0; i < defaultLockoutPolicy.maxFailures; i += 1) {
      await limiter.recordFailure("user-1");
    }
    clock.advance(defaultLockoutPolicy.lockoutSeconds + 1);

    await expect(limiter.assertAllowed("user-1")).resolves.toBeUndefined();
  });

  it("does not lock out someone who mistypes occasionally over a long period", async () => {
    // Without a window the counter is cumulative for the life of the account,
    // so a person who mistypes twice a year is eventually locked out by their
    // own history.
    const clock = fixedClock(start);
    const limiter = createAttemptLimiter({ store: createInMemoryAttemptStore(), clock });

    for (let i = 0; i < 10; i += 1) {
      await limiter.recordFailure("user-1");
      clock.advance(defaultLockoutPolicy.windowSeconds + 1);
      await expect(limiter.assertAllowed("user-1")).resolves.toBeUndefined();
    }
  });

  it("clears the count entirely on success, not partially", async () => {
    // Leaving a partial count means a legitimate user who mistyped four times
    // then succeeded is one typo away from a lockout for the rest of the window.
    const clock = fixedClock(start);
    const store = createInMemoryAttemptStore();
    const limiter = createAttemptLimiter({ store, clock });

    for (let i = 0; i < defaultLockoutPolicy.maxFailures - 1; i += 1) {
      await limiter.recordFailure("user-1");
    }
    await limiter.recordSuccess("user-1");

    expect(await store.load("user-1")).toBeNull();
    await limiter.recordFailure("user-1");
    await expect(limiter.assertAllowed("user-1")).resolves.toBeUndefined();
  });

  it("counts per subject, so one account cannot lock out another", async () => {
    const clock = fixedClock(start);
    const limiter = createAttemptLimiter({ store: createInMemoryAttemptStore(), clock });

    for (let i = 0; i < defaultLockoutPolicy.maxFailures; i += 1) {
      await limiter.recordFailure("user-1");
    }
    await expect(limiter.assertAllowed("user-2")).resolves.toBeUndefined();
  });
});

describe("the PIN policy", () => {
  it("refuses anything that is not digits", () => {
    // A "PIN" that accepts letters is a password with a bad name.
    expect(() => assertPinAcceptable("12a4")).toThrow(WeakSecretError);
  });

  it("refuses repeats and sequences", () => {
    // These are a large share of real PIN choices and the first few thousand
    // guesses of any attack, so allowing them makes the attempt limit far less
    // protective than its number suggests.
    for (const trivial of ["000000", "1111", "123456", "654321", "4321"]) {
      expect(() => assertPinAcceptable(trivial)).toThrow(WeakSecretError);
    }
  });

  it("accepts an ordinary PIN", () => {
    expect(() => assertPinAcceptable("284917")).not.toThrow();
  });

  it("never puts the PIN in the error message", () => {
    try {
      assertPinAcceptable("111111");
      throw new Error("should have thrown");
    } catch (error) {
      expect((error as Error).message).not.toContain("111111");
    }
  });
});

describe("the PIN factor", () => {
  const start = new Date("2026-08-07T12:00:00Z");

  function build() {
    const clock = fixedClock(start);
    const limiter = createAttemptLimiter({ store: createInMemoryAttemptStore(), clock });
    return { clock, factor: createPinFactor({ argon2: fakeArgon2, limiter }) };
  }

  it("REFUSES TO BE BUILT without an attempt limiter", () => {
    // The one mandatory dependency in this package. A PIN's search space is
    // small enough that the attempt limit is its only meaningful defence, so a
    // PIN factor without one is a brute force wearing the costume of a
    // credential.
    expect(() =>
      createPinFactor({ argon2: fakeArgon2, limiter: undefined as never }),
    ).toThrow(MisconfiguredError);
  });

  it("accepts the right PIN", async () => {
    const { factor } = build();
    const stored = await factor.hash("284917");
    await expect(factor.verify("user-1", stored, "284917")).resolves.toEqual({ ok: true });
  });

  it("locks out after repeated wrong PINs", async () => {
    const { factor } = build();
    const stored = await factor.hash("284917");

    for (let i = 0; i < defaultLockoutPolicy.maxFailures; i += 1) {
      await expect(factor.verify("user-1", stored, "999999")).resolves.toEqual({ ok: false });
    }
    // Even the CORRECT PIN is refused once locked out — otherwise the lockout
    // is only a speed bump for someone who guesses right on attempt six.
    await expect(factor.verify("user-1", stored, "284917")).rejects.toThrow(LockedOutError);
  });

  it("counts a malformed attempt as an attempt", async () => {
    // Not counting them would give an attacker a free probe for whether an
    // account has a PIN at all.
    const { factor } = build();
    const stored = await factor.hash("284917");

    for (let i = 0; i < defaultLockoutPolicy.maxFailures; i += 1) {
      await expect(factor.verify("user-1", stored, "abc")).resolves.toEqual({ ok: false });
    }
    await expect(factor.verify("user-1", stored, "284917")).rejects.toThrow(LockedOutError);
  });

  it("fails closed when the subject has no PIN set", async () => {
    const { factor } = build();
    await expect(factor.verify("user-1", null, "284917")).resolves.toEqual({ ok: false });
  });

  it("clears the failure count after a success", async () => {
    const { factor } = build();
    const stored = await factor.hash("284917");

    await factor.verify("user-1", stored, "999999");
    await factor.verify("user-1", stored, "999999");
    await factor.verify("user-1", stored, "284917");

    for (let i = 0; i < defaultLockoutPolicy.maxFailures - 1; i += 1) {
      await expect(factor.verify("user-1", stored, "999999")).resolves.toEqual({ ok: false });
    }
    await expect(factor.verify("user-1", stored, "284917")).resolves.toEqual({ ok: true });
  });

  it("checks the lockout BEFORE hashing", async () => {
    // So a locked-out subject costs an attacker a database read rather than an
    // Argon2 hash — otherwise the lockout is itself a denial-of-service lever.
    let hashCalls = 0;
    const counting: Argon2Binding = {
      hash: fakeArgon2.hash,
      verify: async (...args) => {
        hashCalls += 1;
        return fakeArgon2.verify(...args);
      },
    };
    const clock = fixedClock(start);
    const limiter = createAttemptLimiter({ store: createInMemoryAttemptStore(), clock });
    const factor = createPinFactor({ argon2: counting, limiter });
    const stored = await factor.hash("284917");

    for (let i = 0; i < defaultLockoutPolicy.maxFailures; i += 1) {
      await factor.verify("user-1", stored, "999999");
    }
    const before = hashCalls;
    await expect(factor.verify("user-1", stored, "999999")).rejects.toThrow(LockedOutError);
    expect(hashCalls).toBe(before);
  });
});
