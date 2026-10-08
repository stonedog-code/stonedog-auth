/**
 * The server half, proven against the PHONE half: keys are generated and
 * challenges signed with `@stonedogcode/mobile-auth/device-key` (an in-memory
 * store standing in for the Keystore, node's CSPRNG for the crypto port), and
 * this package verifies them — in both directions.
 */
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";

import { createDeviceKey, signDeviceChallenge, type DeviceKeyStore } from "@stonedogcode/mobile-auth/device-key";

import {
  createDecoyVerifier,
  createDeviceKeyChallenges,
  parseDeviceKeyPem,
  verifyDeviceKeySignature,
  type DeviceKeyChallengeStore,
  type StoredDeviceKeyChallenge,
} from "../device-key.js";
import { MisconfiguredError } from "../errors.js";
import type { Clock } from "../types.js";

/** The phone's Keystore, in memory. The private half is readable only "with authentication". */
function phoneStore(): DeviceKeyStore {
  const values = new Map<string, { value: string; auth: boolean }>();
  return {
    async set(name, value, options) {
      values.set(name, { value, auth: options.requireAuthentication });
    },
    async get(name, options) {
      const v = values.get(name);
      if (!v) return null;
      if (v.auth && !options.requireAuthentication) return null;
      return v.value;
    },
    async remove(name) {
      values.delete(name);
    },
  };
}

const phoneCrypto = {
  randomBytes: (n: number) => new Uint8Array(randomBytes(n)),
  sha256: async (data: Uint8Array) => new Uint8Array(createHash("sha256").update(data).digest()),
};

async function newPhone() {
  const store = phoneStore();
  const { publicKeyPem } = await createDeviceKey({ store, crypto: phoneCrypto, prompt: "Set up fingerprint sign-in" });
  return {
    publicKeyPem,
    sign: (challenge: string) => signDeviceChallenge({ store, challenge, prompt: "Sign in with your fingerprint" }),
  };
}

function fakeChallengeStore(): DeviceKeyChallengeStore & { rows: Map<string, StoredDeviceKeyChallenge> } {
  const rows = new Map<string, StoredDeviceKeyChallenge>();
  return {
    rows,
    async insert(c) {
      rows.set(c.challenge, c);
    },
    async claim(challenge, kind) {
      const row = rows.get(challenge);
      if (!row || row.kind !== kind) return null;
      rows.delete(challenge);
      return row;
    },
  };
}

function fixedClock(start: Date): Clock & { advance(seconds: number): void } {
  let current = start;
  return { now: () => current, advance: (s) => (current = new Date(current.getTime() + s * 1000)) };
}

describe("device key — cross-package, both directions", () => {
  it("a key the phone made and a challenge the server issued verify end to end", async () => {
    const phone = await newPhone();
    const pem = parseDeviceKeyPem(phone.publicKeyPem);
    expect(pem).not.toBeNull();

    const store = fakeChallengeStore();
    const challenges = createDeviceKeyChallenges({ store, prefix: "rz-signin.v1" });
    const challenge = await challenges.issue("u1", "signin");
    expect(challenge).toMatch(/^rz-signin\.v1\.[A-Za-z0-9_-]{43}$/);

    const signature = await phone.sign(challenge);
    // Consume FIRST, then verify over what the store returned.
    const claimed = await challenges.claim(challenge, "signin");
    expect(claimed).toEqual({ subjectId: "u1" });
    expect(verifyDeviceKeySignature(pem!, challenge, signature)).toBe(true);
  });

  it("refuses a tampered challenge, a tampered signature, another phone's signature, and the decoy", async () => {
    const a = await newPhone();
    const b = await newPhone();
    const challenge = "rz-signin.v1." + randomBytes(32).toString("base64url");
    const sig = await a.sign(challenge);
    expect(verifyDeviceKeySignature(a.publicKeyPem, challenge, sig)).toBe(true);
    expect(verifyDeviceKeySignature(a.publicKeyPem, challenge + "x", sig)).toBe(false);
    const flipped = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    expect(verifyDeviceKeySignature(a.publicKeyPem, challenge, flipped)).toBe(false);
    expect(verifyDeviceKeySignature(b.publicKeyPem, challenge, sig)).toBe(false);
    const decoy = createDecoyVerifier();
    expect(decoy(challenge, sig)).toBe(false);
  });

  it("never throws on garbage: a non-PEM key, a non-string signature, a malformed one", async () => {
    const phone = await newPhone();
    const challenge = "rz-signin.v1." + randomBytes(32).toString("base64url");
    const sig = await phone.sign(challenge);
    expect(verifyDeviceKeySignature("not a key", challenge, sig)).toBe(false);
    expect(verifyDeviceKeySignature(phone.publicKeyPem, challenge, 42)).toBe(false);
    expect(verifyDeviceKeySignature(phone.publicKeyPem, challenge, "")).toBe(false);
    expect(verifyDeviceKeySignature(phone.publicKeyPem, challenge, "!".repeat(80))).toBe(false);
    expect(verifyDeviceKeySignature(phone.publicKeyPem, challenge, "A".repeat(200))).toBe(false);
  });
});

describe("parseDeviceKeyPem — P-256 and nothing else", () => {
  it("accepts a P-256 SPKI PEM and returns it normalised", async () => {
    const phone = await newPhone();
    const pem = parseDeviceKeyPem(phone.publicKeyPem);
    expect(pem).toMatch(/^-----BEGIN PUBLIC KEY-----\n/);
    expect(parseDeviceKeyPem(pem)).toBe(pem);
  });

  it("refuses RSA, P-384, Ed25519, a private key, and non-strings", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }).toString();
    const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey.export({ type: "spki", format: "pem" }).toString();
    const ed = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
    const priv = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    for (const bad of [rsa, p384, ed, priv, "", "BEGIN PUBLIC KEY", 42, null, "x".repeat(2000)]) {
      expect(parseDeviceKeyPem(bad)).toBeNull();
    }
  });
});

describe("device-key challenges — single use, bound to a kind, two minutes", () => {
  it("claim spends the challenge: the second claim is null, whatever the signature did", async () => {
    const store = fakeChallengeStore();
    const challenges = createDeviceKeyChallenges({ store });
    const c = await challenges.issue("u1", "signin");
    expect(await challenges.claim(c, "signin")).toEqual({ subjectId: "u1" });
    expect(await challenges.claim(c, "signin")).toBeNull();
    expect(store.rows.size).toBe(0);
  });

  it("a signin challenge cannot be claimed as an enrol challenge, and vice versa", async () => {
    const store = fakeChallengeStore();
    const challenges = createDeviceKeyChallenges({ store });
    const s = await challenges.issue("u1", "signin");
    const e = await challenges.issue("u1", "enrol");
    expect(await challenges.claim(s, "enrol")).toBeNull();
    expect(await challenges.claim(e, "signin")).toBeNull();
    expect(await challenges.claim(s, "signin")).toEqual({ subjectId: "u1" });
  });

  it("an expired challenge is refused AND deleted by the claim", async () => {
    const store = fakeChallengeStore();
    const clock = fixedClock(new Date("2026-10-08T12:00:00Z"));
    const challenges = createDeviceKeyChallenges({ store, clock });
    const c = await challenges.issue("u1", "signin");
    clock.advance(120);
    expect(await challenges.claim(c, "signin")).toBeNull();
    expect(store.rows.size).toBe(0);
  });

  it("an unstored challenge has the real shape and can never be claimed", async () => {
    const store = fakeChallengeStore();
    const challenges = createDeviceKeyChallenges({ store, prefix: "hg-signin.v1" });
    const real = await challenges.issue("u1", "signin");
    const fake = challenges.unstored();
    expect(fake).toMatch(/^hg-signin\.v1\.[A-Za-z0-9_-]{43}$/);
    expect(fake.length).toBe(real.length);
    expect(await challenges.claim(fake, "signin")).toBeNull();
    expect(store.rows.size).toBe(1);
  });

  it("refuses a challenge outside the opaque shape without touching the store", async () => {
    const store = fakeChallengeStore();
    let claims = 0;
    const counting: DeviceKeyChallengeStore = {
      insert: store.insert,
      claim: async (c, k) => {
        claims += 1;
        return store.claim(c, k);
      },
    };
    const challenges = createDeviceKeyChallenges({ store: counting });
    for (const bad of ["", "short", "has space ".repeat(3), "x".repeat(1025), 42 as unknown as string]) {
      expect(await challenges.claim(bad, "signin")).toBeNull();
    }
    expect(claims).toBe(0);
  });

  it("refuses a prefix outside its shape at construction, not at the first request", () => {
    expect(() => createDeviceKeyChallenges({ store: fakeChallengeStore(), prefix: "has space" })).toThrow(MisconfiguredError);
    expect(() => createDeviceKeyChallenges({ store: fakeChallengeStore(), prefix: "" })).toThrow(MisconfiguredError);
  });

  it("the challenge it issues is one the phone will sign", async () => {
    const phone = await newPhone();
    const challenges = createDeviceKeyChallenges({ store: fakeChallengeStore() });
    const c = await challenges.issue("u1", "enrol");
    await expect(phone.sign(c)).resolves.toMatch(/^[A-Za-z0-9+/]+=*$/);
  });
});
