// Imported, not taken from a global: under ESM, Jest injects `describe`/`it`/
// `expect` but NOT the `jest` object.
import { jest } from "@jest/globals";
import * as nativeModule from "argon2";
import * as nodeRsModule from "@node-rs/argon2";

import { nativeArgon2 } from "../argon2/native";
import { nodeRsArgon2 } from "../argon2/nodeRs";
import { createPasswordFactor } from "../password";
import { ARGON2ID_PARAMS } from "../types";

/**
 * Integration tier: the REAL Argon2 bindings, not a fake.
 *
 * The unit tests use a fake because Argon2 is deliberately slow and none of
 * what they assert is about the KDF. But two claims in this package cannot be
 * checked with a fake at all, and both are load-bearing:
 *
 *  1. **The parameters we pass mean what we think.** `algorithm: 2` is written
 *     as a bare number because the binding ships `Algorithm` as an ambient
 *     const enum that TypeScript cannot read under `isolatedModules`. A value
 *     that silently meant Argon2i or Argon2d would look identical in every
 *     unit test. The digest prefix is what proves it.
 *  2. **The two bindings interoperate.** The package tells adopters that
 *     switching binding does not invalidate their password column. That is the
 *     difference between a migration and a mass password reset, and it is only
 *     true if a digest written by one really does verify under the other.
 *
 * Slow by nature — Argon2id at 19 MiB is meant to be — so the timeout is
 * raised rather than the work factor lowered.
 */

jest.setTimeout(30_000);

const nodeRs = nodeRsArgon2(nodeRsModule);
const native = nativeArgon2(nativeModule as unknown as Parameters<typeof nativeArgon2>[0]);

const PASSWORD = "correct horse battery staple";

describe("the parameters we actually pass", () => {
  it("produces an argon2ID digest, not argon2i or argon2d", async () => {
    // `algorithm: 2` is a magic number by necessity. This is the check that
    // stops it being a silent one.
    await expect(nodeRs.hash(PASSWORD, ARGON2ID_PARAMS)).resolves.toMatch(/^\$argon2id\$/);
    await expect(native.hash(PASSWORD, ARGON2ID_PARAMS)).resolves.toMatch(/^\$argon2id\$/);
  });

  it("encodes the work factor we asked for into the digest", async () => {
    // An auditor asks to see the work factor. This is where the answer is
    // checked against what the library actually did, rather than what the
    // constant says.
    const digest = await nodeRs.hash(PASSWORD, ARGON2ID_PARAMS);
    expect(digest).toContain(
      `m=${ARGON2ID_PARAMS.memoryCost},t=${ARGON2ID_PARAMS.timeCost},p=${ARGON2ID_PARAMS.parallelism}`,
    );
  });
});

describe("cross-binding interoperability", () => {
  it("verifies a node-rs digest under the native binding", async () => {
    const digest = await nodeRs.hash(PASSWORD, ARGON2ID_PARAMS);
    await expect(native.verify(digest, PASSWORD)).resolves.toBe(true);
    await expect(native.verify(digest, "wrong password entirely")).resolves.toBe(false);
  });

  it("verifies a native digest under the node-rs binding", async () => {
    const digest = await native.hash(PASSWORD, ARGON2ID_PARAMS);
    await expect(nodeRs.verify(digest, PASSWORD)).resolves.toBe(true);
    await expect(nodeRs.verify(digest, "wrong password entirely")).resolves.toBe(false);
  });

  it("agrees that an existing application column is still valid", async () => {
    // The migration claim, stated as a test. Two applications adopting this
    // package already differ in binding for runtime-image reasons; if this ever
    // fails, adopting the package means resetting everyone's password.
    const factorOnNative = createPasswordFactor({ argon2: native });
    const factorOnNodeRs = createPasswordFactor({ argon2: nodeRs });

    const writtenByNative = await factorOnNative.hash(PASSWORD);
    const writtenByNodeRs = await factorOnNodeRs.hash(PASSWORD);

    await expect(factorOnNodeRs.verify(writtenByNative, PASSWORD)).resolves.toEqual({ ok: true });
    await expect(factorOnNative.verify(writtenByNodeRs, PASSWORD)).resolves.toEqual({ ok: true });
  });

  it("does not report needsRehash across bindings at the same parameters", async () => {
    // Otherwise adopting the package would rewrite every password column on
    // first login for no reason — a lot of writes, and a lot of alarm.
    const factorOnNodeRs = createPasswordFactor({ argon2: nodeRs });
    const writtenByNative = await native.hash(PASSWORD, ARGON2ID_PARAMS);

    expect(factorOnNodeRs.needsRehash(writtenByNative)).toBe(false);
  });
});

describe("both bindings deny rather than throw on a bad digest", () => {
  // The `Argon2Binding` contract says verify returns false for a malformed
  // digest. `@node-rs/argon2` and `argon2` disagree about that natively — one
  // throws — which is exactly the difference the adapters exist to absorb.
  const corrupt = [
    "$argon2id$truncated",
    "$2b$12$abcdefghijklmnopqrstuv",
    "not-a-hash-at-all",
    "",
  ];

  it.each(corrupt)("native: %s", async (digest) => {
    await expect(native.verify(digest, PASSWORD)).resolves.toBe(false);
  });

  it.each(corrupt)("node-rs: %s", async (digest) => {
    // Through the factor, because the core catches what the adapter does not —
    // and the two together are what a consumer actually gets.
    const factor = createPasswordFactor({ argon2: nodeRs });
    await expect(factor.verify(digest, PASSWORD)).resolves.toEqual({ ok: false });
  });
});

describe("a real weak-parameter digest", () => {
  it("is reported as needing a rehash", async () => {
    // The upgrade path: an application that hashed at a lower work factor
    // years ago gets those columns rewritten on next sign-in.
    const weak = { ...ARGON2ID_PARAMS, memoryCost: 8192, timeCost: 1 };
    const old = await nodeRs.hash(PASSWORD, weak);

    const factor = createPasswordFactor({ argon2: nodeRs });
    await expect(factor.verify(old, PASSWORD)).resolves.toEqual({
      ok: true,
      needsRehash: true,
    });
  });
});
