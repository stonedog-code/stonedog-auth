/**
 * Argon2 via `@node-rs/argon2` (`stonedog-auth/argon2-node-rs`).
 *
 * Use this when the runtime image has **no build toolchain** — an Alpine
 * container, or anywhere `npm ci` must not invoke node-gyp. This binding
 * publishes prebuilt platform binaries, including `linux-x64-musl`, so the
 * install resolves one rather than compiling.
 *
 * Interoperable with the native binding: both emit and accept the standard PHC
 * string, so a column written by one verifies under the other.
 */

import type { Argon2Binding, Argon2Params } from "../types";

/**
 * The shape we need from the binding, declared locally.
 *
 * `@node-rs/argon2` is an **optional** peer dependency: a host that never
 * builds a password factor should not have to install it. Importing its types
 * would make this file fail to compile when it is absent, so the contract is
 * restated here instead — six lines, checked against the real module by the
 * integration test.
 */
export interface NodeRsArgon2Module {
  hash(
    plain: string,
    options?: {
      algorithm?: number;
      memoryCost?: number;
      timeCost?: number;
      parallelism?: number;
    },
  ): Promise<string>;
  verify(digest: string, plain: string): Promise<boolean>;
}

/**
 * The module is passed in rather than imported.
 *
 * A bare `import "@node-rs/argon2"` at the top of this file would make the
 * package fail to load for every consumer that does not use passwords, which
 * defeats the point of adopting one factor at a time. It also keeps this file
 * synchronous and testable with a fake.
 */
export function nodeRsArgon2(module: NodeRsArgon2Module): Argon2Binding {
  return {
    hash: (plain: string, params: Argon2Params) =>
      module.hash(plain, {
        // `Algorithm.Argon2id` written as its literal value. The package ships
        // `Algorithm` as an AMBIENT CONST ENUM, which TypeScript cannot read
        // under `isolatedModules` (TS2748) — and isolatedModules is on here for
        // the same reason it is on in the apps. A bare 2 is only safe because
        // something checks it: the tests assert the digest starts with
        // `$argon2id$`, so a value that silently meant Argon2i or Argon2d fails
        // there rather than shipping.
        algorithm: params.algorithm,
        memoryCost: params.memoryCost,
        timeCost: params.timeCost,
        parallelism: params.parallelism,
      }),
    verify: (digest: string, plain: string) => module.verify(digest, plain),
  };
}
