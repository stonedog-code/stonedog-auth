/**
 * Argon2 via the `argon2` package (`stonedog-auth/argon2-native`).
 *
 * The node-gyp binding. Use it where the image already carries a build
 * toolchain, or where this is simply what the application has been running —
 * switching binding is not a reason to rewrite a password column.
 *
 * Interoperable with the `@node-rs/argon2` adapter: both emit and accept the
 * standard PHC string.
 */

import type { Argon2Binding, Argon2Params } from "../types";

/**
 * Declared locally rather than imported, because `argon2` is an **optional**
 * peer dependency — see the note in `nodeRs.ts`.
 *
 * Note the different option name: this binding calls it `type`, while
 * `@node-rs/argon2` calls it `algorithm`. Same value, same meaning; the two
 * adapters exist largely because of small differences like this one.
 */
export interface NativeArgon2Module {
  hash(
    plain: string,
    options?: {
      type?: number;
      memoryCost?: number;
      timeCost?: number;
      parallelism?: number;
    },
  ): Promise<string>;
  verify(digest: string, plain: string): Promise<boolean>;
}

export function nativeArgon2(module: NativeArgon2Module): Argon2Binding {
  return {
    hash: (plain: string, params: Argon2Params) =>
      module.hash(plain, {
        type: params.algorithm,
        memoryCost: params.memoryCost,
        timeCost: params.timeCost,
        parallelism: params.parallelism,
      }),
    // `argon2.verify` THROWS on a malformed digest rather than returning false.
    // The core's `verify` catches that and denies access, but the Argon2Binding
    // contract asks for false — so it is normalised here, where the difference
    // between the two bindings belongs.
    verify: async (digest: string, plain: string) => {
      try {
        return await module.verify(digest, plain);
      } catch {
        return false;
      }
    },
  };
}
