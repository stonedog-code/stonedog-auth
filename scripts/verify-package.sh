#!/usr/bin/env bash
#
# Prove the PACKAGE works, not just the checkout.
#
# Everything the test suite does runs against source files sitting in this
# repository, where `files`, the `exports` map and the tarball contents are
# invisible. Those are exactly what breaks at publish time — after review, when
# the version is already burned and cannot be reused.
#
# So: pack it, install the tarball into a throwaway project, and use it the way
# a consumer would — typecheck against the published `exports`, then execute.
#
# The consumer below installs `@node-rs/argon2` and uses the real binding,
# because the one claim this package makes that a type-check cannot verify is
# that the adapter entry points actually drive a real Argon2.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"
TARBALL="$WORK/$(basename "$(npm pack --pack-destination "$WORK" | tail -1)")"
echo "packed: $(basename "$TARBALL")"

# No test file may reach a consumer: they import jest globals that are not
# dependencies, and consumers compile our source under their own config.
if tar -tzf "$TARBALL" | grep -q "__tests__"; then
  echo "FAIL: the tarball contains test files" >&2
  tar -tzf "$TARBALL" | grep "__tests__" >&2
  exit 1
fi

mkdir -p "$WORK/consumer/src"
cd "$WORK/consumer"

cat > package.json <<'JSON'
{ "name": "consumer-check", "private": true, "type": "module", "version": "1.0.0" }
JSON

cat > tsconfig.json <<'JSON'
{
  "compilerOptions": {
    "target": "ESNext", "module": "ESNext", "moduleResolution": "bundler",
    "strict": true, "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noEmit": true, "skipLibCheck": true,
    "lib": ["esnext"], "types": ["node"]
  },
  "include": ["src/**/*.ts"]
}
JSON

# `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes` are ON above, and
# that is the point rather than thoroughness: this package ships SOURCE, so a
# consumer compiles our code under THEIR config. A strictness flag we do not
# hold ourselves becomes a build error in a repo that does not own the line.
#
# Every import below goes through the package NAME, never a relative path, so
# it resolves via the published `exports` map rather than the file layout.
cat > src/check.ts <<'TS'
import {
  createPasswordFactor,
  createPinFactor,
  createAttemptLimiter,
  createInMemoryAttemptStore,
  createTokenIssuer,
  createTotpFactor,
  createWebAuthnChallenges,
  generateTotpSecret,
  totpCodeAt,
  totpProvisioningUri,
  generateToken,
  hashToken,
  WeakSecretError,
  type Argon2Binding,
  type TokenStore,
  type StoredToken,
} from "@stonedogcode/auth";
import { nodeRsArgon2 } from "@stonedogcode/auth/argon2-node-rs";
import { nativeArgon2 } from "@stonedogcode/auth/argon2-native";
import * as argon2 from "@node-rs/argon2";

const binding: Argon2Binding = nodeRsArgon2(argon2);
if (typeof nativeArgon2 !== "function") throw new Error("argon2-native entry point missing");

const passwords = createPasswordFactor({ argon2: binding });
const hash = await passwords.hash("correct horse battery staple");
if (!hash.startsWith("$argon2id$")) throw new Error("not an argon2id digest");
if (!(await passwords.verify(hash, "correct horse battery staple")).ok) {
  throw new Error("verify rejected the right password");
}
if ((await passwords.verify(hash, "wrong")).ok) throw new Error("verify accepted a wrong password");
if ((await passwords.verify(null, "anything")).ok) throw new Error("verify did not fail closed");

try {
  await passwords.hash("short");
  throw new Error("policy accepted a short password");
} catch (error) {
  if (!(error instanceof WeakSecretError)) throw error;
}

const limiter = createAttemptLimiter({ store: createInMemoryAttemptStore() });
const pins = createPinFactor({ argon2: binding, limiter });
const pinHash = await pins.hash("284917");
if (!(await pins.verify("u1", pinHash, "284917")).ok) throw new Error("pin rejected");

const secret = generateTotpSecret();
const used = new Map<string, number>();
const totp = createTotpFactor({
  store: {
    lastUsedStep: async (id) => used.get(id) ?? null,
    recordUsedStep: async (id, step) => void used.set(id, step),
  },
});
if (!(await totp.verify("u1", secret, totpCodeAt(secret, new Date()))).ok) {
  throw new Error("totp rejected its own code");
}
if (!totpProvisioningUri(secret, { account: "a@b.com", issuer: "X" }).startsWith("otpauth://")) {
  throw new Error("bad provisioning uri");
}

const rows: StoredToken[] = [];
const store: TokenStore = {
  invalidateOutstanding: async (s, k, at) => {
    for (const r of rows) if (r.subjectId === s && r.kind === k && !r.consumedAt) r.consumedAt = at;
  },
  insert: async (t) => void rows.push({ ...t }),
  findMostRecent: async (s, k) =>
    rows.filter((r) => r.subjectId === s && r.kind === k).at(-1) ?? null,
  claim: async (h, k, now) => {
    const row = rows.find(
      (r) => r.tokenHash === h && r.kind === k && !r.consumedAt && r.expiresAt > now,
    );
    if (!row) return null;
    row.consumedAt = now;
    return { ...row };
  },
};
const tokens = createTokenIssuer({ store });
const issued = await tokens.issue("u1", "magic-link");
if (rows[0]?.tokenHash !== hashToken(issued.token)) throw new Error("raw token was persisted");
if (!(await tokens.consume(issued.token, "magic-link")).ok) throw new Error("token would not spend");
if ((await tokens.consume(issued.token, "magic-link")).ok) throw new Error("token spent twice");

const challenges = createWebAuthnChallenges({
  store: {
    insert: async () => {},
    claim: async () => null,
  },
});
if (typeof (await challenges.issue("u1", "authentication")) !== "string") {
  throw new Error("challenge not issued");
}
if (generateToken().length < 40) throw new Error("token too short");

console.log("package verified: all three entry points resolve, types check, code runs");
TS

npm install --silent --no-audit --no-fund \
  "$TARBALL" typescript@^5.9.3 @types/node@^22 "@node-rs/argon2@^2" tsx@^4 >/dev/null

echo "typechecking as a consumer…"
npx tsc --noEmit

echo "running as a consumer…"
npx tsx src/check.ts
