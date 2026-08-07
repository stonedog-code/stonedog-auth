#!/usr/bin/env bash
# Copyright (C) 2026 StoneDogCode L.L.C.
# SPDX-License-Identifier: Apache-2.0
#
# Publish @stonedogcode/auth to npm, end to end.
#
#   npm run publish:stonedog-auth
#
# Run it from a terminal, interactively. npm prompts for the 2FA one-time
# password itself (account `stonedogcode`) and the browser login flow needs a
# human — neither works unattended, which is why this is a script you run
# rather than a step in CI.
#
# Modelled on stonedog-style's and @stonedogcode/howto's scripts of the same
# name, and it keeps their central lesson: a publish that prints no error can
# still have published nothing, or the wrong thing. So this reads the tarball
# before publishing and installs from the registry afterwards, because "the
# registry lists it" and "a user can install it" are different claims, and the
# second is the last to start answering yes.
#
# ## The traps specific to THIS package
#
# 1. **Zero runtime dependencies is a claim the README makes**, and it is the
#    reason a consumer is asked to put this on their sign-in path at all. A
#    dependency added without noticing is inherited by four products on that
#    path, so the check below is a gate rather than a comment.
#
# 2. **Neither Argon2 binding may become a real dependency.** Both are OPTIONAL
#    peers, because which one installs is decided by the runtime image: a
#    node-gyp build needs a toolchain an Alpine image does not carry. Promoting
#    either to `dependencies` breaks every consumer on the other one, at install
#    time, for a reason that has nothing to do with authentication.
#
# 3. **Three entry points** (`.`, `./argon2-node-rs`, `./argon2-native`). A
#    tarball missing any one installs fine and fails at the consumer's first
#    import.
#
# 4. **No `console.*` in shipped source.** This library handles credentials, and
#    whoever writes a log line is debugging at the time — which is exactly when
#    a secret is closest to hand. Also gated in CI; repeated here because a
#    publish is irreversible and CI is not what runs at this moment.
#
# 5. Tests must not ship: they import jest globals that are not dependencies,
#    and consumers compile our source under their own config.
set -euo pipefail

PACKAGE_NAME="@stonedogcode/auth"
# Sanity floor. Comfortably under the real count (15) so ordinary growth does
# not trip it, far above what a `files`-misconfigured package would produce
# (3: package.json, README, LICENSE).
MIN_FILES=12
# Every path `exports` names.
REQUIRED_PATHS=("src/index.ts" "src/argon2/nodeRs.ts" "src/argon2/native.ts")

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mREFUSING: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Publish from a clean, current `main`.
# ---------------------------------------------------------------------------
say "Checking the working tree"
BRANCH="$(git branch --show-current)"
[ -n "$BRANCH" ] || fail "this checkout is in detached HEAD. Run: git checkout main && git pull"
[ "$BRANCH" = "main" ] || fail "on branch '$BRANCH'. Publish from main, never a feature branch."
[ -z "$(git status --porcelain | grep -v '^??')" ] || fail "the working tree has uncommitted changes."

git fetch --quiet origin
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
  BEHIND="$(git rev-list --count HEAD..origin/main)"
  fail "HEAD is not origin/main ($BEHIND commit(s) behind). A checkout one commit behind publishes a tarball missing the very thing you are publishing for, and it looks like a success. Run: git pull"
fi
echo "  clean, on main, at $(git rev-parse --short HEAD)"

# ---------------------------------------------------------------------------
# 2. Authenticate.
#
# A 404 from `npm publish` means AUTH far more often than a missing package —
# npm answers 404 rather than 403 so it cannot leak whether a name exists. `npm
# whoami` turns that confusing failure into a clear one, and is the only thing
# that reveals an `_authToken` that is present but expired.
# ---------------------------------------------------------------------------
say "Checking npm authentication"
if ! NPM_USER="$(npm whoami 2>/dev/null)"; then
  echo "  not logged in — starting the browser login flow"
  npm login
  NPM_USER="$(npm whoami)"
fi
echo "  authenticated as $NPM_USER"

if npm view "$PACKAGE_NAME" version >/dev/null 2>&1; then
  npm owner ls "$PACKAGE_NAME" 2>/dev/null | grep -q "^$NPM_USER " \
    || fail "'$NPM_USER' is not an owner of $PACKAGE_NAME, so publishing will fail with a misleading 404."
  echo "  $NPM_USER is an owner of $PACKAGE_NAME"
else
  echo "  $PACKAGE_NAME does not exist yet — this is the first publish, which creates it"
  # A scoped name needs the scope to be an org you belong to, or your own
  # username. When it is neither, npm answers 404 rather than 403 — it will not
  # leak whether an org exists — so the failure reads as a missing package while
  # auth is perfectly fine. This is the check that turns that into a sentence.
  npm org ls stonedogcode >/dev/null 2>&1 \
    || echo "  NOTE: could not list the 'stonedogcode' org. If the publish 404s, that is why — not a missing package."
fi

# ---------------------------------------------------------------------------
# 3. A version may be published at most once, ever.
# ---------------------------------------------------------------------------
VERSION="$(node -p "require('./package.json').version")"
say "Preparing $PACKAGE_NAME@$VERSION"

if npm view "$PACKAGE_NAME@$VERSION" version >/dev/null 2>&1; then
  fail "$PACKAGE_NAME@$VERSION is already published. A version can never be reused — bump it (npm run version:bump:patch), land that, then re-run."
fi

# ---------------------------------------------------------------------------
# 4. The manifest invariants, before anything slow runs.
# ---------------------------------------------------------------------------
say "Checking the manifest invariants"
node -e '
  const pkg = require("./package.json");

  const deps = Object.keys(pkg.dependencies || {});
  if (deps.length > 0) {
    console.error(`REFUSING: this package claims ZERO runtime dependencies and now has ${deps.length}: ${deps.join(", ")}.`);
    console.error("  Everything here is node:crypto or arithmetic. A package on the sign-in path of four");
    console.error("  products should be auditable in an afternoon, and every dependency it takes is one");
    console.error("  every consumer inherits on that path. If this is deliberate, change the README claim");
    console.error("  in the same commit that adds it.");
    process.exit(1);
  }

  for (const binding of ["@node-rs/argon2", "argon2"]) {
    if (deps.includes(binding)) {
      console.error(`REFUSING: ${binding} is a real dependency. Both bindings must stay OPTIONAL peers —`);
      console.error("  which one installs is decided by the runtime image, and a node-gyp build needs a");
      console.error("  toolchain an Alpine image does not carry. Making either required breaks every");
      console.error("  consumer on the other, at install time.");
      process.exit(1);
    }
    const meta = (pkg.peerDependenciesMeta || {})[binding];
    if (!meta || meta.optional !== true) {
      console.error(`REFUSING: ${binding} is not marked optional in peerDependenciesMeta.`);
      console.error("  npm would warn every consumer that does not install it, including those that");
      console.error("  correctly chose the other binding or use no password factor at all.");
      process.exit(1);
    }
  }

  if (pkg.license !== "Apache-2.0") {
    console.error(`REFUSING: license is "${pkg.license}", expected Apache-2.0.`);
    process.exit(1);
  }
  if (!pkg.publishConfig || pkg.publishConfig.access !== "public") {
    console.error("REFUSING: publishConfig.access is not \"public\". A scoped package defaults to RESTRICTED,");
    console.error("  which needs a paid plan and fails the publish.");
    process.exit(1);
  }
'
echo "  zero dependencies; both argon2 bindings optional peers; Apache-2.0; public"

# ---------------------------------------------------------------------------
# 5. No credential can reach a log from shipped source.
# ---------------------------------------------------------------------------
say "Checking that shipped source writes nothing to the console"
if grep -rnE 'console\.(log|info|warn|error|debug)' src --include='*.ts' | grep -v '__tests__'; then
  fail "shipped source writes to the console. This library handles credentials, and whoever writes a log line is debugging at the time — which is exactly when a secret is closest to hand."
fi
echo "  clean"

# ---------------------------------------------------------------------------
# 6. The gate, then the package check.
#
# Both, in this order. The gate proves the SOURCE is good; verify:package
# proves what a CONSUMER receives is good. Publishing is irreversible on a
# version number, so neither is assumed from a green PR — this checkout may
# carry commits that merged after the last CI run.
# ---------------------------------------------------------------------------
say "Running the gate"
npm run gate

say "Verifying the package as a consumer receives it"
npm run verify:package

# ---------------------------------------------------------------------------
# 7. Read the tarball before trusting it.
# ---------------------------------------------------------------------------
say "Verifying the tarball"
PACK_OUTPUT="$(npm pack --dry-run 2>&1)"
FILE_COUNT="$(printf '%s' "$PACK_OUTPUT" | sed -n 's/.*total files:[[:space:]]*\([0-9]*\).*/\1/p' | tail -1)"

[ -n "$FILE_COUNT" ] || fail "could not read a file count from npm pack."
[ "$FILE_COUNT" -ge "$MIN_FILES" ] \
  || fail "the tarball has only $FILE_COUNT files (expected >= $MIN_FILES). Publishing this would ship a near-empty package on a version number that can never be reused."

printf '%s' "$PACK_OUTPUT" | grep -q '__tests__' \
  && fail "the tarball contains test files. They import jest globals that are not dependencies, and consumers compile our source under their own config."

for path in "${REQUIRED_PATHS[@]}"; do
  printf '%s' "$PACK_OUTPUT" | grep -q "$path" \
    || fail "'$path' is not in the tarball, but package.json's \"exports\" names it. Every consumer import of that entry point would fail."
done

printf '%s' "$PACK_OUTPUT" | grep -q 'README.md' \
  || fail "no README.md in the tarball — npmjs.com would show 'This package does not have a README', and this package's README carries its security disclaimer."
printf '%s' "$PACK_OUTPUT" | grep -q 'LICENSE' \
  || fail "no LICENSE in the tarball. This package is Apache-2.0 and the licence text ships with it."
printf '%s' "$PACK_OUTPUT" | grep -q 'NOTICE' \
  || fail "no NOTICE in the tarball. Apache-2.0 section 4(d) requires it to travel with the work."

echo "  $FILE_COUNT files; entry points, README, LICENSE and NOTICE present; no tests"

say "Tarball contents — read this before confirming"
printf '%s\n' "$PACK_OUTPUT" | sed -n 's/^npm notice[[:space:]]*[0-9.]*[kMG]*B*[[:space:]]*\(src\/.*\)/  \1/p' | sort
echo "  ($FILE_COUNT files total)"

# ---------------------------------------------------------------------------
# 8. Publish. npm prompts for the OTP here.
# ---------------------------------------------------------------------------
say "Publishing $PACKAGE_NAME@$VERSION — npm will ask for your 2FA code"
npm publish --access public

# ---------------------------------------------------------------------------
# 9. PROVE IT. The registry is eventually consistent for a few seconds, so this
#    polls rather than asserting once, and ends with a real install.
# ---------------------------------------------------------------------------
say "Verifying it is actually installable"
PROBE_DIR="$(mktemp -d)"
trap 'rm -rf "$PROBE_DIR"' EXIT

for attempt in $(seq 1 20); do
  if npm view "$PACKAGE_NAME@$VERSION" version >/dev/null 2>&1; then break; fi
  [ "$attempt" -lt 20 ] || fail "$PACKAGE_NAME@$VERSION is still not on the registry after publishing. The publish did NOT succeed, whatever it printed."
  sleep 3
done

printf '{"name":"probe","version":"1.0.0"}' > "$PROBE_DIR/package.json"
(cd "$PROBE_DIR" && npm install --silent "$PACKAGE_NAME@$VERSION" >/dev/null 2>&1) \
  || fail "$PACKAGE_NAME@$VERSION resolves but cannot be installed."

INSTALLED="$(node -p "require('$PROBE_DIR/node_modules/$PACKAGE_NAME/package.json').version")"
[ "$INSTALLED" = "$VERSION" ] || fail "installed $INSTALLED but published $VERSION."

for path in "${REQUIRED_PATHS[@]}"; do
  [ -f "$PROBE_DIR/node_modules/$PACKAGE_NAME/$path" ] \
    || fail "$path is missing from the INSTALLED package, though it was in the tarball."
done

# Installing with no argon2 binding present must NOT warn or fail. That is the
# whole point of the optional peers, and it is the property a consumer using
# only the TOTP or token helpers depends on.
if [ -d "$PROBE_DIR/node_modules/@node-rs" ] || [ -d "$PROBE_DIR/node_modules/argon2" ]; then
  fail "installing $PACKAGE_NAME alone pulled in an Argon2 binding. Both must be optional peers so a consumer using only the token or TOTP helpers installs neither."
fi

printf '\n\033[32m✓ %s@%s is published and installable.\033[0m\n' "$PACKAGE_NAME" "$VERSION"
echo "  https://www.npmjs.com/package/$PACKAGE_NAME"
printf '\n\033[1mNext:\033[0m a consumer installs this plus ONE argon2 binding — @node-rs/argon2 for an\n'
printf '  image with no build toolchain (Alpine), `argon2` where node-gyp is available.\n'
printf '  Both emit the standard PHC string, so an existing password column keeps working.\n'
