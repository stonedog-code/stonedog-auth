# @stonedogcode/auth

Authentication **factor primitives**: password, PIN, TOTP, WebAuthn challenges,
single-use emailed tokens — and, since 0.4.0, the sign-in **method** rules that
stop an account being entered with less than it chose.

Not a framework, not a session manager, and not a replacement for whatever you
use to hold a session. It is the layer underneath — the parts that are identical
in every application and dangerous to write twice.

```bash
npm install @stonedogcode/auth
```

---

## ⚠️ Disclaimer

**This software is provided "AS IS", without warranty of any kind, express or
implied, and without any liability whatsoever.** See sections 7 and 8 of the
[Apache License 2.0](./LICENSE), which govern.

Because this is security-related code, three things are worth stating plainly
rather than leaving to a licence clause:

- **It has not been independently audited.** No third party has reviewed it, and
  no claim of fitness for any regulated purpose — SOC 2, HIPAA, PCI DSS, or any
  other — is made or implied. If your compliance programme needs an audited
  dependency, this is not one.
- **A library cannot make a system secure.** Correct primitives are necessary
  and nowhere near sufficient. Session handling, transport security, credential
  storage, key management, logging hygiene and account-recovery flows are all
  outside this package and all capable of undoing everything in it.
- **You are responsible for how you use it.** The defaults here are chosen
  carefully and documented with their reasoning, but they are defaults, and no
  default fits every threat model. Read what each one assumes.

Reporting something you believe is wrong is welcome and useful. Please do not
open a public issue for a suspected vulnerability — see [Security](#security).

---

## What it is, and what it deliberately is not

Three constraints hold everywhere:

- **No storage.** Every stateful factor takes a port you implement. This package
  owns no schema and issues no migration, so adopting one factor never means a
  migration in four repositories at once.
- **No transport.** Nothing here knows about HTTP, cookies, or a framework. A
  factor that needed a `Request` could not be used from a background job.
- **No secret ever leaves.** Nothing logs, returns, or interpolates a credential
  — including into an error message. Errors carry a reason code, never the input.

**It must never become a prerequisite.** You should be able to keep your own
password hashing and adopt only the TOTP helpers. If taking one factor requires
taking the rest, the interface has been drawn wrong — please say so.

### Installing — this package ships SOURCE, so a bundler must be told

`exports` points at `./src/index.ts`. There is no `dist`, deliberately: the
package is meant to be readable on the sign-in path of several products, and a
bundle is not.

The cost is that a consumer bundling `node_modules` has to opt it in. **In
Next.js:**

```js
// next.config.ts
transpilePackages: ["@stonedogcode/auth"],
```

Omit it and the build fails with:

```
./node_modules/@stonedogcode/auth/src/index.ts
Unknown module type
This module doesn't have an associated type. Use a known file extension, or
register a loader for it.
```

**The trap is which test tier notices.** That is a *production build* failure.
Vitest and Jest transpile `node_modules` on their own terms, so a unit tier and
an integration tier both pass against a config missing this line — rozcards had
394 unit and 624 integration tests green while its build was broken (NEH-480).
Only an end-to-end tier that actually builds the app catches it.

So if you take this package and your build breaks with a message about a module
type, this is why. And if it does *not* break, check that something in your
pipeline builds for real before concluding you are fine.

### Zero runtime dependencies

Everything here is `node:crypto` or arithmetic. A package on the sign-in path of
several products should be auditable in an afternoon, and every dependency it
takes is one that every consumer inherits on that path.

The two Argon2 bindings are **optional peer dependencies**, behind separate
entry points. You install whichever suits your runtime image, or neither.

## Passwords

```ts
import { createPasswordFactor } from "@stonedogcode/auth";
import { nodeRsArgon2 } from "@stonedogcode/auth/argon2-node-rs";
import * as argon2 from "@node-rs/argon2";

const passwords = createPasswordFactor({ argon2: nodeRsArgon2(argon2) });

const hash = await passwords.hash(plaintext);          // throws WeakSecretError
const result = await passwords.verify(user.hash, plaintext);
if (result.ok && result.needsRehash) await store(await passwords.hash(plaintext));
```

**Which binding?** Whichever your runtime image can install.
`@node-rs/argon2` ships prebuilt binaries including `linux-x64-musl`, so it
works on Alpine with no build toolchain; `argon2` builds through node-gyp. Both
emit the standard PHC string, **so a column written by one verifies under the
other** — switching binding is not a password reset. There is an integration
test asserting exactly that, in both directions.

Argon2id at OWASP's second profile (19 MiB, t=2, p=1), pinned rather than left
to the binding's defaults: a default is not a control, an auditor asks to see
the work factor, and a dependency upgrade can change a default with nothing
failing. It is **deliberately not readable from an environment variable** — a
work factor config can lower is one an attacker who reaches config can lower.

`verify` **fails closed** and never throws. A subject with no password at all
(passkey-only, magic-link-only) returns `ok: false`; so does a truncated or
foreign digest. Returning "no hash, nothing to check" is a real bug that has
signed real people in.

Policy is length-only — NIST SP 800-63B dropped composition rules because they
push people toward `Passw0rd!` and away from length. Supply `isBreached` to
check a corpus; it **fails open** if it throws, because a breach-list outage
must not become a sign-up outage.

## PINs

A PIN is not a short password. Six digits is a million possibilities, and a slow
KDF buys nothing against that — so **the attempt limit is the only real
defence**, and `createPinFactor` refuses to be constructed without one. It is
the only mandatory dependency in this package.

```ts
import { createAttemptLimiter, createPinFactor, pinLockoutPolicy } from "@stonedogcode/auth";

const limiter = createAttemptLimiter({ store: yourAttemptStore, policy: pinLockoutPolicy });
const pins = createPinFactor({ argon2: nodeRsArgon2(argon2), limiter });

await pins.verify(userId, user.pinHash, entered);  // throws LockedOutError when locked
```

The lockout is checked *before* hashing, so a locked-out subject costs an
attacker a read rather than an Argon2 hash. Malformed input still counts as an
attempt — not counting it is a free probe for whether an account has a PIN.

Trivial PINs (`000000`, `123456`, `654321`) are rejected: they are a large share
of real choices and the first guesses of any attack, so allowing them makes the
attempt limit far less protective than its number suggests.

## TOTP

```ts
import { createTotpFactor, generateTotpSecret, totpProvisioningUri } from "@stonedogcode/auth";

const secret = generateTotpSecret();
const uri = totpProvisioningUri(secret, { account: email, issuer: "Example" });

const totp = createTotpFactor({ store: yourReplayStore });
await totp.verify(userId, secret, code);
```

Implemented on `node:crypto` and checked against the **RFC 4226 published test
vectors**, so it agrees with real authenticator apps rather than only with
itself.

**Single-use is enforced**, per RFC 6238 §5.2 — and against *earlier* steps too,
not just an exact repeat, because rejecting only the identical code still lets a
code captured one step ago replay after a newer one has been used. `verifyTotpCode`
is exported as the raw check without replay protection, so choosing that is
visible at the call site rather than hidden in a default.

Drift is ±1 step. Each extra step multiplies the guess space an attacker gets
per attempt, so it does not default higher. SHA-1 is the default and that is
correct: HMAC-SHA-1 is unaffected by the collision attacks that retired SHA-1
for signatures, and authenticator apps overwhelmingly ignore the algorithm
parameter — choosing SHA-256 produces codes the user's app cannot generate.

## Emailed tokens — magic links, verification, reset, codes

One mechanism, different `kind`. Two copies of "spend this exactly once" is two
places for a replay bug to live.

```ts
import { createTokenIssuer } from "@stonedogcode/auth";

const tokens = createTokenIssuer({ store: yourTokenStore });
const { token } = await tokens.issue(userId, "magic-link");   // email this, never store it
const result = await tokens.consume(token, "magic-link");
```

- The raw token is returned **once** and never persisted — only its SHA-256. A
  dumped database yields no working links.
- Issuing invalidates outstanding tokens of the same kind, or every reset email
  ever sent to an address stays live until it expires.
- Every failure reports the **same** reason. Distinguishing "no such token" from
  "expired" from "already used" tells an attacker which guess was once real.

**`TokenStore.claim` must be one atomic conditional write.** A read-then-write
implementation satisfies the types and lets two simultaneous clicks on a reset
link both succeed. If your store cannot express a conditional update, use a
transaction with the row locked — do not check first and then write.

`generateNumericCode` uses `randomInt`, not `randomBytes % 10`, which is biased
toward low digits. A 6-digit code is only a credential alongside an attempt
limit and a short expiry — treat it like a PIN.

## WebAuthn / passkeys

**This package does not verify WebAuthn signatures and never will.** Parsing
attestation objects and checking COSE signatures is a large adversarial surface
with real libraries behind it; a second-best reimplementation here would be the
most dangerous file in the package. Use `@simplewebauthn/server` for the
ceremony.

What it owns is what those libraries leave to you, and what callers get wrong:
the challenge must be random, stored server-side, **bound to one subject**,
short-lived, and spent exactly once. Every one of those is a property of storage
and time, which a verification library cannot enforce for you.

```ts
import { createWebAuthnChallenges } from "@stonedogcode/auth";

const challenges = createWebAuthnChallenges({ store: yourChallengeStore });
const challenge = await challenges.issue(userId, "authentication");
// … browser ceremony, then @simplewebauthn/server verification …
const claimed = await challenges.claim(challenge, "authentication", userId);
```

The subject check is not redundant with the randomness: the challenge is public
by the time the browser has it, so that comparison is the only thing binding it
to a person. A failed subject check still **spends** the challenge, or an
attacker retries it against every account id they can think of.

## Sign-in methods

*Since 0.4.0.* A **factor** answers "is this secret right?". A **method** answers
"which secrets does this account require, in what order, and may some other
route stand in for them?" — and that second question is where the downgrade bug
lives. An app that lets a user choose "passkey + PIN" and leaves the magic-link
endpoint open for that same account has built an MFA screen with a
single-factor door beside it.

| method          | steps, in order        | assurance |
|-----------------|------------------------|-----------|
| `magic_link`    | `email-link`           | 1 — the default |
| `email_code`    | `email-code`           | 1 — an accessibility alternative to a link, **not MFA** |
| `password_totp` | `password`, `totp`     | 2 |
| `passkey_pin`   | `webauthn`, `pin`      | 2 |

### Magic link stays the default

Nothing changes for an account on `magic_link`. The library still supplies
`createTokenIssuer` (kind `"magic-link"`); the cross-device flow — the email,
the polling, the cookie — stays in your host, because it is transport and
storage.

### The no-downgrade rule — every door asks

```ts
import { mayAuthenticateWith } from "@stonedogcode/auth";

// In the magic-link route, the email-code route, any legacy provider, the
// mobile exchange — EVERY path that can create a session:
if (!mayAuthenticateWith(user.authMethod, "magic_link")) {
  // Answer generically (no enumeration); email the user that their account
  // signs in with a different method.
  return genericOk();
}
```

Equal or higher assurance is allowed (`magic_link` and `email_code` users may
use either); lower is refused. One door that forgets is the whole account's
assurance. An unknown method value is treated as assurance 2, so a corrupt
column refuses the inbox routes rather than opening them.

### The three alternatives

**`email_code`** — a 6-digit code instead of a link:

```ts
const emailCodes = createEmailCodeFactor({ issuer: tokens, limiter, audit });
const { code } = await emailCodes.issue(user.id);     // email it; never store or log it
await emailCodes.verify(user.id, submitted);          // throws LockedOutError when locked
```

The stored hash is bound to the subject, so two users who happen to hold the
same six digits cannot find — or spend — each other's code.

**`password_totp`** and **`passkey_pin`** — two steps, bridged by a ticket
rather than a session:

```ts
const tickets = createSignInTickets({ store: yourTicketStore });   // 5-minute TTL per step

// POST /signin/start — the email identifies the account, no factor proved yet
const { ticket } = await tickets.start(user.id, "password_totp", "email");

// POST /signin/password
const t = await tickets.peek(ticket);                  // who to check — does NOT spend it
if (!t || !(await passwords.verify(hashFor(t.subjectId), password)).ok) return unauthorised();
const next = await tickets.advance(ticket, "password"); // spends it, returns a NEW ticket

// POST /signin/totp
const done = await tickets.advance(next.ticket, "totp");
if (done?.done) establishTheSession(done.subjectId);
```

A ticket is random, stored only as a hash, **single-use per step** (every
`advance` spends it and issues a successor, right step or wrong), and bound to
the step order: a skipped, repeated or out-of-order step returns `null`.
**Call `advance` only after the factor has verified** — it records that a step
happened; it cannot check the secret. For a passkey, pair it with
`createWebAuthnChallenges` and your WebAuthn verifier as before.

### Recovery codes — never the only secret

Enrolling an assurance-2 method issues ten codes (`xxxx-xxxx-xx`, unambiguous
base32, 50 bits each). Show them once; only their hashes are stored. Input is
case-, hyphen- and space-insensitive. `issue` **replaces** every earlier code.

```ts
const recovery = createRecoveryCodes({ store: yourRecoveryStore, audit });
const codes = await recovery.issue(user.id);           // show once
```

A recovery code replaces **one** step, and a ticket enforces which:

| method          | recovery path                    |
|-----------------|----------------------------------|
| `password_totp` | `password`, then `recovery-code` (it replaces only the TOTP) |
| `passkey_pin`   | `email-code`, then `recovery-code` (an emailed code first, then the code replaces passkey + PIN) |

A ticket fresh from `start` never accepts `"recovery-code"`. When a host
advances with it, the sign-in *was* a recovery: tell the user by email, revoke
their other sessions (`establishSession` / `isSessionCurrent`), and send them to
re-enrol. Consume the code only after `peek` shows the ticket is at the right
point, then `advance`.

### Step-up

Sensitive account changes — changing method, viewing or regenerating recovery
codes, removing a passkey — should require a sign-in with the **current**
method within the last few minutes. The library leaves the clock claim to your
session (it has no session), but everything the re-authentication needs is
here: run the same ticket steps scoped to the signed-in user, and on `done`
stamp your own `authTime`. A session reached by a hand-off or a recovery code
should not count as recent authentication.

### PKCE, for a code returning to an app

```ts
const challenge = pkceChallengeS256(verifier);   // throws on a verifier outside RFC 7636
verifyPkceS256(verifier, storedChallenge);       // constant-time; false on anything malformed
```

S256 only — `plain` is not offered, because with `plain` the challenge *is* the
verifier.

### What this does not claim

The disclaimer at the top applies here in full. These primitives are designed
with SOC 2 and HIPAA-style controls in mind — no downgrade, hashed secrets,
single-use steps, audit events without secrets — but **no fitness for HIPAA,
SOC 2 or any other regulated purpose is claimed**, and none of it has been
independently audited. Whether a system built on them meets a framework depends
on everything outside this package.

## Attempt limiting

The policy lives in this package; the counter lives in your store. That split is
the design: an in-memory counter is per-process, so behind a load balancer it
multiplies every limit by the replica count — and it resets on deploy, which is
something an attacker can wait for.

`createInMemoryAttemptStore()` exists for tests and single-process development,
and is named so it cannot be adopted in production by accident.

## Audit events

`AuthEvent` is a shared shape so several products describe a failed sign-in the
same way, which makes "show me every lockout this week" a question you can ask
once. It carries no secret and no email — `subjectId` is your opaque id, and
everything else is an enum or a count.

## Development

```bash
npm install
npm run gate     # type-check, lint, test
```

The integration tier runs **both** real Argon2 bindings. It is what caught the
one bug this package has had so far: the two bindings emit the PHC parameters in
different orders (`m,p,t` versus `m,t,p`), so a positional parser reports every
digest from the other binding as needing a rehash — silently rewriting an entire
password column on first sign-in after adoption. No unit test with a fake could
have seen it.

## Security

Please report a suspected vulnerability privately, to **security@stonedogcode.com**,
rather than opening a public issue. Include what you did, what happened, and what
you expected; a proof of concept helps but is not required.

There is no bug-bounty programme and no guaranteed response time. This is a
small project and the honest answer is better than an implied SLA.

## Licence

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Copyright 2026 StoneDogCode L.L.C.
