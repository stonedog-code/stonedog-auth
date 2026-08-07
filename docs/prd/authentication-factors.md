# PRD — authentication factor primitives

**Status:** accepted, implemented in 0.1.0.
**Owner:** StoneDogCode L.L.C.

## Summary

A shared library of authentication **factor primitives** — password, PIN, TOTP,
WebAuthn challenge lifecycle, and single-use emailed tokens — usable a factor at
a time, with no storage, no transport, and no framework coupling.

## The problem

Several applications each implement the same credential handling separately.
The duplication is not the expensive part; the *divergence* is. Each copy makes
its own decision about work factors, lockout, token expiry, single-use
enforcement and what an error message says, and those decisions are invisible
until one of them is wrong.

The specific things that were being written more than once:

- Argon2 parameters and a rehash-on-login path
- "spend this token exactly once", for verification, reset and magic links
- TOTP verification, including whether a code can be replayed
- WebAuthn challenge issue/claim around a verification library
- attempt limiting and lockout

## Goals

1. One implementation of each primitive, adoptable independently.
2. **Existing credential columns keep working.** Adoption is a refactor, not a
   mass password reset.
3. No secret is ever logged, returned, or interpolated into an error.
4. Auditable in an afternoon: zero runtime dependencies.

## Non-goals

- **A session manager.** Sessions, cookies and CSRF stay with the host.
- **A NextAuth wrapper.** Considered and rejected — see Alternatives.
- **WebAuthn signature verification.** Delegated to `@simplewebauthn/server`.
- **A user store, a schema, or migrations.** Every stateful factor takes a port.
- **An authorisation model.** That is a different question and a different
  package.

## Users

Application developers integrating sign-in. The package is consumed by
server-side code — API routes, server components, background jobs — and never
by a browser bundle.

## Functional requirements

### Passwords

- Argon2id at OWASP's second profile (19 MiB, t=2, p=1), pinned in code and
  **not** readable from configuration.
- The Argon2 binding is **injected**. Two supported adapters ship as separate
  entry points; the core bundles neither.
- `verify` fails closed and never throws: a null hash, an empty hash, a
  truncated one, or a digest from another algorithm all return `ok: false`.
- `needsRehash` reports a digest written at weaker parameters, so a login can
  transparently upgrade it.
- Policy is length-only (min 12, max 256). An optional host-supplied breach
  check fails **open**.

### PINs

- Same hashing, different gate. `createPinFactor` **requires** an attempt
  limiter and throws at construction without one.
- Digits only; trivial repeats and sequences rejected.
- The lockout is evaluated before any hashing.
- A malformed attempt counts as an attempt.

### TOTP

- RFC 6238 over RFC 4226, on `node:crypto`, asserted against the RFC's published
  vectors.
- Single-use enforced against the last-used step, rejecting **earlier** steps as
  well as an exact repeat.
- ±1 step drift by default. SHA-1 default, for authenticator-app compatibility.
- Provisioning URI names the issuer in both the label and the parameter.

### Emailed tokens

- One mechanism keyed by a host-defined `kind`.
- The raw secret is returned once and never stored; only its SHA-256 is.
- Issuing invalidates outstanding tokens of the same kind.
- Consumption is a single atomic conditional write, specified in the port's
  contract.
- Every failure reports one indistinguishable reason.
- Per-kind TTLs and a resend cooldown.

### WebAuthn

- Challenge issue and single-use claim, bound to a subject and expiring.
- A failed subject check still spends the challenge.
- Signature verification is explicitly out of scope.

### Attempt limiting

- Policy here, counter in the host's store, because an in-memory counter is
  per-process and resets on deploy.
- A window, so occasional typos over months do not accumulate into a lockout.
- Success clears the count entirely rather than decrementing.

## Technical decisions

**Zero runtime dependencies.** Everything is `node:crypto` or arithmetic. A
package on the sign-in path of several products should be readable end to end,
and every dependency it takes is inherited by every consumer on that path.

**Ports, not schemas.** `TokenStore`, `AttemptStore`, `TotpReplayStore` and
`ChallengeStore` are narrow interfaces the host implements against whatever it
already runs. This is what allows adoption one factor at a time.

**Injected clock.** Every expiry, cooldown and lockout takes one, so tests
assert arithmetic without sleeping and a caller inside a transaction can stamp
every row from one instant. Two clocks in one flow is how a cooldown ends up off
by the drift between an application and its database.

**Ships TypeScript source, not a bundle**, matching the other packages in this
family. Consumers compile it under their own configuration, so the strictness
flags here must be at least as strict as any consumer's.

## Alternatives considered

**A NextAuth wrapper.** Rejected. The consuming applications are split across
next-auth v4 and v5-beta, whose configuration shapes differ substantially; a
wrapper would spend most of its surface on that difference and would couple
every application's upgrade timing together — nobody can move until the package
supports both, and the package cannot drop v4 until the slowest application
moves. It would also put the package on the critical path of every login, which
is a much heavier thing to own than something adoptable a factor at a time.

**Bundling one Argon2 binding.** Rejected. Which binding works is decided by the
runtime image, not by preference: a node-gyp build needs a toolchain an Alpine
image does not carry. Bundling either one breaks a consumer for a reason that
has nothing to do with authentication.

**Implementing WebAuthn verification.** Rejected. Large adversarial surface,
mature libraries exist, and the failure mode of getting it subtly wrong is
silent.

**Absorbing an existing MFA *policy*.** Rejected for v1. A policy tying required
factors to privilege levels is a compliance control belonging to the application
that is audited against it. The concept generalises; a specific implementation
with hard-coded factor types and thresholds does not, and a compliance control
should not be refactored as a side effect of a package migration.

## Rollout

1. This package, with all tiers. ✅ 0.1.0
2. The application about to build 2FA adopts first — no legacy factor code, so
   it is the honest test of whether the ports are right.
3. A greenfield internal tool alongside it.
4. The magic-link-only application: token primitives only.
5. The application with the most factors last, keeping its compliance boundary
   intact.

## Risks

- **A port implemented non-atomically.** `TokenStore.claim` and
  `ChallengeStore.claim` are correct only if the host makes them one conditional
  write. The types cannot enforce it; the contract says so loudly and the
  package's own fakes model it correctly so the tests do not pass against a racy
  shape.
- **Becoming a prerequisite.** If adopting one factor starts requiring the
  session contract, the interface has been drawn wrong. Treat that as a defect.
- **False confidence.** A correct primitive is necessary and nowhere near
  sufficient; the README says so in its own section rather than in a footer.

## Testing

Three tiers, all gating.

- **Unit** — every rejection path, with a fake binding. The rejection paths are
  the half that matters in an auth library, so the coverage floor is set on
  branches rather than statements.
- **Integration** — both real Argon2 bindings, asserting the digest is genuinely
  Argon2**id**, that the work factor reaches the library, and that a digest from
  either binding verifies under the other in both directions.
- **End-to-end** — a library has no user journey of its own; the equivalent is a
  consuming application signing a real person in against a real store. That is
  owned by the first adopter and tracked as part of its adoption, not faked here.

The integration tier has already earned itself: it caught the PHC parameter
ordering difference between the two bindings (`m,p,t` versus `m,t,p`), which a
positional parser mis-read as "not an Argon2 hash" and would have silently
rewritten an entire password column on first sign-in after adoption. No unit
test with a fake could have found it.
