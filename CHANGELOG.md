# Changelog

## 0.5.0 — 2026-10-08

The cross-device link ticket, credential surfaces, the last-way-in guard and
the server half of the on-device key — lifted from hopper-web's shipped
"connect a phone" (NEH-1877, NEH-1848) so rozcards does not write a second copy
(NEH-1978; consumers NEH-1880, NEH-1881, NEH-1878).

### Added

- `createLinkTickets` — `mint`, `scan` (by ticket or manual code), `read`,
  `confirm`, `cancel`, `burn`, `complete`, `cancelFromPhone`,
  `claimEnrolment`, over a `LinkTicketStore` port (`insert`, `findOne`,
  `findPending`, `updateMany`). Every transition is one conditional write with
  the FROM state in its where-clause.
- `manualCodeForTicketHash`, `manualCodeKeyFrom`, `normaliseManualCode`,
  `formatManualCode`, `manualCodesEqual` — the derived 40-bit Crockford code,
  byte-compatible with `@stonedogcode/mobile-auth`.
- `credentialAllowedOn(kind, surface, { userVerified })` — true on the
  diagonal only; `mobile` needs `userVerified: true`.
- `canRemoveCredential(method, credentials, removingId)` — refuses removing
  the last credential a method's steps need; a `device-key` satisfies no step.
- `parseDeviceKeyPem`, `verifyDeviceKeySignature`, `createDeviceKeyChallenges`
  (`issue`, `claim`, `unstored`), `createDecoyVerifier`.
- `FactorKind` gains `"device-key"`. **Additive, as `"recovery-code"` was in
  0.4.0** — a consumer with an exhaustive `switch` over `FactorKind` gains a
  case to handle, which is the compiler telling it a new factor exists.

### Unchanged

Every 0.4.0 export keeps its signature and meaning. Still zero runtime
dependencies; `@stonedogcode/mobile-auth` and `@noble/curves` are **dev**
dependencies for the cross-package suite only.

### Review

The PRD (`stonedog-prd/stonedog-auth/cross-device-link-and-device-key.md`)
was reviewed by the second model before implementation. Adopted: cut the PKCE
binding (the nonce is the phone's proof; rozcards' browser-session flow is
NEH-1880's design question), a ceiling on the manual-code scan, documenting
the mint race and `meta` serialisation. Rejected, with reasons in the PRD:
dropping `node:crypto` for edge runtimes, dropping consume-first (a challenge
nobody holds cannot be burned), dropping the decoy verifier.

## 0.4.0

Sign-in methods, step tickets, recovery codes, email code and PKCE (NEH-1729).
