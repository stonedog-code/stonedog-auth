/**
 * @stonedogcode/auth — authentication factor primitives.
 *
 * Not a framework, not a session manager, and not a replacement for NextAuth.
 * It is the layer underneath: the parts of password, PIN, TOTP, WebAuthn and
 * emailed-token handling that are identical in every application and dangerous
 * to write twice.
 *
 * Three constraints hold everywhere in here:
 *
 *  - **No storage.** Every stateful factor takes a port the host implements, so
 *    adopting one never means a migration in four repositories at once.
 *  - **No transport.** Nothing knows about HTTP, cookies, or a framework.
 *  - **No secret ever leaves.** Nothing logs, returns, or interpolates a
 *    credential — including into an error message.
 *
 * It must never become a prerequisite. An application should be able to keep
 * its own password hashing and adopt only the TOTP helpers. If taking one
 * factor requires taking the rest, the interface has been drawn wrong.
 */

export {
  AuthError,
  LockedOutError,
  MisconfiguredError,
  ResendTooSoonError,
  WeakSecretError,
  type WeakSecretReason,
} from "./errors.js";

export {
  ARGON2ID_PARAMS,
  systemClock,
  type Argon2Binding,
  type Argon2Params,
  type AuditSink,
  type AuthEvent,
  type Clock,
  type FactorKind,
  type FactorResult,
  type Subject,
} from "./types.js";

export {
  assertAcceptable,
  createPasswordFactor,
  defaultPasswordPolicy,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  type PasswordFactor,
  type PasswordFactorOptions,
  type PasswordPolicy,
} from "./password.js";

export {
  assertPinAcceptable,
  createPinFactor,
  defaultPinPolicy,
  DEFAULT_PIN_LENGTH,
  type PinFactor,
  type PinFactorOptions,
  type PinPolicy,
} from "./pin.js";

export {
  createAttemptLimiter,
  createInMemoryAttemptStore,
  defaultLockoutPolicy,
  pinLockoutPolicy,
  type AttemptLimiter,
  type AttemptLimiterOptions,
  type AttemptRecord,
  type AttemptStore,
  type LockoutPolicy,
} from "./lockout.js";

export {
  carrySessionEstablishment,
  establishSession,
  isSessionCurrent,
  SESSION_ESTABLISHED_CLAIM,
  type SessionClaims,
} from "./session.js";
export {
  createTokenIssuer,
  defaultTokenPolicy,
  generateNumericCode,
  generateToken,
  hashToken,
  tokenHashEquals,
  type ConsumeResult,
  type IssuedToken,
  type IssueOptions,
  type StoredToken,
  type TokenIssuer,
  type TokenIssuerOptions,
  type TokenHashEncoding,
  type TokenKind,
  type TokenPolicy,
  type TokenStore,
} from "./tokens.js";

export {
  createTotpFactor,
  defaultTotpParams,
  fromBase32,
  generateTotpSecret,
  toBase32,
  totpCodeAt,
  totpProvisioningUri,
  verifyTotpCode,
  type ProvisioningUriOptions,
  type TotpFactor,
  type TotpFactorOptions,
  type TotpParams,
  type TotpReplayStore,
} from "./totp.js";

export {
  AUTH_METHODS,
  canRemoveCredential,
  isDowngrade,
  mayAuthenticateWith,
  methodAssurance,
  requiredSteps,
  type AuthMethod,
  type CredentialFactor,
  type CredentialRecord,
  type RemovalVerdict,
} from "./methods.js";

export { createRecoveryCodes, type RecoveryCodeStore } from "./recovery.js";

export {
  createSignInTickets,
  type SignInTicketStore,
  type StoredTicket,
} from "./signin-ticket.js";

export { createEmailCodeFactor } from "./email-code.js";

export { pkceChallengeS256, verifyPkceS256 } from "./pkce.js";

// 0.5.0 — the cross-device link ticket, per-surface credentials, and the
// server half of the on-device key. Lifted from hopper-web (NEH-1978).
export {
  createLinkTickets,
  LIVE_LINK_STATES,
  type CompleteLinkOutcome,
  type LinkCancelReason,
  type LinkTicketMeta,
  type LinkTicketOptions,
  type LinkTicketPatch,
  type LinkTicketRef,
  type LinkTicketState,
  type LinkTicketStatus,
  type LinkTicketStore,
  type LinkTicketView,
  type LinkTicketWhere,
  type LinkTickets,
  type MintedLinkTicket,
  type NewLinkTicket,
  type ScannedLinkTicket,
  type StoredLinkTicket,
} from "./link-ticket.js";

export {
  formatManualCode,
  MANUAL_CODE_ALPHABET,
  MANUAL_CODE_BITS,
  MANUAL_CODE_LENGTH,
  manualCodeForTicketHash,
  manualCodeKeyFrom,
  manualCodesEqual,
  normaliseManualCode,
} from "./manual-code.js";

export {
  AUTH_SURFACES,
  CREDENTIAL_KINDS,
  credentialAllowedOn,
  type AuthSurface,
  type CredentialKind,
} from "./surfaces.js";

export {
  createDecoyVerifier,
  createDeviceKeyChallenges,
  parseDeviceKeyPem,
  verifyDeviceKeySignature,
  type DeviceKeyChallengeKind,
  type DeviceKeyChallengeOptions,
  type DeviceKeyChallengeStore,
  type DeviceKeyChallenges,
  type StoredDeviceKeyChallenge,
} from "./device-key.js";

export {
  createWebAuthnChallenges,
  generateChallenge,
  type CeremonyKind,
  type ChallengeStore,
  type StoredChallenge,
  type WebAuthnChallenges,
  type WebAuthnOptions,
} from "./webauthn.js";
