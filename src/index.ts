/**
 * stonedog-auth — authentication factor primitives.
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
} from "./errors";

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
} from "./types";

export {
  assertAcceptable,
  createPasswordFactor,
  defaultPasswordPolicy,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  type PasswordFactor,
  type PasswordFactorOptions,
  type PasswordPolicy,
} from "./password";

export {
  assertPinAcceptable,
  createPinFactor,
  defaultPinPolicy,
  DEFAULT_PIN_LENGTH,
  type PinFactor,
  type PinFactorOptions,
  type PinPolicy,
} from "./pin";

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
} from "./lockout";

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
  type TokenKind,
  type TokenPolicy,
  type TokenStore,
} from "./tokens";

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
} from "./totp";

export {
  createWebAuthnChallenges,
  generateChallenge,
  type CeremonyKind,
  type ChallengeStore,
  type StoredChallenge,
  type WebAuthnChallenges,
  type WebAuthnOptions,
} from "./webauthn";
