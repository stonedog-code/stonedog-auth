/**
 * Which SURFACE a credential may sign in to — and may step up on.
 *
 * A credential has a kind, decided when it was enrolled: a `web` passkey lives
 * in a browser's authenticator or a synced credential manager; a `mobile`
 * credential is an on-device key unlocked by the phone's fingerprint
 * (`@stonedogcode/mobile-auth`). Each proves possession of ONE device class,
 * so each may authenticate only the surface it was enrolled for. The crossing
 * this exists to refuse is the quiet one: a mobile key accepted on a web route
 * is a phone standing in for a passkey nobody enrolled on the web, and a web
 * passkey accepted on a mobile route is the inverse.
 *
 * Step-up is the same question. A privileged web action re-confirmed by a
 * mobile credential is the same crossing by another route, so the one function
 * answers both — call it where the credential is RESOLVED, not where it is
 * listed, and derive `surface` from the request rather than from anything the
 * client declares.
 *
 * Pure. No storage, no clock, no transport.
 */

/** Where a credential was enrolled, and therefore where it may be used. */
export type CredentialKind = "web" | "mobile";
/** Where a request arrived. Derived from the request by the host, never declared by the client. */
export type AuthSurface = "web" | "mobile";

export const CREDENTIAL_KINDS: readonly CredentialKind[] = Object.freeze(["web", "mobile"] as const);
export const AUTH_SURFACES: readonly AuthSurface[] = Object.freeze(["web", "mobile"] as const);

/**
 * May a credential of `kind` authenticate — or step up — on `surface`?
 *
 * True only on the diagonal. For a `mobile` credential, `userVerified` must be
 * literally `true`: the on-device key is only as strong as the fingerprint
 * that unlocked it, and a verification the client merely did not mention is
 * one that did not happen. Anything outside the two unions — a string from a
 * column that is neither value — is refused, so a corrupt row closes a door
 * rather than opening one.
 */
export function credentialAllowedOn(
  kind: CredentialKind,
  surface: AuthSurface,
  options: { userVerified?: boolean } = {},
): boolean {
  if (!CREDENTIAL_KINDS.includes(kind)) return false;
  if (!AUTH_SURFACES.includes(surface)) return false;
  if (kind !== surface) return false;
  if (kind === "mobile") return options.userVerified === true;
  return true;
}
