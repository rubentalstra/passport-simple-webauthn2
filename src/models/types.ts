import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  Base64URLString,
} from "@simplewebauthn/server";

/**
 * User model representing your application's user.
 */
export type UserModel = {
  id: string; // Unique identifier for the user
  username: string;
  displayName?: string;
  credentials: Passkey[]; // Array of associated passkeys
};

/**
 * Passkey model representing a WebAuthn credential.
 */
export type Passkey = {
  id: Base64URLString; // Base64URL-encoded credential ID
  publicKey: Uint8Array; // PEM-encoded public key
  user: UserModel; // Associated user
  webauthnUserID: Base64URLString; // User ID used in WebAuthn
  counter: number; // Signature counter to prevent replay attacks
  deviceType: CredentialDeviceType; // 'platform' or 'cross-platform'
  backedUp: boolean; // Indicates if the passkey is backed up
  transports?: AuthenticatorTransportFuture[]; // ['usb', 'nfc', etc.]
};
