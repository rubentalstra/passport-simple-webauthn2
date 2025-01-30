import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  Base64URLString,
} from "@simplewebauthn/server";

/**
 * User model representing a user in the application.
 */
export type UserModel = {
  id: any;
  username: string;
};

/**
 * Passkey model representing a WebAuthn credential.
 */
export type Passkey = {
  id: Base64URLString; // Credential ID
  publicKey: Uint8Array; // Public Key as raw bytes
  user: UserModel; // Linked user
  webauthnUserID: Base64URLString; // WebAuthn user ID
  counter: number; // Prevents replay attacks
  deviceType: CredentialDeviceType; // 'singleDevice' or 'multiDevice'
  backedUp: boolean; // Backup flag
  transports?: AuthenticatorTransportFuture[]; // Array of transport types
};
