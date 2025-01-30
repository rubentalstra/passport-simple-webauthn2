import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  Base64URLString,
} from "@simplewebauthn/server";

/**
 * Represents a user in the application.
 */
export type UserModel = {
  /**
   * Unique identifier for the user.
   */
  id: Uint8Array;

  /**
   * Username of the user.
   */
  username: string;
};

/**
 * Represents a WebAuthn passkey associated with a user.
 */
export type Passkey = {
  /**
   * Credential ID in Base64URL format.
   */
  id: Base64URLString;

  /**
   * Public key as a Uint8Array.
   */
  publicKey: Uint8Array;

  /**
   * Foreign key relation to the user.
   */
  user: UserModel;

  /**
   * WebAuthn user ID associated with this passkey.
   */
  webauthnUserID: Base64URLString;

  /**
   * Signature counter for replay attack prevention.
   */
  counter: number;

  /**
   * Type of device: either `singleDevice` or `multiDevice`.
   */
  deviceType: CredentialDeviceType;

  /**
   * Indicates if the credential is backed up.
   */
  backedUp: boolean;

  /**
   * Array of authenticator transport methods.
   * Examples: ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']
   */
  transports?: AuthenticatorTransportFuture[];
};
