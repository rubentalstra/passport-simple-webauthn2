import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
} from "@simplewebauthn/server";

/**
 * Represents a user in the system.
 */
export interface UserModel {
  id: string;
  username: string;
  // Add other user-related fields as necessary
}

/**
 * Represents a WebAuthn passkey.
 */
export interface Passkey {
  id: string;
  publicKey: Uint8Array;
  counter: number;
  webauthnUserID: string;
  transports?: AuthenticatorTransportFuture[];
  deviceType?: CredentialDeviceType;
  backedUp?: boolean;
  user: UserModel;
}

/**
 * Options required to initialize the SimpleWebAuthnStrategy.
 */
export interface SimpleWebAuthnStrategyOptions {
  findPasskeyByCredentialID: (credentialID: string) => Promise<Passkey | null>;
  updatePasskeyCounter: (
    credentialID: string,
    newCounter: number,
  ) => Promise<void>;
  findUserByWebAuthnID: (webauthnUserID: string) => Promise<UserModel | null>;
  registerPasskey: (passkey: Passkey) => Promise<void>;
}
