// types/index.ts

import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
} from "@simplewebauthn/server";

/**
 * Passkey information stored in the server.
 */
export interface Passkey {
  id: string; // Base64URLString
  publicKey: Uint8Array;
  userID: string; // Base64URLString
  webauthnUserID: string; // Base64URLString
  counter: number;
  deviceType?: CredentialDeviceType;
  backedUp?: boolean;
  transports?: AuthenticatorTransportFuture[] | undefined;
}

/**
 * Options required by the WebAuthn Passport strategies.
 */
export interface SimpleWebAuthnStrategyOptions {
  findPasskeyByCredentialID: (credentialID: string) => Promise<Passkey | null>;
  updatePasskeyCounter: (
    credentialID: string,
    newCounter: number,
  ) => Promise<void>;
  registerPasskey: (userID: string, passkey: Passkey) => Promise<void>;
}
