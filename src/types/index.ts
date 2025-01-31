// types/index.ts

import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  Base64URLString,
} from "@simplewebauthn/server";

export interface Passkey {
  id: Base64URLString;
  publicKey: Uint8Array;
  userID: Base64URLString;
  webauthnUserID: Base64URLString;
  counter: number;
  deviceType?: CredentialDeviceType;
  backedUp?: boolean;
  transports?: AuthenticatorTransportFuture[] | undefined;
}

export interface SimpleWebAuthnStrategyOptions {
  findPasskeyByCredentialID: (credentialID: string) => Promise<Passkey | null>;
  updatePasskeyCounter: (
    credentialID: string,
    newCounter: number,
  ) => Promise<void>;
  findUserIDByWebAuthnID: (
    webauthnUserID: string,
  ) => Promise<Base64URLString | null>;
  registerPasskey: (userID: Base64URLString, passkey: Passkey) => Promise<void>;
}
