// types/index.ts

import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  Base64URLString,
} from "@simplewebauthn/server";

export interface UserModel {
  id: string;
  username: string;
}

export interface Passkey {
  id: Base64URLString;
  publicKey: Uint8Array;
  user: UserModel;
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
  findUserByWebAuthnID: (webauthnUserID: string) => Promise<UserModel | null>;
  registerPasskey: (
    user: UserModel,
    passkey: Passkey,
  ) => Promise<Map<string, Passkey>>;
}
