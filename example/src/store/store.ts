// src/store.ts

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

export const users = new Map<string, UserModel>();
export const passkeys = new Map<string, Passkey>();