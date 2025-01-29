import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  Base64URLString,
} from "@simplewebauthn/server";

export type UserModel = {
  id: any;
  username: string;
};

export type Passkey = {
  id: Base64URLString; // Credential ID in Base64URL format
  publicKey: Uint8Array; // Public key as a Uint8Array
  user: UserModel; // Foreign key relation to the user
  webauthnUserID: Base64URLString; // WebAuthn ID associated with this passkey
  counter: number; // Signature counter for replay attack prevention
  // Either `singleDevice` or `multiDevice`
  deviceType: CredentialDeviceType;
  backedUp: boolean; // Indicates if the credential is backed up
  // Ex: ['ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb']
  transports?: AuthenticatorTransportFuture[];
};
