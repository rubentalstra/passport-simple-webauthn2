// tests/unit/strategy/mocks.ts

import { UserModel, Passkey } from '../../../src/types';
import {
    AuthenticationResponseJSON,
    VerifiedAuthenticationResponse,
    VerifiedRegistrationResponse
} from "@simplewebauthn/server";

export const createMockUser = (overrides?: Partial<UserModel>): UserModel => ({
    id: 'user123',
    username: 'testuser',
    ...overrides,
});

export const createMockPasskey = (overrides?: Partial<Passkey>): Passkey => ({
    id: 'credential123',
    publicKey: new Uint8Array([1, 2, 3]),
    counter: 10,
    webauthnUserID: 'user123',
    transports: ['usb'],
    user: createMockUser(),
    ...overrides,
});

export const createMockAuthenticationResponse = (overrides?: Partial<AuthenticationResponseJSON>): AuthenticationResponseJSON => ({
    id: 'credential123',
    rawId: 'rawId123',
    response: {
        authenticatorData: 'authenticatorData123',
        clientDataJSON: 'clientDataJSON123',
        signature: 'signature123',
        userHandle: 'userHandle123',
    },
    type: 'public-key',
    authenticatorAttachment: 'platform',
    clientExtensionResults: {
        appid: true,
        credProps: { rk: true },
        hmacCreateSecret: false,
    },
    ...overrides,
});

export const createMockVerifiedAuthenticationResponse = (overrides?: Partial<VerifiedAuthenticationResponse>): VerifiedAuthenticationResponse => ({
    verified: true,
    authenticationInfo: {
        newCounter: 11,
        credentialID: 'credential123',
        userVerified: true,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        origin: 'https://example.com',
        rpID: 'example.com',
        ...overrides,
    },
});

export const createMockVerifiedRegistrationResponse = (overrides?: Partial<VerifiedRegistrationResponse>): VerifiedRegistrationResponse => ({
    verified: true,
    registrationInfo: {
        fmt: 'fido-u2f',
        aaguid: 'aaguid123',
        credential: {
            id: 'credential123',
            publicKey: new Uint8Array([1, 2, 3]),
            counter: 0,
        },
        credentialType: 'public-key',
        attestationObject: new Uint8Array([4, 5, 6]),
        userVerified: true,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        origin: 'https://example.com',
        rpID: 'example.com',
        authenticatorExtensionResults: {},
        ...overrides,
    },
});