// tests/unit/strategy/verifyAuthentication.test.ts

import { verifyAuthentication } from '../../../src/strategy/verifyAuthentication';
import { getChallenge, clearChallenge } from '../../../src/strategy/challengeStore';
import { Passkey } from '../../../src/types';
import {
    AuthenticationResponseJSON,
    VerifiedAuthenticationResponse,
    verifyAuthenticationResponse
} from "@simplewebauthn/server";

// Mock the challengeStore and verifyAuthenticationResponse
jest.mock('../../../src/strategy/challengeStore', () => ({
    getChallenge: jest.fn(),
    clearChallenge: jest.fn(),
}));

jest.mock('@simplewebauthn/server', () => ({
    verifyAuthenticationResponse: jest.fn(),
}));

describe('verifyAuthentication', () => {
    const mockPasskey: Passkey = {
        id: 'credential123',
        publicKey: new Uint8Array([1, 2, 3]),
        counter: 10,
        webauthnUserID: 'user123',
        transports: ['usb'],
        user: { id: 'user123', username: 'testuser' },
    };

    const mockVerifiedResponse: VerifiedAuthenticationResponse = {
        verified: true,
        authenticationInfo: {
            newCounter: 11,
            credentialID: 'credential123',
            userVerified: true,
            credentialDeviceType: 'singleDevice',
            credentialBackedUp: false,
            origin: 'https://example.com',
            rpID: 'example.com',
            // If there are additional required fields, include them here
        },
    };

    const mockResponse: AuthenticationResponseJSON = {
        id: mockPasskey.id,
        rawId: 'rawId123',
        response: {
            authenticatorData: 'authenticatorData123',
            clientDataJSON: 'clientDataJSON123',
            signature: 'signature123',
            userHandle: 'userHandle123',
        },
        type: 'public-key',
        authenticatorAttachment: 'platform', // Filled with a realistic value
        clientExtensionResults: { // Filled with realistic mock extension data
            appid: true,
            credProps: { rk: true },
            hmacCreateSecret: false,
        },
    };

    it('should verify authentication and update the passkey counter', async () => {
        (getChallenge as jest.Mock).mockResolvedValue('challenge123');
        (verifyAuthenticationResponse as jest.Mock).mockResolvedValue(mockVerifiedResponse);
        const findPasskey = jest.fn().mockResolvedValue(mockPasskey);
        const updatePasskeyCounter = jest.fn().mockResolvedValue(undefined);

        const result = await verifyAuthentication(mockResponse, findPasskey, updatePasskeyCounter);

        expect(getChallenge).toHaveBeenCalledWith(mockResponse.id);
        expect(verifyAuthenticationResponse).toHaveBeenCalledWith({
            response: mockResponse,
            expectedChallenge: 'challenge123',
            expectedOrigin: 'https://example.com',
            expectedRPID: 'example.com',
            credential: {
                id: mockPasskey.id,
                publicKey: mockPasskey.publicKey,
                counter: mockPasskey.counter,
                transports: ['usb'],
            },
            requireUserVerification: true,
        });
        expect(findPasskey).toHaveBeenCalledWith(mockResponse.id);
        expect(updatePasskeyCounter).toHaveBeenCalledWith(mockPasskey.id, mockVerifiedResponse.authenticationInfo.newCounter);
        expect(clearChallenge).toHaveBeenCalledWith(mockResponse.id);
        expect(result).toEqual(mockVerifiedResponse);
    });

    it('should throw an error if the authentication response is invalid', async () => {
        await expect(verifyAuthentication(null as any, jest.fn(), jest.fn())).rejects.toThrow('Invalid authentication response');
    });

    it('should throw an error if the challenge is missing', async () => {
        (getChallenge as jest.Mock).mockResolvedValue(null);

        await expect(verifyAuthentication(mockResponse, jest.fn(), jest.fn())).rejects.toThrow('Challenge expired or missing');
    });

    it('should throw an error if passkey is not found', async () => {
        (getChallenge as jest.Mock).mockResolvedValue('challenge123');
        const findPasskey = jest.fn().mockResolvedValue(null);

        await expect(verifyAuthentication(mockResponse, findPasskey, jest.fn())).rejects.toThrow('Passkey not found or does not exist');
    });
    it('should throw an error if verification fails', async () => {
        // Arrange
        (getChallenge as jest.Mock).mockResolvedValue('challenge123');
        (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({ verified: false } as VerifiedAuthenticationResponse);
        const findPasskey = jest.fn().mockResolvedValue(mockPasskey);

        // Act & Assert
        await expect(verifyAuthentication(mockResponse, findPasskey, jest.fn())).rejects.toThrow('Authentication failed');
    });
});