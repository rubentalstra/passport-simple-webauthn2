import { verifyAuthentication } from '../../../src/strategy/verifyAuthentication';
import { Passkey } from '../../../src/types';
import {
    AuthenticationResponseJSON,
    VerifiedAuthenticationResponse,
    verifyAuthenticationResponse
} from "@simplewebauthn/server";

// Mock verifyAuthenticationResponse from the WebAuthn server
jest.mock('@simplewebauthn/server', () => ({
    verifyAuthenticationResponse: jest.fn(),
}));

describe('verifyAuthentication', () => {
    const mockPasskey: Passkey = {
        id: 'credential123',
        publicKey: new Uint8Array([1, 2, 3]),
        userID: 'user123',
        webauthnUserID: 'user123', // Should be Base64URLString
        counter: 10,
        transports: ['usb'],
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
        authenticatorAttachment: 'platform',
        clientExtensionResults: {
            appid: true,
            credProps: { rk: true },
            hmacCreateSecret: false,
        },
    };

    it('should verify authentication and update the passkey counter', async () => {
        (verifyAuthenticationResponse as jest.Mock).mockResolvedValue(mockVerifiedResponse);
        const findPasskey = jest.fn().mockResolvedValue(mockPasskey);
        const updatePasskeyCounter = jest.fn().mockResolvedValue(undefined);

        const expectedChallenge = 'challenge123'; // Passed externally

        const result = await verifyAuthentication(mockResponse, expectedChallenge, findPasskey, updatePasskeyCounter);

        expect(verifyAuthenticationResponse).toHaveBeenCalledWith({
            response: mockResponse,
            expectedChallenge: expectedChallenge, // Now passed externally
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
        expect(result).toEqual(mockVerifiedResponse);
    });

    it('should throw an error if the authentication response is invalid', async () => {
        await expect(verifyAuthentication(null as any, 'challenge123', jest.fn(), jest.fn()))
            .rejects.toThrow('Invalid authentication response');
    });

    it('should throw an error if the challenge is missing', async () => {
        await expect(verifyAuthentication(mockResponse, '', jest.fn(), jest.fn()))
            .rejects.toThrow("Passkey not found or does not exist");
    });

    it('should throw an error if passkey is not found', async () => {
        const findPasskey = jest.fn().mockResolvedValue(null);
        await expect(verifyAuthentication(mockResponse, 'challenge123', findPasskey, jest.fn()))
            .rejects.toThrow('Passkey not found or does not exist');
    });

    it('should throw an error if verification fails', async () => {
        (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({ verified: false } as VerifiedAuthenticationResponse);
        const findPasskey = jest.fn().mockResolvedValue(mockPasskey);

        await expect(verifyAuthentication(mockResponse, 'challenge123', findPasskey, jest.fn()))
            .rejects.toThrow('Authentication failed');
    });
});