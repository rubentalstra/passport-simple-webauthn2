import { generateRegistration, verifyRegistration } from '../../../src/auth/registration';
import { UserModel, Passkey } from '../../../src/types';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    RegistrationResponseJSON,
    VerifiedRegistrationResponse
} from '@simplewebauthn/server';

// Mock @simplewebauthn/server functions
jest.mock('@simplewebauthn/server', () => ({
    ...jest.requireActual('@simplewebauthn/server'),
    generateRegistrationOptions: jest.fn(),
    verifyRegistrationResponse: jest.fn(),
}));

describe('generateRegistration', () => {
    const mockUser: UserModel = {
        id: 'user123',
        username: 'testuser',
    };

    it('should generate registration options', async () => {
        const mockOptions = {
            challenge: 'challenge123',
            rp: {
                name: 'Example RP',
                id: 'example.com',
            },
            user: {
                id: Buffer.from(mockUser.id).toString('base64'),
                name: mockUser.username,
                displayName: mockUser.username,
            },
        };

        (generateRegistrationOptions as jest.Mock).mockReturnValue(mockOptions);

        const options = await generateRegistration(mockUser);

        expect(options).toHaveProperty('challenge', 'challenge123');
        expect(options).toHaveProperty('rp');
        expect(options).toHaveProperty('user');
        expect(options.user).toHaveProperty('id');

        expect(Buffer.from(options.user.id, 'base64').toString('utf8')).toEqual(mockUser.id);
    });

    it('should throw an error if registration options generation fails', async () => {
        (generateRegistrationOptions as jest.Mock).mockImplementation(() => {
            throw new Error('Generation failed');
        });

        await expect(generateRegistration(mockUser)).rejects.toThrow("Generation failed");
    });
});

describe('verifyRegistration', () => {
    const mockUser: UserModel = {
        id: 'user123',
        username: 'testuser',
    };

    const mockResponse: RegistrationResponseJSON = {
        id: 'credential123', // ✅ WebAuthn user ID should come from response.id
        rawId: 'rawId123',
        response: {
            attestationObject: 'attestationObject123',
            clientDataJSON: 'clientDataJSON123',
        },
        type: 'public-key',
        authenticatorAttachment: 'platform',
        clientExtensionResults: {
            appid: true,
            credProps: { rk: true },
            hmacCreateSecret: false,
        },
    };

    const mockVerifiedResponse: VerifiedRegistrationResponse = {
        verified: true,
        registrationInfo: {
            fmt: 'fido-u2f',
            aaguid: 'aaguid123',
            credential: {
                id: 'credential123',
                publicKey: new Uint8Array([1, 2, 3]),
                counter: 0,
                transports: ['usb'],
            },
            credentialType: 'public-key',
            attestationObject: new Uint8Array([4, 5, 6]),
            userVerified: true,
            credentialDeviceType: 'singleDevice',
            credentialBackedUp: false,
            origin: 'https://example.com',
            rpID: 'example.com',
            authenticatorExtensionResults: {},
        },
    };

    it('should verify registration and save the passkey', async () => {
        (verifyRegistrationResponse as jest.Mock).mockResolvedValue(mockVerifiedResponse);

        const findUserByWebAuthnID = jest.fn().mockResolvedValue(mockUser);
        const registerPasskey = jest.fn().mockResolvedValue(undefined);
        const expectedChallenge = 'challenge123';

        const result = await verifyRegistration(mockResponse, expectedChallenge, findUserByWebAuthnID, registerPasskey);

        // ✅ Ensure the function searches for the correct user using the WebAuthn credential ID
        expect(findUserByWebAuthnID).toHaveBeenCalledWith(mockResponse.id); // FIXED

        // ✅ Ensure passkey registration includes correct WebAuthn user ID
        expect(registerPasskey).toHaveBeenCalledWith(mockUser, expect.objectContaining({
            id: 'credential123',
            publicKey: new Uint8Array([1, 2, 3]),
            counter: 0,
            webauthnUserID: mockUser.id,  // ✅ Ensure we use the correct user ID
            transports: ['usb'],
            deviceType: 'singleDevice',
            backedUp: false,
            user: mockUser,  // ✅ Correct user object is included
        }));

        expect(result).toEqual(mockVerifiedResponse);
    });

    it('should throw an error if verification fails', async () => {
        (verifyRegistrationResponse as jest.Mock).mockResolvedValue({ verified: false });

        const findUserByWebAuthnID = jest.fn().mockResolvedValue(mockUser);
        const registerPasskey = jest.fn();

        await expect(verifyRegistration(mockResponse, 'challenge123', findUserByWebAuthnID, registerPasskey))
            .rejects.toThrow('Registration verification failed');
    });

    it('should throw an error if user is not found', async () => {
        (verifyRegistrationResponse as jest.Mock).mockResolvedValue(mockVerifiedResponse);

        const findUserByWebAuthnID = jest.fn().mockResolvedValue(null);
        const registerPasskey = jest.fn();

        await expect(verifyRegistration(mockResponse, 'challenge123', findUserByWebAuthnID, registerPasskey))
            .rejects.toThrow('User not found');
    });

    it('should throw an error if WebAuthn user ID is missing', async () => {
        (verifyRegistrationResponse as jest.Mock).mockResolvedValue({
            verified: true,
            registrationInfo: {
                ...mockVerifiedResponse.registrationInfo,
                credential: {
                    id: '', // 🔹 FIX: Explicitly check for empty ID
                    publicKey: new Uint8Array([1, 2, 3]),
                    counter: 0,
                    transports: ['usb'],
                },
            },
        });

        const findUserByWebAuthnID = jest.fn().mockResolvedValue(mockUser);
        const registerPasskey = jest.fn();

        // 🔹 FIX: Ensure `verifyRegistration` rejects when credential ID is missing
        await expect(verifyRegistration(mockResponse, 'challenge123', findUserByWebAuthnID, registerPasskey))
            .rejects.toThrow('User handle (WebAuthn user ID) missing in registration response');
    });
});