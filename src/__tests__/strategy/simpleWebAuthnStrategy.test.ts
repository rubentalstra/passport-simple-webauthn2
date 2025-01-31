import { SimpleWebAuthnStrategy } from '../../../src/strategy/simpleWebAuthnStrategy';
import {
    verifyAuthenticationResponse,
    VerifiedAuthenticationResponse,
    VerifiedRegistrationResponse,
    verifyRegistrationResponse,
    RegistrationResponseJSON,
    AuthenticationResponseJSON
} from '@simplewebauthn/server';
import { Request } from 'express';
import { Passkey, UserModel } from '../../../src/types';

// Mock dependencies
jest.mock('@simplewebauthn/server', () => ({
    verifyAuthenticationResponse: jest.fn(),
    verifyRegistrationResponse: jest.fn(),
}));

describe('SimpleWebAuthnStrategy', () => {
    let strategy: SimpleWebAuthnStrategy;
    const mockUser: UserModel = { id: 'user123', username: 'testuser' };
    const mockPasskey: Passkey = {
        id: 'credential123',
        publicKey: new Uint8Array([1, 2, 3]),
        user: mockUser,
        webauthnUserID: 'user123', // Should be Base64URLString
        counter: 10,
        transports: ['usb'],
    };

    const mockAuthenticationResponse: AuthenticationResponseJSON = {
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

    const mockRegistrationResponse: RegistrationResponseJSON = {
        id: mockPasskey.id,
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

    beforeEach(() => {
        jest.resetAllMocks();

        const options = {
            findPasskeyByCredentialID: jest.fn().mockResolvedValue(mockPasskey),
            updatePasskeyCounter: jest.fn().mockResolvedValue(undefined),
            findUserByWebAuthnID: jest.fn().mockResolvedValue(mockUser),
            registerPasskey: jest.fn().mockResolvedValue(undefined),
        };

        strategy = new SimpleWebAuthnStrategy(options);
    });

    it('should handle authentication successfully', async () => {
        const mockVerification: VerifiedAuthenticationResponse = {
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

        (verifyAuthenticationResponse as jest.Mock).mockResolvedValue(mockVerification);

        const success = jest.fn();
        const fail = jest.fn();
        const error = jest.fn();

        (strategy as any).success = success;
        (strategy as any).fail = fail;
        (strategy as any).error = error;

        const mockRequest = {
            path: '/webauthn/login',
            body: {
                response: mockAuthenticationResponse,
                expectedChallenge: 'challenge123', // Passed externally now
            },
        } as unknown as Request;

        strategy.authenticate(mockRequest);
        await new Promise(setImmediate);

        expect(verifyAuthenticationResponse).toHaveBeenCalledWith(expect.objectContaining({
            response: mockAuthenticationResponse,
            expectedChallenge: 'challenge123', // Now passed externally
            expectedOrigin: 'https://example.com',
            expectedRPID: 'example.com',
            credential: {
                id: mockPasskey.id,
                publicKey: mockPasskey.publicKey,
                counter: mockPasskey.counter,
                transports: ['usb'],
            },
            requireUserVerification: true,
        }));
        expect((strategy as any).updatePasskeyCounter).toHaveBeenCalledWith(mockPasskey.id, 11);
        expect(success).toHaveBeenCalledWith(mockPasskey.webauthnUserID);
        expect(fail).not.toHaveBeenCalled();
        expect(error).not.toHaveBeenCalled();
    });

    it('should handle registration successfully', async () => {
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

        (verifyRegistrationResponse as jest.Mock).mockResolvedValue(mockVerifiedResponse);

        const success = jest.fn();
        const fail = jest.fn();
        const error = jest.fn();

        (strategy as any).success = success;
        (strategy as any).fail = fail;
        (strategy as any).error = error;

        const mockRequest = {
            path: '/webauthn/register',
            body: {
                response: mockRegistrationResponse,
                expectedChallenge: 'challenge123', // Passed externally now
            },
        } as unknown as Request;

        strategy.authenticate(mockRequest);
        await new Promise(setImmediate);

        expect(verifyRegistrationResponse).toHaveBeenCalledWith(expect.objectContaining({
            response: mockRegistrationResponse,
            expectedChallenge: 'challenge123', // Now passed externally
            expectedOrigin: 'https://example.com',
            expectedRPID: 'example.com',
            requireUserVerification: true,
        }));
        expect((strategy as any).registerPasskey).toHaveBeenCalledWith(
            mockUser,
            expect.objectContaining({
                id: 'credential123',
                publicKey: expect.any(Uint8Array),
                counter: 0,
                webauthnUserID: mockUser.id,
                transports: ['usb'],
                deviceType: 'singleDevice',
                backedUp: false,
            })
        );
        expect(success).toHaveBeenCalledWith(mockUser);
        expect(fail).not.toHaveBeenCalled();
        expect(error).not.toHaveBeenCalled();
    });

    it('should fail authentication if response data is missing', async () => {
        const mockRequest = {
            path: '/webauthn/login',
            body: {},
        } as unknown as Request;

        const fail = jest.fn();
        (strategy as any).fail = fail;

        strategy.authenticate(mockRequest);
        await new Promise(setImmediate);

        expect(fail).toHaveBeenCalledWith({ message: "Missing response or challenge" }, 400);
    });

    it('should fail registration if verification fails', async () => {
        const mockFailedVerification: VerifiedRegistrationResponse = {
            verified: false,
        };

        (verifyRegistrationResponse as jest.Mock).mockResolvedValue(mockFailedVerification);

        const mockRequest = {
            path: '/webauthn/register',
            body: {
                response: mockRegistrationResponse,
                expectedChallenge: 'challenge123',
            },
        } as unknown as Request;

        const fail = jest.fn();
        (strategy as any).fail = fail;

        strategy.authenticate(mockRequest);
        await new Promise(setImmediate);

        expect(fail).toHaveBeenCalledWith({ message: "Registration verification failed" }, 403);
    });

    it('should handle unknown action gracefully', async () => {
        const mockRequest = {
            path: '/webauthn/unknown',
            body: {},
        } as unknown as Request;

        const fail = jest.fn();
        (strategy as any).fail = fail;

        strategy.authenticate(mockRequest);
        await new Promise(setImmediate);

        expect(fail).toHaveBeenCalledWith({ message: "Unknown action" }, 400);
    });
});