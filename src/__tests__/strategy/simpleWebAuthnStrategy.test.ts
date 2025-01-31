// tests/unit/strategy/SimpleWebAuthnStrategy.test.ts

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
import { getChallenge, clearChallenge } from '../../../src/strategy/challengeStore';

// Mock dependencies
jest.mock('@simplewebauthn/server', () => ({
    verifyAuthenticationResponse: jest.fn(),
    verifyRegistrationResponse: jest.fn(),
}));

jest.mock('../../../src/strategy/challengeStore', () => ({
    getChallenge: jest.fn(),
    clearChallenge: jest.fn(),
}));

describe('SimpleWebAuthnStrategy', () => {
    let strategy: SimpleWebAuthnStrategy;
    const mockUser = { id: 'user123', username: 'testuser' };
    const mockPasskey = {
        id: 'credential123',
        publicKey: new Uint8Array([1, 2, 3]),
        counter: 10,
        webauthnUserID: 'user123',
        transports: ['usb'],
        user: mockUser,
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
        authenticatorAttachment: 'platform', // 'platform' or 'cross-platform'
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
        // Arrange
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
        (getChallenge as jest.Mock).mockResolvedValue('challenge123');

        const success = jest.fn();
        const fail = jest.fn();
        const error = jest.fn();

        // Spy on the strategy's success, fail, and error methods
        (strategy as any).success = success;
        (strategy as any).fail = fail;
        (strategy as any).error = error;

        // Act
        strategy.authenticate({
            path: '/webauthn/login',
            body: {
                response: mockAuthenticationResponse,
            },
        } as unknown as Request);
        await new Promise(setImmediate); // Wait for async operations

        // Assert
        expect(getChallenge).toHaveBeenCalledWith(mockPasskey.id);
        expect(verifyAuthenticationResponse).toHaveBeenCalledWith(expect.objectContaining({
            response: mockAuthenticationResponse,
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
        }));
        expect((strategy as any).updatePasskeyCounter).toHaveBeenCalledWith(mockPasskey.id, 11);
        expect(clearChallenge).toHaveBeenCalledWith(mockPasskey.id);
        expect(success).toHaveBeenCalledWith(mockUser);
        expect(fail).not.toHaveBeenCalled();
        expect(error).not.toHaveBeenCalled();
    });

    it('should handle registration successfully', async () => {
        // Arrange
        const mockVerifiedResponse: VerifiedRegistrationResponse = {
            verified: true,
            registrationInfo: {
                fmt: 'fido-u2f',
                aaguid: 'aaguid123',
                credential: {
                    id: 'credential123',
                    publicKey: new Uint8Array([1, 2, 3]),
                    counter: 0, // Added counter
                    transports: ['usb'], // Added transports
                },
                credentialType: 'public-key',
                attestationObject: new Uint8Array([4, 5, 6]),
                userVerified: true,
                credentialDeviceType: 'singleDevice', // Changed to match received value
                credentialBackedUp: false,
                origin: 'https://example.com',
                rpID: 'example.com',
                authenticatorExtensionResults: {},
            },
        };

        (verifyRegistrationResponse as jest.Mock).mockResolvedValue(mockVerifiedResponse);
        (getChallenge as jest.Mock).mockResolvedValue('challenge123');

        const success = jest.fn();
        const fail = jest.fn();
        const error = jest.fn();

        // Spy on the strategy's success, fail, and error methods
        (strategy as any).success = success;
        (strategy as any).fail = fail;
        (strategy as any).error = error;

        // Act
        strategy.authenticate({
            path: '/webauthn/register',
            body: {
                response: mockRegistrationResponse,
            },
        } as unknown as Request);
        await new Promise(setImmediate); // Wait for async operations

        // Assert
        expect(getChallenge).toHaveBeenCalledWith(mockPasskey.id);
        expect(verifyRegistrationResponse).toHaveBeenCalledWith(expect.objectContaining({
            response: mockRegistrationResponse,
            expectedChallenge: 'challenge123',
            expectedOrigin: 'https://example.com',
            expectedRPID: 'example.com',
            requireUserVerification: true,
        }));
        expect((strategy as any).registerPasskey).toHaveBeenCalledWith(expect.objectContaining({
            id: 'credential123',
            publicKey: new Uint8Array([1, 2, 3]),
            counter: 0,
            webauthnUserID: 'user123',
            user: mockUser,
            transports: ['usb'],
            deviceType: 'singleDevice', // Changed to match received value
            backedUp: false,
        }));
        expect(clearChallenge).toHaveBeenCalledWith(mockPasskey.id);
        expect(success).toHaveBeenCalledWith(mockUser);
        expect(fail).not.toHaveBeenCalled();
        expect(error).not.toHaveBeenCalled();
    });

    it('should fail authentication if response data is missing', async () => {
        // Arrange
        const mockRequest = {
            path: '/webauthn/login',
            body: {},
        } as unknown as Request;

        const success = jest.fn();
        const fail = jest.fn();
        const error = jest.fn();

        (strategy as any).success = success;
        (strategy as any).fail = fail;
        (strategy as any).error = error;

        // Act
        strategy.authenticate(mockRequest);
        await new Promise(setImmediate); // Wait for async operations

        // Assert
        expect(fail).toHaveBeenCalledWith({ message: "Missing response data" }, 400);
        expect(success).not.toHaveBeenCalled();
        expect(error).not.toHaveBeenCalled();
    });

    it('should fail registration if verification fails', async () => {
        // Arrange
        const mockFailedVerification: VerifiedRegistrationResponse = {
            verified: false,
        };

        (verifyRegistrationResponse as jest.Mock).mockResolvedValue(mockFailedVerification);
        (getChallenge as jest.Mock).mockResolvedValue('challenge123');

        const mockRegistrationRequest = {
            path: '/webauthn/register',
            body: {
                response: mockRegistrationResponse,
            },
        } as unknown as Request;

        const success = jest.fn();
        const fail = jest.fn();
        const error = jest.fn();

        (strategy as any).success = success;
        (strategy as any).fail = fail;
        (strategy as any).error = error;

        // Act
        strategy.authenticate(mockRegistrationRequest);
        await new Promise(setImmediate); // Wait for async operations

        // Assert
        expect(fail).toHaveBeenCalledWith({ message: "Registration verification failed" }, 403);
        expect(success).not.toHaveBeenCalled();
        expect(error).not.toHaveBeenCalled();
    });

    it('should handle unknown action gracefully', async () => {
        // Arrange
        const mockRequest = {
            path: '/webauthn/unknown',
            body: {},
        } as unknown as Request;

        const success = jest.fn();
        const fail = jest.fn();
        const error = jest.fn();

        (strategy as any).success = success;
        (strategy as any).fail = fail;
        (strategy as any).error = error;

        // Act
        strategy.authenticate(mockRequest);
        await new Promise(setImmediate); // Wait for async operations

        // Assert
        expect(fail).toHaveBeenCalledWith({ message: "Unknown action" }, 400);
        expect(success).not.toHaveBeenCalled();
        expect(error).not.toHaveBeenCalled();
    });
});