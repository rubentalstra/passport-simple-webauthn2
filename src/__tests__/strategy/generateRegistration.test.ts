// tests/unit/strategy/generateRegistration.test.ts

import { generateRegistration } from '../../../src/strategy/verifyRegistration';
import { saveChallenge } from '../../../src/strategy/challengeStore';
import { UserModel } from '../../types';
import * as SimpleWebAuthnServer from '@simplewebauthn/server'; // Import as namespace

// Mock the challengeStore functions
jest.mock('../../../src/strategy/challengeStore', () => ({
    saveChallenge: jest.fn(),
}));

// Mock @simplewebauthn/server functions, preserving other implementations
jest.mock('@simplewebauthn/server', () => ({
    ...jest.requireActual('@simplewebauthn/server'),
    verifyAuthenticationResponse: jest.fn(),
    verifyRegistrationResponse: jest.fn(),
    generateRegistrationOptions: jest.fn(), // Include in the mock
}));

describe('generateRegistration', () => {
    const mockUser: UserModel = {
        id: 'user123',
        username: 'testuser',
        // Add other fields if necessary
    };

    it('should generate registration options and save the challenge', async () => {
        // Arrange: Mock 'generateRegistrationOptions' to return expected options
        const mockOptions = {
            challenge: 'challenge123',
            rp: {
                name: 'Example RP',
                id: 'example.com',
            },
            user: {
                id: Buffer.from(mockUser.id).toString('base64'), // WebAuthn expects user.id as base64
                name: mockUser.username,
                displayName: mockUser.username,
            },
            // Add other necessary properties as per your implementation
        };
        (SimpleWebAuthnServer.generateRegistrationOptions as jest.Mock).mockReturnValue(mockOptions);

        // Act
        const options = await generateRegistration(mockUser);

        // Assert
        expect(options).toHaveProperty('challenge');
        expect(options).toHaveProperty('rp');
        expect(options).toHaveProperty('user');
        expect(options.user).toHaveProperty('id');

        // Corrected expectation: Decode Base64 and compare to 'user123'
        expect(Buffer.from(options.user.id, 'base64').toString('utf8')).toEqual(mockUser.id);

        expect(saveChallenge).toHaveBeenCalledWith(mockUser.id, options.challenge);
    });

    it('should throw an error if registration options generation fails', async () => {
        // Arrange
        (SimpleWebAuthnServer.generateRegistrationOptions as jest.Mock).mockImplementation(() => {
            throw new Error('Generation failed');
        });

        // Act & Assert
        await expect(generateRegistration(mockUser)).rejects.toThrow('Failed to generate registration options');
    });
});