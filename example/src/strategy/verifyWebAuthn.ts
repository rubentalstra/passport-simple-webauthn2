// src/strategy/verifyWebAuthn.ts

import { Request } from 'express';
import {
    verifyRegistrationResponse,
    VerifiedRegistrationResponse,
    verifyAuthenticationResponse,
    VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';
import User, { UserModel } from '../models/User';
import { getChallenge, clearChallenge } from './challengeStore';

export const verifyRegistration = async (req: Request): Promise<UserModel> => {
    const { response, username } = req.body;

    if (!response || !username) {
        throw new Error('Missing registration response or username');
    }

    const user = await User.findOne({ username });
    if (!user) {
        throw new Error('User not found');
    }

    const expectedChallenge = await getChallenge(user.id);
    if (!expectedChallenge) {
        throw new Error('No challenge found for user');
    }

    const verification: VerifiedRegistrationResponse = await verifyRegistrationResponse({
        response,
        expectedChallenge,
        expectedOrigin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000',
        expectedRPID: process.env.WEBAUTHN_RP_ID || 'localhost',
        requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
        throw new Error('Registration verification failed');
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

    // Save the passkey
    user.passkeys.push({
        id: Buffer.from(credential.id).toString('base64'),
        webauthnUserID: user.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports || [],
        deviceType: credentialDeviceType || 'unknown',
        backedUp: credentialBackedUp || false,
        user: user,
    });

    await user.save();
    await clearChallenge(user.id);

    return user;
};

export const verifyAuthentication = async (req: Request): Promise<UserModel> => {
    const { response, username } = req.body;

    if (!response || !username) {
        throw new Error('Missing authentication response or username');
    }

    const user = await User.findOne({ username });
    if (!user) {
        throw new Error('User not found');
    }

    const expectedChallenge = await getChallenge(user.id);
    if (!expectedChallenge) {
        throw new Error('No challenge found for user');
    }

    const passkey = user.passkeys.find(p => p.id === response.id);
    if (!passkey) {
        throw new Error('Passkey not found');
    }

    const verification: VerifiedAuthenticationResponse = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000',
        expectedRPID: process.env.WEBAUTHN_RP_ID || 'localhost',
        credential: {
            id: passkey.id,
            publicKey: passkey.publicKey,
            counter: passkey.counter,
            transports: passkey.transports,
        },
        requireUserVerification: true,
    });

    if (!verification.verified || !verification.authenticationInfo) {
        throw new Error('Authentication verification failed');
    }

    // Update counter
    passkey.counter = verification.authenticationInfo.newCounter;
    await user.save();
    await clearChallenge(user.id);

    return user;
};