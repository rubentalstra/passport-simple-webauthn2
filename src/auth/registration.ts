// registration.ts

import type {
  RegistrationResponseJSON,
  VerifiedRegistrationResponse,
  PublicKeyCredentialCreationOptionsJSON,
} from "@simplewebauthn/server";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "../challengeStore";
import type { UserModel, Passkey } from "../types";

/**
 * Generates registration options for a new WebAuthn credential.
 * @param user - The user requesting registration.
 * @returns A promise that resolves to the registration options JSON.
 */
export const generateRegistration = async (
  user: UserModel,
): Promise<PublicKeyCredentialCreationOptionsJSON> => {
  try {
    const options = await generateRegistrationOptions({
      rpName: process.env.RP_NAME || "Example RP",
      rpID: process.env.RP_ID || "example.com",
      userID: Buffer.from(user.id),
      userName: user.username,
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
        authenticatorAttachment: "platform",
      },
      supportedAlgorithmIDs: [-7, -257, -8],
    });

    await saveChallenge(user.id, options.challenge);
    return options;
  } catch (error: any) {
    throw new Error(
      error instanceof Error
        ? error.message
        : "Failed to generate registration options",
    );
  }
};

/**
 * Verifies the registration response from the client.
 * @param response - The registration response JSON from the client.
 * @param findUserByWebAuthnID - Function to find a user by their WebAuthn ID.
 * @param registerPasskey - Function to store the new passkey in the database.
 * @returns A promise that resolves to the verified registration response.
 */
export const verifyRegistration = async (
  response: RegistrationResponseJSON,
  findUserByWebAuthnID: (webauthnUserID: string) => Promise<UserModel | null>,
  registerPasskey: (user: UserModel, passkey: Passkey) => Promise<void>,
): Promise<VerifiedRegistrationResponse> => {
  try {
    if (!response || !response.id) {
      throw new Error("Invalid registration response");
    }

    const storedChallenge = await getChallenge(response.id);
    if (!storedChallenge) {
      throw new Error("Challenge expired or missing");
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: storedChallenge,
      expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
      expectedRPID: process.env.RP_ID || "example.com",
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new Error("Registration verification failed");
    }

    const webauthnUserID = response.id;
    if (!webauthnUserID) {
      throw new Error(
        "User handle (WebAuthn user ID) missing in registration response",
      );
    }

    const user = await findUserByWebAuthnID(webauthnUserID);
    if (!user) {
      throw new Error("User not found");
    }

    const passkey: Passkey = {
      id: verification.registrationInfo.credential.id,
      publicKey: verification.registrationInfo.credential.publicKey,
      user: user,
      counter: verification.registrationInfo.credential.counter,
      webauthnUserID,
      transports: verification.registrationInfo.credential.transports ?? [],
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
    };

    // Corrected to pass only passkey
    await registerPasskey(user, passkey);
    await clearChallenge(response.id);

    return verification;
  } catch (error: any) {
    throw new Error(
      error instanceof Error ? error.message : "Unknown registration error",
    );
  }
};
