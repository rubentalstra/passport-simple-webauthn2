import type {
  RegistrationResponseJSON,
  VerifiedRegistrationResponse,
  PublicKeyCredentialCreationOptionsJSON,
} from "@simplewebauthn/server";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type { Passkey } from "../types";

/**
 * Generates registration options for a new WebAuthn credential.
 * @param userID - The user ID requesting registration.
 * @param username - The associated username (for display purposes).
 * @returns A promise that resolves to the registration options JSON.
 */
export const generateRegistration = async (
  userID: string,
  username: string,
): Promise<PublicKeyCredentialCreationOptionsJSON> => {
  try {
    return await generateRegistrationOptions({
      rpName: process.env.RP_NAME || "Example RP",
      rpID: process.env.RP_ID || "example.com",
      userName: username,
      userID: new TextEncoder().encode(userID), // Only store the userID
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
        authenticatorAttachment: "platform",
      },
      supportedAlgorithmIDs: [-7, -257, -8],
    });
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
 * @param expectedChallenge - The expected challenge.
 * @param findUserIDByWebAuthnID - Function to find a user ID by WebAuthn ID.
 * @param registerPasskey - Function to store the new passkey in the database.
 * @returns A promise that resolves to the verified registration response.
 */
export const verifyRegistration = async (
  response: RegistrationResponseJSON,
  expectedChallenge: string,
  findUserIDByWebAuthnID: (webauthnUserID: string) => Promise<string | null>,
  registerPasskey: (userID: string, passkey: Passkey) => Promise<void>,
): Promise<VerifiedRegistrationResponse> => {
  try {
    if (!response || !response.id) {
      throw new Error("Invalid registration response");
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
      expectedRPID: process.env.RP_ID || "example.com",
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new Error("Registration verification failed");
    }

    const credential = verification.registrationInfo.credential;
    const webauthnUserID = credential.id;
    if (!webauthnUserID || webauthnUserID.trim() === "") {
      throw new Error(
        "User handle (WebAuthn user ID) missing in registration response",
      );
    }

    const userID = await findUserIDByWebAuthnID(webauthnUserID);
    if (!userID) {
      throw new Error("User not found");
    }

    const passkey: Passkey = {
      id: credential.id,
      publicKey: credential.publicKey,
      userID, // Store only the userID
      webauthnUserID,
      counter: verification.registrationInfo.credential.counter,
      transports: credential.transports ?? [],
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
    };

    await registerPasskey(userID, passkey);

    return verification;
  } catch (error: any) {
    throw new Error(
      error instanceof Error ? error.message : "Unknown registration error",
    );
  }
};
