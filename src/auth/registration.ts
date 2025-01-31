import type {
  RegistrationResponseJSON,
  VerifiedRegistrationResponse,
  PublicKeyCredentialCreationOptionsJSON,
} from "@simplewebauthn/server";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
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
    return await generateRegistrationOptions({
      rpName: process.env.RP_NAME || "Example RP",
      rpID: process.env.RP_ID || "example.com",
      userName: user.username,
      userID: new TextEncoder().encode(user.id),
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
 * @param expectedChallenge - The expected challenge (retrieved externally).
 * @param findUserByWebAuthnID - Function to find a user by their WebAuthn ID.
 * @param registerPasskey - Function to store the new passkey in the database.
 * @returns A promise that resolves to the verified registration response.
 */
export const verifyRegistration = async (
  response: RegistrationResponseJSON,
  expectedChallenge: string,
  findUserByWebAuthnID: (webauthnUserID: string) => Promise<UserModel | null>,
  registerPasskey: (
    user: UserModel,
    passkey: Passkey,
  ) => Promise<Map<string, Passkey>>,
): Promise<VerifiedRegistrationResponse> => {
  try {
    if (!response || !response.id) {
      throw new Error("Invalid registration response");
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge, // ✅ Ensure challenge is passed externally
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

    let user = await findUserByWebAuthnID(webauthnUserID);
    if (!user) {
      throw new Error("User not found");
    }

    const passkey: Passkey = {
      id: credential.id,
      publicKey: credential.publicKey,
      userID: user.id, // ✅ Store only `userID`
      webauthnUserID, // ✅ Store correct WebAuthn user ID
      counter: verification.registrationInfo.credential.counter,
      transports: credential.transports ?? [],
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
    };

    await registerPasskey(user, passkey);

    return verification;
  } catch (error: any) {
    throw new Error(
      error instanceof Error ? error.message : "Unknown registration error",
    );
  }
};
