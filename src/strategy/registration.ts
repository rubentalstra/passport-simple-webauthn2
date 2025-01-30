import type { Request } from "express";
import type {
  VerifiedRegistrationResponse,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from "@simplewebauthn/server";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "./challengeStore";

/**
 * Represents a user during the registration process.
 */
export interface RegistrationUser {
  /**
   * Unique identifier for the user.
   */
  id: Uint8Array;

  /**
   * Username of the user.
   */
  name: string;

  /**
   * Display name of the user.
   */
  displayName: string;

  /**
   * Array of existing WebAuthn credentials associated with the user.
   */
  credentials: WebAuthnCredential[];
}

/**
 * Generates registration options for a new WebAuthn credential.
 * @param req - The Express request object.
 * @param user - The user registering a new credential.
 * @returns A promise that resolves to the registration options JSON.
 * @throws Will throw an error if userId or challenge is invalid.
 */
export const generateRegistration = async (
  req: Request,
  user: RegistrationUser,
): Promise<PublicKeyCredentialCreationOptionsJSON> => {
  const options = await generateRegistrationOptions({
    rpName: process.env.RP_NAME || "Example RP",
    rpID: process.env.RP_ID || "example.com",
    userID: user.id,
    userName: user.name,
    attestationType: "direct",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    supportedAlgorithmIDs: [-8, -7, -257],
  });

  await saveChallenge(
    req,
    Buffer.from(user.id).toString("base64url"),
    options.challenge,
  );

  return options;
};

/**
 * Verifies the registration response from the client.
 * @param req - The Express request object.
 * @param user - The user registering a new credential.
 * @param response - The registration response JSON from the client.
 * @returns A promise that resolves to the verified registration response.
 * @throws Will throw an error if the challenge is missing or verification fails.
 */
export const verifyRegistration = async (
  req: Request,
  user: RegistrationUser,
  response: RegistrationResponseJSON,
): Promise<VerifiedRegistrationResponse> => {
  const userIdBase64 = Buffer.from(user.id).toString("base64url");
  const storedChallenge = await getChallenge(req, userIdBase64);
  if (!storedChallenge) throw new Error("Challenge expired or missing");

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: storedChallenge,
    expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
    expectedRPID: process.env.RP_ID || "example.com",
  });

  if (!verification.verified)
    throw new Error("Registration verification failed");

  await clearChallenge(req, userIdBase64);
  return verification;
};
