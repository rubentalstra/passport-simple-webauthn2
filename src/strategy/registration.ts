import type { Request } from "express";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  VerifiedRegistrationResponse,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from "@simplewebauthn/server";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "./challengeStore";

/**
 * Generates registration options for a new WebAuthn credential.
 * @param req - The Express request object.
 * @returns A promise that resolves to the registration options JSON.
 */
export const generateRegistration = async (
  req: Request,
): Promise<PublicKeyCredentialCreationOptionsJSON> => {
  if (!req.user) throw new Error("User not authenticated");

  const user = req.user as {
    id: string;
    name: string;
    displayName: string;
    credentials: WebAuthnCredential[];
  };

  const options = await generateRegistrationOptions({
    rpName: process.env.RP_NAME || "Example RP",
    rpID: process.env.RP_ID || "example.com",
    userID: Buffer.from(user.id),
    userName: user.name,
    userDisplayName: user.displayName || user.name,
    attestationType: "direct",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    supportedAlgorithmIDs: [-8, -7, -257],
    preferredAuthenticatorType: "securityKey",
  });

  await saveChallenge(req, user.id, options.challenge);
  return options;
};

/**
 * Verifies the registration response from the client.
 * @param req - The Express request object.
 * @param response - The registration response JSON from the client.
 * @returns A promise that resolves to the verified registration response.
 */
export const verifyRegistration = async (
  req: Request,
  response: RegistrationResponseJSON,
): Promise<VerifiedRegistrationResponse> => {
  if (!req.user) throw new Error("User not authenticated");

  const user = req.user as { id: string };
  const storedChallenge = await getChallenge(req, user.id);
  if (!storedChallenge) throw new Error("Challenge expired or missing");

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: storedChallenge,
    expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
    expectedRPID: process.env.RP_ID || "example.com",
  });

  if (!verification.verified)
    throw new Error("Registration verification failed");

  await clearChallenge(req, user.id);
  return verification;
};
