import type { Request } from "express";
import type {
  PublicKeyCredentialRequestOptionsJSON,
  VerifiedAuthenticationResponse,
  AuthenticationResponseJSON,
  WebAuthnCredential,
} from "@simplewebauthn/server";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "./challengeStore";

/**
 * Represents a user during the authentication process.
 */
export interface AuthUser {
  /**
   * Unique identifier for the user.
   */
  id: Uint8Array;

  /**
   * Array of WebAuthn credentials associated with the user.
   */
  credentials: WebAuthnCredential[];
}

/**
 * Generates authentication options for an existing WebAuthn credential.
 * @param req - The Express request object.
 * @returns A promise that resolves to the authentication options JSON.
 * @throws Will throw an error if the user is not authenticated.
 */
export const generateAuthentication = async (
  req: Request,
): Promise<PublicKeyCredentialRequestOptionsJSON> => {
  if (!req.session.userId) throw new Error("User not authenticated");

  const options = await generateAuthenticationOptions({
    rpID: process.env.RP_ID || "example.com",
  });

  const userIdBase64 = Buffer.from(req.session.userId).toString("base64url");
  await saveChallenge(req, userIdBase64, options.challenge);

  return options;
};

/**
 * Verifies the authentication response from the client.
 * @param req - The Express request object.
 * @param user - The user attempting to authenticate.
 * @param response - The authentication response JSON from the client.
 * @returns A promise that resolves to the verified authentication response.
 * @throws Will throw an error if the challenge is missing, credential not found, or verification fails.
 */
export const verifyAuthentication = async (
  req: Request,
  user: AuthUser,
  response: AuthenticationResponseJSON,
): Promise<VerifiedAuthenticationResponse> => {
  const userIdBase64 = Buffer.from(user.id).toString("base64url");
  const storedChallenge = await getChallenge(req, userIdBase64);
  if (!storedChallenge) throw new Error("Challenge expired or missing");

  const credential = user.credentials.find((cred) => cred.id === response.id);
  if (!credential) throw new Error("Credential not found");

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: storedChallenge,
    expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
    expectedRPID: process.env.RP_ID || "example.com",
    credential,
    requireUserVerification: true,
  });

  if (!verification.verified) throw new Error("Authentication failed");

  await clearChallenge(req, userIdBase64);
  return verification;
};
