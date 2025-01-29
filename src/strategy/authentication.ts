import type { Request } from "express";
import type {
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
   * Unique identifier for the user as a Uint8Array.
   */
  id: Uint8Array;

  /**
   * Array of WebAuthn credentials associated with the user.
   */
  credentials: WebAuthnCredential[];
}

/**
 * Generates authentication options for an existing WebAuthn credential.
 *
 * @param req - Express request object.
 * @returns The authentication options.
 * @throws Error if the user is not authenticated or challenge saving fails.
 */
export const generateAuthentication = async (req: Request) => {
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
 *
 * @param req - Express request object.
 * @param user - The user attempting to authenticate.
 * @param response - The authentication response JSON from the client.
 * @returns The verified authentication response.
 * @throws Error if challenge is missing, credential is not found, or verification fails.
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

  const verification: VerifiedAuthenticationResponse =
    await verifyAuthenticationResponse({
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
