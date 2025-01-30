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
 * Generates authentication options for an existing WebAuthn credential.
 * @param req - The Express request object.
 * @returns A promise that resolves to the authentication options JSON.
 */
export const generateAuthentication = async (
  req: Request,
): Promise<PublicKeyCredentialRequestOptionsJSON> => {
  if (!req.user) throw new Error("User not authenticated");

  const user = req.user as { id: string; credentials: WebAuthnCredential[] };
  const userCredentials = user.credentials.map((cred) => ({
    id: cred.id as string,
    transports: cred.transports || [],
  }));

  const options = await generateAuthenticationOptions({
    rpID: process.env.RP_ID || "example.com",
    allowCredentials: userCredentials.length > 0 ? userCredentials : undefined,
    timeout: 60000,
    userVerification: "preferred",
  });

  await saveChallenge(req, user.id, options.challenge);
  return options;
};

/**
 * Verifies the authentication response from the client.
 * @param req - The Express request object.
 * @param response - The authentication response JSON from the client.
 * @returns A promise that resolves to the verified authentication response.
 */
export const verifyAuthentication = async (
  req: Request,
  response: AuthenticationResponseJSON,
): Promise<VerifiedAuthenticationResponse> => {
  if (!req.user) throw new Error("User not authenticated");

  const user = req.user as { id: string; credentials: WebAuthnCredential[] };
  const storedChallenge = await getChallenge(req, user.id);
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

  await clearChallenge(req, user.id);
  return verification;
};
