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

export interface AuthUser {
  id: Uint8Array;
  credentials: WebAuthnCredential[];
}

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
