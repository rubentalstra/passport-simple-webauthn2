import { Strategy } from "passport-strategy";
import type { Request } from "express";
import {
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type { SimpleWebAuthnStrategyOptions, Passkey } from "../types";
import type { VerifiedRegistrationResponse } from "@simplewebauthn/server";

/**
 * Passport strategy for WebAuthn authentication.
 */
export class SimpleWebAuthnStrategy extends Strategy {
  public name = "simple-webauthn";

  private readonly findPasskeyByCredentialID: SimpleWebAuthnStrategyOptions["findPasskeyByCredentialID"];
  private readonly updatePasskeyCounter: SimpleWebAuthnStrategyOptions["updatePasskeyCounter"];
  private readonly findUserIDByWebAuthnID: SimpleWebAuthnStrategyOptions["findUserIDByWebAuthnID"];
  private readonly registerPasskey: SimpleWebAuthnStrategyOptions["registerPasskey"];

  constructor(options: SimpleWebAuthnStrategyOptions) {
    super();
    this.findPasskeyByCredentialID = options.findPasskeyByCredentialID;
    this.updatePasskeyCounter = options.updatePasskeyCounter;
    this.findUserIDByWebAuthnID = options.findUserIDByWebAuthnID;
    this.registerPasskey = options.registerPasskey;
  }

  authenticate(req: Request, _options?: any): void {
    const action = req.path.split("/").pop();
    if (action === "login") {
      this.handleAuthentication(req);
    } else if (action === "register") {
      this.handleRegistration(req);
    } else {
      this.fail({ message: "Unknown action" }, 400);
    }
  }

  private async handleAuthentication(req: Request): Promise<void> {
    try {
      const { response, expectedChallenge } = req.body;
      if (!response || !expectedChallenge) {
        return this.fail({ message: "Missing response or challenge" }, 400);
      }

      const passkey = await this.findPasskeyByCredentialID(response.id);
      if (!passkey) {
        return this.fail({ message: "Credential not found" }, 404);
      }

      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
        expectedRPID: process.env.RP_ID || "example.com",
        credential: {
          id: passkey.id,
          publicKey: passkey.publicKey,
          counter: passkey.counter,
          transports: passkey.transports ?? [],
        },
        requireUserVerification: true,
      });

      if (!verification.verified) {
        return this.fail({ message: "Verification failed" }, 403);
      }

      await this.updatePasskeyCounter(
        passkey.id,
        verification.authenticationInfo.newCounter,
      );

      this.success(passkey.userID);
    } catch (error) {
      this.error(error instanceof Error ? error : new Error("Unknown error"));
    }
  }

  private async handleRegistration(req: Request): Promise<void> {
    try {
      const { response, expectedChallenge } = req.body;
      if (!response || !expectedChallenge) {
        return this.fail({ message: "Missing response or challenge" }, 400);
      }

      const verification: VerifiedRegistrationResponse =
        await verifyRegistrationResponse({
          response,
          expectedChallenge,
          expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
          expectedRPID: process.env.RP_ID || "example.com",
          requireUserVerification: true,
        });

      if (!verification.verified || !verification.registrationInfo) {
        return this.fail({ message: "Registration verification failed" }, 403);
      }

      const credential = verification.registrationInfo.credential;
      const webauthnUserID = credential.id;
      const userID = await this.findUserIDByWebAuthnID(webauthnUserID);

      if (!userID) {
        return this.fail({ message: "User not found" }, 404);
      }

      const newPasskey: Passkey = {
        id: credential.id,
        publicKey: credential.publicKey,
        userID,
        webauthnUserID,
        counter: verification.registrationInfo.credential.counter,
        deviceType: verification.registrationInfo.credentialDeviceType,
        backedUp: verification.registrationInfo.credentialBackedUp,
        transports: credential.transports ?? [],
      };

      await this.registerPasskey(userID, newPasskey);

      this.success(userID);
    } catch (error) {
      this.error(error instanceof Error ? error : new Error("Unknown error"));
    }
  }
}
