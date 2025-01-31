import { Strategy } from "passport-strategy";
import type { Request } from "express";
import type {
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
} from "@simplewebauthn/server";
import {
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { getChallenge, clearChallenge } from "./challengeStore";
import type { SimpleWebAuthnStrategyOptions, Passkey } from "../types";

/**
 * Passport strategy for WebAuthn authentication.
 */
export class SimpleWebAuthnStrategy extends Strategy {
  public name = "simple-webauthn";

  private readonly findPasskeyByCredentialID: SimpleWebAuthnStrategyOptions["findPasskeyByCredentialID"];
  private readonly updatePasskeyCounter: SimpleWebAuthnStrategyOptions["updatePasskeyCounter"];
  private readonly findUserByWebAuthnID: SimpleWebAuthnStrategyOptions["findUserByWebAuthnID"];
  private readonly registerPasskey: SimpleWebAuthnStrategyOptions["registerPasskey"];

  constructor(options: SimpleWebAuthnStrategyOptions) {
    super();
    this.findPasskeyByCredentialID = options.findPasskeyByCredentialID;
    this.updatePasskeyCounter = options.updatePasskeyCounter;
    this.findUserByWebAuthnID = options.findUserByWebAuthnID;
    this.registerPasskey = options.registerPasskey;
  }

  authenticate(req: Request): void {
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
      const { response } = req.body;
      if (!response) {
        return this.fail({ message: "Missing response data" }, 400);
      }

      const storedChallenge = await getChallenge(response.id);
      if (!storedChallenge) {
        return this.fail({ message: "Challenge expired or missing" }, 403);
      }

      const passkey = await this.findPasskeyByCredentialID(response.id);
      if (!passkey) {
        return this.fail({ message: "Credential not found" }, 404);
      }

      const verification: VerifiedAuthenticationResponse =
        await verifyAuthenticationResponse({
          response,
          expectedChallenge: storedChallenge,
          expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
          expectedRPID: process.env.RP_ID || "example.com",
          credential: {
            id: passkey.id,
            publicKey: passkey.publicKey, // Uint8Array
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
      await clearChallenge(response.id);

      this.success(passkey.user);
    } catch (error) {
      this.error(
        error instanceof Error ? error : new Error("An unknown error occurred"),
      );
    }
  }

  private async handleRegistration(req: Request): Promise<void> {
    try {
      const { response } = req.body;
      if (!response) {
        return this.fail({ message: "Missing response data" }, 400);
      }

      const storedChallenge = await getChallenge(response.id);
      if (!storedChallenge) {
        return this.fail({ message: "Challenge expired or missing" }, 403);
      }

      const verification: VerifiedRegistrationResponse =
        await verifyRegistrationResponse({
          response,
          expectedChallenge: storedChallenge,
          expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
          expectedRPID: process.env.RP_ID || "example.com",
          requireUserVerification: true,
        });

      if (!verification.verified || !verification.registrationInfo) {
        return this.fail({ message: "Registration verification failed" }, 403);
      }

      const webauthnUserID = response.id;
      if (!webauthnUserID) {
        return this.fail(
          {
            message:
              "User handle (WebAuthn user ID) missing in registration response",
          },
          400,
        );
      }

      const user = await this.findUserByWebAuthnID(webauthnUserID);
      if (!user) {
        return this.fail({ message: "User not found" }, 404);
      }

      const newPasskey: Passkey = {
        id: verification.registrationInfo.credential.id,
        publicKey: verification.registrationInfo.credential.publicKey, // Uint8Array
        counter: verification.registrationInfo.credential.counter,
        webauthnUserID: user.id,
        transports: verification.registrationInfo.credential.transports ?? [],
        deviceType: verification.registrationInfo.credentialDeviceType,
        backedUp: verification.registrationInfo.credentialBackedUp,
        user,
      };

      // Corrected to pass only newPasskey
      await this.registerPasskey(newPasskey);
      await clearChallenge(response.id);

      this.success(user);
    } catch (error) {
      this.error(
        error instanceof Error ? error : new Error("An unknown error occurred"),
      );
    }
  }
}
