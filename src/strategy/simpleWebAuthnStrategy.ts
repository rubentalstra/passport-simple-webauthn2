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

  /**
   * Authenticate method adhering to Passport's Strategy interface.
   * @param req - Express request object
   * @param _options - Optional parameters
   */
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

      const verification: VerifiedAuthenticationResponse =
        await verifyAuthenticationResponse({
          response,
          expectedChallenge, // Now passed externally
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

      this.success(passkey.webauthnUserID);
    } catch (error) {
      this.error(
        error instanceof Error ? error : new Error("An unknown error occurred"),
      );
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
          expectedChallenge, // Now passed externally
          expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
          expectedRPID: process.env.RP_ID || "example.com",
          requireUserVerification: true,
        });

      if (!verification.verified || !verification.registrationInfo) {
        return this.fail({ message: "Registration verification failed" }, 403);
      }

      // ✅ FIX: Use correct WebAuthn user ID from registrationInfo instead of response.id
      const webauthnUserID = verification.registrationInfo.credential.id;
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
        user: user,
        counter: verification.registrationInfo.credential.counter,
        webauthnUserID: user.id, // ✅ Ensure correct WebAuthn ID is stored
        transports: verification.registrationInfo.credential.transports ?? [],
        deviceType: verification.registrationInfo.credentialDeviceType,
        backedUp: verification.registrationInfo.credentialBackedUp,
      };

      await this.registerPasskey(user, newPasskey);

      this.success(user);
    } catch (error) {
      this.error(
        error instanceof Error ? error : new Error("An unknown error occurred"),
      );
    }
  }
}
