import { Strategy } from "passport-strategy";
import type { Request } from "express";
import type {
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
} from "@simplewebauthn/server";
import { verifyAuthentication } from "./authentication";
import { verifyRegistration } from "./registration";
import type { UserModel } from "../models/types";

/**
 * Options for the SimpleWebAuthnStrategy.
 */
interface SimpleWebAuthnStrategyOptions {
  /**
   * Function to verify authentication responses.
   * @param credentialID - The credential ID from the authentication response.
   * @param cb - Callback function to handle the verification result.
   */
  verify: (
    credentialID: string,
    cb: (error: any, user?: UserModel, publicKey?: string) => void,
  ) => void;

  /**
   * Function to handle registration of new credentials.
   * @param user - The user object.
   * @param credentialID - The credential ID from the registration response.
   * @param publicKey - The PEM-encoded public key.
   * @param cb - Callback function to handle the registration result.
   */
  register: (
    user: UserModel,
    credentialID: string,
    publicKey: string,
    cb: (error: any, user?: UserModel) => void,
  ) => void;
}

/**
 * Passport strategy for WebAuthn authentication.
 */
export class SimpleWebAuthnStrategy extends Strategy {
  public name = "simple-webauthn";
  private readonly verifyFunc: SimpleWebAuthnStrategyOptions["verify"];
  private readonly registerFunc: SimpleWebAuthnStrategyOptions["register"];

  constructor(options: SimpleWebAuthnStrategyOptions) {
    super();
    this.verifyFunc = options.verify;
    this.registerFunc = options.register;
  }

  /**
   * Authenticate request based on WebAuthn response.
   * @param req - The Express request object.
   * @param options
   */
  authenticate(req: Request, options?: any): void {
    const action = req.path.split("/").pop(); // e.g., 'login' or 'register'

    if (action === "login") {
      this.handleAuthentication(req);
    } else if (action === "register") {
      this.handleRegistration(req);
    } else {
      this.fail({ message: "Unknown action" }, 400);
    }
  }

  /**
   * Handle authentication requests.
   * @param req - The Express request object.
   */
  private async handleAuthentication(req: Request): Promise<void> {
    try {
      const { response } = req.body;
      if (!response) {
        return this.fail({ message: "Missing response data" }, 400);
      }

      const verification: VerifiedAuthenticationResponse =
        await verifyAuthentication(req, response);

      if (!verification.verified) {
        return this.fail({ message: "Verification failed" }, 403);
      }

      const credentialID = verification.authenticationInfo.credentialID;

      if (!credentialID) {
        return this.fail({ message: "Invalid verification information" }, 400);
      }

      this.verifyFunc(credentialID, (err, user, publicKey) => {
        if (err) {
          return this.error(err);
        }
        if (!user) {
          return this.fail({ message: "User not found" }, 404);
        }
        return this.success(user);
      });
    } catch (error) {
      return this.error(
        error instanceof Error ? error : new Error("An unknown error occurred"),
      );
    }
  }

  /**
   * Handle registration requests.
   * @param req - The Express request object.
   */
  private async handleRegistration(req: Request): Promise<void> {
    try {
      const { response } = req.body;
      if (!response) {
        return this.fail({ message: "Missing response data" }, 400);
      }

      const verification: VerifiedRegistrationResponse =
        await verifyRegistration(req, response);

      if (!verification.verified || !verification.registrationInfo) {
        return this.fail({ message: "Registration verification failed" }, 403);
      }

      const { credential } = verification.registrationInfo;

      if (!credential) {
        return this.fail({ message: "Invalid registration information" }, 400);
      }

      this.registerFunc(
        req.user as UserModel,
        credential.id,
        Buffer.from(credential.publicKey).toString("base64url"),
        (err, registeredUser) => {
          if (err) {
            return this.error(err);
          }
          if (!registeredUser) {
            return this.fail({ message: "Registration failed" }, 500);
          }
          return this.success(registeredUser);
        },
      );
    } catch (error) {
      return this.error(
        error instanceof Error ? error : new Error("An unknown error occurred"),
      );
    }
  }
}
