import { Strategy as PassportStrategy } from "passport-strategy";
import { verifyAuthentication } from "./authentication";
import type { Request } from "express";
import type {
  VerifiedAuthenticationResponse,
  WebAuthnCredential,
} from "@simplewebauthn/server";

/**
 * Options for configuring the SimpleWebAuthnStrategy.
 */
export interface SimpleWebAuthnStrategyOptions {
  /**
   * Function to retrieve a user based on the provided ID.
   *
   * @param req - Express request object.
   * @param id - User ID as a Uint8Array.
   * @returns A promise that resolves to the user object or null if not found.
   */
  getUser: (
    req: Request,
    id: Uint8Array,
  ) => Promise<{ id: Uint8Array; credentials: WebAuthnCredential[] } | null>;
}

/**
 * Passport strategy for handling WebAuthn authentication.
 */
export class SimpleWebAuthnStrategy extends PassportStrategy {
  /**
   * The name of the strategy.
   */
  name = "simple-webauthn";

  private options: SimpleWebAuthnStrategyOptions;

  /**
   * Creates an instance of SimpleWebAuthnStrategy.
   *
   * @param options - Configuration options for the strategy.
   */
  constructor(options: SimpleWebAuthnStrategyOptions) {
    super();
    this.options = options;
  }

  /**
   * Authenticates a request using WebAuthn.
   *
   * This method overrides PassportStrategy's `authenticate` method.
   * It processes the authentication response and verifies it using WebAuthn.
   *
   * @param req - Express request object.
   * @param _options - Optional authentication options.
   */
  authenticate(req: Request, _options?: any): void {
    (async (): Promise<void> => {
      try {
        const { userId, response } = req.body;

        // Validate presence of userId and response
        if (!userId || !response) {
          return this.fail({ message: "Missing userId or response" }, 400);
        }

        // Decode userId from base64url
        const decodedUserId = Buffer.from(userId, "base64url");

        // Retrieve user using the provided getUser function
        const user = await this.options.getUser(req, decodedUserId);
        if (!user) {
          return this.fail({ message: "User not found" }, 404);
        }

        // Verify the authentication response
        const verification: VerifiedAuthenticationResponse =
          await verifyAuthentication(req, user, response);

        // Check if verification was successful
        if (!verification.verified) {
          return this.fail({ message: "Verification failed" }, 403);
        }

        // Successful authentication
        return this.success(user);
      } catch (error) {
        // Handle errors and pass them to Passport
        if (error instanceof Error) {
          return this.error(error);
        }
        return this.error(new Error("An unknown error occurred"));
      }
    })();
  }
}
