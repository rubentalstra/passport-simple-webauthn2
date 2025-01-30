import { Strategy as PassportStrategy } from "passport-strategy";
import type { Request } from "express";
import type {
  VerifiedAuthenticationResponse,
  WebAuthnCredential,
} from "@simplewebauthn/server";
import { verifyAuthentication } from "./authentication";

/**
 * Passport strategy for WebAuthn authentication.
 */
export class SimpleWebAuthnStrategy extends PassportStrategy {
  public name = "simple-webauthn";

  /**
   * Authenticate request based on WebAuthn response.
   * @param req - The Express request object.
   */
  authenticate(req: Request): void {
    (async (): Promise<void> => {
      try {
        if (!req.user)
          return this.fail({ message: "User not authenticated" }, 401);

        const { response } = req.body;
        if (!response)
          return this.fail({ message: "Missing response data" }, 400);

        const user = req.user as {
          id: string;
          credentials: WebAuthnCredential[];
        };

        const verification: VerifiedAuthenticationResponse =
          await verifyAuthentication(req, response);

        if (!verification.verified)
          return this.fail({ message: "Verification failed" }, 403);

        return this.success(user);
      } catch (error) {
        return this.error(
          error instanceof Error
            ? error
            : new Error("An unknown error occurred"),
        );
      }
    })();
  }
}
