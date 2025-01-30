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
  getUser: (
    req: Request,
    id: Uint8Array,
  ) => Promise<{ id: Uint8Array; credentials: WebAuthnCredential[] } | null>;
}

/**
 * Passport strategy for WebAuthn authentication.
 */
export class SimpleWebAuthnStrategy extends PassportStrategy {
  name = "simple-webauthn";
  private options: SimpleWebAuthnStrategyOptions;

  constructor(options: SimpleWebAuthnStrategyOptions) {
    super();
    this.options = options;
  }

  authenticate(req: Request, _options?: any): void {
    (async (): Promise<void> => {
      try {
        const { userId, response } = req.body;
        if (!userId || !response)
          return this.fail({ message: "Missing userId or response" }, 400);

        const decodedUserId = Buffer.from(userId, "base64url");
        const user = await this.options.getUser(req, decodedUserId);
        if (!user) return this.fail({ message: "User not found" }, 404);

        const verification: VerifiedAuthenticationResponse =
          await verifyAuthentication(req, user, response);

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
