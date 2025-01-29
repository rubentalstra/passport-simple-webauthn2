import "express-session";

/**
 * Extends the express-session module to include a `userId` property.
 */
declare module "express-session" {
  interface SessionData {
    /**
     * The unique identifier for the authenticated user.
     */
    userId?: string;
  }
}
