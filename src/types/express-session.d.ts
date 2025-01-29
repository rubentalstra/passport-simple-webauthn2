import "express-session";

declare module "express-session" {
  interface SessionData {
    userId?: string; // Ensure `userId` exists on the session object
  }
}
