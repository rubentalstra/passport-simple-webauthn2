# passport-simple-webauthn2

[![Version](https://img.shields.io/npm/v/passport-simple-webauthn2)](https://www.npmjs.com/package/passport-simple-webauthn2)
[![License](https://img.shields.io/npm/l/passport-simple-webauthn2)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/rubentalstra/passport-simple-webauthn2/publish.yml?branch=main)](https://github.com/rubentalstra/passport-simple-webauthn2/actions)
[![Downloads](https://img.shields.io/npm/dt/passport-simple-webauthn2)](https://www.npmjs.com/package/passport-simple-webauthn2)
[![Maintainability](https://api.codeclimate.com/v1/badges/7811835787034e6b7e00/maintainability)](https://codeclimate.com/github/rubentalstra/passport-simple-webauthn2/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/7811835787034e6b7e00/test_coverage)](https://codeclimate.com/github/rubentalstra/passport-simple-webauthn2/test_coverage)

**Passport Strategy for authenticating with Web Authentication (WebAuthn) using FIDO2 Passkeys.**

> **Note:** While the strategy returns the complete user object (including passkey data) upon successful registration or login, **it is your responsibility to determine what gets stored in the session**. For example, the provided Passport serialization logic only stores the user's ID.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
    - [1. Setting Up Your Express Application](#1-setting-up-your-express-application)
    - [2. Configuring the Strategy](#2-configuring-the-strategy)
    - [3. Registration Routes](#3-registration-routes)
    - [4. Authentication Routes](#4-authentication-routes)
    - [5. Example Application](#5-example-application)
- [API Reference](#api-reference)
    - [WebAuthnStrategy](#webauthnstrategy)
    - [Utility Functions](#utility-functions)
- [Type Definitions](#type-definitions)
- [Contributing](#contributing)
- [License](#license)
- [Additional Information](#additional-information)

---

## Features

- **WebAuthn Integration:** Uses [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn) for robust WebAuthn registration and authentication.
- **Passport.js Compatibility:** Integrates seamlessly into your Passport.js workflows.
- **Full User Object on Callback:** On a successful registration or login, the strategy returns the full user object (including passkey details).
- **Flexible Session Storage:** **It’s up to you** whether to store the full user object or only a portion (typically the user ID) in the session—configure this using Passport’s serialize/deserialize methods.
- **TypeScript Support:** Fully typed with TypeScript for enhanced developer experience.
- **Challenge Management:** Automatically generates, stores, and verifies WebAuthn challenges.
- **Customizable Stores:** Plug in your own user and challenge store implementations (e.g. MongoDB, Redis, etc.).

---

## Installation

Install via npm:

```bash
npm install passport-simple-webauthn2
```

Or with Yarn:

```bash
yarn add passport-simple-webauthn2
```

---

## Prerequisites

- **Node.js:** Version 14 or higher is recommended.
- **Express.js:** This strategy is designed for Express.js applications.
- **Passport.js:** Familiarity with Passport.js is assumed.
- **Session Management:** Use a session middleware such as `express-session`.

---

## Usage

The following examples demonstrate how to integrate **passport-simple-webauthn2** into your Express application. The package exports a single class, `WebAuthnStrategy`, which you configure with your relying party (RP) details along with user and challenge store implementations.

### 1. Setting Up Your Express Application

Create your Express application (e.g., `src/app.ts`). In this example, notice that while the strategy returns the full user object upon successful authentication, the Passport serialization logic stores only the user's ID in the session. You can adjust this behavior as needed.

```typescript
// src/app.ts
import express from "express";
import session from "express-session";
import passport from "passport";
import bodyParser from "body-parser";
import path from "path";
import registerRoutes from "./routes/register";
import authenticateRoutes from "./routes/authenticate";

const app = express();

// Set EJS as the view engine (optional)
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middleware setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration (ensure to use secure settings in production)
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 },
  })
);

// Initialize Passport.js
app.use(passport.initialize());
app.use(passport.session());

// Passport Serialization: Here we store only the user's ID in the session.
// (You can choose to store the entire user object if that better suits your needs.)
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id: string, done) => {
  try {
    // Retrieve the full user object from your user store.
    const user = await /* your user store method */ userStore.get(id, true);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Use registration and authentication routes
app.use("/auth", registerRoutes);
app.use("/auth", authenticateRoutes);

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

export default app;
```

### 2. Configuring the Strategy

Set up the **WebAuthnStrategy** with your own user and challenge store implementations. Below is an example using custom MongoDB stores:

```typescript
// src/auth/passport.ts
import passport from "passport";
import { WebAuthnStrategy } from "passport-simple-webauthn2";
import { MongoUserStore } from "../stores/MongoUserStore";
import { MongoChallengeStore } from "../stores/MongoChallengeStore";

// Initialize your stores (implementations must adhere to the UserStore and ChallengeStore interfaces)
const userStore = new MongoUserStore();
const challengeStore = new MongoChallengeStore();

// Create an instance of the WebAuthn strategy
const webAuthnStrategy = new WebAuthnStrategy({
  rpID: process.env.RP_ID || "localhost",       // Your domain (e.g., "example.com")
  rpName: process.env.RP_NAME || "Your App",      // Display name for your application
  userStore,
  challengeStore,
  debug: true, // Enable detailed logging if needed
});

// Use the strategy with Passport
passport.use("webauthn", webAuthnStrategy);

export default passport;
```

### 3. Registration Routes

Implement routes to register a new WebAuthn credential. On success, the strategy returns the full user object (with updated passkeys). You can then decide what to do with that user object (for example, storing only its ID in the session).

```typescript
// src/routes/register.ts
import express, { Request, Response } from "express";
import passport from "passport";

const router = express.Router();

// Initiate registration challenge (GET request)
router.get("/register", passport.authenticate("webauthn", { session: false }), (req: Request, res: Response) => {
  // The strategy returns serialized registration options (challenge details)
  res.json(req.user);
});

// Registration callback (POST request)
router.post("/register", passport.authenticate("webauthn", { session: false }), (req: Request, res: Response) => {
  // On success, req.user contains the updated full user object (with new passkey)
  res.json({ user: req.user });
});

export default router;
```

### 4. Authentication Routes

Implement routes for authenticating an existing WebAuthn credential. On success, the strategy returns the full user object.

```typescript
// src/routes/authenticate.ts
import express, { Request, Response } from "express";
import passport from "passport";

const router = express.Router();

// Initiate authentication challenge (GET request)
router.get("/login", passport.authenticate("webauthn", { session: false }), (req: Request, res: Response) => {
  res.json(req.user);
});

// Authentication callback (POST request)
router.post("/login", passport.authenticate("webauthn"), (req: Request, res: Response) => {
  // On success, req.user is the authenticated full user object.
  res.json({ user: req.user });
});

export default router;
```

### 5. Example Application

Below is a complete example application that uses MongoDB for user and challenge storage. It demonstrates route configuration, session management, and integration with Passport.js. Notice how the Passport serialization logic only stores the user’s ID, even though the strategy returns the full user object.

```typescript
// src/index.ts
import dotenv from "dotenv";
dotenv.config();

import express, { Request, Response, NextFunction } from "express";
import mongoose from "mongoose";
import cors from "cors";
import session from "express-session";
import passport from "passport";
import path from "path";
import { MongoUserStore } from "./stores/MongoUserStore";
import { MongoChallengeStore } from "./stores/MongoChallengeStore";
import { WebAuthnStrategy } from "passport-simple-webauthn2";

const app = express();
const PORT = process.env.PORT || 5000;

// Set EJS as the view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "../src/views"));

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Cookie-based session storage (adjust settings for production)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "default_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to true in production with HTTPS
      httpOnly: true,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Initialize stores
const userStore = new MongoUserStore();
const challengeStore = new MongoChallengeStore();

// Passport Serialization: Store only the user's ID in the session.
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await userStore.get(id, true);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Initialize and use the WebAuthn strategy
passport.use(
  new WebAuthnStrategy({
    rpID: process.env.RP_ID || "yourdomain.com",
    rpName: process.env.RP_NAME || "Your App",
    userStore,
    challengeStore,
    debug: true,
  })
);

// Routes

// Homepage & views
app.get("/", (req: Request, res: Response) => {
  res.render("index");
});
app.get("/register", (req: Request, res: Response) => {
  res.render("register");
});
app.get("/login", (req: Request, res: Response) => {
  res.render("login");
});

// Registration Challenge Endpoint (GET)
app.get(
  "/webauthn/register",
  passport.authenticate("webauthn", { session: false }),
  (req, res) => {
    res.json(req.user); // Returns registration options (challenge)
  }
);

// Registration Callback Endpoint (POST)
app.post(
  "/webauthn/register",
  passport.authenticate("webauthn", { session: false }),
  (req, res) => {
    // On success, req.user contains the updated user (with new passkey)
    res.json({ user: req.user });
  }
);

// Login Challenge Endpoint (GET)
app.get(
  "/webauthn/login",
  passport.authenticate("webauthn", { session: false }),
  (req, res) => {
    res.json(req.user); // Returns authentication options (challenge)
  }
);

// Login Callback Endpoint (POST)
app.post("/webauthn/login", passport.authenticate("webauthn"), (req, res) => {
  // On success, req.user is the authenticated user.
  res.json({ user: req.user });
});

// Account Route: Display user passkeys via an EJS view
app.get("/account", (req: Request, res: Response) => {
  if (!req.isAuthenticated() || !req.user) {
    return res.redirect("/login");
  }
  try {
    res.render("account", { passkeys: (req.user as any).passkeys });
  } catch (error) {
    console.error("Error loading account:", error);
    res.redirect("/login");
  }
});

// Logout Route
app.post("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.redirect("/");
    });
  });
});

// MongoDB Connection (for user data, not sessions)
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/webauthnDB")
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
```

---

## API Reference

### WebAuthnStrategy

The strategy class extends Passport’s base strategy and implements a full WebAuthn flow. It automatically infers the mode (registration or login) from the request URL. You can also call its helper methods directly:

- **`registerChallenge(req: Request, username: string): Promise<Record<string, unknown>>`**  
  Generates and returns serialized registration options (challenge) for a user. It creates a new user if one does not exist.

- **`registerCallback(req: Request, username: string, credential: RegistrationResponseJSON): Promise<WebAuthnUser>`**  
  Verifies the registration response and saves a new passkey to the user’s account. Returns the updated user object.

- **`loginChallenge(req: Request, username: string): Promise<Record<string, unknown>>`**  
  Generates and returns serialized authentication options (challenge) based on the user’s stored passkeys.

- **`loginCallback(req: Request, username: string, credential: AuthenticationResponseJSON): Promise<WebAuthnUser>`**  
  Verifies the authentication response, updates the passkey counter, and returns the authenticated user.

- **`authenticate(req: Request, options?: any): Promise<void>`**  
  Fully integrated Passport method that infers the mode based on the request path and method (GET for challenge, POST for callback).

### Utility Functions

The package provides several utility functions for serializing options:

- **`bufferToBase64URL(buffer: Buffer | ArrayBuffer | string): string`**  
  Converts a binary buffer into a base64url string.

- **`serializeRegistrationOptions(options: Record<string, any>): Record<string, unknown>`**  
  Serializes the registration options by converting the challenge to a base64url string.

- **`serializeAuthenticationOptions(options: Record<string, any>): Record<string, unknown>`**  
  Serializes the authentication options by converting the challenge to a base64url string.

---

## Type Definitions

### WebAuthnUser

```typescript
export interface WebAuthnUser {
  id?: string; // Optional when creating a new user; must be defined after saving
  username: string;
  passkeys: any[]; // Passkey objects contain id, publicKey, counter, and transports
}
```

### UserStore

Implement this interface to manage user data:

```typescript
export interface UserStore {
  /**
   * Retrieves a user by a unique identifier or username.
   * @param identifier The user's username or id.
   * @param byID Optional: true to lookup by id; false (default) to lookup by username.
   */
  get(identifier: string, byID?: boolean): Promise<WebAuthnUser | undefined>;

  /**
   * Saves (or upserts) the user and returns the updated user.
   */
  save(user: WebAuthnUser): Promise<WebAuthnUser>;
}
```

### ChallengeStore

Implement this interface to manage WebAuthn challenges:

```typescript
export interface ChallengeStore {
  /**
   * Retrieves the challenge string for a given user identifier.
   */
  get(userId: string): Promise<string | undefined>;

  /**
   * Saves the challenge string for a given user identifier.
   */
  save(userId: string, challenge: string): Promise<void>;

  /**
   * Deletes the stored challenge for a given user identifier.
   */
  delete(userId: string): Promise<void>;
}
```

---

## Contributing

Contributions are welcome! Follow these steps:

1. **Fork the Repository**
2. **Clone Your Fork:**
   ```bash
   git clone https://github.com/rubentalstra/passport-simple-webauthn2.git
   cd passport-simple-webauthn2
   ```
3. **Install Dependencies:**
   ```bash
   npm install
   ```
4. **Create a Feature Branch:**
   ```bash
   git checkout -b feature/YourFeatureName
   ```
5. **Make Your Changes & Run Tests:**
   ```bash
   npm test
   ```
6. **Commit & Push Your Changes:**
   ```bash
   git commit -m "Add Your Feature Description"
   git push origin feature/YourFeatureName
   ```
7. **Create a Pull Request**

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Additional Information

### Environment Variables

Configure your environment (e.g., via a `.env` file) with variables such as:
- `RP_ID`: Your Relying Party ID (domain).
- `RP_NAME`: Your Relying Party name.
- `SESSION_SECRET`: A secret string for session signing.
- `MONGO_URI`: MongoDB connection URI.

### Security Considerations

- **HTTPS:** Ensure your application uses HTTPS in production.
- **Session Security:** Configure secure cookies and proper session options.
- **Challenge Storage:** Consider using a distributed store (e.g., Redis) for scalability.

### Testing

Run tests with:

```bash
npm test
```

### Documentation

Generate documentation with [TypeDoc](https://typedoc.org/):

```bash
npm run docs
```

The generated docs will be available in the `docs` folder.