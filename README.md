# passport-simple-webauthn2

![Version](https://img.shields.io/npm/v/passport-simple-webauthn2)
![License](https://img.shields.io/npm/l/passport-simple-webauthn2)
![Build](https://img.shields.io/github/actions/workflow/status/rubentalstra/passport-simple-webauthn2/publish.yml?branch=main)
![Downloads](https://img.shields.io/npm/dt/passport-simple-webauthn2)

**Passport strategy for authenticating with Web Authentication (WebAuthn) using FIDO2 Passkeys.**

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
    - [1. Setting Up Your Express Application](#1-setting-up-your-express-application)
    - [2. Configuring the Strategy](#2-configuring-the-strategy)
    - [3. Registration Routes](#3-registration-routes)
    - [4. Authentication Routes](#4-authentication-routes)
- [API Reference](#api-reference)
    - [Strategy](#simplewebauthnstrategy)
    - [Utility Functions](#utility-functions)
- [Type Definitions](#type-definitions)
- [Contributing](#contributing)
- [License](#license)

## Features

- **WebAuthn Integration:** Leverages the power of [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn) for robust Web Authentication.
- **Passport.js Compatibility:** Seamlessly integrates with Passport.js, enabling easy use within existing authentication workflows.
- **TypeScript Support:** Fully typed with TypeScript, ensuring type safety and better developer experience.
- **Challenge Management:** Handles generation, storage, and verification of WebAuthn challenges.
- **Customizable User Retrieval:** Allows developers to define custom logic for retrieving users based on WebAuthn credentials.

## Installation

```bash
npm install passport-simple-webauthn2
```

or with Yarn:

```bash
yarn add passport-simple-webauthn2
```

## Prerequisites

- **Node.js**: Ensure you have Node.js installed (version 14 or higher recommended).
- **Express.js**: This strategy is designed to work with Express.js applications.
- **Passport.js**: Familiarity with Passport.js is beneficial.
- **Session Management**: Configure session management using `express-session` or similar middleware.

## Usage

Integrate `passport-simple-webauthn2` into your Node.js Express application by following these steps:

### 1. Setting Up Your Express Application

First, set up a basic Express application with Passport.js and session management.

```typescript
// src/app.ts
import express from "express";
import session from "express-session";
import passport from "passport";
import bodyParser from "body-parser";
import { Strategy } from "passport-simple-webauthn2";

// Initialize Express app
const app = express();

// Middleware setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize Passport.js
app.use(passport.initialize());
app.use(passport.session());

// User serialization
passport.serializeUser((user, done) => {
  done(null, (user as any).id); // Adjust based on your user object structure
});

passport.deserializeUser(async (id, done) => {
  // Implement user retrieval based on ID
  const user = await getUserById(id); // Replace with your user retrieval logic
  done(null, user);
});

// Define your routes here...

export default app;
```

### 2. Configuring the Strategy

Set up the `Strategy` with your user retrieval logic.

```typescript
// src/auth/passport.ts
import passport from "passport";
import { Strategy, SimpleWebAuthnStrategyOptions } from "passport-simple-webauthn2";
import type { Request } from "express";

// Example User Model
interface User {
  id: Uint8Array;
  username: string;
  credentials: WebAuthnCredential[];
}

// Mock user retrieval function
const getUser: SimpleWebAuthnStrategyOptions["getUser"] = async (req: Request, id: Uint8Array) => {
  // Replace this with your actual user retrieval logic (e.g., database query)
  const user = await findUserById(id); // Implement this function
  return user;
};

// Initialize the strategy
const strategyOptions: SimpleWebAuthnStrategyOptions = {
  getUser,
};

const webAuthnStrategy = new Strategy(strategyOptions);

// Use the strategy with Passport
passport.use(webAuthnStrategy);

export default passport;
```

### 3. Registration Routes

Implement routes to handle user registration (i.e., registering new WebAuthn credentials).

```typescript
// src/routes/register.ts
import express, { Request, Response } from "express";
import { generateRegistration, verifyRegistration } from "passport-simple-webauthn2";
import type { RegistrationUser } from "passport-simple-webauthn2";

const router = express.Router();

// Route to initiate registration
router.post("/register/options", async (req: Request, res: Response) => {
  const { username, displayName } = req.body;

  // Create a new user or retrieve existing user
  const user: RegistrationUser = {
    id: generateUserId(), // Implement this function to generate a unique Uint8Array ID
    name: username,
    displayName: displayName,
    credentials: [], // Initially, no credentials
  };

  // Generate registration options
  const options = await generateRegistration(req, user);

  // Optionally, save the user to your database here

  res.json(options);
});

// Route to handle registration response
router.post("/register/response", async (req: Request, res: Response) => {
  const { userId, response } = req.body;

  // Retrieve user from your database
  const user = await getUserById(Buffer.from(userId, "base64url")); // Implement this function

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  try {
    const verification = await verifyRegistration(req, user, response);

    if (verification.verified) {
      // Save the credential to your database
      user.credentials.push(verification.registrationInfo!);
      await saveUser(user); // Implement this function
      res.json({ success: true });
    } else {
      res.status(400).json({ error: "Verification failed" });
    }
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

export default router;
```

### 4. Authentication Routes

Implement routes to handle user authentication (i.e., logging in with WebAuthn credentials).

```typescript
// src/routes/authenticate.ts
import express, { Request, Response } from "express";
import passport from "passport";
import { generateAuthentication, verifyAuthentication } from "passport-simple-webauthn2";
import type { AuthUser } from "passport-simple-webauthn2";

const router = express.Router();

// Route to initiate authentication
router.post("/authenticate/options", async (req: Request, res: Response) => {
  try {
    const options = await generateAuthentication(req);
    res.json(options);
  } catch (error) {
    res.status(400).json({ error: (error as Error).message });
  }
});

// Route to handle authentication response
router.post("/authenticate/response", passport.authenticate("simple-webauthn"), (req: Request, res: Response) => {
  // Successful authentication
  res.json({ success: true });
});

export default router;
```

### 5. Integrating Routes into Your Application

Finally, integrate the registration and authentication routes into your Express application.

```typescript
// src/app.ts
import express from "express";
import session from "express-session";
import passport from "passport";
import bodyParser from "body-parser";
import passportSetup from "./auth/passport";
import registerRoutes from "./routes/register";
import authenticateRoutes from "./routes/authenticate";

// Initialize Express app
const app = express();

// Middleware setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize Passport.js
app.use(passport.initialize());
app.use(passport.session());

// User serialization
passport.serializeUser((user, done) => {
  done(null, (user as any).id); // Adjust based on your user object structure
});

passport.deserializeUser(async (id, done) => {
  // Implement user retrieval based on ID
  const user = await getUserById(id); // Replace with your user retrieval logic
  done(null, user);
});

// Use Passport strategy
passportSetup;

// Use registration and authentication routes
app.use("/auth", registerRoutes);
app.use("/auth", authenticateRoutes);

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

## API Reference

### Strategy

#### `Strategy(options: SimpleWebAuthnStrategyOptions)`

Creates an instance of the WebAuthn Passport strategy.

- **Parameters:**
    - `options`: Configuration options for the strategy.
    - `getUser`: Function to retrieve a user based on the provided ID.

#### Methods

##### `authenticate(req: Request, _options?: any): void`

Overrides Passport's `authenticate` method to handle WebAuthn authentication.

- **Parameters:**
    - `req`: Express request object.
    - `_options`: Optional authentication options (unused).

### Utility Functions

The package exports several utility functions for handling registration and authentication processes.

#### `generateRegistration(req: Request, user: RegistrationUser): Promise<RegistrationOptions>`

Generates registration options for a new WebAuthn credential.

- **Parameters:**
    - `req`: Express request object.
    - `user`: The user registering a new credential.

- **Returns:** Registration options compatible with WebAuthn clients.

#### `verifyRegistration(req: Request, user: RegistrationUser, response: RegistrationResponseJSON): Promise<VerifiedRegistrationResponse>`

Verifies the registration response from the client.

- **Parameters:**
    - `req`: Express request object.
    - `user`: The user registering a new credential.
    - `response`: The registration response JSON from the client.

- **Returns:** Verification result indicating success or failure.

#### `generateAuthentication(req: Request): Promise<AuthenticationOptions>`

Generates authentication options for an existing WebAuthn credential.

- **Parameters:**
    - `req`: Express request object.

- **Returns:** Authentication options compatible with WebAuthn clients.

#### `verifyAuthentication(req: Request, user: AuthUser, response: AuthenticationResponseJSON): Promise<VerifiedAuthenticationResponse>`

Verifies the authentication response from the client.

- **Parameters:**
    - `req`: Express request object.
    - `user`: The user attempting to authenticate.
    - `response`: The authentication response JSON from the client.

- **Returns:** Verification result indicating success or failure.

#### Challenge Store Functions

Functions to manage challenges during the authentication process.

- `saveChallenge(req: Request, userId: string, challenge: string): Promise<void>`
- `getChallenge(req: Request, userId: string): Promise<string | null>`
- `clearChallenge(req: Request, userId: string): Promise<void>`

## Type Definitions

The package provides comprehensive TypeScript type definitions to ensure type safety and enhance developer experience.

### `UserModel`

Represents a user in the application.

```typescript
export type UserModel = {
  id: any;
  username: string;
};
```

### `Passkey`

Represents a WebAuthn passkey associated with a user.

```typescript
export type Passkey = {
  id: Base64URLString;
  publicKey: Uint8Array;
  user: UserModel;
  webauthnUserID: Base64URLString;
  counter: number;
  deviceType: CredentialDeviceType;
  backedUp: boolean;
  transports?: AuthenticatorTransportFuture[];
};
```

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the Repository:** Click the "Fork" button at the top-right corner of the repository page.

2. **Clone Your Fork:**

   ```bash
   git clone https://github.com/your-username/passport-simple-webauthn2.git
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

5. **Make Your Changes:** Implement your feature or bug fix.

6. **Run Tests:** Ensure all tests pass.

   ```bash
   npm test
   ```

7. **Commit Your Changes:**

   ```bash
   git commit -m "Add Your Feature Description"
   ```

8. **Push to Your Fork:**

   ```bash
   git push origin feature/YourFeatureName
   ```

9. **Create a Pull Request:** Navigate to the original repository and create a pull request from your fork.

## License

This project is licensed under the [MIT License](LICENSE).

---

## Additional Information

### Environment Variables

Ensure you have the following environment variables set in your application for proper configuration:

- `RP_NAME`: Relying Party name (e.g., your application's name).
- `RP_ID`: Relying Party ID (e.g., your domain, e.g., `example.com`).

### Security Considerations

- **HTTPS:** WebAuthn requires a secure context. Ensure your application is served over HTTPS in production environments.
- **Session Security:** Configure session management with secure settings (e.g., `secure`, `httpOnly` cookies) to prevent session hijacking.
- **Challenge Storage:** The current implementation uses an in-memory store for challenges. For scalability and persistence, consider integrating a distributed store like Redis.

### Testing

The package includes comprehensive tests to ensure reliability. To run the tests:

```bash
npm test
```

Ensure all tests pass before deploying or contributing to the project.

### Documentation

Detailed documentation is generated using [TypeDoc](https://typedoc.org/). To generate documentation:

```bash
npm run docs
```

The generated documentation will be available in the `docs` directory.

---

## Example Project

For a complete example of how to integrate `passport-simple-webauthn2` into a Node.js Express application, refer to the [example project](https://github.com/rubentalstra/passport-simple-webauthn2-example).

---

Feel free to open issues or submit pull requests for any features or bugs you encounter. Happy authenticating!