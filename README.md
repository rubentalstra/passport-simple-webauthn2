# passport-simple-webauthn2

![Version](https://img.shields.io/npm/v/passport-simple-webauthn2)
![License](https://img.shields.io/npm/l/passport-simple-webauthn2)
![Build](https://img.shields.io/github/actions/workflow/status/rubentalstra/passport-simple-webauthn2/publish.yml?branch=main)
![Downloads](https://img.shields.io/npm/dt/passport-simple-webauthn2)

**Passport strategy for authenticating with Web Authentication (WebAuthn) using FIDO2 Passkeys.**

> **Note:** This version returns and stores the full user object (instead of only an identifier) in the session. See the [Usage](#usage) section for instructions on how to configure Passport accordingly.

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
    - [Strategy](#strategy)
    - [Utility Functions](#utility-functions)
- [Type Definitions](#type-definitions)
- [Contributing](#contributing)
- [License](#license)
- [Additional Information](#additional-information)

## Features

- **WebAuthn Integration:** Leverages [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn) for robust Web Authentication.
- **Passport.js Compatibility:** Seamlessly integrates with Passport.js for use in existing authentication workflows.
- **Full User Object in Session:** The strategy now returns the complete user object, and the recommended Passport configuration stores the entire user in the session.
- **TypeScript Support:** Fully typed with TypeScript for enhanced type safety and developer experience.
- **Challenge Management:** Automatically generates, stores, and verifies WebAuthn challenges.
- **Customizable User Retrieval:** Define your own logic to retrieve users based on WebAuthn credentials.

## Installation

Install via npm:

```bash
npm install passport-simple-webauthn2
```

Or with Yarn:

```bash
yarn add passport-simple-webauthn2
```

## Prerequisites

- **Node.js:** Version 14 or higher is recommended.
- **Express.js:** This strategy is designed for Express.js applications.
- **Passport.js:** Familiarity with Passport.js is helpful.
- **Session Management:** Configure sessions using `express-session` (or similar) as shown below.

## Usage

Integrate **passport-simple-webauthn2** into your Express application. The example below demonstrates the complete setup, including updated Passport configuration to store the full user object.

### 1. Setting Up Your Express Application

Create your Express application (e.g., in `src/app.ts`). Note how Passport is configured to serialize and deserialize the full user object:

```typescript
// src/app.ts
import express from "express";
import session from "express-session";
import passport from "passport";
import bodyParser from "body-parser";
import path from "path";
import registerRoutes from "./routes/register";
import authenticateRoutes from "./routes/authenticate";

// Initialize Express app
const app = express();

// Set view engine (optional, for rendering EJS pages)
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middleware setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
    // In production, set secure cookies and proper options
    cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 },
  })
);

// Initialize Passport.js
app.use(passport.initialize());
app.use(passport.session());

// Passport Serialization: Store the full user object in the session
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
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

Set up the **passport-simple-webauthn2** strategy with your own user retrieval and challenge storage logic. For example:

```typescript
// src/auth/passport.ts
import passport from "passport";
import { Strategy, SimpleWebAuthnStrategyOptions } from "passport-simple-webauthn2";
import type { Request } from "express";
import { MongoUserStore } from "../stores/MongoUserStore";
import { MongoChallengeStore } from "../stores/MongoChallengeStore";

// Initialize your stores
const userStore = new MongoUserStore();
const challengeStore = new MongoChallengeStore();

// Configure the strategy options
const strategyOptions: SimpleWebAuthnStrategyOptions = {
  rpID: process.env.RP_ID || "localhost",       // e.g., your domain
  rpName: process.env.RP_NAME || "Your App",
  userStore,
  challengeStore,
  debug: true,  // Enable debug logging if needed
};

// Create an instance of the strategy
const webAuthnStrategy = new Strategy(strategyOptions);

// Use the strategy with Passport
passport.use("webauthn", webAuthnStrategy);

export default passport;
```

### 3. Registration Routes

Implement routes to register a new WebAuthn credential. The strategy automatically returns the full user object upon successful registration. For example:

```typescript
// src/routes/register.ts
import express, { Request, Response } from "express";
import passport from "passport";

const router = express.Router();

// Initiate registration challenge (GET request)
router.get("/register", passport.authenticate("webauthn", { session: false }), (req: Request, res: Response) => {
  // Returns registration options (challenge)
  res.json(req.user);
});

// Registration callback (POST request)
router.post("/register", passport.authenticate("webauthn", { session: false }), (req: Request, res: Response) => {
  // On success, req.user contains the updated user object with the new passkey
  res.json({ user: req.user });
});

export default router;
```

### 4. Authentication Routes

Implement routes to authenticate using an existing WebAuthn credential. Again, on success, the strategy returns the full user object.

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
  // Successful authentication returns the full user object in req.user
  res.json({ user: req.user });
});

export default router;
```

### Bonus: Account Page with EJS

An example EJS template (`views/account.ejs`) to display user passkeys in a nicely formatted table:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Your Account</title>
  <!-- Bootstrap CSS for styling -->
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
  <style>
    body { margin-top: 30px; }
    .container { max-width: 800px; }
    .passkey-table { margin-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Your Account</h1>
    <h2>Registered Passkeys</h2>
    <% if (passkeys && passkeys.length > 0) { %>
      <table class="table table-striped passkey-table">
        <thead class="thead-dark">
          <tr>
            <th>ID</th>
            <th>Counter</th>
            <th>Transports</th>
          </tr>
        </thead>
        <tbody>
          <% passkeys.forEach(passkey => { %>
            <tr>
              <td><%= passkey.id %></td>
              <td><%= passkey.counter %></td>
              <td>
                <% if (passkey.transports && passkey.transports.length > 0) { %>
                  <%= passkey.transports.join(', ') %>
                <% } else { %>
                  N/A
                <% } %>
              </td>
            </tr>
          <% }); %>
        </tbody>
      </table>
    <% } else { %>
      <div class="alert alert-info" role="alert">No passkeys found.</div>
    <% } %>
    <form action="/logout" method="POST" class="mt-4">
      <button type="submit" class="btn btn-danger">Logout</button>
    </form>
  </div>
  <!-- Bootstrap JS (optional) -->
  <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

## API Reference

### Strategy

#### `new Strategy(options: SimpleWebAuthnStrategyOptions)`

Creates an instance of the WebAuthn Passport strategy.

- **Parameters:**
    - `options`: An object containing configuration options:
        - `rpID`: Your Relying Party ID (domain).
        - `rpName`: Your Relying Party name.
        - `userStore`: An object implementing the `UserStore` interface.
        - `challengeStore`: An object implementing the `ChallengeStore` interface.
        - `debug` (optional): Enable debug logging if needed.

#### Methods

##### `authenticate(req: Request, _options?: any): void`

Overrides Passport's default method to:
- Infer the mode (registration or login) based on the request path.
- Generate and send a challenge for GET requests.
- Verify credentials for POST requests.
- Returns the full user object on success.

### Utility Functions

The package provides several utility functions to handle registration and authentication flows:

- **`generateRegistration(req: Request, user: RegistrationUser): Promise<RegistrationOptions>`**  
  Generates registration options for a new WebAuthn credential.

- **`registration(req: Request, user: RegistrationUser, response: RegistrationResponseJSON): Promise<VerifiedRegistrationResponse>`**  
  Verifies the registration response from the client.

- **`generateAuthentication(req: Request): Promise<AuthenticationOptions>`**  
  Generates authentication options for existing credentials.

- **`verifyAuthentication(req: Request, user: AuthUser, response: AuthenticationResponseJSON): Promise<VerifiedAuthenticationResponse>`**  
  Verifies the authentication response from the client.

#### Challenge Store Functions

Functions to manage challenges during authentication:

- `saveChallenge(req: Request, userId: string, challenge: string): Promise<void>`
- `getChallenge(req: Request, userId: string): Promise<string | null>`
- `clearChallenge(req: Request, userId: string): Promise<void>`

## Type Definitions

### User Model

Represents a user in your application.

```typescript
export type UserModel = {
  id: any;
  username: string;
  passkeys: Passkey[];
};
```

### Passkey

Represents a WebAuthn passkey.

```typescript
export type Passkey = {
  id: Base64URLString;
  publicKey: Uint8Array;
  counter: number;
  transports?: string[];
  // Additional metadata as needed...
};
```

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the Repository**
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

## License

This project is licensed under the [MIT License](LICENSE).

---

## Additional Information

### Environment Variables

Configure your environment with variables such as:
- `RP_ID`: Relying Party ID (domain).
- `RP_NAME`: Relying Party name.

### Security Considerations

- **HTTPS:** Ensure your application uses HTTPS in production.
- **Session Security:** Configure secure session cookies and proper options.
- **Challenge Storage:** While the default challenge store works for many cases, consider using a distributed store (e.g., Redis) in scalable environments.

### Testing

Run the tests with:

```bash
npm test
```

### Documentation

Generate documentation with [TypeDoc](https://typedoc.org/):

```bash
npm run docs
```

The generated docs are available in the `docs` folder.

### Example Projects

For a complete example of an Express integration, see the [example project](https://github.com/rubentalstra/passport-simple-webauthn2/tree/main/example).

---

Happy authenticating!
