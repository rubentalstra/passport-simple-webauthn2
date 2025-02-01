import {WebAuthnUser} from "../type";

export interface UserStore {
    get(identifier: string, byID?: boolean): Promise<WebAuthnUser | undefined>;
    save(user: WebAuthnUser): Promise<WebAuthnUser>;
}

export class InMemoryUserStore implements UserStore {
    private users: Map<string, WebAuthnUser> = new Map();

    async get(identifier: string, byID = false): Promise<WebAuthnUser | undefined> {
        if (byID) {
            return this.users.get(identifier);
        } else {
            // Search by username.
            for (const user of this.users.values()) {
                if (user.username === identifier) {
                    return user;
                }
            }
        }
        return undefined;
    }

    async save(user: WebAuthnUser): Promise<WebAuthnUser> {
        // If no ID is set, generate one. (Requires Node 14.17+ for crypto.randomUUID)
        if (!user.id) {
            user.id = crypto.randomUUID();
        }
        this.users.set(user.id, user);
        return user;
    }
}