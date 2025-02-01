import { User } from "../models/User";
import type { UserStore, WebAuthnUser } from "../../../dist/types";

export class MongoUserStore implements UserStore {
    async get(identifier: string, byID = false): Promise<WebAuthnUser | undefined> {
        try {
            return await User.findOne(byID ? { userID: identifier } : { username: identifier })
                .lean()
                .exec() as WebAuthnUser | undefined;
        } catch (error) {
            console.error(`❌ Error fetching user (${byID ? "userID" : "username"}: ${identifier}):`, error);
            return undefined;
        }
    }

    async save(user: WebAuthnUser): Promise<void> {
        try {
            const existingUser = await User.findOne({ userID: user.userID }).lean().exec();

            if (existingUser) {
                user.passkeys = user.passkeys.map((passkey) => {
                    const existingPasskey = existingUser.passkeys.find((p) => p.id === passkey.id);
                    return existingPasskey ? { ...passkey, publicKey: existingPasskey.publicKey } : passkey;
                });
            }

            await User.findOneAndUpdate(
                { userID: user.userID },
                { username: user.username, passkeys: user.passkeys },
                { upsert: true, new: true, setDefaultsOnInsert: true }
            ).exec();
        } catch (error) {
            console.error(`❌ Error saving user (${user.userID}):`, error);
        }
    }

    /**
     * Updates the passkeys for a user.
     */
    async updatePasskeys(username: string, passkeys: WebAuthnUser["passkeys"]): Promise<void> {
        try {
            await User.findOneAndUpdate(
                { username },
                { $set: { passkeys } },
                { new: true }
            ).exec();
        } catch (error) {
            console.error(`❌ Error updating passkeys for username: ${username}`, error);
        }
    }

    /**
     * Updates the counter for a specific passkey.
     */
    async updatePasskeyCounter(username: string, credentialID: string, counter?: number): Promise<void> {
        try {
            await User.findOneAndUpdate(
                { username, "passkeys.id": credentialID },
                { $set: { "passkeys.$.counter": counter } }
            ).exec();
        } catch (error) {
            console.error(`❌ Error updating passkey counter for username: ${username}, credentialID: ${credentialID}`, error);
        }
    }
}