import { User } from "../models/User";
import type { UserStore, WebAuthnUser } from "../../../../dist/types";

export class MongoUserStore implements UserStore {
    async get(identifier: string, byID = false): Promise<WebAuthnUser | undefined> {
        try {
            return await User.findOne(byID ? { userID: identifier } : { username: identifier })
                .lean()
                .exec() as WebAuthnUser | undefined;
        } catch (error) {
            console.error(
                `❌ Error fetching user (${byID ? "userID" : "username"}: ${identifier}):`,
                error
            );
            return undefined;
        }
    }

    async save(user: WebAuthnUser): Promise<void> {
        try {
            // Upsert the user. When passkeys are provided, filter out duplicates.
            const uniquePasskeys = user.passkeys.reduce((acc: typeof user.passkeys, passkey) => {
                if (!acc.find((p) => p.id === passkey.id)) {
                    acc.push(passkey);
                }
                return acc;
            }, []);

            await User.findOneAndUpdate(
                { userID: user.userID },
                { userID: user.userID, username: user.username, passkeys: uniquePasskeys },
                { upsert: true, new: true, setDefaultsOnInsert: true }
            ).exec();
        } catch (error) {
            console.error(`❌ Error saving user (${user.userID}):`, error);
        }
    }
}