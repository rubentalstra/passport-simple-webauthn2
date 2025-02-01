import { User } from "../models/User";
import type { UserStore, WebAuthnUser } from "../../../dist/types";

export class MongoUserStore implements UserStore {
    async get(identifier: string, byID = false): Promise<WebAuthnUser | undefined> {
        try {
            const query = byID ? { userID: identifier } : { username: identifier };
            const user = await User.findOne(query).lean().exec();

            // console.log("🔹 Fetched User Data:", user);
            return user as WebAuthnUser | undefined;
        } catch (error) {
            // console.error(`❌ Error fetching user (${byID ? "userID" : "username"}: ${identifier}):`, error);
            return undefined;
        }
    }

    async save(user: WebAuthnUser): Promise<void> {
        try {
            const existingUser = await User.findOne({ userID: user.userID }).lean().exec();

            if (existingUser) {
                user.passkeys = user.passkeys.map((passkey) => {
                    const existingPasskey = existingUser.passkeys.find((p) => p.id === passkey.id);
                    if (existingPasskey) {
                        return { ...passkey, publicKey: existingPasskey.publicKey };
                    }
                    if (!passkey.publicKey || (Buffer.isBuffer(passkey.publicKey) && passkey.publicKey.length === 0)) {
                        return passkey;
                    }
                    return passkey;
                });
            }

            await User.findOneAndUpdate(
                { userID: user.userID },
                { $set: { username: user.username, passkeys: user.passkeys } },
                { upsert: true, new: true, setDefaultsOnInsert: true }
            ).exec();

            // console.log(`✅ Successfully saved user: ${user.userID}`);
        } catch (error) {
            console.error(`❌ Error saving user (${user.userID}):`, error);
        }
    }
}