import { User, IUser } from "../models/User";
import type { UserStore, WebAuthnUser } from  "passport-simple-webauthn2";

export class MongoUserStore implements UserStore {
    async get(identifier: string, byID = false): Promise<WebAuthnUser | undefined> {
        const user = await User.findOne(byID ? { userID: identifier } : { username: identifier }).exec();
        return user ? user.toObject() : undefined;
    }

    async save(user: WebAuthnUser): Promise<void> {
        await User.findOneAndUpdate({ userID: user.userID }, user, { upsert: true, new: true });
    }
}