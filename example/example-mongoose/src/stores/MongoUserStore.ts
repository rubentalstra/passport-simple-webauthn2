import { User } from "../models/User";
import type { UserStore, WebAuthnUser } from "../../../../dist/types";

export class MongoUserStore implements UserStore {
    async get(identifier: string, byID = false): Promise<WebAuthnUser | undefined> {
        const query = byID ? { _id: identifier } : { username: identifier };
        const user = await User.findOne(query).lean().exec();
        if (user) {
            // Map MongoDB's _id to our id field.
            return {
                id: user._id.toString(),
                username: user.username,
                passkeys: user.passkeys,
            };
        }
        return undefined;
    }

    async save(user: WebAuthnUser): Promise<WebAuthnUser> {
        // If the user doesn't have an id, let the database generate one.
        if (!user.id) {
            const createdUser = await User.create({
                username: user.username,
                passkeys: user.passkeys,
            });
            return {
                id: createdUser.id.toString(),
                username: createdUser.username,
                passkeys: createdUser.passkeys,
            };
        } else {
            // Update the existing document.
            const updatedUser = await User.findByIdAndUpdate(
                user.id,
                { username: user.username, passkeys: user.passkeys },
                { new: true, upsert: true }
            ).exec();
            if (!updatedUser) {
                throw new Error("Failed to update user");
            }
            return {
                id: updatedUser.id.toString(),
                username: updatedUser.username,
                passkeys: updatedUser.passkeys,
            };
        }
    }
}