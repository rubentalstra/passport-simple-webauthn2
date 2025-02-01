import { UserStore, WebAuthnUser } from "./types";
import { MongoClient } from "mongodb";

export class MongoUserStore implements UserStore {
    private collection;

    constructor(mongoUri: string, dbName: string, collectionName: string) {
        const client = new MongoClient(mongoUri);
        this.collection = client.db(dbName).collection(collectionName);
    }

    async get(identifier: string, byID = false): Promise<WebAuthnUser | undefined> {
        return this.collection.findOne(byID ? { userID: identifier } : { username: identifier });
    }

    async save(user: WebAuthnUser): Promise<void> {
        await this.collection.updateOne({ userID: user.userID }, { $set: user }, { upsert: true });
    }
}