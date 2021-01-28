import { Sequelize } from "sequelize";
import { Config } from "../../src/config/config";
import { Database } from "../../src/database/postgresql";
import { HorusecConfigModel } from "../../src/models/horusec-config";

describe("Routes", () => {
    const db: Sequelize = new Database(new Config().getConfig()).getConnection();

    it("check if model exists into database instance", () => {
        const model: HorusecConfigModel = new HorusecConfigModel(db);

        const response: boolean = db.models[model.tableName] === null ||
            db.models[model.tableName] === undefined;

        expect(response).toBe(false);
    });
});

