import { Sequelize } from "sequelize";
import { Config } from "../../src/config/config";
import { Database } from "../../src/database/postgresql_database";
import { HorusecConfigModel } from "../../src/models/horusec_config_model";

describe("Routes", () => {
    it("check if model exists into database instance", () => {
        const db: Sequelize = new Database(new Config().getConfig()).getConnection();

        const model: HorusecConfigModel = new HorusecConfigModel(db);

        const response: boolean = db.models[model.tableName] === null ||
            db.models[model.tableName] === undefined;

        expect(response).toBe(false);
    });
    it("check if model not exists into database instance", () => {
        const mockDB: any = {
            models: {},
            define: (s: string, o: any) => "Test123",
        };
        try {
            // tslint:disable-next-line: no-unused-expression
            new HorusecConfigModel(mockDB);
        } catch (error) {
            expect(error).toBeInstanceOf(Error);
            expect(error).toHaveProperty("message", "Model (HorusecConfigModel) wasn't configured correctly!");
        }
    });
});

