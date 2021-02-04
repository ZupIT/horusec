"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = require("../../src/config/config");
const postgresql_database_1 = require("../../src/database/postgresql_database");
const horusec_config_model_1 = require("../../src/models/horusec_config_model");
describe("Routes", () => {
    it("check if model exists into database instance", () => {
        const db = new postgresql_database_1.Database(new config_1.Config().getConfig()).getConnection();
        const model = new horusec_config_model_1.HorusecConfigModel(db);
        const response = db.models[model.tableName] === null ||
            db.models[model.tableName] === undefined;
        expect(response).toBe(false);
    });
    it("check if model not exists into database instance", () => {
        const mockDB = {
            models: {},
            define: (s, o) => "Test123",
        };
        try {
            // tslint:disable-next-line: no-unused-expression
            new horusec_config_model_1.HorusecConfigModel(mockDB);
        }
        catch (error) {
            expect(error).toBeInstanceOf(Error);
            expect(error).toHaveProperty("message", "Model (HorusecConfigModel) wasn't configured correctly!");
        }
    });
});
//# sourceMappingURL=horusec_config_model.test.js.map