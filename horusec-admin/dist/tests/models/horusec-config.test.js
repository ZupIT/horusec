"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = require("../../src/config/config");
const postgresql_1 = require("../../src/database/postgresql");
const horusec_config_1 = require("../../src/models/horusec-config");
describe("Routes", () => {
    const db = new postgresql_1.Database(new config_1.Config().getConfig()).getConnection();
    it("check if model exists into database instance", () => {
        const model = new horusec_config_1.HorusecConfigModel(db);
        const response = db.models[model.tableName] === null ||
            db.models[model.tableName] === undefined;
        expect(response).toBe(false);
    });
});
//# sourceMappingURL=horusec-config.test.js.map