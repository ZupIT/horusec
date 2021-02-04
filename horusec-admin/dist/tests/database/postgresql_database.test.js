"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const sequelize_1 = require("sequelize");
const config_1 = require("../../src/config/config");
const postgresql_database_1 = require("../../src/database/postgresql_database");
describe("Test Database", () => {
    it("Check if connection broken by invalid connection in postgresql", () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "postgresql://SuP3#R:P*55w0r2d@postgresql://root:root@123.4.5.6:5432/horusec_db?sslmode=disable1:5432/horusec_db?sslmode=disable";
        const database = new postgresql_database_1.Database(new config_1.Config().getConfig());
        expect(database.checkHealth()).rejects.toThrow(Error);
    });
    it("Check if connection is relesed with success in postgresql", () => {
        const database = new postgresql_database_1.Database(new config_1.Config().getConfig());
        expect(database.checkHealth()).rejects.not.toThrow(Error);
    });
    it("Check if connection is relesed with success in sqlite in memory", () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        const database = new postgresql_database_1.Database(new config_1.Config().getConfig());
        expect(database.checkHealth()).rejects.not.toThrow(Error);
    });
    it("Should when get connection if is empty recreate connection", () => {
        const database = new postgresql_database_1.Database(new config_1.Config().getConfig());
        database["db"] = null;
        expect(database.getConnection()).toBeInstanceOf(sequelize_1.Sequelize);
    });
});
//# sourceMappingURL=postgresql_database.test.js.map