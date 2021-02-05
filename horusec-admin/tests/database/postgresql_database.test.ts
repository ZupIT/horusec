import { Sequelize } from "sequelize";
import { Config } from "../../src/config/config";
import { Database } from "../../src/database/postgresql_database";

describe("Test Database", () => {
    it("Check if connection broken by invalid connection in postgresql", () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "postgresql://SuP3#R:P*55w0r2d@postgresql://root:root@123.4.5.6:5432/horusec_db?sslmode=disable1:5432/horusec_db?sslmode=disable";
        const database: Database = new Database(new Config().getConfig());
        expect(database.checkHealth()).rejects.toThrow(Error);
    });
    it("Check if connection is relesed with success in postgresql", () => {
        const database: Database = new Database(new Config().getConfig());
        expect(database.checkHealth()).rejects.not.toThrow(Error);
    });
    it("Check if connection is relesed with success in sqlite in memory", () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        const database: Database = new Database(new Config().getConfig());
        expect(database.checkHealth()).rejects.not.toThrow(Error);
    });
    it("Should when get connection if is empty recreate connection", () => {
        const database: Database = new Database(new Config().getConfig());
        database["db"] = null;
        expect(database.getConnection()).toBeInstanceOf(Sequelize);
    });
});
