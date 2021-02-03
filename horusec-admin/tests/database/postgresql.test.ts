import { Sequelize } from "sequelize";
import { Config } from "../../src/config/config";
import { Database } from "../../src/database/postgresql";

describe("Test Database", () => {
    it("Check if connection broken by invalid connection in postgresql", async () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "postgresql://SuP3#R:P*55w0r2d@postgresql://root:root@123.4.5.6:5432/horusec_db?sslmode=disable1:5432/horusec_db?sslmode=disable";
        const database: Database = new Database(new Config().getConfig());
        expect(await database.checkHealth).toThrow(Error);
    });
    it("Check if connection is relesed with success in postgresql", () => {
        expect(new Database(new Config().getConfig()).getConnection()).toBeInstanceOf(Sequelize);
    });
    it("Check if connection is relesed with success in sqlite in memory", () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        expect(new Database(new Config().getConfig()).getConnection()).toBeInstanceOf(Sequelize);
    });
});
