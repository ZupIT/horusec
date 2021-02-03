import { Sequelize } from "sequelize";
import { Config } from "../../src/config/config";
import { Database } from "../../src/database/postgresql";

describe("Test Database", () => {
    it("Check if connection is relesed with success in postgresql", () => {
        expect(new Database(new Config().getConfig()).getConnection()).toBeInstanceOf(Sequelize);
    });
    it("Check if connection is relesed with success in sqlite in memory", () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        expect(new Database(new Config().getConfig()).getConnection()).toBeInstanceOf(Sequelize);
    });
});
