import { Config } from "../../src/config/config";

describe("Test Config", () => {
    it("Check if set port correctly", () => {
        expect(new Config().getConfig().Port).toBe(3000);
        process.env.HORUSEC_PORT = "5000";
        expect(new Config().getConfig().Port).toBe(5000);
    });
    it("Check if set uri correctly", () => {
        expect(new Config().getConfig().URI).toBe("postgresql://root:root@127.0.0.1:5432/horusec_db?sslmode=disable");
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        expect(new Config().getConfig().Port).toBe(5000);
    });
    it("Check if set logMode correctly with true", () => {
        expect(new Config().getConfig().LogMode).toBe(false);
        process.env.HORUSEC_DATABASE_SQL_LOG_MODE = "true";
        expect(new Config().getConfig().LogMode).toBe(true);
        process.env.HORUSEC_DATABASE_SQL_LOG_MODE = "1";
        expect(new Config().getConfig().LogMode).toBe(true);
    });
});
