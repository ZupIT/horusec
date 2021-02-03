import { Config } from "../../src/config/config";
import { Database } from "../../src/database/postgresql";

describe("Test Database", () => {
    it("Check if connection", () => {
        expect(new Database(new Config().getConfig()));
    });
});
