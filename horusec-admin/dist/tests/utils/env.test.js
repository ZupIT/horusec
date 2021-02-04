"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const env_1 = require("../../src/utils/env");
describe("Test GetEnvOrDefault", () => {
    const utils = new env_1.EnvUtil();
    it("check if environment exists and return your value", () => {
        process.env.HORUSEC_PORT = "3000";
        const response = utils.getEnvOrDefault("HORUSEC_PORT", "5000");
        expect(response).toBe("3000");
    });
    it("check if environment not exists and return default value", () => {
        const response = utils.getEnvOrDefault("HORUSEC_NOT_EXISTS_PORT", "5000");
        expect(response).toBe("5000");
    });
});
//# sourceMappingURL=env.test.js.map