"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const token_1 = require("../../src/utils/token");
describe("Test generateToken", () => {
    const token = new token_1.TokenUtil();
    function hasDuplicates(array) {
        const valuesSoFar = [];
        array.forEach((value) => {
            if (valuesSoFar.indexOf(value) !== -1) {
                return true;
            }
            valuesSoFar.push(value);
        });
        return valuesSoFar.length !== array.length;
    }
    it("check if token created is not duplicated run in 1000 times", () => {
        let tokens = [];
        for (let i = 0; i < 1000; i++) {
            tokens = tokens.concat(token.generateToken());
        }
        expect(hasDuplicates(tokens)).toBe(false);
    });
});
//# sourceMappingURL=token.test.js.map