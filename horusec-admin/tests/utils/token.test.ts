import { TokenUtil } from "../../src/utils/token";

describe("Test generateToken", () => {
    const token: TokenUtil = new TokenUtil();
    function hasDuplicates(array: string[]): boolean {
        const valuesSoFar: string[] = [];

        array.forEach((value) => {
            if (valuesSoFar.indexOf(value) !== -1) {
                return true;
            }
            valuesSoFar.push(value);
        });

        return valuesSoFar.length !== array.length;
    }
    it("check if token created is not duplicated run in 1000 times", () => {
        let tokens: string[] = [];

        for (let i: any = 0; i < 1000; i++) {
            tokens = tokens.concat(token.generateToken());
        }

        expect(hasDuplicates(tokens)).toBe(false);
    });
});

