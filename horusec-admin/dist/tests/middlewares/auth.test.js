"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const auth_1 = require("../../src/middlewares/auth");
describe("Test AuthTokenAPI", () => {
    it("check if auth middleware api call next step when access token is valid", () => {
        const auth = new auth_1.AuthMiddleware("123");
        const req = { headers: { authorization: "123" } };
        const res = null;
        const next = jest.fn();
        auth.authTokenAPI(req, res, next);
        expect(next).toBeCalled();
    });
    it("check if auth middleware api return 401 when access token is not valid", () => {
        const auth = new auth_1.AuthMiddleware("123");
        const req = { headers: { authorization: "987" } };
        const res = {};
        res.render = jest.fn();
        const next = jest.fn();
        auth.authTokenAPI(req, res, next);
        expect(res.render).toBeCalled();
    });
});
describe("Test AuthTokenView", () => {
    it("check if auth middleware view call next step when access token is valid", () => {
        const auth = new auth_1.AuthMiddleware("123");
        const req = { headers: { cookie: "horusec::access_token=123" } };
        const res = {};
        const next = jest.fn();
        auth.authTokenView(req, res, next);
        expect(next).toBeCalled();
    });
    it("check if auth middleware view return 401 when access token is exists", () => {
        const auth = new auth_1.AuthMiddleware("123");
        const req = { headers: {} };
        const res = {};
        res.render = jest.fn();
        const next = jest.fn();
        auth.authTokenView(req, res, next);
        expect(res.render).toBeCalled();
    });
    it("check if auth middleware view return 401 when access token is not valid", () => {
        const auth = new auth_1.AuthMiddleware();
        const req = { headers: { cookie: "horusec::access_token=987" } };
        const res = {};
        res.render = jest.fn();
        const next = jest.fn();
        auth.authTokenView(req, res, next);
        expect(res.render).toBeCalled();
    });
});
//# sourceMappingURL=auth.test.js.map