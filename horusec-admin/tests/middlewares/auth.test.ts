import { AuthMiddleware } from "../../src/middlewares/auth";

describe("Test AuthTokenAPI", () => {
    it("check if auth middleware api call next step when access token is valid", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth.setAccessToken("123");

        const req: any = { headers: { authorization: "123" } };
        const res: any = null;
        const next: jest.Mock = jest.fn();

        auth.authTokenAPI(req, res, next);

        expect(next).toBeCalled();
    });

    it("check if auth middleware api return 401 when access token is not valid", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth.setAccessToken("123");

        const req: any = { headers: { authorization: "987" } };
        const res: any = {};
        res.send = jest.fn();
        res.status = () => res;
        const next: jest.Mock = jest.fn();

        auth.authTokenAPI(req, res, next);

        expect(res.send).toBeCalled();
    });
});

describe("Test AuthTokenView", () => {
    it("check if auth middleware view call next step when access token is valid", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth.setAccessToken("123");

        const req: any = { headers: { cookie: "horusec::access_token=123" } };
        const res: any = {};
        const next: jest.Mock = jest.fn();

        auth.authTokenView(req, res, next);

        expect(next).toBeCalled();
    });

    it("check if auth middleware view return 401 when access token is exists", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth.setAccessToken("123");

        const req: any = { headers: {} };
        const res: any = {};
        res.send = jest.fn();
        res.status = () => res;
        const next: jest.Mock = jest.fn();

        auth.authTokenView(req, res, next);

        expect(res.send).toBeCalled();
    });
    it("check if auth middleware view return 401 when access token is not valid", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth.setAccessToken("123");

        const req: any = { headers: { cookie: "horusec::access_token=987" } };
        const res: any = {};
        res.send = jest.fn();
        res.status = () => res;
        const next: jest.Mock = jest.fn();

        auth.authTokenView(req, res, next);

        expect(res.send).toBeCalled();
    });
});
