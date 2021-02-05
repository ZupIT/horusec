import { AuthMiddleware } from "../../src/middlewares/auth_middleware";

describe("Test AuthTokenAPI", () => {
    it("check if auth middleware api call next step when access token is valid", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth["setAccessToken"]("123");

        const req: any = { headers: { authorization: "123" } };
        const res: any = null;
        const next: jest.Mock = jest.fn();

        auth.authTokenAPI(req, res, next);

        expect(next).toBeCalled();
    });

    it("check if auth middleware api return 401 when access token is not valid", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth["setAccessToken"]("123");

        const req: any = { headers: { authorization: "987" } };
        const res: any = {};
        res.render = jest.fn();
        const next: jest.Mock = jest.fn();

        auth.authTokenAPI(req, res, next);

        expect(res.render).toBeCalled();
    });
    it("check if auth middleware api return 401 with retry 3 times and sucess in 4 retry", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth["setAccessToken"]("123");

        const req: any = { headers: { authorization: "987" } };
        const res: any = {};
        res.render = jest.fn();
        const next: jest.Mock = jest.fn();

        auth.authTokenAPI(req, res, next);
        expect(res.render).toBeCalled();
        auth.authTokenAPI(req, res, next);
        expect(res.render).toBeCalled();
        auth.authTokenAPI(req, res, next);
        expect(res.render).toBeCalled();
        auth["setAccessToken"]("987");
        auth.authTokenAPI(req, res, next);
        expect(next).toBeCalled();
    });
});

describe("Test AuthTokenView", () => {
    it("check if auth middleware view call next step when access token is valid", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth["setAccessToken"]("123");

        const req: any = { headers: { cookie: "horusec::access_token=123" } };
        const res: any = {};
        const next: jest.Mock = jest.fn();

        auth.authTokenView(req, res, next);

        expect(next).toBeCalled();
    });
    it("check if auth middleware view return 401 when access token is not exists", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth["setAccessToken"]("123");

        const req: any = { headers: {} };
        const res: any = {};
        res.render = jest.fn();
        const next: jest.Mock = jest.fn();

        auth.authTokenView(req, res, next);

        expect(res.render).toBeCalled();
    });
    it("check if auth middleware view return 401 when access token exist cookies but not founds", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth["setAccessToken"]("123");

        const req: any = { headers: { cookie: "pt-br" } };
        const res: any = {};
        res.render = jest.fn();
        const next: jest.Mock = jest.fn();

        auth.authTokenView(req, res, next);

        expect(res.render).toBeCalled();
    });
    it("check if auth middleware view return 401 when access token exist cookies but not founds", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth["setAccessToken"]("123");

        const req: any = { headers: { cookie: "pt-br" } };
        const res: any = {};
        res.render = jest.fn();
        const next: jest.Mock = jest.fn();

        auth.authTokenView(req, res, next);

        expect(res.render).toBeCalled();
    });
    it("check if auth middleware view return 401 when access token is not valid", () => {
        const auth: AuthMiddleware = new AuthMiddleware();

        const req: any = { headers: { cookie: "horusec::access_token=987" } };
        const res: any = {};
        res.render = jest.fn();
        const next: jest.Mock = jest.fn();

        auth.authTokenView(req, res, next);

        expect(res.render).toBeCalled();
    });
    it("check if auth middleware view return 401 with retry 3 times and sucess in 4 retry", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth["setAccessToken"]("123");

        const req: any = { headers: { cookie: "horusec::access_token=987" } };
        const res: any = {};
        res.render = jest.fn();
        const next: jest.Mock = jest.fn();

        auth.authTokenView(req, res, next);
        expect(res.render).toBeCalled();
        auth.authTokenView(req, res, next);
        expect(res.render).toBeCalled();
        auth.authTokenView(req, res, next);
        expect(res.render).toBeCalled();
        auth["setAccessToken"]("987");
        auth.authTokenView(req, res, next);
        expect(next).toBeCalled();
    });
});

describe("Test setAccessToken", () => {
    it("check if when force set access token your value is equal", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth["setAccessToken"]("123");
        expect(auth["accessToken"]).toBe("123");
    });
    it("check if set access token random your value is not empty", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        auth["setAccessToken"]();
        expect(auth["accessToken"]).not.toBe("");
    });
});

describe("Test extractCookieValue", () => {
    it("Should return empty content because not exists content on cookies", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        expect(auth["extractCookieValue"]("horusec::access_token", "")).toBe("");
    });
    it("Should return whitespace content because not exists content on cookies", () => {
        const auth: AuthMiddleware = new AuthMiddleware();
        expect(auth["extractCookieValue"]("horusec::access_token", " ")).toBe("");
    });
});
