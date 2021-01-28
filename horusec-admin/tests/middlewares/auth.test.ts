import { Fn } from "sequelize/types/lib/utils";
import { AuthMiddleware } from "../../src/middlewares/auth";

const exit: any = (code?: number) => null;

describe("Auth Middleware test", () => {
  it("check if model exists into database instance", () => {
    const auth: AuthMiddleware = new AuthMiddleware();
    auth.setAccessToken("123");

    const req: any = {headers: { authorization: "123"}};
    const res: any = null;
    const next: jest.Mock = jest.fn();

    auth.checkAuthValidation(req, res, next);

    expect(next).toBeCalled();
  });

  it("check if auth middleware return 401 when access token is not valid", () => {
    const auth: AuthMiddleware = new AuthMiddleware();
    auth.setAccessToken("123");

    const req: any = {headers: { authorization: "987"}};
    const res: any = {};
    res.send = jest.fn();
    res.status = () => res;
    const next: jest.Mock = jest.fn();

    auth.checkAuthValidation(req, res, next);

    expect(res.send).toBeCalled();
  });

  // it("check if middleware will kill service if try three or more times", (done) => {
  //   const auth: AuthMiddleware = new AuthMiddleware();
  //   auth.setAccessToken("123");

  //   const req: any = {headers: { authorization: "987"}};
  //   const res: any = {};
  //   res.send = jest.fn();
  //   jest.setTimeout(3);
  //   res.status = () => res;
  //   const next: jest.Mock = jest.fn();
  //   process.exit = exit;
  //   const mockExit: any = jest.spyOn(process, "exit");
  //   auth.checkAuthValidation(req, res, next);
  //   auth.checkAuthValidation(req, res, next);
  //   auth.checkAuthValidation(req, res, next);
  //   expect(mockExit).toHaveBeenCalledWith(1);
  // });
});
