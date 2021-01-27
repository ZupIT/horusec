import { Request, Response } from "express-serve-static-core";

export class AuthMiddleware {
  totalRetry = 0;
  constructor(
    public accessToken: string,
  ) {}

  public checkAuthValidation(req: Request, res: Response, next: any): any {
    if (req.headers.authorization === this.accessToken) {
      return next(req, res);
    }

    this.totalRetry++;

    if (this.totalRetry > 3) {
      throw new Error("Total attempts reached, the application will be restarted for security.");
    }

    return res.status(401).send({ message: "User no authorized" });
  }
}