import { HorusecController } from "../controllers/horusec";
import { Express, Response } from "express-serve-static-core";
import { Sequelize } from "sequelize";
import { AuthMiddleware } from "../middlewares/auth";

export class AppRoutes {
  constructor(
    public db: Sequelize,
    public accessToken: string,
    public horusecController: HorusecController = new HorusecController(db),
    public auth: AuthMiddleware = new AuthMiddleware(),
  ) {
    this.auth.setAccessToken(this.accessToken);
  }

  public start(app: Express): Express {
    app.get(
      "/",
      (_, res: Response) => res.render("index"),
    );

    app.post(
      "/",
      (req, res, next) => this.auth.checkAuthValidation(req, res, next),
      (req, res) => this.horusecController.setHorusecConfig(req, res),
    );

    return app;
  }
}
