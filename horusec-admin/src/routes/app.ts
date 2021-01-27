import { HorusecController } from "../controllers/horusec";
import { Express, Response } from "express-serve-static-core";
import { Sequelize } from "sequelize";
import { AuthMiddleware } from "../middlewares/auth";

export class AppRoutes {
  constructor(
    public db: Sequelize,
    public app: Express,
    public accessToken: string,
    private horusecController: HorusecController = null,
    private auth: AuthMiddleware = null,
  ) {
    this.horusecController = new HorusecController(this.db);
    this.auth = new AuthMiddleware(this.accessToken);
  }

  public start(): void {
    this.app.get("/", (_, res: Response) => res.render("index"));

    this.app.post("/", this.auth.checkAuthValidation, this.horusecController.setHorusecConfig);
  }
}
