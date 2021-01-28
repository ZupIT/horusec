import { HorusecController } from "../controllers/horusec";
import { Express, Response } from "express-serve-static-core";
import { Sequelize } from "sequelize";
import { AuthMiddleware } from "../middlewares/auth";
import { Router } from "express";
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
        app.use("/", [
            Router().get("", (_, res: Response) => res.render("index")),

            Router().post("",
                (req, res, next) => this.auth.validateAccessTokenOnHeaders(req, res, next),
                (req, res) => this.horusecController.setHorusecConfig(req, res)),
        ]);

        app.use("/home", [
            Router().get("", (_, res: Response) => res.render("home")),
        ]);

        app.use("/config", [
            Router().get("/general", (_, res: Response) => res.render("config-general")),

            Router().get("/auth", (_, res: Response) => res.render("config-auth")),

            Router().get("/manager", (_, res: Response) => res.render("config-manager")),
        ]);

        return app;
    }
}
