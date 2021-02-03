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
            Router().get("", (_, res: Response) => res.redirect("/view"))
        ])

        app.use("/view", [
            Router().get("",
                (_, res: Response) => res.render("pages/index")),
            Router().get("/home",
                (req, res, next) => this.auth.validateAccessTokenOnLocalStorage(req, res, next),
                (_, res: Response) => res.render("pages/home")),
            Router().get("/config-general",
                (req, res, next) => this.auth.validateAccessTokenOnLocalStorage(req, res, next),
                (_, res: Response) => res.render("pages/config-general")),
            Router().get("/config-auth",
                (req, res, next) => this.auth.validateAccessTokenOnLocalStorage(req, res, next),
                (_, res: Response) => res.render("pages/config-auth")),
            Router().get("/config-manager",
                (req, res, next) => this.auth.validateAccessTokenOnLocalStorage(req, res, next),
                (_, res: Response) => res.render("pages/config-manager")),
        ]);

        app.use("/api", [
            Router().post("/auth",
                (req, res, next) => this.auth.validateAccessTokenOnHeaders(req, res, next),
                (_, res) => res.status(204).send()),
            Router().patch("/config",
                (req, res, next) => this.auth.validateAccessTokenOnHeaders(req, res, next),
                (req, res) => this.horusecController.setHorusecConfig(req, res)),
        ]);

        return app;
    }
}
