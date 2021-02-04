import { HorusecController } from "../controllers/horusec_controller";
import { Express } from "express-serve-static-core";
import { AuthMiddleware } from "../middlewares/auth_middleware";
import { Router } from "express";
import { HealthController } from "../controllers/health_controller";
import { Database } from "../database/postgresql_database";

export class AppRoutes {
    constructor(
        public db: Database,
        public horusecController: HorusecController = new HorusecController(db),
        public healthController: HealthController = new HealthController(db),
        public auth: AuthMiddleware = new AuthMiddleware(),
    ) {}

    public start(app: Express): Express {
        app.use("/", [
            Router().get("", (_, res) => res.redirect("/view")),
        ]);

        app.use("/view", [
            Router().get("",
                (_, res) => res.render("pages/index")),
            Router().get("/not-authorized",
                (_, res) => res.render("pages/not-authorized")),
            Router().get("/home",
                (req, res, next) => this.auth.authTokenView(req, res, next),
                (_, res) => res.render("pages/home")),
            Router().get("/config-general",
                (req, res, next) => this.auth.authTokenView(req, res, next),
                (_, res) => res.render("pages/config-general")),
            Router().get("/config-auth",
                (req, res, next) => this.auth.authTokenView(req, res, next),
                (_, res) => res.render("pages/config-auth")),
            Router().get("/config-manager",
                (req, res, next) => this.auth.authTokenView(req, res, next),
                (_, res) => res.render("pages/config-manager")),
        ]);

        app.use("/api", [
            Router().get("/health",
                (_, res) => this.healthController.checkHealth(_, res)),
            Router().post("/auth",
                (req, res, next) => this.auth.authTokenAPI(req, res, next),
                (_, res) => res.status(204).send()),
            Router().patch("/config",
                (req, res, next) => this.auth.authTokenAPI(req, res, next),
                (req, res) => this.horusecController.setHorusecConfig(req, res)),
        ]);
        app.use("**", [
            Router().get("", (_, res) => res.render("pages/not-found")),
        ]);
        return app;
    }
}
