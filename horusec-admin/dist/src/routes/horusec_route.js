"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppRoutes = void 0;
const horusec_controller_1 = require("../controllers/horusec_controller");
const auth_middleware_1 = require("../middlewares/auth_middleware");
const express_1 = require("express");
const health_controller_1 = require("../controllers/health_controller");
class AppRoutes {
    constructor(db, horusecController = new horusec_controller_1.HorusecController(db), healthController = new health_controller_1.HealthController(db), auth = new auth_middleware_1.AuthMiddleware()) {
        this.db = db;
        this.horusecController = horusecController;
        this.healthController = healthController;
        this.auth = auth;
    }
    start(app) {
        app.use("/", [
            express_1.Router().get("", (_, res) => res.redirect("/view")),
        ]);
        app.use("/view", [
            express_1.Router().get("", (_, res) => res.render("pages/index")),
            express_1.Router().get("/not-authorized", (_, res) => res.render("pages/not-authorized")),
            express_1.Router().get("/home", (req, res, next) => this.auth.authTokenView(req, res, next), (_, res) => res.render("pages/home")),
            express_1.Router().get("/config-general", (req, res, next) => this.auth.authTokenView(req, res, next), (_, res) => res.render("pages/config-general")),
            express_1.Router().get("/config-auth", (req, res, next) => this.auth.authTokenView(req, res, next), (_, res) => res.render("pages/config-auth")),
            express_1.Router().get("/config-manager", (req, res, next) => this.auth.authTokenView(req, res, next), (_, res) => res.render("pages/config-manager")),
        ]);
        app.use("/api", [
            express_1.Router().get("/health", (_, res) => this.healthController.checkHealth(_, res)),
            express_1.Router().post("/auth", (req, res, next) => this.auth.authTokenAPI(req, res, next), (_, res) => res.status(204).send()),
            express_1.Router().patch("/config", (req, res, next) => this.auth.authTokenAPI(req, res, next), (req, res) => this.horusecController.setHorusecConfig(req, res)),
        ]);
        app.use("**", [
            express_1.Router().get("", (_, res) => res.render("pages/not-found")),
        ]);
        return app;
    }
}
exports.AppRoutes = AppRoutes;
//# sourceMappingURL=horusec_route.js.map