"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppRoutes = void 0;
const horusec_1 = require("../controllers/horusec");
const auth_1 = require("../middlewares/auth");
const express_1 = require("express");
class AppRoutes {
    constructor(db, horusecController = new horusec_1.HorusecController(db), auth = new auth_1.AuthMiddleware()) {
        this.db = db;
        this.horusecController = horusecController;
        this.auth = auth;
    }
    start(app) {
        app.use("/", [
            express_1.Router().get("", (_, res) => res.redirect("/view")),
        ]);
        app.use("/view", [
            express_1.Router().get("", (_, res) => res.render("pages/index")),
            express_1.Router().get("/home", (req, res, next) => this.auth.authTokenView(req, res, next), (_, res) => res.render("pages/home")),
            express_1.Router().get("/config-general", (req, res, next) => this.auth.authTokenView(req, res, next), (_, res) => res.render("pages/config-general")),
            express_1.Router().get("/config-auth", (req, res, next) => this.auth.authTokenView(req, res, next), (_, res) => res.render("pages/config-auth")),
            express_1.Router().get("/config-manager", (req, res, next) => this.auth.authTokenView(req, res, next), (_, res) => res.render("pages/config-manager")),
        ]);
        app.use("/api", [
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
//# sourceMappingURL=horusec.js.map