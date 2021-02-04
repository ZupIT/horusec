"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthMiddleware = void 0;
const token_util_1 = require("../utils/token_util");
class AuthMiddleware {
    constructor() {
        this.totalRetry = 0;
        this.accessToken = "";
        this.setAccessToken();
        setInterval(() => this.setAccessToken(), ((5 * 60) * 1000));
    }
    authTokenView(req, res, next) {
        if (!req.headers.cookie) {
            return res.render("pages/not-authorized");
        }
        const currentToken = this.extractCookieValue("horusec::access_token", req.headers.cookie);
        if (currentToken === this.accessToken) {
            return next();
        }
        this.totalRetry++;
        if (this.totalRetry >= 3) {
            console.error("Total attempts reached, the application will be restarted for security.");
            this.accessToken = new token_util_1.TokenUtil().generateToken();
            this.totalRetry = 0;
        }
        return res.render("pages/not-authorized");
    }
    authTokenAPI(req, res, next) {
        if (req.headers.authorization === this.accessToken) {
            return next();
        }
        this.totalRetry++;
        if (this.totalRetry >= 3) {
            console.error("Total attempts reached, the application will be restarted for security.");
            this.accessToken = new token_util_1.TokenUtil().generateToken();
            this.totalRetry = 0;
        }
        return res.render("pages/not-authorized");
    }
    setAccessToken(forceSetAccessToken = "") {
        if (forceSetAccessToken) {
            this.accessToken = forceSetAccessToken;
        }
        else {
            this.accessToken = new token_util_1.TokenUtil().generateToken();
            console.warn(`[${(new Date()).toISOString()}] Your access token is: ${this.accessToken}`);
        }
    }
    extractCookieValue(cname, cookies) {
        const name = cname + "=";
        const decodedCookie = decodeURIComponent(cookies);
        const ca = decodedCookie.split(";");
        // tslint:disable-next-line: prefer-for-of
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === " ") {
                c = c.substring(1);
            }
            if (c.indexOf(name) === 0) {
                return c.substring(name.length, c.length);
            }
        }
        return "";
    }
}
exports.AuthMiddleware = AuthMiddleware;
//# sourceMappingURL=auth_middleware.js.map