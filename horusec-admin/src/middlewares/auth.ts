import { Request, Response } from "express-serve-static-core";
import { TokenUtil } from "../utils/token";

export class AuthMiddleware {
    private totalRetry = 0;
    private accessToken = "";

    constructor(
        public forceSetAccessToken: string = "",
    ) {
        this.setAccessToken(this.forceSetAccessToken);

        setInterval(() => this.setAccessToken(), ((5 * 60) * 1000));
    }

    public authTokenView(req: Request, res: Response, next: any): any {
        if (!req.headers.cookie) {
            return res.render("pages/not-authorized");
        }

        const currentToken: string = this.extractCookieValue("horusec::access_token", req.headers.cookie);

        if (currentToken === this.accessToken) {
            return next();
        }

        this.totalRetry++;
        if (this.totalRetry >= 3) {
            console.error("Total attempts reached, the application will be restarted for security.");
            this.accessToken = new TokenUtil().generateToken();
            this.totalRetry = 0;
        }

        return res.render("pages/not-authorized");
    }

    public authTokenAPI(req: Request, res: Response, next: any): any {
        if (req.headers.authorization === this.accessToken) {
            return next();
        }

        this.totalRetry++;
        if (this.totalRetry >= 3) {
            console.error("Total attempts reached, " +
                "the application will be restarted for security.");
            process.exit(1);
        }

        return res.render("pages/not-authorized");
    }

    private setAccessToken(forceSetAccessToken: string = ""): void {
        if (forceSetAccessToken) {
            this.accessToken = forceSetAccessToken;
        } else {
            this.accessToken = new TokenUtil().generateToken();
            console.warn(`[${(new Date()).toISOString()}] Your access token is: ${this.accessToken}`);
        }
    }

    private extractCookieValue(cname: string, cookies: string): string {
        const name: string = cname + "=";
        const decodedCookie: string = decodeURIComponent(cookies);
        const ca: string[] = decodedCookie.split(";");
        // tslint:disable-next-line: prefer-for-of
        for (let i: any = 0; i < ca.length; i++) {
          let c: string = ca[i];
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
