import { Request, Response } from "express-serve-static-core";

export class AuthMiddleware {
    private totalRetry = 0;
    private accessToken = "";

    public setAccessToken(accessToken: string): void {
        this.accessToken = accessToken;
        console.warn(`[${(new Date()).toISOString()}] Your access token is: ${this.accessToken}`);
    }

    public authTokenView(req: Request, res: Response, next: any): any {
        const currentToken: string = this.extractCookieValue("horusec::access_token", req.headers.cookie);
        if (currentToken === this.accessToken) {
            return next();
        }

        this.totalRetry++;
        if (this.totalRetry >= 3) {
            console.error("Total attempts reached, " +
                "the application will be restarted for security.");
            process.exit(1);
        }

        return res.status(401).send("USER NOT AUTHORIZED");
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

        return res.status(401).send("USER NOT AUTHORIZED");
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
