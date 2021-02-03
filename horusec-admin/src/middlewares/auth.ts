import { Request, Response } from "express-serve-static-core";

export class AuthMiddleware {
    private totalRetry = 0;
    private accessToken = "";

    public setAccessToken(accessToken: string): void {
        this.accessToken = accessToken;
        console.warn(`[${(new Date()).toISOString()}] Your access token is: ${this.accessToken}`)
    }

    public authTokenView(req: Request, res: Response, next: any): any {
        if (!req.headers.cookie) {
            return res.status(401).send('USER NOT AUTHORIZED');
        }
        if (req.headers.cookie.split("=")[1] === this.accessToken) {
            return next();
        }

        this.totalRetry++;
        if (this.totalRetry >= 3) {
            console.error("Total attempts reached, " +
                "the application will be restarted for security.");
            process.exit(1);
        }

        return res.status(401).send('USER NOT AUTHORIZED');
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

        return res.status(401).send('USER NOT AUTHORIZED');
    }
}
