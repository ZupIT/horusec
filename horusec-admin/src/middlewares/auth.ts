import { Request, Response } from "express-serve-static-core";

export class AuthMiddleware {
    private totalRetry = 0;
    private accessToken = "";

    public setAccessToken(accessToken: string): void {
        this.accessToken = accessToken;
    }

    public validateAccessTokenOnHeaders(req: Request, res: Response, next: any): any {
        if (req.headers.authorization === this.accessToken) {
            return next();
        }

        this.totalRetry++;
        if (this.totalRetry >= 3) {
            console.error("Total attempts reached, " +
                "the application will be restarted for security.");
            process.exit(1);
        }

        return res.status(401).send({ message: "User no authorized" });
    }
}
