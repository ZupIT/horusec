import { Database } from "../database/postgresql_database";
import { Request, Response } from "express-serve-static-core";

export class HealthController {
    constructor(public db: Database) {}

    public checkHealth(_: Request, res: Response): any {
        return this.db.checkHealth()
            .then(() => {
                return res.status(204).send();
            })
            .catch((err) => {
                return res.status(500).send(err);
            });
    }
}
