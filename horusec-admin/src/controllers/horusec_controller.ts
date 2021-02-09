import { HorusecConfigModel, IModelInterface } from "../models/horusec_config_model";
import { Request, Response } from "express-serve-static-core";
import { Database } from "../database/postgresql_database";

export class HorusecController {
    horusecConfigModel: IModelInterface;

    constructor(
        public db: Database,
    ) {
        this.horusecConfigModel = new HorusecConfigModel(this.db.getConnection()).model;
    }

    public getHorusecConfig(_: Request, res: Response): Promise<any> {
        return this.horusecConfigModel.findOne()
            .then((result) => {
                if (result === null) {
                    return res.status(200).send({});
                }
                return res.status(200).send(result);
            })
            .catch((err) => {
                console.error(`Some happen when get content ${err}`);
                return res.status(500).send(err);
            });
    }

    public setHorusecConfig(req: Request, res: Response): any {
        if (!req.body) {
            return res.status(400).send({ message: "Body is required" });
        }

        const configToUpdate: any = {
            horusec_config_id: 1,
        };

        Object.keys(req.body).forEach((key: string) => {
            if (req.body[key]) {
                configToUpdate[key] = req.body[key];
            }
        });

        return this.horusecConfigModel.upsert(configToUpdate)
            .then(() => res.status(204).send())
            .catch((err) => {
                console.error(`Some happen when upsert content ${err}`);
                return res.status(500).send(err);
            });
    }
}
