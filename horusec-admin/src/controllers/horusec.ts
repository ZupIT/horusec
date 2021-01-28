import { Sequelize } from "sequelize/types";
import { HorusecConfigModel, IModelInterface } from "../models/horusec-config";
import { Request, Response } from "express-serve-static-core";

export class HorusecController {
  model: IModelInterface;

  constructor(
    public db: Sequelize,
  ) {
    this.model = new HorusecConfigModel(db).model;
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

    return this.model.upsert(configToUpdate)
      .then(() => res.status(204).send())
      .catch((err) => {
        console.error(`Some happen when create content ${err}`);
        return res.status(500).send(err);
      });
  }
}
