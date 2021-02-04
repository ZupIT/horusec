"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HorusecController = void 0;
const horusec_config_model_1 = require("../models/horusec_config_model");
class HorusecController {
    constructor(db) {
        this.db = db;
        this.horusecConfigModel = new horusec_config_model_1.HorusecConfigModel(this.db.getConnection()).model;
    }
    setHorusecConfig(req, res) {
        if (!req.body) {
            return res.status(400).send({ message: "Body is required" });
        }
        console.log(req.body);
        const configToUpdate = {
            horusec_config_id: 1,
        };
        Object.keys(req.body).forEach((key) => {
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
exports.HorusecController = HorusecController;
//# sourceMappingURL=horusec_controller.js.map