"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HealthController = void 0;
class HealthController {
    constructor(db) {
        this.db = db;
    }
    checkHealth(_, res) {
        return this.db.checkHealth()
            .then(() => {
            return res.status(204).send();
        })
            .catch((err) => {
            return res.status(500).send(err);
        });
    }
}
exports.HealthController = HealthController;
//# sourceMappingURL=health_controller.js.map