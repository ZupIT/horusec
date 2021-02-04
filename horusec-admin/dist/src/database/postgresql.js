"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Database = void 0;
const sequelize_1 = require("sequelize");
class Database {
    constructor(config) {
        this.config = config;
        this.db = new sequelize_1.Sequelize(this.config.URI, {
            logQueryParameters: this.config.LogMode,
            logging: this.config.LogMode,
        });
    }
    checkHealth() {
        return this.db.authenticate()
            .catch((err) => {
            console.error("Unable to connect to the database:", err);
            throw new Error(err);
        });
    }
    getConnection() {
        return this.db;
    }
}
exports.Database = Database;
//# sourceMappingURL=postgresql.js.map