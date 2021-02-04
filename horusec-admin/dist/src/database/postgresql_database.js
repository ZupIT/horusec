"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Database = void 0;
const sequelize_1 = require("sequelize");
class Database {
    constructor(config) {
        this.config = config;
        this.connect();
    }
    connect() {
        this.db = new sequelize_1.Sequelize(this.config.URI, {
            logQueryParameters: this.config.LogMode,
            logging: this.config.LogMode,
        });
    }
    checkHealth() {
        return this.db.authenticate();
    }
    getConnection() {
        if (!this.db) {
            this.connect();
        }
        return this.db;
    }
}
exports.Database = Database;
//# sourceMappingURL=postgresql_database.js.map