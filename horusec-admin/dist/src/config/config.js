"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Config = void 0;
const env_util_1 = require("../utils/env_util");
class Config {
    constructor(_env = new env_util_1.EnvUtil()) {
        this._env = _env;
        this.setPort();
        this.setURI();
        this.setLogMode();
    }
    getConfig() {
        return {
            Port: this.Port,
            URI: this.URI,
            LogMode: this.LogMode,
        };
    }
    setPort() {
        this.Port = parseInt(this._env.getEnvOrDefault("HORUSEC_PORT", "3000"), 10);
    }
    setURI() {
        this.URI = this._env.getEnvOrDefault("HORUSEC_DATABASE_SQL_URI", "postgresql://root:root@127.0.0.1:5432/horusec_db?sslmode=disable");
    }
    setLogMode() {
        const logMode = this._env.getEnvOrDefault("HORUSEC_DATABASE_SQL_LOG_MODE", "false");
        this.LogMode = logMode === "true" || logMode === "1";
    }
}
exports.Config = Config;
//# sourceMappingURL=config.js.map