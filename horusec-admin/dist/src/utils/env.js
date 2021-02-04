"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EnvUtil = void 0;
class EnvUtil {
    getEnvOrDefault(envName, defaultValue) {
        if (process.env[envName]) {
            return process.env[envName];
        }
        return defaultValue;
    }
}
exports.EnvUtil = EnvUtil;
//# sourceMappingURL=env.js.map