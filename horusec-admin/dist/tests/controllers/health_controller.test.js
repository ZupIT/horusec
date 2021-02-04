"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = require("../../src/config/config");
const health_controller_1 = require("../../src/controllers/health_controller");
const postgresql_database_1 = require("../../src/database/postgresql_database");
describe("Test checkHealth", () => {
    it("Check when check health return status 204", () => __awaiter(void 0, void 0, void 0, function* () {
        const db = new postgresql_database_1.Database(new config_1.Config().getConfig());
        const res = {};
        const req = {};
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        yield new health_controller_1.HealthController(db).checkHealth(req, res);
        expect(res.status).toHaveBeenCalledWith(204);
        expect(res.send).toHaveBeenCalled();
    }));
    it("Check when check health return status 500", () => __awaiter(void 0, void 0, void 0, function* () {
        process.env.HORUSEC_DATABASE_SQL_URI = "postgresql://SuP3#R:P*55w0r2d@postgresql://root:root@123.4.5.6:5432/horusec_db?sslmode=disable1:5432/horusec_db?sslmode=disable";
        const db = new postgresql_database_1.Database(new config_1.Config().getConfig());
        const res = {};
        const req = {};
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        yield new health_controller_1.HealthController(db).checkHealth(req, res);
        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.send).toHaveBeenCalled();
    }));
});
//# sourceMappingURL=health_controller.test.js.map