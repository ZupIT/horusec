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
const horusec_controller_1 = require("../../src/controllers/horusec_controller");
const postgresql_database_1 = require("../../src/database/postgresql_database");
describe("Test checkHsetHorusecConfigealth", () => {
    it("Check when update content return status 204 with empty body", () => __awaiter(void 0, void 0, void 0, function* () {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        const db = new postgresql_database_1.Database(new config_1.Config().getConfig());
        const controller = new horusec_controller_1.HorusecController(db);
        yield controller["horusecConfigModel"].sync({ force: true });
        const res = {};
        const req = {
            body: {},
        };
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        yield controller.setHorusecConfig(req, res);
        expect(res.status).toHaveBeenCalledWith(204);
        expect(res.send).toHaveBeenCalled();
    }));
    it("Check when update content return status 204 with body one item", () => __awaiter(void 0, void 0, void 0, function* () {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        const db = new postgresql_database_1.Database(new config_1.Config().getConfig());
        const controller = new horusec_controller_1.HorusecController(db);
        yield controller["horusecConfigModel"].sync({ force: true });
        const res = {};
        const req = {
            body: {
                horusec_enable_application_admin: "true",
            },
        };
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        yield controller.setHorusecConfig(req, res);
        expect(res.status).toHaveBeenCalledWith(204);
        expect(res.send).toHaveBeenCalled();
    }));
    it("Check when update content return status 204 with body two itens but one is empty", () => __awaiter(void 0, void 0, void 0, function* () {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        const db = new postgresql_database_1.Database(new config_1.Config().getConfig());
        const controller = new horusec_controller_1.HorusecController(db);
        yield controller["horusecConfigModel"].sync({ force: true });
        const res = {};
        const req = {
            body: {
                horusec_enable_application_admin: "true",
                horusec_auth_type: "",
            },
        };
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        yield controller.setHorusecConfig(req, res);
        expect(res.status).toHaveBeenCalledWith(204);
        expect(res.send).toHaveBeenCalled();
    }));
    it("Check when update content return status 400", () => __awaiter(void 0, void 0, void 0, function* () {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        const db = new postgresql_database_1.Database(new config_1.Config().getConfig());
        const res = {};
        const req = {};
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        yield new horusec_controller_1.HorusecController(db).setHorusecConfig(req, res);
        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.send).toHaveBeenCalled();
    }));
    it("Check when update content return status 500 because is not connected on database", () => __awaiter(void 0, void 0, void 0, function* () {
        process.env.HORUSEC_DATABASE_SQL_URI = "postgresql://SuP3#R:P*55w0r2d@postgresql://root:root@123.4.5.6:5432/horusec_db?sslmode=disable1:5432/horusec_db?sslmode=disable";
        const db = new postgresql_database_1.Database(new config_1.Config().getConfig());
        const res = {};
        const req = {
            body: {
                horusec_enable_application_admin: "true",
            },
        };
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        yield new horusec_controller_1.HorusecController(db).setHorusecConfig(req, res);
        expect(res.status).toHaveBeenCalledWith(500);
    }));
});
//# sourceMappingURL=horusec_controller.test.js.map