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
const sequelize_1 = require("sequelize");
const config_1 = require("../../src/config/config");
const postgresql_1 = require("../../src/database/postgresql");
describe("Test Database", () => {
    it("Check if connection broken by invalid connection in postgresql", () => __awaiter(void 0, void 0, void 0, function* () {
        process.env.HORUSEC_DATABASE_SQL_URI = "postgresql://SuP3#R:P*55w0r2d@postgresql://root:root@123.4.5.6:5432/horusec_db?sslmode=disable1:5432/horusec_db?sslmode=disable";
        const database = new postgresql_1.Database(new config_1.Config().getConfig());
        expect(yield database.checkHealth).toThrow(Error);
    }));
    it("Check if connection is relesed with success in postgresql", () => {
        expect(new postgresql_1.Database(new config_1.Config().getConfig()).getConnection()).toBeInstanceOf(sequelize_1.Sequelize);
    });
    it("Check if connection is relesed with success in sqlite in memory", () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        expect(new postgresql_1.Database(new config_1.Config().getConfig()).getConnection()).toBeInstanceOf(sequelize_1.Sequelize);
    });
});
//# sourceMappingURL=postgresql.test.js.map