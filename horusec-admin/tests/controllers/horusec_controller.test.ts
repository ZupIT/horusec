import { Config } from "../../src/config/config";
import { HealthController } from "../../src/controllers/health_controller";
import { HorusecController } from "../../src/controllers/horusec_controller";
import { Database } from "../../src/database/postgresql_database";

describe("Test checkHsetHorusecConfigealth", () => {
    it("Check when update content return status 204 with empty body", async () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        const db: Database = new Database(new Config().getConfig());
        const controller: HorusecController = new HorusecController(db);
        await controller["horusecConfigModel"].sync({force: true});

        const res: any = {};
        const req: any = {
            body: {},
        };
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);

        await controller.setHorusecConfig(req, res);

        expect(res.status).toHaveBeenCalledWith(204);
        expect(res.send).toHaveBeenCalled();
    });
    it("Check when update content return status 204 with body one item", async () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        const db: Database = new Database(new Config().getConfig());
        const controller: HorusecController = new HorusecController(db);
        await controller["horusecConfigModel"].sync({force: true});

        const res: any = {};
        const req: any = {
            body: {
                horusec_enable_application_admin: "true",
            },
        };
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);

        await controller.setHorusecConfig(req, res);

        expect(res.status).toHaveBeenCalledWith(204);
        expect(res.send).toHaveBeenCalled();
    });
    it("Check when update content return status 204 with body two itens but one is empty", async () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        const db: Database = new Database(new Config().getConfig());
        const controller: HorusecController = new HorusecController(db);
        await controller["horusecConfigModel"].sync({force: true});

        const res: any = {};
        const req: any = {
            body: {
                horusec_enable_application_admin: "true",
                horusec_auth_type: "",
            },
        };
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);

        await controller.setHorusecConfig(req, res);

        expect(res.status).toHaveBeenCalledWith(204);
        expect(res.send).toHaveBeenCalled();
    });
    it("Check when update content return status 400", async () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "sqlite::memory:";
        const db: Database = new Database(new Config().getConfig());
        const res: any = {};
        const req: any = {};
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        await new HorusecController(db).setHorusecConfig(req, res);
        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.send).toHaveBeenCalled();
    });
    it("Check when update content return status 500 because is not connected on database", async () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "postgresql://SuP3#R:P*55w0r2d@postgresql://root:root@123.4.5.6:5432/horusec_db?sslmode=disable1:5432/horusec_db?sslmode=disable";
        const db: Database = new Database(new Config().getConfig());
        const res: any = {};
        const req: any = {
            body: {
                horusec_enable_application_admin: "true",
            },
        };
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        await new HorusecController(db).setHorusecConfig(req, res);
        expect(res.status).toHaveBeenCalledWith(500);
    });
});
