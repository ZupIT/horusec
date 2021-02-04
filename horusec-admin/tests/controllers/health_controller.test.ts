import { Config } from "../../src/config/config";
import { HealthController } from "../../src/controllers/health_controller";
import { Database } from "../../src/database/postgresql_database";

describe("Test checkHealth", () => {
    it("Check when check health return status 204", async () => {
        const db: Database = new Database(new Config().getConfig());
        const res: any = {};
        const req: any = {};
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        await new HealthController(db).checkHealth(req, res);
        expect(res.status).toHaveBeenCalledWith(204);
        expect(res.send).toHaveBeenCalled();
    });
    it("Check when check health return status 500", async () => {
        process.env.HORUSEC_DATABASE_SQL_URI = "postgresql://SuP3#R:P*55w0r2d@postgresql://root:root@123.4.5.6:5432/horusec_db?sslmode=disable1:5432/horusec_db?sslmode=disable";
        const db: Database = new Database(new Config().getConfig());
        const res: any = {};
        const req: any = {};
        res.status = jest.fn().mockReturnValue(res);
        res.send = jest.fn().mockReturnValue(res);
        await new HealthController(db).checkHealth(req, res);
        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.send).toHaveBeenCalled();
    });
});
