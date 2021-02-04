import { Sequelize } from "sequelize";
import { IConfig } from "../config/config";

export class Database {
    private db: Sequelize;

    constructor(
        public config: IConfig,
    ) {
        this.connect();
    }

    private connect(): void {
        this.db = new Sequelize(this.config.URI, {
            logQueryParameters: this.config.LogMode,
            logging: this.config.LogMode,
        });
    }

    public checkHealth(): Promise<void> {
        return this.db.authenticate();
    }

    public getConnection(): Sequelize {
        if (!this.db) {
            this.connect();
        }
        return this.db;
    }
}
