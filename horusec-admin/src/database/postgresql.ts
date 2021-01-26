import { Sequelize } from "sequelize";
import { Config, IConfig } from "../config/config";

export class Database {
  config: IConfig;
  db: Sequelize;

  constructor() {
    this.config = new Config().getConfig();
    this.db = new Sequelize(this.config.dbUri);
    this.checkHealth();
  }

  checkHealth(): Promise<void> {
    return this.db.authenticate()
      .catch((err) => {
        console.error("Unable to connect to the database:", err);
        throw new Error(err);
      });
  }

  getConnection(): Sequelize {
    return this.db;
  }
}
