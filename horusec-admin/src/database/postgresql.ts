import { Sequelize } from "sequelize";
import { Config, IConfig } from "../config/config";

export class Database {
  private config: IConfig;

  private db: Sequelize;

  constructor() {
    this.config = new Config().getConfig();
    this.db = new Sequelize(this.config.URI, {
      logQueryParameters: this.config.LogMode,
      logging: this.config.LogMode,
    });
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
