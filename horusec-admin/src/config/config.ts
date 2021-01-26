import { EnvUtil } from "../utils/env";

export interface IConfig {
  port: number;
  dbUri: string;
}

export class Config {
  public port: number;
  public dbUri: string;

  constructor() {
    const _env: EnvUtil = new EnvUtil();

    this.port = parseInt(_env.getEnvOrDefault("PORT", "3000"), 10);
    this.dbUri = _env.getEnvOrDefault("PORT", "postgresql://root:root@127.0.0.1:5432/horusec_db?sslmode=disable");
  }

  getConfig(): IConfig {
    return {
      port: this.port,
      dbUri: this.dbUri,
    };
  }
}
