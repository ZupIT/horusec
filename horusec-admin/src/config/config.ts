import { EnvUtil } from "../utils/env";

export interface IConfig {
  Port: number;
  URI: string;
  LogMode: boolean;
}

export class Config {
  public Port: number;
  public URI: string;
  public LogMode: boolean;

  constructor() {
    const _env: EnvUtil = new EnvUtil();

    this.Port = parseInt(_env.getEnvOrDefault("HORUSEC_PORT", "3000"), 10);
    this.URI = _env.getEnvOrDefault("HORUSEC_DATABASE_SQL_URI", "postgresql://root:root@127.0.0.1:5432/horusec_db?sslmode=disable");
    const logMode: string = _env.getEnvOrDefault("HORUSEC_DATABASE_SQL_LOG_MODE", "false");
    this.LogMode = logMode === "true" || logMode === "1";
  }

  getConfig(): IConfig {
    return {
      Port: this.Port,
      URI: this.URI,
      LogMode: this.LogMode,
    };
  }
}
