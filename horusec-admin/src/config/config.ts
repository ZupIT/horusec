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

  constructor(
    private _env: EnvUtil = new EnvUtil(),
  ) {
    this.setPort();
    this.setURI();
    this.setLogMode();
  }

  public getConfig(): IConfig {
    return {
      Port: this.Port,
      URI: this.URI,
      LogMode: this.LogMode,
    };
  }

  private setPort(): void {
    this.Port = parseInt(this._env.getEnvOrDefault("HORUSEC_PORT", "3000"), 10);
  }

  private setURI(): void {
    this.URI = this._env.getEnvOrDefault("HORUSEC_DATABASE_SQL_URI", "postgresql://root:root@127.0.0.1:5432/horusec_db?sslmode=disable");
  }

  private setLogMode(): void {
    const logMode: string = this._env.getEnvOrDefault("HORUSEC_DATABASE_SQL_LOG_MODE", "false");
    this.LogMode = logMode === "true" || logMode === "1";
  }
}
