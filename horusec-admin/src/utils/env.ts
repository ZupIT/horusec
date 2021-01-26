export class EnvUtil {
  getEnvOrDefault(envName: string, defaultValue: string): string {
    if (process.env[envName]) {
      return process.env[envName];
    }

    return defaultValue;
  }
}
