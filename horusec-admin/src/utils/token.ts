import * as crypto from "crypto";

export class TokenUtil {
  public generateToken(): string {
    return crypto.createHash("sha512").digest("hex");
  }
}
