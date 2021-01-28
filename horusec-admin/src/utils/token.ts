import * as crypto from "crypto";

export class TokenUtil {
  public generateToken(): string {
    return crypto.randomBytes(50).toString("hex");
  }
}
