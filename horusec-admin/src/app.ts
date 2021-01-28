import express, { urlencoded, json } from "express";
import { Sequelize } from "sequelize";
import { Config, IConfig } from "./config/config";
import { Database } from "./database/postgresql";
import { Express } from "express-serve-static-core";
import { AppRoutes } from "./routes/horusec";
import { TokenUtil } from "./utils/token";

let app: Express = express();
const config: IConfig = new Config().getConfig();
const db: Sequelize = new Database(config).getConnection();
const token: TokenUtil = new TokenUtil();
const accessToken: string = token.generateToken();
const routes: AppRoutes = new AppRoutes(db, accessToken);

app.use(urlencoded({ extended: true }));
app.use(json());
app.set("view engine", "ejs");
app.use(express.static("public"));

app = routes.start(app);

app.listen(config.Port, () => console.warn(`
  app is running on http://localhost:${config.Port}

  Your Access token is: ${accessToken}
`));

export default app;
