import express from "express";
import { Sequelize } from "sequelize";
import { Config, IConfig } from "./config/config";
import { Database } from "./database/postgresql";
import { Express } from "express-serve-static-core";
import { AppRoutes } from "./routes/app";
import { TokenUtil } from "./utils/token";

const config: IConfig = new Config().getConfig();
const db: Sequelize = new Database().getConnection();
const app: Express = express();
const token: TokenUtil = new TokenUtil();
const accessToken: string = token.generateToken();
const routes: AppRoutes = new AppRoutes(db, app, accessToken);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set("view engine", "ejs");
app.use(express.static("public"));

routes.start();

app.listen(config.Port, () => console.warn(`
  app is running on http://localhost:${config.Port}

  Your Access token is: ${accessToken}
`));
