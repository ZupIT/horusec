import express, { urlencoded, json } from "express";
import { Sequelize } from "sequelize";
import { Config, IConfig } from "./config/config";
import { Database } from "./database/postgresql_database";
import { Express } from "express-serve-static-core";
import { AppRoutes } from "./routes/horusec_route";

let app: Express = express();
const config: IConfig = new Config().getConfig();
const database: Database = new Database(config);
database.checkHealth().catch((err) => { throw new Error(err); });

const routes: AppRoutes = new AppRoutes(database);

app.use(urlencoded({ extended: true }));
app.use(json());
app.set("view engine", "ejs");
app.use(express.static("public"));

app = routes.start(app);

app.listen(config.Port, () => console.warn(`app is running on http://localhost:${config.Port}`));
