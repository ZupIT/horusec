import express from "express";
import { Sequelize } from "sequelize";
import { Config, IConfig } from "./config/config";
import { Database } from "./database/postgresql";
import { HorusecConfigModel, ModelInterface } from "./models/horusec-config";


const config: IConfig = new Config().getConfig();
const db: Sequelize = new Database().getConnection();
const model: ModelInterface = new HorusecConfigModel(db).model;
const app: any = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set("view engine", "ejs");

app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("index", { todos: [] });
});

app.post("/", (req, res) => {
  const body: any = req.body;
  model.create(body)
    .then((result) => {
      console.log("Content has been created!")
    })
    .catch((err) => console.error(`Some happen when create content ${err}`));
});

app.listen(config.port, () => console.warn(`app is running on http://localhost:${config.port}`));
