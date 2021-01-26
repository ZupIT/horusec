import express from "express";
import { Sequelize } from "sequelize";
import { Config, IConfig } from "./config/config";
import { Database } from "./database/postgresql";
import { HorusecConfigModel, IModelInterface } from "./models/horusec-config";


const config: IConfig = new Config().getConfig();
const db: Sequelize = new Database().getConnection();
const model: IModelInterface = new HorusecConfigModel(db).model;
const app: any = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set("view engine", "ejs");

app.use(express.static("public"));

app.get("/", (_, res) => {
  return res.render("index");
});

app.post("/", (req, res) => {
  if (!req.body) {
    return res.status(400).send({ message: "Body is required" });
  }

  const configToUpdate: object = parseBodyToConfigToUpdate(req.body);
  return model.upsert(configToUpdate)
    .then(() => {
      return res.status(204).send();
    })
    .catch((err) => {
      console.error(`Some happen when create content ${err}`);
      return res.status(500).send(err);
    });
});

app.listen(config.Port, () => console.warn(`app is running on http://localhost:${config.Port}`));

function parseBodyToConfigToUpdate(body: object): object {
  const response: object = {
    horusec_config_id: 1,
  };

  if (body["horusec_auth_type"]) { response["horusec_auth_type"] = body["horusec_auth_type"]; }
  if (body["horusec_disabled_broker"]) { response["horusec_disabled_broker"] = body["horusec_disabled_broker"]; }
  if (body["horusec_jwt_secret_key"]) { response["horusec_jwt_secret_key"] = body["horusec_jwt_secret_key"]; }
  if (body["horusec_keycloak_base_path"]) { response["horusec_keycloak_base_path"] = body["horusec_keycloak_base_path"]; }
  if (body["horusec_keycloak_client_id"]) { response["horusec_keycloak_client_id"] = body["horusec_keycloak_client_id"]; }
  if (body["horusec_keycloak_client_secret"]) { response["horusec_keycloak_client_secret"] = body["horusec_keycloak_client_secret"]; }
  if (body["horusec_keycloak_realm"]) { response["horusec_keycloak_realm"] = body["horusec_keycloak_realm"]; }
  if (body["react_app_keycloak_client_id"]) { response["react_app_keycloak_client_id"] = body["react_app_keycloak_client_id"]; }
  if (body["react_app_keycloak_realm"]) { response["react_app_keycloak_realm"] = body["react_app_keycloak_realm"]; }
  if (body["react_app_keycloak_base_path"]) { response["react_app_keycloak_base_path"] = body["react_app_keycloak_base_path"]; }
  if (body["horusec_ldap_base"]) { response["horusec_ldap_base"] = body["horusec_ldap_base"]; }
  if (body["horusec_ldap_host"]) { response["horusec_ldap_host"] = body["horusec_ldap_host"]; }
  if (body["horusec_ldap_port"]) { response["horusec_ldap_port"] = body["horusec_ldap_port"]; }
  if (body["horusec_ldap_usessl"]) { response["horusec_ldap_usessl"] = body["horusec_ldap_usessl"]; }
  if (body["horusec_ldap_skip_tls"]) { response["horusec_ldap_skip_tls"] = body["horusec_ldap_skip_tls"]; }
  if (body["horusec_ldap_insecure_skip_verify"]) { response["horusec_ldap_insecure_skip_verify"] = body["horusec_ldap_insecure_skip_verify"]; }
  if (body["horusec_ldap_binddn"]) { response["horusec_ldap_binddn"] = body["horusec_ldap_binddn"]; }
  if (body["horusec_ldap_bindpassword"]) { response["horusec_ldap_bindpassword"] = body["horusec_ldap_bindpassword"]; }
  if (body["horusec_ldap_userfilter"]) { response["horusec_ldap_userfilter"] = body["horusec_ldap_userfilter"]; }
  if (body["horusec_ldap_admin_group"]) { response["horusec_ldap_admin_group"] = body["horusec_ldap_admin_group"]; }

  return response;
}
