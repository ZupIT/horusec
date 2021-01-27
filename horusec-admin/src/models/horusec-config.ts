import { DataTypes, Model, ModelCtor, Sequelize } from "sequelize";

export interface IModelInterface extends ModelCtor<Model> {}

export class HorusecConfigModel {
  private tableName = "horusec_config";
  public model: IModelInterface;

  constructor(private _db: Sequelize) {
    this.model = this._db.define(this.tableName, {
      horusec_config_id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
      },
      horusec_auth_type: {
        type: DataTypes.STRING,
      },
      horusec_disabled_broker: {
        type: DataTypes.STRING,
      },
      horusec_jwt_secret_key: {
        type: DataTypes.STRING,
      },
      horusec_keycloak_base_path: {
        type: DataTypes.STRING,
      },
      horusec_keycloak_client_id: {
        type: DataTypes.STRING,
      },
      horusec_keycloak_client_secret: {
        type: DataTypes.STRING,
      },
      horusec_keycloak_realm: {
        type: DataTypes.STRING,
      },
      react_app_keycloak_client_id: {
        type: DataTypes.STRING,
      },
      react_app_keycloak_realm: {
        type: DataTypes.STRING,
      },
      react_app_keycloak_base_path: {
        type: DataTypes.STRING,
      },
      horusec_ldap_base: {
        type: DataTypes.STRING,
      },
      horusec_ldap_host: {
        type: DataTypes.STRING,
      },
      horusec_ldap_port: {
        type: DataTypes.STRING,
      },
      horusec_ldap_usessl: {
        type: DataTypes.STRING,
      },
      horusec_ldap_skip_tls: {
        type: DataTypes.STRING,
      },
      horusec_ldap_insecure_skip_verify: {
        type: DataTypes.STRING,
      },
      horusec_ldap_binddn: {
        type: DataTypes.STRING,
      },
      horusec_ldap_bindpassword: {
        type: DataTypes.STRING,
      },
      horusec_ldap_userfilter: {
        type: DataTypes.STRING,
      },
      horusec_ldap_admin_group: {
        type: DataTypes.STRING,
      },
    }, {
      freezeTableName: true,
      tableName: this.tableName,
    });

    if (this.model !== this._db.models.horusec_config) {
      throw new Error("Model (HorusecConfig) wasn't configured correctly!");
    }
  }
}
