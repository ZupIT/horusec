import { DataTypes, Model, ModelCtor, Sequelize } from "sequelize";

export interface IModelInterface extends ModelCtor<Model> { }

export class HorusecConfigModel {
    public tableName = "horusec_config";
    public model: IModelInterface;

    constructor(private _db: Sequelize) {
        this.model = this._db.define(this.tableName, {
            horusec_config_id: {
                type: DataTypes.INTEGER,
                autoIncrement: true,
                primaryKey: true,
            },
            horusec_enable_application_admin: {
                type: DataTypes.STRING,
            },
            horusec_auth_type: {
                type: DataTypes.STRING,
            },
            horusec_disabled_broker: {
                type: DataTypes.STRING,
            },
            horusec_application_admin_data: {
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
            horusec_keycloak_otp: {
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
            react_app_keycloak_client_id: {
                type: DataTypes.STRING,
            },
            react_app_keycloak_realm: {
                type: DataTypes.STRING,
            },
            react_app_keycloak_base_path: {
                type: DataTypes.STRING,
            },
            react_app_horusec_endpoint_api: {
                type: DataTypes.STRING,
            },
            react_app_horusec_endpoint_analytic: {
                type: DataTypes.STRING,
            },
            react_app_horusec_endpoint_account: {
                type: DataTypes.STRING,
            },
            react_app_horusec_endpoint_auth: {
                type: DataTypes.STRING,
            },
            react_app_horusec_manager_path: {
                type: DataTypes.STRING,
            },
        }, {
            freezeTableName: true,
            tableName: this.tableName,
        });

        if (this.model !== this._db.models[this.tableName]) {
            throw new Error("Model (HorusecConfigModel) wasn't configured correctly!");
        }
    }
}
