"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HorusecConfigModel = void 0;
const sequelize_1 = require("sequelize");
class HorusecConfigModel {
    constructor(_db) {
        this._db = _db;
        this.tableName = "horusec_config";
        this.model = this._db.define(this.tableName, {
            horusec_config_id: {
                type: sequelize_1.DataTypes.INTEGER,
                autoIncrement: true,
                primaryKey: true,
            },
            horusec_enable_application_admin: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_auth_type: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_disabled_broker: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_jwt_secret_key: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_keycloak_base_path: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_keycloak_client_id: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_keycloak_client_secret: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_keycloak_realm: {
                type: sequelize_1.DataTypes.STRING,
            },
            react_app_keycloak_client_id: {
                type: sequelize_1.DataTypes.STRING,
            },
            react_app_keycloak_realm: {
                type: sequelize_1.DataTypes.STRING,
            },
            react_app_keycloak_base_path: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_ldap_base: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_ldap_host: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_ldap_port: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_ldap_usessl: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_ldap_skip_tls: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_ldap_insecure_skip_verify: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_ldap_binddn: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_ldap_bindpassword: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_ldap_userfilter: {
                type: sequelize_1.DataTypes.STRING,
            },
            horusec_ldap_admin_group: {
                type: sequelize_1.DataTypes.STRING,
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
exports.HorusecConfigModel = HorusecConfigModel;
//# sourceMappingURL=horusec_config_model.js.map