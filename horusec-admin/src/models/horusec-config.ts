import { DataTypes, Model, ModelCtor, Sequelize } from "sequelize";

export interface ModelInterface extends ModelCtor<Model> {};

export class HorusecConfigModel {
  public model: ModelInterface;

  constructor(private _db: Sequelize) {
    this.model = this._db.define('horusec_config', {
      id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
      },
      keycloak_host: {
        type: DataTypes.STRING,
        allowNull: false
      },
    });

    if (this.model !== this._db.models.horusec_config) {
      throw new Error("Model (HorusecConfig) wasn't configured correctly!")
    }
  }
}
