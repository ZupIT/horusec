"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importStar(require("express"));
const config_1 = require("./config/config");
const postgresql_database_1 = require("./database/postgresql_database");
const horusec_route_1 = require("./routes/horusec_route");
let app = express_1.default();
const config = new config_1.Config().getConfig();
const database = new postgresql_database_1.Database(config);
database.checkHealth().catch((err) => { throw new Error(err); });
const routes = new horusec_route_1.AppRoutes(database);
app.use(express_1.urlencoded({ extended: true }));
app.use(express_1.json());
app.set("view engine", "ejs");
app.use(express_1.default.static("public"));
app = routes.start(app);
app.listen(config.Port, () => console.warn(`app is running on http://localhost:${config.Port}`));
//# sourceMappingURL=app.js.map