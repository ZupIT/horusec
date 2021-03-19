import { AxiosResponse } from "axios";
import { Requests } from "../../utils/request";

export interface IUserRepresentation {
    username: string;
    email: string;
    emailVerified: boolean;
    enabled: boolean;
}

export interface IUserCredentialsRepresentation {
    temporary: boolean;
    type: "password";
    value: string;
}

export class KeycloakRequests {
    baseURL: string;
    constructor(private _requests: Requests) {
        this.baseURL = `${this._requests.baseURL}${this._requests.services.Keycloak}`;
    }

    public async SetupKeycloakAndReturnClientSecret(
        user: IUserRepresentation, credentials: IUserCredentialsRepresentation): Promise<string> {
        const responseLogin: AxiosResponse = await this.loginInKeycloak("keycloak", "keycloak");
        const bearerToken: string = "Bearer " + responseLogin?.data?.access_token;
        this._requests.setHeadersAllRequests({
            "content-type": "application/json",
            "cache-control": "no-cache",
            "Authorization": bearerToken,
        });
        await this.updateRolesToAcceptOAuth();
        await this.deleteAllUsersInKeyCloak();
        await this.createUserInKeyCloak(user, credentials);
        return this.getClientSecretInAccountClient();
    }

    private async loginInKeycloak(defaultUsername: string, defaultPassword: string): Promise<AxiosResponse|null> {
        const payload: any = `client_id=admin-cli&username=${defaultUsername}&password=${defaultPassword}&grant_type=password`;
        const url: any = `${this.baseURL}/auth/realms/master/protocol/openid-connect/token`;
        const headers: any = { "content-type": "application/x-www-form-urlencoded", "cache-control": "no-cache" };
        const response: AxiosResponse = await this._requests.post(url, payload, headers);
        expect(response.status).equal(200);
        return response;
    }

    private async updateRolesToAcceptOAuth(): Promise<void> {
        const responseAllClients: AxiosResponse = await this.listAllClientsInKeycloak();
        const allClients: any = responseAllClients?.data;
        let client: any;
        allClients.forEach(actualClient => {
            if (actualClient["clientId"] === "account") {
                client = this.decoratorClient(actualClient);
            }
        });
        const clientID: string = client["id"];
        const responseUpdateClient: AxiosResponse = await this._requests.put(
            `${this.baseURL}/auth/admin/realms/master/clients/${clientID}`, client);
        expect(responseUpdateClient.status).equal(204);

        // Update Role to admin accept all content
        const role: any = await this.getRoleAdminInKeycloak();
        const roleID: string = role["id"];
        const responseAllRoles: AxiosResponse = await this.getAllRolesFromClientID(clientID);
        const responseUpdateRoleAdmin: AxiosResponse = await this._requests.post(
            `${this.baseURL}/auth/admin/realms/master/roles-by-id/${roleID}/composites`, responseAllRoles.data);
        expect(responseUpdateRoleAdmin.status).equal(204);
    }
    decoratorClient(actualClient: any): any {
        actualClient["authorizationServicesEnabled"] = true;
        actualClient["directAccessGrantsEnabled"] = true;
        actualClient["enabled"] = true;
        actualClient["implicitFlowEnabled"] = true;
        actualClient["serviceAccountsEnabled"] = true;
        actualClient["standardFlowEnabled"] = true;
        actualClient["surrogateAuthRequired"] = true;
        actualClient["attributes"]["access.token.lifespan"] = 5940;
        actualClient["attributes"]["client.offline.session.idle.timeout"] = 5940;
        actualClient["attributes"]["client.offline.session.max.lifespan"] = 5940;
        actualClient["attributes"]["client.session.idle.timeout"] = 5940;
        actualClient["attributes"]["client.session.max.lifespan"] = 5940;
        return actualClient;
    }

    private async listAllClientsInKeycloak(): Promise<AxiosResponse> {
        const response: AxiosResponse = await this._requests.get(`${this.baseURL}/auth/admin/realms/master/clients`);
        expect(response.status).equal(200);
        return response;
    }

    private async getRoleAdminInKeycloak(): Promise<any> {
        const responseGetAllRoles: AxiosResponse = await this._requests.get(`${this.baseURL}/auth/admin/realms/master/roles`);
        expect(responseGetAllRoles.status).equal(200);
        let role: any;
        responseGetAllRoles.data.forEach((currentRole: any) => {
            if (currentRole["name"] === "admin") {
                role = currentRole;
            }
        });
        return role;
    }

    private async getAllRolesFromClientID(clientID: string): Promise<AxiosResponse> {
        const response: AxiosResponse = await this._requests.get(`${this.baseURL}/auth/admin/realms/master/clients/${clientID}/roles`);
        expect(response.status).equal(200);
        return response;
    }

    private async deleteAllUsersInKeyCloak(): Promise<void> {
        const responseAllUsers: AxiosResponse = await this.listAllUsersInKeycloak();
        let idsToRemove: string[] = [];
        responseAllUsers.data.forEach(user => {
            if (user["username"] !== "keycloak") {
                idsToRemove = idsToRemove.concat(user["id"]);
            }
        });
        // tslint:disable-next-line: prefer-for-of
        for (let i: any = 0; i < idsToRemove.length; i++) {
            const responseDeleteUser: AxiosResponse = await this._requests.delete(`${this.baseURL}/auth/admin/realms/master/users/${idsToRemove[i]}`);
            expect(responseDeleteUser.status).equal(204);
        }
    }

    private async listAllUsersInKeycloak(): Promise<AxiosResponse> {
        const response: AxiosResponse = await this._requests.get(`${this.baseURL}/auth/admin/realms/master/users`);
        expect(response.status).equal(200);
        return response;
    }


    private async createUserInKeyCloak(
        user: IUserRepresentation, credentials: IUserCredentialsRepresentation): Promise<void> {
        const responseCreateUser: AxiosResponse = await this._requests.post(`${this.baseURL}/auth/admin/realms/master/users`, user);
        expect(responseCreateUser.status).equal(201);
        const responseAllUsers: AxiosResponse = await this.listAllUsersInKeycloak();
        let idToSetCredential: string;
        responseAllUsers.data.forEach(currentUser => {
            if (currentUser["username"] === user.username) {
                idToSetCredential = currentUser["id"];
            }
        });
        const responseResetPasswordUser: AxiosResponse = await this._requests.put(
            `${this.baseURL}/auth/admin/realms/master/users/${idToSetCredential}/reset-password`, credentials);
        expect(responseResetPasswordUser.status).equal(204);

        const role: any = await this.getRoleAdminInKeycloak();
        const allRoles: any[] = [role];
        const responseUpdateRealm: AxiosResponse = await this._requests.post(
            `${this.baseURL}/auth/admin/realms/master/users/${idToSetCredential}/role-mappings/realm`, allRoles);
        expect(responseUpdateRealm.status).equal(204);
    }

    private async getClientSecretInAccountClient(): Promise<string> {
        const responseAllClients: AxiosResponse = await this.listAllClientsInKeycloak();
        let clientID: string;
        responseAllClients.data.forEach(client => {
            if (client["clientId"] === "admin-cli") {
                clientID = client["id"];
            }
        });
        const responseClientSecret: AxiosResponse = await this._requests.get(
            `${this.baseURL}/auth/admin/realms/master/clients/${clientID}/client-secret`);
        expect(responseClientSecret.status).equal(200);
        return responseClientSecret.data["value"];
    }

}
