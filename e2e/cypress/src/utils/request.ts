import axios, { AxiosInstance } from "axios";

export interface IServices {
    Auth: string;
    Api: string;
    Analytic: string;
    Account: string;
    Manager: string;
    Keycloak: string;
}

export class Requests {
    public baseURL = "http://127.0.0.1";
    public services: IServices = {
        Auth: ":8006",
        Api: ":8000",
        Analytic: ":8005",
        Account: ":8003",
        Manager: ":8043",
        Keycloak: ":8080",
    };
    private _axiosInstance: AxiosInstance;

    constructor() {
        this._axiosInstance = this._axios();
    }

    public setAuthorization(accessToken: string): Requests {
        this._axiosInstance = this._axios(accessToken);
        return this;
    }

    public get(url: string, headers?: any): Promise<any> {
        return this._axiosInstance.get(url, headers);
    }

    public post(url: string, body?: any, headers?: any): Promise<any> {
        return this._axiosInstance.post(url, body, headers);
    }

    public put(url: string, body?: any, headers?: any): Promise<any> {
        return this._axiosInstance.post(url, body, headers);
    }

    public patch(url: string, body?: any, headers?: any): Promise<any> {
        return this._axiosInstance.post(url, body, headers);
    }

    public delete(url: string, headers?: any): Promise<any> {
        return this._axiosInstance.post(url, headers);
    }

    private _axios(accessToken: string = ""): AxiosInstance {
        return axios.create({
            timeout: 15000,
            headers: { "X-Horusec-Authorization": accessToken },
        });
    }
}
