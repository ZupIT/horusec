interface AuthFunctions {
  login(email?: string, password?: string): Promise<any>;
  logout(): Promise<any>;
}

export interface Authenticator {
  [key: string]: AuthFunctions;
}
