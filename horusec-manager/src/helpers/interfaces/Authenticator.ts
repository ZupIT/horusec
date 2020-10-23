interface AuthFunctions {
  login: Function;
  logout: Function;
}

export interface Authenticator {
  [key: string]: AuthFunctions;
}
