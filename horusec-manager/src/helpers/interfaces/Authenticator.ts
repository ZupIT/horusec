import { LoginParams } from './LoginParams';

interface AuthFunctions {
  login(params?: LoginParams): Promise<any>;
  logout(): Promise<any>;
}

export interface Authenticator {
  [key: string]: AuthFunctions;
}
