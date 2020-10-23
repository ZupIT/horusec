const login = () => new Promise(() => console.log('ldap login'));

const logout = () => new Promise(() => console.log('ldap logout'));

export default {
  login,
  logout,
};
