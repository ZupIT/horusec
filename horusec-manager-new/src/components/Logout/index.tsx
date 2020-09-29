import React from 'react';
import Styled from './styled';
import useAuth from 'helpers/hooks/useAuth';
import { useHistory } from 'react-router-dom';

const Logout: React.FC = () => {
  const history = useHistory();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout().then(() => history.replace('/login'));
  };

  return (
    <Styled.LogoutIcon
      onClick={() => handleLogout()}
      size="16px"
      name="logout"
    />
  );
};

export default Logout;
