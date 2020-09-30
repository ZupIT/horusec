import React, { useState } from 'react';
import { Field } from 'helpers/interfaces/Field';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';

interface CreateAccountProps {
  children: JSX.Element;
}

interface CreateAccountContext {
  username: Field;
  setUsername: Function;
  email: Field;
  setEmail: Function;
  password: Field;
  setPassword: Function;
  confirmPass: Field;
  setConfirmPass: Function;
  isLoading: boolean;
  createAccount: Function;
  successDialogVisible: boolean;
}

const fieldInitialValue: Field = {
  isValid: false,
  value: '',
};

const CreateAccountContext = React.createContext<CreateAccountContext>({
  username: fieldInitialValue,
  setUsername: () => '',
  email: fieldInitialValue,
  setEmail: () => '',
  password: fieldInitialValue,
  setPassword: () => '',
  confirmPass: fieldInitialValue,
  setConfirmPass: () => '',
  isLoading: false,
  createAccount: () => '',
  successDialogVisible: false,
});

const CreateAccounteProvider = ({ children }: CreateAccountProps) => {
  const [email, setEmail] = useState<Field>(fieldInitialValue);
  const [username, setUsername] = useState<Field>(fieldInitialValue);
  const [password, setPassword] = useState<Field>(fieldInitialValue);
  const [confirmPass, setConfirmPass] = useState<Field>(fieldInitialValue);
  const [successDialogVisible, setSuccessDialogVisible] = useState(false);
  const [isLoading, setLoading] = useState(false);

  const { dispatchMessage } = useResponseMessage();

  const createAccount = () => {
    setLoading(true);
    accountService
      .createAccount(username.value, password.value, email.value)
      .then(() => {
        setSuccessDialogVisible(true);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
        setLoading(false);
      });
  };

  return (
    <CreateAccountContext.Provider
      value={{
        email,
        username,
        password,
        confirmPass,
        setEmail,
        setUsername,
        setPassword,
        setConfirmPass,
        isLoading,
        createAccount,
        successDialogVisible,
      }}
    >
      {children}
    </CreateAccountContext.Provider>
  );
};

export { CreateAccountContext, CreateAccounteProvider };
