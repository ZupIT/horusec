/**
 * Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React, { useState, Dispatch, SetStateAction } from 'react';
import { Field } from 'helpers/interfaces/Field';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';

interface CreateAccountProps {
  children: JSX.Element;
}

interface CreateAccountContext {
  username: Field;
  email: Field;
  password: Field;
  confirmPass: Field;
  isLoading: boolean;
  successDialogVisible: boolean;
  createAccount(): void;
  verifyUsernameAndEmail(): Promise<void>;
  setEmail: Dispatch<SetStateAction<Field>>;
  setPassword: Dispatch<SetStateAction<Field>>;
  setConfirmPass: Dispatch<SetStateAction<Field>>;
  setUsername: Dispatch<SetStateAction<Field>>;
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
  verifyUsernameAndEmail: () => null,
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

  const verifyUsernameAndEmail = (): Promise<void> => {
    setLoading(true);

    return new Promise((resolve, reject) => {
      accountService
        .verifyUniqueUsernameEmail(email.value, username.value)
        .then(() => {
          setLoading(false);
          resolve();
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
          setLoading(false);
          reject(err);
        });
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
        verifyUsernameAndEmail,
      }}
    >
      {children}
    </CreateAccountContext.Provider>
  );
};

export { CreateAccountContext, CreateAccounteProvider };
