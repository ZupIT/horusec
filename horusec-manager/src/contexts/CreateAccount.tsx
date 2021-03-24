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
  username: string;
  email: string;
  isLoading: boolean;
  successDialogVisible: boolean;
  createAccount(password: string): void;
  verifyUsernameAndEmail(email: string, username: string): Promise<void>;
}

const CreateAccountContext = React.createContext<CreateAccountContext>(
  {} as CreateAccountContext
);

const CreateAccounteProvider = ({ children }: CreateAccountProps) => {
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [successDialogVisible, setSuccessDialogVisible] = useState(false);
  const [isLoading, setLoading] = useState(false);

  const { dispatchMessage } = useResponseMessage();

  const createAccount = (password: string) => {
    setLoading(true);
    accountService
      .createAccount(username, password, email)
      .then(() => {
        setSuccessDialogVisible(true);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
        setLoading(false);
      });
  };

  const verifyUsernameAndEmail = (
    email: string,
    username: string
  ): Promise<void> => {
    setLoading(true);
    return new Promise((resolve, reject) => {
      accountService
        .verifyUniqueUsernameEmail(email, username)
        .then(() => {
          setLoading(false);
          setEmail(email);
          setUsername(username);
          resolve();
        })
        .catch((err) => {
          setLoading(false);
          dispatchMessage(err?.response?.data);
          reject(err);
        });
    });
  };

  return (
    <CreateAccountContext.Provider
      value={{
        email,
        username,
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
