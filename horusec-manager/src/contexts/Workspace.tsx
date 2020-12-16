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

import React, { useState, useEffect } from 'react';
import companyService from 'services/company';
import { Workspace } from 'helpers/interfaces/Workspace';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { useHistory } from 'react-router-dom';

interface WorkspaceCtx {
  currentWorkspace: Workspace;
}

const WorkspaceContext = React.createContext<WorkspaceCtx>({
  currentWorkspace: null,
});

const WorkspaceProvider = ({ children }: { children: JSX.Element }) => {
  const [currentWorkspace, setCurrentWorkspace] = useState<Workspace>(null);

  const { dispatchMessage } = useResponseMessage();
  const history = useHistory();

  const fetchAll = () => {
    companyService
      .getAll()
      .then((result) => {
        const workspaces = result?.data?.content as Workspace[];

        if (workspaces && workspaces.length > 0) {
          setCurrentWorkspace(workspaces[0]);
          history.replace('/home/dashboard');
        } else {
          history.replace('/home/add-workspace');
        }
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      });
  };

  useEffect(() => {
    fetchAll();

    // eslint-disable-next-line
  }, []);

  return (
    <WorkspaceContext.Provider
      value={{
        currentWorkspace,
      }}
    >
      {children}
    </WorkspaceContext.Provider>
  );
};

export { WorkspaceProvider, WorkspaceContext };
