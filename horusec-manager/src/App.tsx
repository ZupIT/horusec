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

import React from 'react';

import Routes from './routes';
import GlobalStyle from 'assets/style/global';
import { ThemeProvider } from 'styled-components';
import { ThemeProvider as ThemeProviderMatUi } from '@material-ui/core';
import { FlashMessageProvider } from 'contexts/FlashMessage';
import { AuthProvider } from 'contexts/Auth';
import { getCurrentTheme } from 'helpers/localStorage/currentTheme';
import { ReactKeycloakProvider } from '@react-keycloak/web';
import {
  keycloakInstance,
  keycloakConfig,
  keycloakInitOptions,
} from 'config/keycloak';
import { handleSetKeyclockData } from 'helpers/localStorage/tokens';
import themeMatUi from 'config/themes/material-ui';

function App() {
  const theme = getCurrentTheme();

  const AppContent = () => (
    <ThemeProviderMatUi theme={themeMatUi}>
      <ThemeProvider theme={theme}>
        <GlobalStyle />

        <FlashMessageProvider>
          <AuthProvider>
            <Routes />
          </AuthProvider>
        </FlashMessageProvider>
      </ThemeProvider>
    </ThemeProviderMatUi>
  );

  return keycloakConfig.clientId ? (
    <ReactKeycloakProvider
      authClient={keycloakInstance}
      autoRefreshToken={true}
      initOptions={keycloakInitOptions}
      onTokens={({ token, refreshToken, idToken }) =>
        handleSetKeyclockData(token, refreshToken, idToken)
      }
    >
      <AppContent />
    </ReactKeycloakProvider>
  ) : (
    <AppContent />
  );
}

export default App;
