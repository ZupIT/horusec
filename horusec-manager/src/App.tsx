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
import { FlashMessageProvider } from 'contexts/FlashMessage';
import { AuthProvider } from 'contexts/Auth';
import { getCurrentTheme } from 'helpers/localStorage/currentTheme';
import { setIsMicrofrontend } from 'helpers/localStorage/microfrontend';
import { ReactKeycloakProvider } from '@react-keycloak/web';
import { keycloakInstance, keycloackConfig } from 'config/keycloak';
import { handleSetKeyclockData } from 'helpers/localStorage/tokens';

function App({ isMicrofrontend }: { isMicrofrontend?: boolean }) {
  const theme = getCurrentTheme();

  setIsMicrofrontend(isMicrofrontend || false);

  const AppContent = () => (
    <ThemeProvider theme={theme}>
      <GlobalStyle />

      <FlashMessageProvider>
        <AuthProvider>
          <Routes />
        </AuthProvider>
      </FlashMessageProvider>
    </ThemeProvider>
  );

  return keycloackConfig.clientId ? (
    <ReactKeycloakProvider
      authClient={keycloakInstance}
      onTokens={(tokens) =>
        handleSetKeyclockData(tokens.token, tokens.refreshToken)
      }
    >
      <AppContent />
    </ReactKeycloakProvider>
  ) : (
    <AppContent />
  );
}

export default App;
