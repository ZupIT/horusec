import React from 'react';

import Routes from './routes';
import GlobalStyle from 'assets/style/global';
import { ThemeProvider } from 'styled-components';

import { FlashMessageProvider } from 'contexts/FlashMessage';
import { AuthProvider } from 'contexts/Auth';
import { getCurrentTheme } from 'helpers/localStorage/currentTheme';

function App() {
  const theme = getCurrentTheme();

  return (
    <ThemeProvider theme={theme}>
      <GlobalStyle />

      <FlashMessageProvider>
        <AuthProvider>
          <Routes />
        </AuthProvider>
      </FlashMessageProvider>
    </ThemeProvider>
  );
}

export default App;
