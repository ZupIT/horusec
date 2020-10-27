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

import { createGlobalStyle } from 'styled-components';

import SFThin from '../fonts/SF-Pro-Display-Thin.otf';
import SFRegular from '../fonts/SF-Pro-Display-Regular.otf';
import SFBold from '../fonts/SF-Pro-Display-Bold.otf';
import { getCurrentTheme } from 'helpers/localStorage/currentTheme';

const theme = getCurrentTheme();

const GlobalStyle = createGlobalStyle`
  @font-face {
    font-family: 'SFThin';
    src: url(${SFThin});
  }

  @font-face {
    font-family: 'SFRegular';
    src: url(${SFRegular});
  }

  @font-face {
    font-family: 'SFBold';
    src: url(${SFBold});
  }

  @keyframes shimmer {
  0% {
    background-position: -1000px 0;
  }
  100% {
    background-position: 1000px 0;
  }
}

  html,
  body,
  #root {
    height: 100vh;
    background-color: ${theme.colors.background.primary};
    overflow-y: hidden;
  }

  body,
  input,
  button,
  textarea,
  div.react-datepicker * {
    font-family: 'SFRegular', sans-serif !important;
  }

  a {
    text-decoration: none;
  }

  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    scrollbar-width: thin;
    scrollbar-color: dark;

    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
  }

  textarea,
  select,
  input {
    filter: none;
  }

  /* React Date Picker */

  div.react-datepicker-wrapper {
    div.react-datepicker__input-container {
      input {
        background: none;
        outline: none;
        border: none;
        color: ${theme.colors.text.primary};
        font-size: ${theme.metrics.fontSize.medium} !important;
        max-width: 120px;
      }
    }
  }

  div.react-datepicker__tab-loop {
    div.react-datepicker-popper {
      div {
        div.react-datepicker {
          background-color: ${theme.colors.datePicker.background};
          border: none !important;
          border-radius: 0 !important;
          font-size: ${theme.metrics.fontSize.small};

          div.react-datepicker__triangle {
            border-bottom-color: ${theme.colors.datePicker.background};

            ::before {
              color: ${theme.colors.datePicker.background};
              border-bottom-color: ${theme.colors.datePicker.background};
            }
          }

          div.react-datepicker__month-container {
            * { color: ${theme.colors.datePicker.text.primary} !important; }

            div.react-datepicker__header {
              background-color: ${theme.colors.datePicker.background};
              border: none !important;

              div.react-datepicker__day-names {
                div.react-datepicker__day-name { color: ${theme.colors.datePicker.text.secundary} !important; }
              }
            }

            div.react-datepicker__month {
              div.react-datepicker__week {
                div.react-datepicker__day {
                   :hover {
                    background-color: ${theme.colors.datePicker.highlight} !important;
                  }
                }

                div.react-datepicker__day--keyboard-selected, div.react-datepicker__day--selected {
                  background-color: ${theme.colors.datePicker.highlight} !important;
                }

                div.react-datepicker__day--today  {
                  background-color: ${theme.colors.datePicker.today} !important;
                }
              }
            }
          }
        }
      }
    }
  }


`;

export default GlobalStyle;
