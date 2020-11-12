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

import commom from './common';

export default {
  ...commom,
  colors: {
    success: 'rgba(16, 170, 128, 0.49)',

    background: {
      primary: '#1C1C1E',
      secundary: '#2C2C2E',
      overlap: '#242426',
      highlight: '#3A3A3C',
    },

    scrollbar: '#1C1C1E',

    icon: {
      primary: '#F5F5FB',
    },

    button: {
      primary: '#EF4123',
      secundary: '#F7941E',
      text: '#F2F2F9',
      border: '#F2F2F7',
      disabled: '#2C2C2E',
      disableInDark: '#636366',
    },

    optionButton: {
      text: '#98989E',
      border: '#98989E',
    },

    text: {
      primary: '#F5F5FB',
      secundary: '#B4B6BA',
      opaque: '#BEBEBE',
      highlight: '#00B1FF',
      link: '#0095FF',
    },

    input: {
      border: '#98989E',
      label: '#98989E',
      text: '#F2F2F9',
      active: '#FFFFFF',
      error: '#E02020',
      focus: '#FFFFFF',
      disabled: '#2C2C2E',
    },

    datePicker: {
      text: {
        primary: '#C7C7D4',
        secundary: '#636366',
      },
      title: '#98989E',
      background: '#2C2C2E',
      highlight: '#F04223',
      today: '#636366',
      border: '#FFFFFF',
    },

    select: {
      text: '#C7C7D4',
      title: '#98989E',
      background: '#2C2C2E',
      border: '#FFFFFF',
      hover: '#444447',
      darkBackground: '#343436',
    },

    flashMessage: {
      text: '#F5F5FB',
      error: '#FF453A',
      success: '#10AA80',
    },

    dialog: {
      backgroundScreen: '#1c1c1ecc',
      background: '#2C2C2E',
      text: '#F4F4FA',
      confirmBtn: '#FF453A',
    },

    chart: {
      title: '#B4B6BA',
      legend: '#ACACB2',
    },

    vulnerabilities: {
      HIGH: '#E84138',
      MEDIUM: '#e67e22',
      LOW: '#10AA80',
      AUDIT: '#64D2FF',
      NOSEC: '#34495e',
      INFO: '#746dda',
      DEFAULT: '#8E8E93',
    },

    languages: {
      PYTHON: '#366b97',
      KOTLIN: '#746dda',
      JAVA: '#f0931e',
      GO: '#66d1dd',
      GIT: '#e84f33',
      JAVASCRIPT: '#f0d81e',
      RUBY: '#970f03',
      LEAKS: '#2a2038',
      HCL: '#062c38',
      UNKNOWN: '#7f8c8d',
      'C#': '#6508bf',
    },

    dataTable: {
      backgorund: '#2C2C2E',
      title: '#C7C7D4',
      column: {
        text: '#98989E',
      },
      row: {
        text: '#F2F2F9',
        background: '#3A3A3C',
      },
    },

    checkbox: {
      border: '#F5F5FB',
      checked: {
        primary: '#EF4123',
        secundary: '#F7941E',
      },
    },

    methods: {
      get: '#4d9880',
      post: '#2a2038',
      unknown: '#3A3A3C',
    },
  },
};
