/*
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

module.exports = {
  webpack(config) {
    config.entry = './src/microfrontend.tsx';
    config.output.libraryTarget = 'system';
    config.plugins = config.plugins.filter(
      (plugin) => plugin.constructor.name !== 'HtmlWebpackPlugin'
    );
    config.output = {
      ...config.output,
      filename: 'main.js',
    };
    config.externals = ['react', 'react-dom', 'react-router-dom', 'lodash'];
    config.optimization.runtimeChunk = false;
    config.optimization.splitChunks = {
      cacheGroups: {
        default: false,
        vendors: false,
      },
    };

    return config;
  },
  devServer(configFunction) {
    return function (proxy, allowedHost) {
      const config = configFunction(proxy, allowedHost);
      config.disableHostCheck = true;
      config.headers = config.headers || {};
      config.headers['Access-Control-Allow-Origin'] = '*';
      return config;
    };
  },
};
