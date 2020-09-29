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

import { useEffect, useState } from 'react';

const useDynamicImport = (name: string) => {
  const [uri, setUri] = useState('');

  useEffect(() => {
    let abort: () => void;

    (async () => {
      const abortController = new Promise((resolve) => {
        abort = resolve;
      });
      const svgData = import(`assets/svg/${name}.svg`);
      Promise.race([abortController, svgData]).then((data: any) => {
        if (data) {
          setUri(data?.default || '');
        }
      });
    })();

    return () => abort();
  }, [name, setUri]);

  return [uri];
};

export default useDynamicImport;
