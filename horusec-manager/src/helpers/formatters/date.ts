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

import { getCurrentLanguage } from 'helpers/localStorage/currentLanguage';
import { format } from 'date-fns';

const formatInitialAndFinalDate = (initial: Date, final: Date) => {
  if (initial && final) {
    const initialDate = format(initial, `yyyy-MM-dd'T00:00:00Z'`);
    const finalDate = format(final, `yyyy-MM-dd'T23:59:59Z'`);

    return { initialDate, finalDate };
  }

  return { initialDate: null, finalDate: null };
};

const formatToHumanDate = (date: string) => {
  const { dateFormat } = getCurrentLanguage();

  return format(new Date(date).setHours(24), dateFormat);
};

export { formatInitialAndFinalDate, formatToHumanDate };
