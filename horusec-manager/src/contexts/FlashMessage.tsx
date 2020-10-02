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
import { Flash } from 'components';

interface FlashMessageProps {
  children: JSX.Element;
}

interface FlashContext {
  isVisible: boolean;
  message: string;
  setMessage: Function;
}

const FlashMessageContext = React.createContext<FlashContext>({
  isVisible: false,
  message: '',
  setMessage: () => '',
});

const FlashMessageProvider = ({ children }: FlashMessageProps) => {
  const [isVisible, setVisible] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (message) {
      setVisible(true);

      setTimeout(() => {
        setVisible(false);
        setMessage('');
      }, 3200);
    }
  }, [message]);

  return (
    <FlashMessageContext.Provider value={{ isVisible, message, setMessage }}>
      {children}

      <Flash isVisible={isVisible} message={message} />
    </FlashMessageContext.Provider>
  );
};

export { FlashMessageProvider, FlashMessageContext };
