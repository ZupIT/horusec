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

import React, { useState, useEffect, useRef } from 'react';
import Styled from './styled';
import HorusecLogo from 'assets/logos/horusec.svg';

interface Props {
  isVisible: boolean;
}

const Splash: React.FC<Props> = ({ isVisible }) => {
  const splashRef = useRef(null);

  const [visible, setVisible] = useState(true);
  const [startAnimation, setStartAnimation] = useState(true);

  useEffect(() => {
    if (!isVisible) {
      setTimeout(() => {
        setStartAnimation(false);
      }, 1500);

      setTimeout(() => {
        setVisible(false);
      }, 3200);
    }
  }, [isVisible]);

  return (
    <Styled.Container isVisible={visible} ref={splashRef}>
      <h1>
        <Styled.Logo
          isVisible={startAnimation}
          src={HorusecLogo}
          alt="Horusec Logo"
        />
      </h1>
    </Styled.Container>
  );
};

export default Splash;
