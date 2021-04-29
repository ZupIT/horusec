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
import Styled from './styled';
import { Icon, Button } from 'components';
import { useTranslation } from 'react-i18next';
import useClipboard from 'react-use-clipboard';

interface Props {
  tokenValue: string;
  onConfirm: () => void;
}

const SuccessAddToken: React.FC<Props> = ({ tokenValue, onConfirm }) => {
  const { t } = useTranslation();
  const [isCopied, setCopied] = useClipboard(tokenValue);

  return (
    <Styled.Background>
      <Styled.Wrapper>
        <Styled.Head>
          <Icon name="lock" size="24px" />

          <Styled.Title>{t('REPOSITORIES_SCREEN.TOKEN_SUCCESS')}</Styled.Title>
        </Styled.Head>

        <Styled.TokenWrapper isCopy={isCopied} onClick={setCopied}>
          <Styled.Token>{tokenValue}</Styled.Token>

          <Icon name="copy" size="20px" className="copy" />
        </Styled.TokenWrapper>

        <Styled.Info>{t('REPOSITORIES_SCREEN.TOKEN_INFO')}</Styled.Info>

        <Button
          text={t('REPOSITORIES_SCREEN.CONFIRM')}
          rounded
          width={110}
          onClick={onConfirm}
        />
      </Styled.Wrapper>
    </Styled.Background>
  );
};

export default SuccessAddToken;
