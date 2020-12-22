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
import { useTranslation } from 'react-i18next';
import { Vulnerability } from 'helpers/interfaces/Vulnerability';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  vulnerability: Vulnerability;
}

const VulnerabilityDetails: React.FC<Props> = ({
  isOpen,
  onClose,
  vulnerability,
}) => {
  const { t } = useTranslation();

  return isOpen ? (
    <Styled.Background>
      <Styled.Wrapper>
        <Styled.Header>
          <Styled.TitleWrapper>
            <Styled.Close name="info" size="22px" onClick={onClose} />
            <Styled.Title>
              {t('VULNERABILITIES_SCREEN.DETAILS.TITLE')}
            </Styled.Title>
          </Styled.TitleWrapper>

          <Styled.Close name="close" size="24px" onClick={onClose} />
        </Styled.Header>

        <Styled.Row>
          <Styled.ItemTitle>
            {t('VULNERABILITIES_SCREEN.DETAILS.HASH')}
          </Styled.ItemTitle>
          <Styled.ItemValue>{vulnerability.vulnHash}</Styled.ItemValue>
        </Styled.Row>

        <Styled.Row>
          <Styled.ItemTitle>
            {t('VULNERABILITIES_SCREEN.DETAILS.FILE')}
          </Styled.ItemTitle>
          <Styled.ItemValue>{vulnerability.file}</Styled.ItemValue>
        </Styled.Row>

        <Styled.Row>
          <Styled.ItemTitle>
            {t('VULNERABILITIES_SCREEN.DETAILS.LINE')}
          </Styled.ItemTitle>
          <Styled.ItemValue>{vulnerability.line}</Styled.ItemValue>
        </Styled.Row>

        <Styled.Row>
          <Styled.ItemTitle>
            {t('VULNERABILITIES_SCREEN.DETAILS.COLUMN')}
          </Styled.ItemTitle>
          <Styled.ItemValue>{vulnerability.column}</Styled.ItemValue>
        </Styled.Row>

        <Styled.Row>
          <Styled.ItemTitle>
            {t('VULNERABILITIES_SCREEN.DETAILS.LANGUAGE')}
          </Styled.ItemTitle>
          <Styled.ItemValue>{vulnerability.language}</Styled.ItemValue>
        </Styled.Row>

        <Styled.Row>
          <Styled.ItemTitle>
            {t('VULNERABILITIES_SCREEN.DETAILS.SECURITY_TOOL')}
          </Styled.ItemTitle>
          <Styled.ItemValue>{vulnerability.securityTool}</Styled.ItemValue>
        </Styled.Row>

        <Styled.Row>
          <Styled.ItemTitle>
            {t('VULNERABILITIES_SCREEN.DETAILS.SEVERITY')}
          </Styled.ItemTitle>
          <Styled.ItemValue>{vulnerability.severity}</Styled.ItemValue>
        </Styled.Row>

        <Styled.Row>
          <Styled.ItemTitle>
            {t('VULNERABILITIES_SCREEN.DETAILS.CONFIDENCE')}
          </Styled.ItemTitle>
          <Styled.ItemValue>{vulnerability.confidence}</Styled.ItemValue>
        </Styled.Row>

        <Styled.Row>
          <Styled.ItemTitle>
            {t('VULNERABILITIES_SCREEN.DETAILS.CODE')}
          </Styled.ItemTitle>
          <Styled.ItemValue>{vulnerability.code}</Styled.ItemValue>
        </Styled.Row>

        <Styled.Row>
          <Styled.ItemTitle>
            {t('VULNERABILITIES_SCREEN.DETAILS.DETAILS')}
          </Styled.ItemTitle>
          <Styled.ItemValue>{vulnerability.details}</Styled.ItemValue>
        </Styled.Row>
      </Styled.Wrapper>
    </Styled.Background>
  ) : null;
};

export default VulnerabilityDetails;
