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

interface Props {
  isOpen: boolean;
  onClose: () => void;
  rolesType: 'REPOSITORY' | 'COMPANY';
}

const Permissions: React.FC<Props> = ({ isOpen, onClose, rolesType }) => {
  const { t } = useTranslation();

  const renderRulesOfPermissions = () => {
    const admin: string[] = [];
    const user: string[] = [];

    if (rolesType === 'REPOSITORY') {
      admin.push(
        t('PERMISSIONS.REPOSITORY.RULES.HANDLER'),
        t('PERMISSIONS.REPOSITORY.RULES.HANDLER_TOKENS'),
        t('PERMISSIONS.REPOSITORY.RULES.HANDLER_USER'),
        t('PERMISSIONS.REPOSITORY.RULES.ANALYTIC_REPO')
      );
      user.push(t('PERMISSIONS.REPOSITORY.RULES.ANALYTIC_REPO'));
    }

    if (rolesType === 'COMPANY') {
      admin.push(
        t('PERMISSIONS.COMPANY.RULES.HANDLER'),
        t('PERMISSIONS.COMPANY.RULES.HANDLER_USER'),
        t('PERMISSIONS.COMPANY.RULES.CREATE'),
        t('PERMISSIONS.COMPANY.RULES.ANALYTIC_COMPANY')
      );
      user.push(t('PERMISSIONS.COMPANY.RULES.ANALYTIC_REPO'));
    }

    return { admin, user };
  };

  return isOpen ? (
    <Styled.Background>
      <Styled.Wrapper>
        <Styled.Header>
          <Styled.TitleWrapper>
            <Styled.Close name="lock" size="22px" onClick={onClose} />
            <Styled.Title>{t('PERMISSIONS.TITLE')}</Styled.Title>
          </Styled.TitleWrapper>

          <Styled.Close name="close" size="24px" onClick={onClose} />
        </Styled.Header>

        <Styled.Subtitle>{t(`PERMISSIONS.ADMIN`)}</Styled.Subtitle>

        <Styled.List>
          {renderRulesOfPermissions().admin.map((rule, index) => (
            <Styled.Item key={index}>{rule}</Styled.Item>
          ))}
        </Styled.List>

        <Styled.Subtitle>{t(`PERMISSIONS.USER`)}</Styled.Subtitle>

        <Styled.List>
          {renderRulesOfPermissions().user.map((rule, index) => (
            <Styled.Item key={index}>{rule}</Styled.Item>
          ))}
        </Styled.List>
      </Styled.Wrapper>
    </Styled.Background>
  ) : null;
};

export default Permissions;
