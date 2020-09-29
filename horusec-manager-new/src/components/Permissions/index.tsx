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
    const member: string[] = [];

    if (rolesType === 'REPOSITORY') {
      admin.push(
        t('PERMISSIONS.REPOSITORY.RULES.TOKENS'),
        t('PERMISSIONS.REPOSITORY.RULES.OTHER_USERS'),
        t('PERMISSIONS.REPOSITORY.RULES.ANALYTIC')
      );
      member.push(
        t('PERMISSIONS.REPOSITORY.RULES.YOUR_REPOSITORY'),
        t('PERMISSIONS.REPOSITORY.RULES.ANALYTIC')
      );
    }

    if (rolesType === 'COMPANY') {
      admin.push(
        t('PERMISSIONS.COMPANY.RULES.HANDLER'),
        t('PERMISSIONS.COMPANY.RULES.REMOVE'),
        t('PERMISSIONS.COMPANY.RULES.INVITE'),
        t('PERMISSIONS.COMPANY.RULES.ANALYTIC')
      );
      member.push(t('PERMISSIONS.COMPANY.RULES.ANALYTIC'));
    }

    return { admin, member };
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

        <Styled.Subtitle>{t(`PERMISSIONS.${rolesType}.ADMIN`)}</Styled.Subtitle>

        <Styled.List>
          {renderRulesOfPermissions().admin.map((rule, index) => (
            <Styled.Item key={index}>{rule}</Styled.Item>
          ))}
        </Styled.List>

        <Styled.Subtitle>
          {t(`PERMISSIONS.${rolesType}.MEMBER`)}
        </Styled.Subtitle>

        <Styled.List>
          {renderRulesOfPermissions().member.map((rule, index) => (
            <Styled.Item key={index}>{rule}</Styled.Item>
          ))}
        </Styled.List>
      </Styled.Wrapper>
    </Styled.Background>
  ) : null;
};

export default Permissions;
