import React, { useState, useEffect } from 'react';
import Styled from './styled';
import { Repository } from 'helpers/interfaces/Repository';
import { useTranslation } from 'react-i18next';
import { Button, Icon, Dialog } from 'components';
import repositoryService from 'services/repository';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { RepositoryToken } from 'helpers/interfaces/RepositoryToken';
import useLanguage from 'helpers/hooks/useLanguage';
import { find } from 'lodash';
import moment from 'moment';
import AddToken from './Add';

interface Props {
  isVisible: boolean;
  repoToManagerTokens: Repository;
  onClose: () => void;
}

const Tokens: React.FC<Props> = ({
  isVisible,
  onClose,
  repoToManagerTokens,
}) => {
  const { t } = useTranslation();
  const { dispatchMessage } = useResponseMessage();

  const [tokens, setTokens] = useState<RepositoryToken[]>([]);
  const [dateFormat, setDateFormat] = useState('DD/MM/YYYY');
  const { i18n } = useTranslation();
  const { allLanguages } = useLanguage();
  const [isLoading, setLoading] = useState(true);
  const [deleteIsLoading, setDeleteIsLoading] = useState(false);

  const [tokenToDelete, setTokenToDelete] = useState<RepositoryToken>(null);
  const [addTokenVisible, setAddTokenVisible] = useState(false);

  const fetchData = () => {
    setLoading(true);
    repositoryService
      .getAllTokens(
        repoToManagerTokens.companyID,
        repoToManagerTokens.repositoryID
      )
      .then((result) => {
        setTokens(result?.data?.content);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const handleConfirmDeleteToken = () => {
    setDeleteIsLoading(true);
    repositoryService
      .removeToken(
        tokenToDelete.companyID,
        tokenToDelete.repositoryID,
        tokenToDelete.tokenID
      )
      .then(() => {
        setTokenToDelete(null);
        fetchData();
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setDeleteIsLoading(false);
      });
  };

  useEffect(() => {
    if (repoToManagerTokens) {
      fetchData();
    }
    //eslint-disable-next-line
  }, [repoToManagerTokens]);

  useEffect(() => {
    const lang = find(allLanguages, { i18nValue: i18n.language });
    setDateFormat(lang.dateFormat);
  }, [i18n.language, allLanguages]);

  return isVisible ? (
    <Styled.Background>
      <Styled.Wrapper>
        <Styled.Header>
          <Styled.Title>{t('TOKENS')}</Styled.Title>

          <Styled.Close name="close" size="24px" onClick={onClose} />
        </Styled.Header>

        <Button
          text={t('ADD_TOKEN')}
          rounded
          width={150}
          icon="plus"
          onClick={() => setAddTokenVisible(true)}
        />

        <Styled.Table>
          <Styled.LoadingWrapper isLoading={isLoading}>
            <Icon name="loading" size="120px" className="loading" />
          </Styled.LoadingWrapper>

          <Styled.Head>
            <Styled.Column>{t('TOKEN')}</Styled.Column>
            <Styled.Column>{t('DESCRIPTION')}</Styled.Column>
            <Styled.Column>{t('EXPIRES')}</Styled.Column>
            <Styled.Column>{t('ACTION')}</Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {!tokens || tokens.length <= 0 ? (
              <Styled.EmptyText>{t('NO_TOKENS')}</Styled.EmptyText>
            ) : null}

            {tokens.map((token) => (
              <Styled.Row key={token.tokenID}>
                <Styled.Cell>***************{token.suffixValue}</Styled.Cell>

                <Styled.Cell>{token.description}</Styled.Cell>

                <Styled.Cell>
                  {moment(token.expiresAt).format(dateFormat.toUpperCase())}
                </Styled.Cell>

                <Styled.Cell className="row">
                  <Button
                    rounded
                    outline
                    opaque
                    text={t('DELETE')}
                    width={90}
                    height={30}
                    icon="delete"
                    onClick={() => setTokenToDelete(token)}
                  />
                </Styled.Cell>
              </Styled.Row>
            ))}
          </Styled.Body>
        </Styled.Table>
      </Styled.Wrapper>

      <Dialog
        message={t('CONFIRM_DELETE_TOKEN')}
        confirmText={t('YES')}
        loadingConfirm={deleteIsLoading}
        defaultButton
        hasCancel
        isVisible={!!tokenToDelete}
        onCancel={() => setTokenToDelete(null)}
        onConfirm={handleConfirmDeleteToken}
      />

      <AddToken
        isVisible={addTokenVisible}
        currentRepository={repoToManagerTokens}
        onCancel={() => setAddTokenVisible(false)}
        onConfirm={() => {
          setAddTokenVisible(false);
          fetchData();
        }}
      />
    </Styled.Background>
  ) : null;
};

export default Tokens;
