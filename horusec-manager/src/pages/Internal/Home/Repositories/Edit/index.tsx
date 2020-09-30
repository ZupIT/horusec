import React, { useState, useEffect } from 'react';
import { Dialog } from 'components';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import { isEmptyString } from 'helpers/validators';
import { Field } from 'helpers/interfaces/Field';
import { useTheme } from 'styled-components';
import repositoryService from 'services/repository';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { Repository } from 'helpers/interfaces/Repository';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  repoToEdit: Repository;
}

const EditRepository: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
  repoToEdit,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { dispatchMessage } = useResponseMessage();

  const [isLoading, setLoading] = useState(false);
  const [name, setName] = useState<Field>({
    value: repoToEdit?.name,
    isValid: true,
  });
  const [description, setDescription] = useState<Field>({
    value: repoToEdit?.description,
    isValid: true,
  });

  const handleConfirmSave = () => {
    if (name.isValid) {
      setLoading(true);

      repositoryService
        .update(
          repoToEdit.companyID,
          repoToEdit.repositoryID,
          name.value,
          description.value
        )
        .then(() => {
          onConfirm();
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        })
        .finally(() => {
          setLoading(false);
        });
    }
  };

  useEffect(() => {
    if (repoToEdit) {
      setName({ value: repoToEdit?.name, isValid: true });
      setDescription({ value: repoToEdit?.description, isValid: true });
    }
  }, [repoToEdit]);

  return (
    <Dialog
      isVisible={isVisible}
      message={t('EDIT_REPO')}
      onCancel={onCancel}
      onConfirm={handleConfirmSave}
      confirmText={t('SAVE')}
      disableConfirm={!name.isValid}
      disabledColor={colors.button.disableInDark}
      loadingConfirm={isLoading}
      width={600}
      defaultButton
      hasCancel
    >
      <Styled.SubTitle>{t('EDIT_REPO_BELOW')}</Styled.SubTitle>

      <Styled.Form onSubmit={handleConfirmSave}>
        <Styled.Field
          label={t('NAME_REPO')}
          invalidMessage={t('INVALID_NAME')}
          onChangeValue={(field: Field) => setName(field)}
          validation={isEmptyString}
          name="name"
          type="text"
          width="100%"
          initialValue={name.value}
        />

        <Styled.Field
          label={t('DESCRIPTION_REPO')}
          onChangeValue={(field: Field) => setDescription(field)}
          name="description"
          type="text"
          width="100%"
          initialValue={description.value}
        />
      </Styled.Form>
    </Dialog>
  );
};

export default EditRepository;
