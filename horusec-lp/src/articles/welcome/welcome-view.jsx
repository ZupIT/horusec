import React from 'react';
import { useTranslation } from 'react-i18next';
import ButtonComponent from '../../components/button';

export default () => {
  const { t, i18n } = useTranslation('LandingPage', { useSuspense: false });

  return (
    <div className="row">
      <div className="col">
        <h1 className="mb-3" dangerouslySetInnerHTML={{
            __html: t("IDENTIFIQUE VULNERABILIDADES DE FORMA SIMPLES E RÁPIDA", {
              interpolation: { escapeValue: false },
            }),
          }}></h1>

        <p className="mb-4" dangerouslySetInnerHTML={{
            __html: t("O Horusec é uma estrutura de código aberto que potencializa a identificação de vulnerabilidades em seu projeto com apenas um comando.", {
              interpolation: { escapeValue: false },
            }),
          }}></p>

        {i18n && i18n.language ? <ButtonComponent href={t('Link Docs')} target="_blank">{t('Documentação')}</ButtonComponent> : null}
      </div>
    </div>
  );
};
