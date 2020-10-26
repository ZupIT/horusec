import React from 'react';
import PreviewComponent from '../../components/image-preview';
import {PipelineFirstImage, PipelineSecondImage} from '../../components/image';
import { useTranslation } from 'react-i18next';

export default () => {
  const { t } = useTranslation('LandingPage', { useSuspense: false });

  return (
    <>
      <div className="row justify-content-center mb-4">
        <div className="col-auto">
          <h2 className="text-center mb-2" dangerouslySetInnerHTML={{
              __html: t("ADICIONE EM SEU PIPELINE E TENHA MAIS SEGURANÇA", {
                interpolation: { escapeValue: false },
              }),
            }}></h2>

          <p className="text-center" dangerouslySetInnerHTML={{
              __html: t("Outro objetivo é garantir que a nova funcionalidade do seu projeto esteja segura para isto adicionamos um novo step.", {
                interpolation: { escapeValue: false },
              }),
            }}></p>
        </div>
      </div>

      <div className="row justify-content-between">
        <div className="col-12 mb-3 col-md-6 mb-md-0">
          <PreviewComponent>
            <PipelineFirstImage />
          </PreviewComponent>
        </div>

        <div className="col-12 col-md-6">
          <PreviewComponent>
            <PipelineSecondImage />
          </PreviewComponent>
        </div>
      </div>
    </>
  );
};
