import React from 'react';
import {Link} from 'gatsby';
import LogoCharles from '../../svgs/logo-charles.svg';
import LogoBeagle from '../../svgs/logo-beagle.svg';
import LogoRitchie from '../../svgs/logo-ritchie.svg';
import LogoLivepass from '../../svgs/logo-livepass.svg';
import LogoHorussec from '../../svgs/logo-horus.svg';
import LogoIti from '../../svgs/logo-iti.svg';
import LogoItau from '../../svgs/logo-itau.svg';
import { useTranslation } from 'react-i18next';

export default () => {
  const { t } = useTranslation('LandingPage', { useSuspense: false });

  return (
    <>
      <div className="row justify-content-center mb-4">
        <div className="col-auto">
          <h2 className="text-center">{t('PROJETOS QUE JÁ ESTÃO REALIZANDO DESENVOLVIMENTO SEGURO')}</h2>
        </div>
      </div>

      <div className="row justify-content-center flex-column flex-md-row justify-content-md-around align-items-md-center mb-4">
        <div className="col-auto text-center mb-4 mb-md-0">
          <a href="https://charlescd.io/" target="_blank" rel="noreferrer">
            <LogoCharles />
          </a>
        </div>

        <div className="col-auto text-center mb-4 mb-md-0">
          <a href="http://usebeagle.io/" target="_blank" rel="noreferrer">
            <LogoBeagle />
          </a>
        </div>

        <div className="col-auto text-center">
          <a href="https://ritchiecli.io/" target="_blank" rel="noreferrer">
            <LogoRitchie />
          </a>
        </div>
      </div>

      <div className="row justify-content-center flex-column flex-md-row justify-content-md-around align-items-md-center">
        <div className="col-auto mb-4 text-center mb-md-0">
          <a href="http://livepass.zup.com.br/" target="_blank" rel="noreferrer">
            <LogoLivepass />
          </a>
        </div>

        <div className="col-auto mb-4 text-center mb-md-0">
          <Link to="/">
            <LogoHorussec />
          </Link>
        </div>

        <div className="col-auto mb-4 text-center mb-md-0">
          <a href="http://iti.itau/" target="_blank" rel="noreferrer">
            <LogoIti />
          </a>
        </div>

        <div className="col-auto text-center">
          <a href="https://www.itau.com.br/" target="_blank" rel="noreferrer">
            <LogoItau />
          </a>
        </div>
      </div>
    </>
  );
};
