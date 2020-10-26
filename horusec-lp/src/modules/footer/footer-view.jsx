import React from 'react';
import LogoPowered from '../../svgs/logo-poweredby-zup.svg';
import IconInstagram from '../../svgs/icon-instagram.svg';
import IconLinkedin from '../../svgs/icon-linkedin.svg';
import IconYoutube from '../../svgs/icon-youtube.svg';
import IconMedium from '../../svgs/icon-medium.svg';
import IconTwitter from '../../svgs/icon-twitter.svg';
import {Title, Paragraph, Menu, MenuItem, Anchor, Copyright} from './footer-styled';
import { useTranslation } from 'react-i18next';

export default () => {
  const { t, i18n } = useTranslation('LandingPage', { useSuspense: false });

  return (
    <footer>
      <div className="row justify-content-center mb-4">
        <div className="col-auto">
          <LogoPowered />
        </div>
      </div>

      <div className="row mb-4">
        <div className="col-6 col-md-3 mb-3 mb-md-0">
          <Title className="mb-2">{t('Onde estamos?')}</Title>

          <Paragraph
            dangerouslySetInnerHTML={{
              __html: t("Endereço", {
                interpolation: { escapeValue: false },
              }),
            }}
          >
          </Paragraph>
        </div>

        <div className="col-6 col-md-3">
          <Title className="mb-2">{t('Conhecimento')}</Title>

          <Menu>
            <MenuItem>
              {i18n && i18n.language ? <Anchor href={t('Link Blog')} target="_blank" rel="noreferrer">{t('Blog')}</Anchor> : null}
            </MenuItem>

            <MenuItem>
              {i18n && i18n.language ? <Anchor href={t('Link Comunidade')} target="_blank" rel="noreferrer">{t('Comunidade')}</Anchor> : null}
            </MenuItem>

            <MenuItem>
            {i18n && i18n.language ? <Anchor href={t('Link Política de Privacidade')} target="_blank" rel="noreferrer">{t('Política de Privacidade')}</Anchor> : null}
            </MenuItem>
          </Menu>
        </div>

        <div className="col-6 col-md-3 mb-3 mb-md-0">
          <Anchor href="#" dangerouslySetInnerHTML={{
              __html: t("Receba nossas últimas novidades", {
                interpolation: { escapeValue: false },
              }),
            }}></Anchor>
        </div>

        <div className="col-6 col-md-3">
          <Title className="mb-2">{t('Fale com a gente')}</Title>

          <Paragraph>
            +55 34 2589 1800 <br />
            opensource@zup.com.br
          </Paragraph>

          <div className="row no-gutters align-items-center">
            <div className="col-auto">
              <a href="https://www.instagram.com/zupinnovation" blank="_blank" rel="noreferrer">
                <IconInstagram />
              </a>
            </div>

            <div className="col-auto ml-1">
                <a href="https://www.linkedin.com/company/zup-it-solutions" blank="_blank" rel="noreferrer">
                  <IconLinkedin />
                </a>
            </div>

            <div className="col-auto ml-1">
                <a href="https://www.youtube.com/channel/UCJWZyJ-36yNscqnnHiwjkhQ" blank="_blank" rel="noreferrer">
                  <IconYoutube />
                </a>
            </div>

            <div className="col-auto ml-1">
                <a href="https://medium.com/zup-it" blank="_blank" rel="noreferrer">
                  <IconMedium />
                </a>
            </div>

            <div className="col-auto ml-1">
                <a href="https://twitter.com/ZupInnovation" blank="_blank" rel="noreferrer">
                  <IconTwitter />
                </a>
            </div>
          </div>
        </div>
      </div>

      <div className="row justify-content-center mb-1">
        <div className="col-auto">
          <Copyright>©Copyright 2020 Zup. All Rights Reserved</Copyright>
        </div>
      </div>
    </footer>
  );
};
