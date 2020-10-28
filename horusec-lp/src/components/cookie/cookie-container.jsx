import React from 'react';
import { graphql, StaticQuery } from 'gatsby';
import styled from 'styled-components';
import BackgroundImage from 'gatsby-background-image';
import Cookie from './cookie-view';
import { useTranslation } from 'react-i18next';

const Component = ({ className, onAccept }) => {
  const { t } = useTranslation('LandingPage', { useSuspense: false });

  return (
    <StaticQuery
      query={graphql`
        query {
          desktop: file(relativePath: { eq: "bg-cookie-modal.jpg" }) {
            childImageSharp {
              fluid {
                ...GatsbyImageSharpFluid_withWebp
              }
            }
          }
        }
      `}
      render={(data) => {
        // Set ImageData.
        const imageData = data.desktop.childImageSharp.fluid;

        return (
          <BackgroundImage Tag="section" className={className} fluid={imageData} backgroundColor={`none`}>
            <Cookie
              text={t(
                'This website uses cookies in order to offer you a better browsing experience and an effective platform usability. When you keep browsing here, we understand you accept the cookies and agree with our policy. For more information, check out our privacy policy.',
              )}
              acceptText={t(
                'Aceitar'
              )}
              onAccept={onAccept}
            />
          </BackgroundImage>
        );
      }}
    />
  );
};

export default styled(Component)`
  width: 899px;
  height: 140px;
  border-radius: 12px;
  overflow: hidden;

  position: fixed !important;
  bottom: 40px;
  left: 50%;
  transform: translateX(-50%);

  @media (max-width: 900px) {
    width: 90%;
    height: auto;
  }
`;
