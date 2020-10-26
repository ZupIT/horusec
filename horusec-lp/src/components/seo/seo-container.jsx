import React from 'react';
import SEO from './seo-view';
import { useStaticQuery, graphql } from 'gatsby';

const SEOContainer = ({ description, lang, meta, title }) => {
  const { site } = useStaticQuery(
    graphql`
      query {
        site {
          siteMetadata {
            title
            description
            author
          }
        }
      }
    `,
  );

  return site ? <SEO site={site} description={description} lang={lang} meta={meta} title={title}  /> : null;
};

export default SEOContainer;
