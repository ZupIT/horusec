import React from 'react';
import SEOComponent from '../../components/seo'
import HeaderModule from '../header';
import FooterModule from '../footer';

export default ({page, children}) => {
  return (
    <>
      <SEOComponent title={page.title} />

      <div className="wrapper">
        <div className="container-fluid">
          <div>
            <HeaderModule />
          </div>

          {children}

          <div style={{marginTop: '140px'}}>
            <FooterModule />
          </div>
        </div>
      </div>
    </>
  );
};
