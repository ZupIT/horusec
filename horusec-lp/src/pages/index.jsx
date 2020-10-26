import React from 'react';
import LayoutModule from '../modules/layout';
import WelcomeArticle from '../articles/welcome';
import AboutArticle from '../articles/about';
import ManageArticle from '../articles/manage';
import PipelineArticle from '../articles/pipeline';
import ArchitectureArticle from '../articles/architecture';
import FeaturesArticle from '../articles/features';
import PortfolioArticle from '../articles/portfolio';

export default () => {
  return (
    <LayoutModule page={{title: 'Home'}}>
      <div style={{marginTop: '40px'}}>
        <WelcomeArticle />
      </div>

      <div style={{marginTop: '100px'}}>
        <AboutArticle />
      </div>

      <div style={{marginTop: '100px'}}>
        <ManageArticle />
      </div>

      <div style={{marginTop: '100px'}}>
        <PipelineArticle />
      </div>

      <div style={{marginTop: '140px'}}>
        <ArchitectureArticle />
      </div>

      <div style={{marginTop: '100px'}}>
        <FeaturesArticle />
      </div>

      <div style={{marginTop: '140px'}}>
        <PortfolioArticle />
      </div>
    </LayoutModule>
  );
};
