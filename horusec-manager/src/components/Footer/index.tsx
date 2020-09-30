import React from 'react';
import Styled from './styled';
import packageJson from '../../../package.json';

const Footer: React.FC = () => {
  const { version } = packageJson;

  return (
    <Styled.Footer>
      <Styled.Text>Version {version}</Styled.Text>
    </Styled.Footer>
  );
};

export default Footer;
