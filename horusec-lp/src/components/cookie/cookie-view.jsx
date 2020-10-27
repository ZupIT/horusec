import React from 'react';
import CloseIcon from '../../svgs/icon-close-white.svg';
import ButtonComponent from '../button';
import { Cookie, Actions, ActionItem, Text } from './cookie-styled';

export default ({ text, acceptText, onAccept }) => {
  return (
    <Cookie>
      <Actions>
        <ActionItem className="d-none d-md-block">
          <CloseIcon onClick={onAccept} />
        </ActionItem>
      </Actions>

      <div className="row align-items-center">
        <div className="col-12 mb-2 mb-md-0 col-md-8">
          <Text
            dangerouslySetInnerHTML={{
              __html: text,
            }}
          ></Text>
        </div>

        <div className="col-12 col-md-3">
          <div onClick={onAccept}>
            <ButtonComponent style={{ padding: '15px 20px' }} background="linear-gradient(90deg, #EF4123 0%, #F7941E 100%);">
              {acceptText}
            </ButtonComponent>
          </div>
        </div>
      </div>
    </Cookie>
  );
};
