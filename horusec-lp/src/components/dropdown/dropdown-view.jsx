import React from 'react';
import IconDownArrow from '../../svgs/icon-down-arrow-blue.svg';
import {Dropdown, Label, Action, Options, OptionItem} from './dropdown-styled';

export default ({value, items, toggleAction, isItOpen}) => {
  return (
    <Dropdown onClick={toggleAction}>
      <div className="row no-gutters align-items-center" style={{cursor: 'pointer'}}>
        <div className="col-auto d-flex">
          <Label>{value}</Label>
        </div>

        <div className="col-auto ml-2 d-flex">
          <Action className="d-flex">
              <IconDownArrow />
          </Action>
        </div>
      </div>

      <Options isItOpen={isItOpen}>
        {items
          ? items.map((item) => (
              <OptionItem key={item.id} data-value={item.value} data-label={item.label} onClick={item.action}>
                {item.label}
              </OptionItem>
            ))
          : null}
      </Options>
    </Dropdown>
  );
};
