import React, { useState } from 'react';
import View from './dropdown-view';

export default ({items, value, isItOpen}) => {
  const [isListOpen, setIsListOpen] = useState(isItOpen);

  const toggleList = () => {
    setIsListOpen(!isListOpen);
  };

  return (
    <View value={value} items={items} toggleAction={toggleList} isItOpen={isListOpen} />
  );
};
