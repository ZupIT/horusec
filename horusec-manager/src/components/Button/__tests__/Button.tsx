/**
 * Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React from 'react';
import '@testing-library/jest-dom/extend-expect';
import {
  renderWithTheme,
  fireEvent,
  waitForElement,
} from 'helpers/unit-tests/utils';

import Button from '..';

test('renders button component with default properties', () => {
  const props = { text: 'Testing', id: 'btn-test' };

  const { getByTestId } = renderWithTheme(<Button {...props} />);

  const button = getByTestId(props.id);

  expect(button).toBeInTheDocument();
  expect(button).toHaveTextContent(props.text);
});

test('no action when click on disabled button', async () => {
  const click = jest.fn();
  const props = { text: 'Testing', id: 'btn-test-disabled', isDisabled: true };

  const { getByTestId } = renderWithTheme(
    <Button onClick={click} {...props} />
  );

  const button = await waitForElement(() => getByTestId(props.id));

  fireEvent.click(button);

  expect(click).not.toBeCalled();
});

test('no action when click on loading button', async () => {
  const handleClick = jest.fn();
  const props = { text: 'Testing', id: 'btn-test-loading', isLoading: true };

  const { getByTestId } = renderWithTheme(
    <Button onClick={handleClick} {...props} />
  );

  const button = await waitForElement(() => getByTestId(props.id));

  fireEvent.click(button);

  expect(handleClick).not.toBeCalled();
});
