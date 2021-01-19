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

import React, { useState } from 'react';
import Styled from './styled';
import { useTranslation } from 'react-i18next';
import { Icon } from 'components';
import { PaginationInfo } from 'helpers/interfaces/Pagination';

interface Props {
  onChange: (pagination: PaginationInfo) => void;
  pagination: PaginationInfo;
}

const Pagination: React.FC<Props> = ({ onChange, pagination }) => {
  const { t } = useTranslation();

  const [visibleListItems, setVisibleListItems] = useState(false);

  const handlePagination = (action: 'next' | 'previous') => {
    let currentPage = pagination.currentPage;
    action === 'next' ? currentPage++ : currentPage--;

    if (currentPage > 0 && currentPage <= pagination.totalPages) {
      onChange({ ...pagination, currentPage });
    }
  };

  return (
    <Styled.Wrapper>
      <Styled.ItemWrapper
        onClick={() => setVisibleListItems(!visibleListItems)}
      >
        <Styled.Text>{t('GENERAL.PAGINATION.ITENS_PAGE')}</Styled.Text>

        <Styled.Text>{pagination.pageSize}</Styled.Text>

        <Icon name="page-select" size="13px" />

        <Styled.ListItems isVisible={visibleListItems}>
          <Styled.Item
            onClick={() => onChange({ ...pagination, pageSize: 10 })}
          >
            10
          </Styled.Item>
          <Styled.Item
            onClick={() => onChange({ ...pagination, pageSize: 50 })}
          >
            50
          </Styled.Item>
          <Styled.Item
            onClick={() => onChange({ ...pagination, pageSize: 100 })}
          >
            100
          </Styled.Item>
        </Styled.ListItems>
      </Styled.ItemWrapper>

      <Styled.PagesWrapper>
        <Styled.Text>{pagination.currentPage}</Styled.Text>

        <Styled.Text>{t('GENERAL.PAGINATION.OF')}</Styled.Text>

        <Styled.Text>{pagination.totalPages}</Styled.Text>

        <Styled.Text>{t('GENERAL.PAGINATION.PAGES')}</Styled.Text>
      </Styled.PagesWrapper>

      <Styled.Previous
        onClick={() => handlePagination('previous')}
        name="page-previous"
        size="13px"
      />

      <Styled.Next
        onClick={() => handlePagination('next')}
        name="page-next"
        size="13px"
      />
    </Styled.Wrapper>
  );
};

export default Pagination;
