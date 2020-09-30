import React, { useState, useEffect } from 'react';
import { Counter } from 'components';
import { useTranslation } from 'react-i18next';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import analyticService from 'services/analytic';

interface Props {
  filters?: FilterValues;
}

const TotalRepositories: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();

  const [total, setTotal] = useState(null);
  const [isLoading, setLoading] = useState(false);

  useEffect(() => {
    if (filters) {
      setLoading(true);

      analyticService
        .getTotalRepositories(filters)
        .then((result) => {
          setTotal(result.data.content);
        })
        .catch(() => {
          setTotal(null);
        })
        .finally(() => {
          setLoading(false);
        });
    }
  }, [filters]);

  return (
    <div className="block half-space">
      <Counter
        value={total}
        isLoading={isLoading}
        title={t('DASHBOARD_SCREEN.TOTAL_REPOSITORIES')}
      />
    </div>
  );
};

export default TotalRepositories;
