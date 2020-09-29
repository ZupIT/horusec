import React, { useState, useEffect } from 'react';
import { Counter } from 'components';
import { useTranslation } from 'react-i18next';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import analyticService from 'services/analytic';

interface Props {
  filters?: FilterValues;
}

const TotalDevelopers: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();

  const [total, setTotal] = useState(null);
  const [isLoading, setLoading] = useState(false);

  useEffect(() => {
    if (filters) {
      setLoading(true);

      analyticService
        .getTotalDevelopers(filters)
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
        title={t('TOTAL_DEVELOPERS')}
      />
    </div>
  );
};

export default TotalDevelopers;
