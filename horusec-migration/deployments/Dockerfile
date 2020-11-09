FROM migrate/migrate:v4.13.0

ADD development-kit/pkg/databases/relational/migration /horusec-migrations
ADD horusec-migration/deployments/scripts/migrate.sh /usr/local/bin

RUN chmod +x /usr/local/bin/migrate.sh

ENTRYPOINT [ "migrate.sh" ] 