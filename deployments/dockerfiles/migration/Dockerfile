FROM migrate/migrate:v4.13.0

ADD development-kit/pkg/databases/relational/migration /horusec-migrations
ADD deployments/dockerfiles/migration/migrate.sh /usr/local/bin

RUN chmod +x /usr/local/bin/migrate.sh

ENTRYPOINT [ "migrate.sh" ] 