FROM migrate/migrate:v4.13.0

ADD development-kit/pkg/databases/relational/migration /horusec-migrations

ENTRYPOINT [ "migrate", "-source /horusec-migrations" ] 