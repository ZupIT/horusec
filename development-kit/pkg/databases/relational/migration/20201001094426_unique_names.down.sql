BEGIN;

ALTER TABLE accounts DROP CONSTRAINT uk_accounts_username;

ALTER TABLE companies DROP CONSTRAINT uk_companies_username;

ALTER TABLE repositories DROP CONSTRAINT uk_repositories_username;

COMMIT;