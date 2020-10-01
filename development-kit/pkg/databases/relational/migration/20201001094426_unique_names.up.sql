BEGIN;

ALTER TABLE accounts ADD CONSTRAINT uk_accounts_username UNIQUE (username);

ALTER TABLE companies ADD CONSTRAINT uk_companies_username UNIQUE (name);

ALTER TABLE repositories ADD CONSTRAINT uk_repositories_username UNIQUE (name);

COMMIT;