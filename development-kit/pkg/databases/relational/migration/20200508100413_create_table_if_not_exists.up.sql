BEGIN;

CREATE TABLE IF NOT EXISTS "accounts"
(
    "account_id"     UUID NOT NULL,
    "password"       VARCHAR(255) NOT NULL,
    "email"          VARCHAR(255) UNIQUE NOT NULL,
    "username"       VARCHAR(255) NOT NULL,
    "is_confirmed"   BOOLEAN NOT NULL,
    "created_at"     DATE NOT NULL,
    "updated_at"     DATE,
    PRIMARY KEY (account_id)
);

CREATE TABLE IF NOT EXISTS "companies"
(
    "company_id"     UUID NOT NULL,
    "name"           VARCHAR(255) NOT NULL,
    "description"    VARCHAR(255),
    "created_at"     DATE NOT NULL,
    "updated_at"     DATE,
    PRIMARY KEY (company_id)
);

CREATE TABLE IF NOT EXISTS "account_company"
(
    "company_id"     UUID NOT NULL,
    "account_id"     UUID NOT NULL,
    "role"           VARCHAR(255) NOT NULL,
    "created_at"     DATE NOT NULL,
    "updated_at"     DATE,
    FOREIGN KEY (company_id) REFERENCES companies (company_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts (account_id) ON DELETE CASCADE,
    UNIQUE (company_id, account_id)
    
);

CREATE TABLE IF NOT EXISTS "repositories"
(
    "repository_id"     UUID NOT NULL,
    "company_id"        UUID NOT NULL,
    "description"       VARCHAR(255),
    "name"              VARCHAR(255) NOT NULL,
    "created_at"        DATE NOT NULL,
    "updated_at"        DATE,
    PRIMARY KEY (repository_id),
    FOREIGN KEY (company_id) REFERENCES companies (company_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "account_repository"
(
    "repository_id"      UUID NOT NULL,
    "account_id"         UUID NOT NULL,
    "company_id"         UUID NOT NULL,
    "role"               VARCHAR(255) NOT NULL,
    "created_at"         DATE NOT NULL,
    "updated_at"         DATE,
    FOREIGN KEY (repository_id) REFERENCES repositories (repository_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts (account_id) ON DELETE CASCADE,
    UNIQUE (repository_id, account_id)
);

COMMIT;


