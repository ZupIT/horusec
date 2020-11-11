BEGIN;

CREATE TABLE IF NOT EXISTS "webhooks"
(
    "webhook_id"        UUID NOT NULL,
    "repository_id"     UUID NOT NULL,
    "company_id"        UUID NOT NULL,
    "description"       VARCHAR(255),
    "method"            VARCHAR(255) NOT NULL,
    "url"               VARCHAR(500) NOT NULL,
    "headers"           JSONB,
    "created_at"        DATE NOT NULL,
    "updated_at"        DATE,
    PRIMARY KEY (webhook_id),
    FOREIGN KEY (repository_id) REFERENCES repositories (repository_id) ON DELETE CASCADE,
    FOREIGN KEY (company_id) REFERENCES companies (company_id) ON DELETE CASCADE,
    UNIQUE (repository_id)
);

COMMIT;
