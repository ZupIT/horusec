BEGIN;

CREATE TABLE IF NOT EXISTS "analysis"
(
    analysis_id     UUID NOT NULL,
    repository_id   UUID NOT NULL,
    repository_name VARCHAR(255) NOT NULL,
    company_id      UUID NOT NULL,
    company_name    VARCHAR(255) NOT NULL,
    status          VARCHAR(255) NOT NULL,
    errors          TEXT NOT NULL,
    created_at      DATE NOT NULL,
    finished_at     DATE NOT NULL,
    PRIMARY KEY (analysis_id),
    FOREIGN KEY (repository_id) REFERENCES "repositories" (repository_id) ON DELETE CASCADE,
    FOREIGN KEY (company_id) REFERENCES "companies" (company_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "vulnerabilities"
(
    vulnerability_id UUID NOT NULL,
    analysis_id      UUID NOT NULL,
    line             VARCHAR(255),
    "column"         VARCHAR(255),
    confidence       VARCHAR(255),
    file             VARCHAR,
    code             VARCHAR,
    details          VARCHAR,
    type             VARCHAR(255),
    vulnerable_below VARCHAR(255),
    version          VARCHAR(255),
    security_tool    VARCHAR(255) NOT NULL,
    language         VARCHAR(255) NOT NULL,
    severity         VARCHAR(255),
    commit_author    VARCHAR(255),
    commit_email     VARCHAR(255),
    commit_hash      VARCHAR(255),
    commit_message   VARCHAR,
    commit_date      VARCHAR(255),
    PRIMARY KEY (vulnerability_id),
    FOREIGN KEY (analysis_id) REFERENCES "analysis" (analysis_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "tokens"
(
    token_id      UUID NOT NULL,
    description   VARCHAR(255) NOT NULL,
    repository_id UUID NOT NULL,
    company_id    UUID NOT NULL,
    suffix_value  VARCHAR(255) NOT NULL,
    value         VARCHAR(255) NOT NULL,
    created_at    DATE NOT NULL,
    expires_at    DATE NOT NULL,
    PRIMARY KEY (token_id),
    FOREIGN KEY (repository_id) REFERENCES "repositories" (repository_id) ON DELETE CASCADE,
    FOREIGN KEY (company_id) REFERENCES "companies" (company_id) ON DELETE CASCADE
);

COMMIT;
