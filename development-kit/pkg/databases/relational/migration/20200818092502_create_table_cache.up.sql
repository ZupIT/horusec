BEGIN;

CREATE TABLE IF NOT EXISTS "cache"
(
    "key"        TEXT NOT NULL,
    "value"      TEXT NOT NULL,
    "expires_at" TIMESTAMP NOT NULL DEFAULT NOW(),
    "created_at" TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (key)
);

COMMIT;
