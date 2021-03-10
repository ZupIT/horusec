BEGIN;

ALTER TABLE "tokens" ADD "is_expirable" BOOLEAN default true;

COMMIT;