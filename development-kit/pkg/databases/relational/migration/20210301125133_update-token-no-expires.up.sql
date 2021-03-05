BEGIN;

ALTER TABLE "tokens" ADD "is_expirable" BOOLEAN DEFAULT true;

COMMIT;