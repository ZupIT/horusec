BEGIN;

ALTER TABLE "tokens" ADD "is_expirable" BOOLEAN;

UPDATE tokens set is_expirable=true WHERE is_expirable=NULL;

ALTER TABLE "tokens" ALTER COLUMN is_expirable SET NOT NULL;

COMMIT;