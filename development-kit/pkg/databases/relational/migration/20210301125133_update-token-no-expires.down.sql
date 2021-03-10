BEGIN;

ALTER TABLE "tokens" DROP COLUMN "is_expirable";

COMMIT;
