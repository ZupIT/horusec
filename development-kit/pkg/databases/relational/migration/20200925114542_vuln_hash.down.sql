BEGIN;

ALTER TABLE "vulnerabilities"
DROP COLUMN "vuln_hash";

COMMIT;