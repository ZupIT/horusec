BEGIN;

ALTER TABLE "vulnerabilities"
ADD 
    "vuln_hash" VARCHAR(40);

COMMIT;