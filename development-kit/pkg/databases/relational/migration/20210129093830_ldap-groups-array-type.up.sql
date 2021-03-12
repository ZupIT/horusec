BEGIN;

alter table companies
    alter authz_member drop default,
    alter authz_member type text[] using array[authz_member],
    alter authz_member set default '{}';

alter table companies
    alter authz_admin drop default,
    alter authz_admin type text[] using array[authz_admin],
    alter authz_admin set default '{}';

alter table repositories
    alter authz_member drop default,
    alter authz_member type text[] using array[authz_member],
    alter authz_member set default '{}';

alter table repositories
    alter authz_supervisor drop default,
    alter authz_supervisor type text[] using array[authz_supervisor],
    alter authz_supervisor set default '{}';

alter table repositories
    alter authz_admin drop default,
    alter authz_admin type text[] using array[authz_admin],
    alter authz_admin set default '{}';

COMMIT;