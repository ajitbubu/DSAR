#!/usr/bin/env bash
# Creates the least-privilege roles and databases. Runs once on first Postgres start
# (docker-entrypoint-initdb.d) and in CI. Local/dev passwords only.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname postgres \
  -v migrator_pw="${IDP_MIGRATOR_PASSWORD}" \
  -v app_pw="${IDP_APP_PASSWORD}" \
  -v relay_pw="${IDP_RELAY_PASSWORD}" <<'SQL'
CREATE ROLE idp_migrator LOGIN PASSWORD :'migrator_pw' NOSUPERUSER NOCREATEROLE NOBYPASSRLS;
CREATE ROLE idp_app      LOGIN PASSWORD :'app_pw'      NOSUPERUSER NOCREATEROLE NOBYPASSRLS;
CREATE ROLE idp_relay    LOGIN PASSWORD :'relay_pw'    NOSUPERUSER NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE idprivacy      OWNER idp_migrator;
CREATE DATABASE idprivacy_test OWNER idp_migrator;
REVOKE ALL ON DATABASE idprivacy, idprivacy_test FROM PUBLIC;
GRANT CONNECT ON DATABASE idprivacy, idprivacy_test TO idp_app, idp_relay;
SQL
