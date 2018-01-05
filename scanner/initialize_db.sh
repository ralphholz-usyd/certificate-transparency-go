#!/bin/bash


sudo -u postgres psql -p 7777 -c "CREATE DATABASE ct2 WITH TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'en_US.utf8' LC_CTYPE = 'en_US.utf8';"

sudo -u postgres psql -p 7777 -d ct2 -c "CREATE TABLE ct_log (log_id text PRIMARY KEY, log_url text, tree_size integer, last_download timestamp without time zone);"

sudo -u postgres psql -p 7777 -d ct2 -c "CREATE TABLE entry (log_id text, log_url text, index integer, cert_hash text, chain_entries text[]);"

sudo -u postgres psql -p 7777 -d ct2 -c "CREATE TABLE cert (cert_hash text PRIMARY KEY, cert bytea, is_ca boolean, common_name text, san_dns text[], san_ip text[], san_email text[], issuer_cn text, pub_key bytea, signature_algorithm text, pub_key_algorithm text, not_before timestamp with time zone, not_after timestamp with time zone, policy_identifiers text[], x509_version integer, key_usage text, ext_key_usage text[], basic_constraints text, cert_policies text[], extensions text[], unhandled_extensions text[], inclusion_time bigint, max_path_len integer, active_scan text);"

sudo -u postgres psql -p 7777 -d ct2 -c "CREATE TABLE unparsable (unparsable_cert bytea, error text);"