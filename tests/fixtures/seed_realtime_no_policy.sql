-- Run in a separate, empty fixture database: no-policy cannot coexist with
-- the authenticated/PUBLIC policies in seed_pg.sql.
BEGIN;
CREATE SCHEMA storage;
CREATE TABLE storage.buckets (id text, name text, public boolean);
CREATE SCHEMA IF NOT EXISTS realtime;
CREATE TABLE IF NOT EXISTS realtime.messages (id bigint, topic text);
ALTER TABLE realtime.messages ENABLE ROW LEVEL SECURITY;
COMMIT;
