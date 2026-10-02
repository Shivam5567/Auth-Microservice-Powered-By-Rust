-- The official Postgres image only creates one database. This runs once, on
-- first start of an empty data directory, to give the orders service its own.
--
-- Separate databases rather than a shared schema: the two services share no
-- transaction, and keeping them apart makes that explicit.
CREATE DATABASE orders OWNER auth;
