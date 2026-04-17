CREATE OR REPLACE FUNCTION rsa_sign(
  data        text,
  private_key text,
  algorithm   text DEFAULT 'RS256'
)
RETURNS bytea
AS '$libdir/pg_rsa', 'rsa_sign'
LANGUAGE C STRICT IMMUTABLE;
