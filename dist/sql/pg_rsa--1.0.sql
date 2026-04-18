DO $$ BEGIN
CREATE TYPE @extschema@.pg_rsa_algorithms AS ENUM ('SHA256', 'SHA384', 'SHA512');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE OR REPLACE FUNCTION @extschema@.pg_rsa_sign(
    message     text,
    private_key text,
    algorithm   @extschema@.pg_rsa_algorithms DEFAULT 'SHA256'
)
RETURNS bytea
AS 'pg_rsa', 'v1_0__rsa_sign'
LANGUAGE C CALLED ON NULL INPUT;

CREATE OR REPLACE FUNCTION @extschema@.pg_rsa_sign_base64(
    message     text,
    private_key text,
    algorithm   @extschema@.pg_rsa_algorithms DEFAULT 'SHA256'
)
RETURNS text
AS 'pg_rsa', 'v1_0__rsa_sign_b64'
LANGUAGE C CALLED ON NULL INPUT;

CREATE OR REPLACE FUNCTION @extschema@.pg_rsa_verify(
    message     text,
    private_key text,
    algorithm   @extschema@.pg_rsa_algorithms,
    signature   bytea
) RETURNS boolean
AS 'pg_rsa', 'v1_0__rsa_verify'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION @extschema@.pg_rsa_verify_b64(
    message     text,
    private_key text,
    algorithm   @extschema@.pg_rsa_algorithms,
    signature   text
) RETURNS boolean
AS 'pg_rsa', 'v1_0__rsa_verify_b64'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION @extschema@.pg_rsa_test()
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
priv_key text := '-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDAepxsxyvGAJCs
SO0nd4NADSEEnyvgNA/DzKISwPa1GTT1me4A6ti7EJNcSQN5UBKd9u/YZGpPHqs1
aXr8Oh5OSv7CtXbcrspigYRBQgjOHYUe9t7sdsXP2YIbVCG0ZyH4rN+ItQgpCi7T
88odFA1dyB//zsOcly606RMO9oUATXF1Ipd6CJIIWhWhbsbigXBtCpcIJofhswX+
74iHVMWDT5tKdRfdY7x6eTWeo4XPrDp9rXvJi3VpSTnlUiLpLTW+gmn6Yo8gDBKD
zPytzP0ozD5M7M3230D7FGWhsSIxQ/IPNgA+XkifuuI4dsKc8Dlnfgp71JPoytRq
Xa62RMVTAgMBAAECggEAAqNX4G4aGKPxzdNPSH0eJ6Hj+M55riojlN4dXLU1bGrE
uA0GlTbxkGzyRaNMsx64ra1rmYNGM0W3Ve3XU0tcAtI8KVbcwGveaD3WWVx38zIE
1+kb+xDvNjU6Hr3sEULWcr4ovihikdzPyhwLWuI2AyYx4NnBKfm6omHSLb3v/mr3
eUc7PoK7230+MKFd4r1jjyW0/P41aENColT9t041psHTIzVyTgsiMJ+rF50n435K
EWiCnmBdh94idKNJcTRvFeOjlUjwcoZHfv9eMEzWOT/Lbhki8qLCzRjdO/WGMBn3
7Z1ShyyCrxeDZ/fn66n4+3H9vObsdNQ/5mTUvIUKuQKBgQD+mPHuSxhO1mLE7GGm
90aQNiGy8/PpryZMXkUI8OwPKOQNaBhYFicBYQ6spiLSBp8uJKudam5ugq7wbx9x
aI0B1EJnY03TKkuUGShEfaMt/HMVLbWe9KUQK/cXUKv04eR8zh59pLAyLklCaEzN
CX0TvOEhNhwcp33EjMUOc/3QpwKBgQDBig+rsLtHOzYKvec0Ghb9WfSJmUK/yAfg
ZRNHW2mOxNqxNxr2xqx+7EAbQEwNa7Gvzq5VKcGcWis35m6Fg/MZqxRV5iQ5AriH
nH4D8MaAEiUCLC+sNmweCgfK04L5w9+R9hYLZIbRyFuf6sF7XaLjOp0ZpNrqP4sS
qe79OVRvdQKBgFXAuiwjCwry1s2xOKr+Orw0H2GhHZSmM+YhEmuSilAI29dQKnLw
8y5ZvJGWW8AWDuOB4nPg91UtmzLMmvCd4HCvR7Z/EiV/53j4iEGZd67ziuelP7lM
eZRa2pz1xRV0SHtpCYgUQmyEfpRpgQTGn2RYiBOhoBJer9PV/kGB/AmdAoGAd3sP
H5RUma4BN/Jy6KRuquu83rGiFpmb2zkrBLN3YC9BP4Rgfha66QRaszgne2WP5ZQ3
5dWIdEjqQ3Fbq8uA6cjHHhydIiD+4KGI3k/ni6sn88Zpi+xxJL5Wfy3CvwTgYdDF
XTUrUhlaD0izN8DfzV4jHHC8wT6HUfdc1jFtYf0CgYAerkWaYhkUN7N89GaIQ8/7
3MVYRnrnBBKiNPK4SEPKy3ajQGmRWTL0VJyXjKXbqJNeZjgWF/y2SBeQDdJyQ56o
WWYnbbHeAmkDroRppYUTS2LaRPphvP9+L6E2iLcxVxFhk9NdrfLHbSUu9WjWpyzg
jhqQqSHrzObNYavSh72MIg==
-----END PRIVATE KEY-----';

    pub_key text := '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHqcbMcrxgCQrEjtJ3eD
QA0hBJ8r4DQPw8yiEsD2tRk09ZnuAOrYuxCTXEkDeVASnfbv2GRqTx6rNWl6/Doe
Tkr+wrV23K7KYoGEQUIIzh2FHvbe7HbFz9mCG1QhtGch+KzfiLUIKQou0/PKHRQN
Xcgf/87DnJcutOkTDvaFAE1xdSKXegiSCFoVoW7G4oFwbQqXCCaH4bMF/u+Ih1TF
g0+bSnUX3WO8enk1nqOFz6w6fa17yYt1aUk55VIi6S01voJp+mKPIAwSg8z8rcz9
KMw+TOzN9t9A+xRlobEiMUPyDzYAPl5In7riOHbCnPA5Z34Ke9ST6MrUal2utkTF
UwIDAQAB
-----END PUBLIC KEY-----';

BEGIN
    -- 1. rsa_sign returns bytea
    ASSERT pg_typeof(@extschema@.pg_rsa_sign('hello'::text, priv_key, 'SHA256'::@extschema@.pg_rsa_algorithms)) = 'bytea'::regtype,
        'pg_rsa_sign should return bytea';

    -- 2. pg_rsa_sign_base64 returns text
    ASSERT pg_typeof(@extschema@.pg_rsa_sign_base64('hello'::text, priv_key, 'SHA256'::@extschema@.pg_rsa_algorithms)) = 'text'::regtype,
        'pg_rsa_sign_base64 should return text';

    -- 3. pg_rsa_sign_base64 output is valid base64
    ASSERT @extschema@.pg_rsa_sign_base64('hello'::text, priv_key, 'SHA256'::@extschema@.pg_rsa_algorithms) ~ '^[A-Za-z0-9+/]+=*$',
        'pg_rsa_sign_base64 should return valid base64';

    -- 4. sign then verify SHA256
    ASSERT @extschema@.pg_rsa_verify('hello'::text, pub_key, 'SHA256'::@extschema@.pg_rsa_algorithms,
        @extschema@.pg_rsa_sign('hello'::text, priv_key, 'SHA256'::@extschema@.pg_rsa_algorithms)),
        'SHA256 signature should verify';

    -- 5. sign then verify SHA384
    ASSERT @extschema@.pg_rsa_verify('hello'::text, pub_key, 'SHA384'::@extschema@.pg_rsa_algorithms,
        @extschema@.pg_rsa_sign('hello'::text, priv_key, 'SHA384'::@extschema@.pg_rsa_algorithms)),
        'SHA384 signature should verify';

    -- 6. sign then verify SHA512
    ASSERT @extschema@.pg_rsa_verify('hello'::text, pub_key, 'SHA512'::@extschema@.pg_rsa_algorithms,
        @extschema@.pg_rsa_sign('hello'::text, priv_key, 'SHA512'::@extschema@.pg_rsa_algorithms)),
        'SHA512 signature should verify';

    -- 7. sign_base64 then verify_b64
    ASSERT @extschema@.pg_rsa_verify_b64('hello'::text, pub_key, 'SHA256'::@extschema@.pg_rsa_algorithms,
        @extschema@.pg_rsa_sign_base64('hello'::text, priv_key, 'SHA256'::@extschema@.pg_rsa_algorithms)),
        'base64 signature should verify';

    -- 8. wrong message fails verification
    ASSERT @extschema@.pg_rsa_verify('world'::text, pub_key, 'SHA256'::@extschema@.pg_rsa_algorithms,
        @extschema@.pg_rsa_sign('hello'::text, priv_key, 'SHA256'::@extschema@.pg_rsa_algorithms)) = false,
        'wrong message should fail verification';

    -- 9. deterministic: same message produces same signature
    ASSERT @extschema@.pg_rsa_sign('hello'::text, priv_key, 'SHA256'::@extschema@.pg_rsa_algorithms)
        = @extschema@.pg_rsa_sign('hello'::text, priv_key, 'SHA256'::@extschema@.pg_rsa_algorithms),
        'pg_rsa_sign should be deterministic';

    -- 10. different messages produce different signatures
    ASSERT @extschema@.pg_rsa_sign('hello'::text, priv_key, 'SHA256'::@extschema@.pg_rsa_algorithms)
        != @extschema@.pg_rsa_sign('world'::text, priv_key, 'SHA256'::@extschema@.pg_rsa_algorithms),
        'different messages should produce different signatures';

    RETURN true;
END;
$$;