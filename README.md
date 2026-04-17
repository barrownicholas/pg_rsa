# pg_rsa

A PostgreSQL extension for RSA signing using OpenSSL.

## Functions

```sql
rsa_sign(data text, private_key text, algorithm text DEFAULT 'RS256') RETURNS bytea
```

Supported algorithms: `RS256`, `RS384`, `RS512`.

## Installation

```bash
make
sudo make install
psql -c "CREATE EXTENSION pg_rsa;"
```

## Requirements

- PostgreSQL 15 or 17
- OpenSSL
- pkg-config

## Usage

```sql
SELECT encode(rsa_sign('my data', '-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----', 'RS256'), 'base64');
```
