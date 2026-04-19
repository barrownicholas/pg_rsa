# pg_rsa

A PostgreSQL extension for RSA signing and verification using OpenSSL.

## Functions

```sql
-- Sign a message, returns raw bytes
pg_rsa_sign(message text, private_key text, algorithm pg_rsa_algorithms DEFAULT 'SHA256') RETURNS bytea

-- Sign a message, returns base64-encoded string
pg_rsa_sign_b64(message text, private_key text, algorithm pg_rsa_algorithms DEFAULT 'SHA256') RETURNS text

-- Verify a signature (raw bytes)
pg_rsa_verify(message text, public_key text, algorithm pg_rsa_algorithms, signature bytea) RETURNS boolean

-- Verify a base64-encoded signature
pg_rsa_verify_b64(message text, public_key text, algorithm pg_rsa_algorithms, signature text) RETURNS boolean

-- Run built-in self-tests
pg_rsa_test() RETURNS boolean
```

Supported algorithms (`pg_rsa_algorithms` enum): `SHA256`, `SHA384`, `SHA512`

## Installation

### From source

```bash
make
sudo make install
psql -c "CREATE EXTENSION pg_rsa;"
psql -c 'SELECT pg_rsa_test();'
```

### Docker

```bash
docker build --build-arg PG_VERSION=17 -t pg_rsa .
docker run -e POSTGRES_PASSWORD=postgres pg_rsa
```

## Requirements

- PostgreSQL 15+
- OpenSSL
- GCC / Make

## Usage

```sql
CREATE EXTENSION pg_rsa;

-- Sign
SELECT pg_rsa_sign_b64('my message', '-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----');

-- Verify
SELECT pg_rsa_verify_b64('my message', '-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----', 'SHA256', '<base64-signature>');
```