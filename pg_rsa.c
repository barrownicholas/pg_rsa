#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(rsa_sign);

static const EVP_MD *
get_evp_md(const char *algorithm)
{
    if (strcmp(algorithm, "RS256") == 0)
        return EVP_sha256();
    else if (strcmp(algorithm, "RS384") == 0)
        return EVP_sha384();
    else if (strcmp(algorithm, "RS512") == 0)
        return EVP_sha512();
    else
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("pg_rsa: unsupported algorithm \"%s\", "
                               "must be RS256, RS384, or RS512", algorithm)));
    return NULL; /* unreachable */
}

Datum
rsa_sign(PG_FUNCTION_ARGS)
{
    text           *data_text      = PG_GETARG_TEXT_PP(0);
    text           *pkey_text      = PG_GETARG_TEXT_PP(1);
    text           *alg_text       = PG_GETARG_TEXT_PP(2);

    char           *data           = VARDATA_ANY(data_text);
    int             data_len       = VARSIZE_ANY_EXHDR(data_text);
    char           *pem            = text_to_cstring(pkey_text);
    char           *algorithm      = text_to_cstring(alg_text);

    const EVP_MD   *md             = NULL;
    BIO            *bio            = NULL;
    EVP_PKEY       *pkey           = NULL;
    EVP_MD_CTX     *ctx            = NULL;
    bytea          *result         = NULL;
    size_t          sig_len        = 0;
    unsigned char  *sig_buf        = NULL;

    /* Resolve digest algorithm */
    md = get_evp_md(algorithm);

    /* Load private key */
    bio = BIO_new_mem_buf(pem, -1);
    if (!bio)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("pg_rsa: failed to create BIO")));

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("pg_rsa: failed to load private key: %s",
                               ERR_reason_error_string(ERR_get_error()))));

    /* Create signing context */
    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(pkey);
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("pg_rsa: failed to create EVP_MD_CTX")));
    }

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("pg_rsa: EVP_DigestSignInit failed: %s",
                               ERR_reason_error_string(ERR_get_error()))));
    }

    if (EVP_DigestSignUpdate(ctx, data, data_len) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("pg_rsa: EVP_DigestSignUpdate failed: %s",
                               ERR_reason_error_string(ERR_get_error()))));
    }

    /* Get signature length */
    if (EVP_DigestSignFinal(ctx, NULL, &sig_len) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("pg_rsa: EVP_DigestSignFinal (len) failed: %s",
                               ERR_reason_error_string(ERR_get_error()))));
    }

    sig_buf = palloc(sig_len);

    /* Produce signature */
    if (EVP_DigestSignFinal(ctx, sig_buf, &sig_len) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("pg_rsa: EVP_DigestSignFinal failed: %s",
                               ERR_reason_error_string(ERR_get_error()))));
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    result = (bytea *) palloc(VARHDRSZ + sig_len);
    SET_VARSIZE(result, VARHDRSZ + sig_len);
    memcpy(VARDATA(result), sig_buf, sig_len);

    PG_RETURN_BYTEA_P(result);
}
