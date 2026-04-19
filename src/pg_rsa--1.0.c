#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "catalog/pg_enum.h"
#include "utils/syscache.h"
#include "access/htup_details.h"
#include <openssl/evp.h>
#include "../src/pg_rsa_impl.c"

PG_FUNCTION_INFO_V1(v1_0__rsa_sign);
PG_FUNCTION_INFO_V1(v1_0__rsa_sign_b64);
PG_FUNCTION_INFO_V1(v1_0__rsa_verify);
PG_FUNCTION_INFO_V1(v1_0__rsa_verify_b64);

static const char *
get_enum_label(Oid enum_oid) {
    HeapTuple tup;
    Form_pg_enum en;
    const char *label;

    tup = SearchSysCache1(ENUMOID, ObjectIdGetDatum(enum_oid));
    if (!HeapTupleIsValid(tup))
        ereport(ERROR, (errmsg("invalid enum OID: %u", enum_oid)));

    en = (Form_pg_enum) GETSTRUCT(tup);
    label = pstrdup(NameStr(en->enumlabel));
    ReleaseSysCache(tup);
    return label;
}

static const EVP_MD *
get_digest_type(const char *algorithm) {
    if (strcmp(algorithm, "SHA256") == 0) return EVP_sha256();
    if (strcmp(algorithm, "SHA384") == 0) return EVP_sha384();
    if (strcmp(algorithm, "SHA512") == 0) return EVP_sha512();
    ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                errmsg("unsupported algorithm: %s", algorithm)));
}

Datum
v1_0__rsa_sign(PG_FUNCTION_ARGS) {
    unsigned char *sig = NULL;
    ssize_t sig_len;

    const char *msg       = text_to_cstring(PG_GETARG_TEXT_PP(0));
    const char *pem_key   = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char *algorithm = get_enum_label(PG_GETARG_OID(2));

    sig_len = _rsa_sign(msg, pem_key, get_digest_type(algorithm), &sig, palloc);

    if (sig_len <= 0) {
        if (sig) pfree(sig);
        ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                errmsg("rsa_sign failed")));
    }
    PG_RETURN_BYTEA_P(cstring_to_text_with_len((const char *)sig, sig_len));
}

Datum
v1_0__rsa_sign_b64(PG_FUNCTION_ARGS) {
    unsigned char *sig = NULL;
    char *b64 = NULL;
    int encoded_len = 0;
    ssize_t sig_len;

    const char *msg       = text_to_cstring(PG_GETARG_TEXT_PP(0));
    const char *pem_key   = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char *algorithm = get_enum_label(PG_GETARG_OID(2));

    sig_len = _rsa_sign(msg, pem_key, get_digest_type(algorithm), &sig, palloc);

    if (sig_len <= 0) {
        if (sig) pfree(sig);
        ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                errmsg("rsa_sign_b64 failed")));
    }

    b64 = palloc(4 * ((sig_len + 2) / 3) + 1);
    encoded_len = EVP_EncodeBlock((unsigned char *) b64, sig, (int) sig_len);
    pfree(sig);
    PG_RETURN_TEXT_P(cstring_to_text_with_len(b64, encoded_len));
}

Datum
v1_0__rsa_verify(PG_FUNCTION_ARGS) {
    int result;

    const char *msg       = text_to_cstring(PG_GETARG_TEXT_PP(0));
    const char *pem_key   = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char *algorithm = get_enum_label(PG_GETARG_OID(2));
    bytea *sig_bytea      = PG_GETARG_BYTEA_PP(3);

    const unsigned char *sig = (const unsigned char *) VARDATA_ANY(sig_bytea);
    size_t sig_len = VARSIZE_ANY_EXHDR(sig_bytea);

    result = _rsa_verify(msg, pem_key, get_digest_type(algorithm), sig, sig_len);
    if (result < 0)
        ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                errmsg("rsa_verify failed")));

    PG_RETURN_BOOL(result == 1);
}

Datum
v1_0__rsa_verify_b64(PG_FUNCTION_ARGS) {
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int decoded_len = 0;
    int result = 0;

    const char *msg       = text_to_cstring(PG_GETARG_TEXT_PP(0));
    const char *pem_key   = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char *algorithm = get_enum_label(PG_GETARG_OID(2));
    const char *b64       = text_to_cstring(PG_GETARG_TEXT_PP(3));

    const size_t b64_len = strlen(b64);
    sig = palloc(b64_len);
    decoded_len = EVP_DecodeBlock(sig, (const unsigned char *) b64, (int) b64_len);

    if (decoded_len < 0) {
        pfree(sig);
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                errmsg("invalid base64 signature")));
    }

    sig_len = decoded_len;
    if (b64_len >= 2 && b64[b64_len - 1] == '=') sig_len--;
    if (b64_len >= 2 && b64[b64_len - 2] == '=') sig_len--;

    result = _rsa_verify(msg, pem_key, get_digest_type(algorithm), sig, sig_len);
    pfree(sig);

    if (result < 0)
        ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                errmsg("rsa_verify_b64 failed")));

    PG_RETURN_BOOL(result == 1);
}