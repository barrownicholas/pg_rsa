#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

EVP_PKEY *__load_private_key_from(const char *pem_str);

EVP_PKEY *__load_public_key_from(const char *pem_str);


/*
 * Signs msg with the PEM-encoded RSA private key using the named digest.
 * Returns signature length (-1 on error)
 */
static ssize_t
_rsa_sign(
    const char *msg,
    const char *pem_key,
    const EVP_MD *type,
    unsigned char **out_sig,
    void *(*_malloc)(size_t)
) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    size_t sig_len = 0;
    ssize_t return_code = -1;

    pkey = __load_private_key_from(pem_key);
    if (!pkey) goto cleanup;

    // context object tracks signing state
    ctx = EVP_MD_CTX_new();
    if (!ctx) goto cleanup;

    // initialize object for signing
    if (EVP_DigestSignInit(ctx, NULL, type, NULL, pkey) <= 0) goto cleanup;

    // pass msg for signing
    if (EVP_DigestSignUpdate(ctx, msg, strlen(msg)) <= 0) goto cleanup;

    // determine the signature length
    if (EVP_DigestSignFinal(ctx, NULL, &sig_len) <= 0) goto cleanup;

    // allocate memory for the signature
    *out_sig = _malloc(sig_len);
    if (!*out_sig) goto cleanup;

    // sign the signature
    if (EVP_DigestSignFinal(ctx, *out_sig, &sig_len) <= 0) goto cleanup;

    // done
    return_code = sig_len;
    goto cleanup;

cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_MD_CTX_free(ctx);
    return return_code;
}

/*
 * Verifies msg against a signature using the PEM-encoded RSA public key.
 * Returns 1 if valid, 0 if invalid, -1 on error.
 */
static int
_rsa_verify(
    const char *msg,
    const char *pem_key,
    const EVP_MD *type,
    const unsigned char *sig,
    const size_t sig_len
) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int return_code = -1;

    pkey = __load_public_key_from(pem_key);
    if (!pkey) goto cleanup;

    // context object tracks verification state
    ctx = EVP_MD_CTX_new();
    if (!ctx) goto cleanup;

    // initialize object for verification
    if (EVP_DigestVerifyInit(ctx, NULL, type, NULL, pkey) <= 0) goto cleanup;

    // pass msg for verification
    if (EVP_DigestVerifyUpdate(ctx, msg, strlen(msg)) <= 0) goto cleanup;

    // verify the signature — 1 = valid, 0 = invalid
    return_code = EVP_DigestVerifyFinal(ctx, sig, sig_len);

cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_MD_CTX_free(ctx);
    return return_code;
}

EVP_PKEY *__load_private_key_from(const char *pem_str) {
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;

    // wrap key into OpenSSL I/O object
    bio = BIO_new_mem_buf(pem_str, -1);
    if (!bio) return NULL;

    // load private key
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

EVP_PKEY *__load_public_key_from(const char *pem_str) {
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;

    // wrap key into OpenSSL I/O object
    bio = BIO_new_mem_buf(pem_str, -1);
    if (!bio) return NULL;

    // load public key
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}
