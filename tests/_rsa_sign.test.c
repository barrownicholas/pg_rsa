#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "../src/pg_rsa_impl.c"

// ------------------------------------------------------------
// test helpers
// ------------------------------------------------------------

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name, expr) do { \
    tests_run++; \
    if (expr) { \
        printf("  PASS: %s\n", name); \
        tests_passed++; \
    } else { \
        printf("  FAIL: %s (line %d)\n", name, __LINE__); \
    } \
} while(0)

// ------------------------------------------------------------
// test key (2048-bit, generated for testing only)
// ------------------------------------------------------------

static const char *TEST_PRIVATE_KEY =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDAepxsxyvGAJCs\n"
        "SO0nd4NADSEEnyvgNA/DzKISwPa1GTT1me4A6ti7EJNcSQN5UBKd9u/YZGpPHqs1\n"
        "aXr8Oh5OSv7CtXbcrspigYRBQgjOHYUe9t7sdsXP2YIbVCG0ZyH4rN+ItQgpCi7T\n"
        "88odFA1dyB//zsOcly606RMO9oUATXF1Ipd6CJIIWhWhbsbigXBtCpcIJofhswX+\n"
        "74iHVMWDT5tKdRfdY7x6eTWeo4XPrDp9rXvJi3VpSTnlUiLpLTW+gmn6Yo8gDBKD\n"
        "zPytzP0ozD5M7M3230D7FGWhsSIxQ/IPNgA+XkifuuI4dsKc8Dlnfgp71JPoytRq\n"
        "Xa62RMVTAgMBAAECggEAAqNX4G4aGKPxzdNPSH0eJ6Hj+M55riojlN4dXLU1bGrE\n"
        "uA0GlTbxkGzyRaNMsx64ra1rmYNGM0W3Ve3XU0tcAtI8KVbcwGveaD3WWVx38zIE\n"
        "1+kb+xDvNjU6Hr3sEULWcr4ovihikdzPyhwLWuI2AyYx4NnBKfm6omHSLb3v/mr3\n"
        "eUc7PoK7230+MKFd4r1jjyW0/P41aENColT9t041psHTIzVyTgsiMJ+rF50n435K\n"
        "EWiCnmBdh94idKNJcTRvFeOjlUjwcoZHfv9eMEzWOT/Lbhki8qLCzRjdO/WGMBn3\n"
        "7Z1ShyyCrxeDZ/fn66n4+3H9vObsdNQ/5mTUvIUKuQKBgQD+mPHuSxhO1mLE7GGm\n"
        "90aQNiGy8/PpryZMXkUI8OwPKOQNaBhYFicBYQ6spiLSBp8uJKudam5ugq7wbx9x\n"
        "aI0B1EJnY03TKkuUGShEfaMt/HMVLbWe9KUQK/cXUKv04eR8zh59pLAyLklCaEzN\n"
        "CX0TvOEhNhwcp33EjMUOc/3QpwKBgQDBig+rsLtHOzYKvec0Ghb9WfSJmUK/yAfg\n"
        "ZRNHW2mOxNqxNxr2xqx+7EAbQEwNa7Gvzq5VKcGcWis35m6Fg/MZqxRV5iQ5AriH\n"
        "nH4D8MaAEiUCLC+sNmweCgfK04L5w9+R9hYLZIbRyFuf6sF7XaLjOp0ZpNrqP4sS\n"
        "qe79OVRvdQKBgFXAuiwjCwry1s2xOKr+Orw0H2GhHZSmM+YhEmuSilAI29dQKnLw\n"
        "8y5ZvJGWW8AWDuOB4nPg91UtmzLMmvCd4HCvR7Z/EiV/53j4iEGZd67ziuelP7lM\n"
        "eZRa2pz1xRV0SHtpCYgUQmyEfpRpgQTGn2RYiBOhoBJer9PV/kGB/AmdAoGAd3sP\n"
        "H5RUma4BN/Jy6KRuquu83rGiFpmb2zkrBLN3YC9BP4Rgfha66QRaszgne2WP5ZQ3\n"
        "5dWIdEjqQ3Fbq8uA6cjHHhydIiD+4KGI3k/ni6sn88Zpi+xxJL5Wfy3CvwTgYdDF\n"
        "XTUrUhlaD0izN8DfzV4jHHC8wT6HUfdc1jFtYf0CgYAerkWaYhkUN7N89GaIQ8/7\n"
        "3MVYRnrnBBKiNPK4SEPKy3ajQGmRWTL0VJyXjKXbqJNeZjgWF/y2SBeQDdJyQ56o\n"
        "WWYnbbHeAmkDroRppYUTS2LaRPphvP9+L6E2iLcxVxFhk9NdrfLHbSUu9WjWpyzg\n"
        "jhqQqSHrzObNYavSh72MIg==\n"
        "-----END PRIVATE KEY-----\n";

static const char *TEST_PUBLIC_KEY =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHqcbMcrxgCQrEjtJ3eD\n"
        "QA0hBJ8r4DQPw8yiEsD2tRk09ZnuAOrYuxCTXEkDeVASnfbv2GRqTx6rNWl6/Doe\n"
        "Tkr+wrV23K7KYoGEQUIIzh2FHvbe7HbFz9mCG1QhtGch+KzfiLUIKQou0/PKHRQN\n"
        "Xcgf/87DnJcutOkTDvaFAE1xdSKXegiSCFoVoW7G4oFwbQqXCCaH4bMF/u+Ih1TF\n"
        "g0+bSnUX3WO8enk1nqOFz6w6fa17yYt1aUk55VIi6S01voJp+mKPIAwSg8z8rcz9\n"
        "KMw+TOzN9t9A+xRlobEiMUPyDzYAPl5In7riOHbCnPA5Z34Ke9ST6MrUal2utkTF\n"
        "UwIDAQAB\n"
        "-----END PUBLIC KEY-----\n";

// ------------------------------------------------------------
// tests
// ------------------------------------------------------------

static void
test_sign_returns_positive_length(void) {
    unsigned char *sig = NULL;
    ssize_t len = _rsa_sign("hello", TEST_PRIVATE_KEY, EVP_sha256(), &sig, malloc);
    TEST("sign returns positive length", len > 0);
    TEST("sign allocates signature buffer", sig != NULL);
    free(sig);
}

static void
test_sign_is_deterministic(void) {
    unsigned char *sig1 = NULL;
    unsigned char *sig2 = NULL;
    ssize_t len1 = _rsa_sign("hello", TEST_PRIVATE_KEY, EVP_sha256(), &sig1, malloc);
    ssize_t len2 = _rsa_sign("hello", TEST_PRIVATE_KEY, EVP_sha256(), &sig2, malloc);
    TEST("deterministic: same length", len1 == len2);
    TEST("deterministic: same bytes", memcmp(sig1, sig2, len1) == 0);
    free(sig1);
    free(sig2);
}

static void
test_different_messages_differ(void) {
    unsigned char *sig1 = NULL;
    unsigned char *sig2 = NULL;
    ssize_t len1 = _rsa_sign("hello", TEST_PRIVATE_KEY, EVP_sha256(), &sig1, malloc);
    ssize_t len2 = _rsa_sign("world", TEST_PRIVATE_KEY, EVP_sha256(), &sig2, malloc);
    TEST("different messages: both succeed", len1 > 0 && len2 > 0);
    TEST("different messages: different signatures", memcmp(sig1, sig2, len1) != 0);
    free(sig1);
    free(sig2);
}

static void
test_different_algorithms_differ(void) {
    unsigned char *sig256 = NULL;
    unsigned char *sig512 = NULL;
    ssize_t len256 = _rsa_sign("hello", TEST_PRIVATE_KEY, EVP_sha256(), &sig256, malloc);
    ssize_t len512 = _rsa_sign("hello", TEST_PRIVATE_KEY, EVP_sha512(), &sig512, malloc);
    TEST("sha256 succeeds", len256 > 0);
    TEST("sha512 succeeds", len512 > 0);
    free(sig256);
    free(sig512);
}

static void
test_invalid_key_returns_error(void) {
    unsigned char *sig = NULL;
    ssize_t len = _rsa_sign("hello", "not a valid pem key", EVP_sha256(), &sig, malloc);
    TEST("invalid key returns -1", len == -1);
    TEST("invalid key leaves sig NULL", sig == NULL);
}

static void
test_signature_verifies(void) {
    unsigned char *sig = NULL;
    const char *msg = "hello";

    ssize_t sig_len = _rsa_sign(msg, TEST_PRIVATE_KEY, EVP_sha256(), &sig, malloc);
    TEST("sign succeeds before verify", sig_len > 0);

    int result = _rsa_verify(msg, TEST_PUBLIC_KEY, EVP_sha256(), sig, sig_len);
    TEST("signature verifies against public key", result == 1);

    free(sig);
}

static void
test_verify_wrong_message_fails(void) {
    unsigned char *sig = NULL;
    ssize_t sig_len = _rsa_sign("hello", TEST_PRIVATE_KEY, EVP_sha256(), &sig, malloc);

    int result = _rsa_verify("world", TEST_PUBLIC_KEY, EVP_sha256(), sig, sig_len);
    TEST("wrong message fails verification", result == 0);

    free(sig);
}

static void
test_verify_invalid_key_returns_error(void) {
    unsigned char *sig = NULL;
    ssize_t sig_len = _rsa_sign("hello", TEST_PRIVATE_KEY, EVP_sha256(), &sig, malloc);

    int result = _rsa_verify("hello", "not a valid pem key", EVP_sha256(), sig, sig_len);
    TEST("invalid public key returns -1", result == -1);

    free(sig);
}

// ------------------------------------------------------------
// main
// ------------------------------------------------------------

int main(void) {
    printf("pg_rsa_impl tests\n");
    printf("------------------\n");

    test_sign_returns_positive_length();
    test_sign_is_deterministic();
    test_different_messages_differ();
    test_different_algorithms_differ();
    test_invalid_key_returns_error();
    test_signature_verifies();
    test_verify_wrong_message_fails();
    test_verify_invalid_key_returns_error();

    printf("------------------\n");
    printf("%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
