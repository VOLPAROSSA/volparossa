// SPDX-License-Identifier: GPL-3.0-only

#include "tls_identity.h"

#include <openssl/bio.h>
#include <openssl/bytestring.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define TEST_VERIFICATION_TIME INT64_C(1800000000)
#define TEST_NOT_BEFORE INT64_C(1700000000)
#define TEST_NOT_AFTER INT64_C(1900000000)

typedef struct test_identity_fixture {
    uint8_t *certificate_pem;
    size_t certificate_pem_len;
    uint8_t *private_key_pem;
    size_t private_key_pem_len;
    uint8_t certificate_sha256[VMP_TLS_IDENTITY_SHA256_LEN];
    uint8_t spki_sha256[VMP_TLS_IDENTITY_SHA256_LEN];
} test_identity_fixture_t;

static EVP_PKEY *generate_key(void)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    assert(context != NULL);
    assert(EVP_PKEY_keygen_init(context) == 1);
    assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
               context, NID_X9_62_prime256v1) == 1);
    EVP_PKEY *key = NULL;
    assert(EVP_PKEY_keygen(context, &key) == 1);
    assert(key != NULL);
    EVP_PKEY_CTX_free(context);
    return key;
}

static void copy_bio_contents(BIO *bio, uint8_t **out, size_t *out_len)
{
    const uint8_t *contents = NULL;
    size_t contents_len = 0U;
    assert(BIO_mem_contents(bio, &contents, &contents_len) == 1);
    assert(contents != NULL);
    assert(contents_len > 0U);
    uint8_t *copy = OPENSSL_malloc(contents_len);
    assert(copy != NULL);
    memcpy(copy, contents, contents_len);
    *out = copy;
    *out_len = contents_len;
}

static void sha256_certificate_and_spki(
    const X509 *certificate,
    uint8_t certificate_sha256[VMP_TLS_IDENTITY_SHA256_LEN],
    uint8_t spki_sha256[VMP_TLS_IDENTITY_SHA256_LEN])
{
    int der_length = i2d_X509(certificate, NULL);
    assert(der_length > 0);
    uint8_t *der = OPENSSL_malloc((size_t)der_length);
    assert(der != NULL);
    uint8_t *cursor = der;
    assert(i2d_X509(certificate, &cursor) == der_length);
    assert(cursor == &der[(size_t)der_length]);
    assert(SHA256(der, (size_t)der_length, certificate_sha256) ==
           certificate_sha256);
    OPENSSL_cleanse(der, (size_t)der_length);
    OPENSSL_free(der);

    const EVP_PKEY *public_key = X509_get0_pubkey(certificate);
    assert(public_key != NULL);
    der_length = i2d_PUBKEY(public_key, NULL);
    assert(der_length > 0);
    der = OPENSSL_malloc((size_t)der_length);
    assert(der != NULL);
    cursor = der;
    assert(i2d_PUBKEY(public_key, &cursor) == der_length);
    assert(cursor == &der[(size_t)der_length]);
    assert(SHA256(der, (size_t)der_length, spki_sha256) == spki_sha256);
    OPENSSL_cleanse(der, (size_t)der_length);
    OPENSSL_free(der);
}

static test_identity_fixture_t make_fixture(const char *common_name,
                                            const char *dns_san,
                                            int64_t not_before,
                                            int64_t not_after)
{
    test_identity_fixture_t fixture;
    OPENSSL_cleanse(&fixture, sizeof(fixture));
    EVP_PKEY *key = generate_key();
    X509 *certificate = X509_new();
    assert(certificate != NULL);
    assert(X509_set_version(certificate, 2L) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1L) == 1);
    assert(ASN1_TIME_set_posix(X509_getm_notBefore(certificate), not_before) !=
           NULL);
    assert(ASN1_TIME_set_posix(X509_getm_notAfter(certificate), not_after) !=
           NULL);
    assert(X509_set_pubkey(certificate, key) == 1);

    X509_NAME *subject = X509_get_subject_name(certificate);
    assert(subject != NULL);
    assert(X509_NAME_add_entry_by_txt(
               subject, "CN", MBSTRING_ASC,
               (const uint8_t *)(const void *)common_name, -1, -1, 0) == 1);
    assert(X509_set_issuer_name(certificate, subject) == 1);

    if (dns_san != NULL) {
        const size_t dns_san_len = strlen(dns_san);
        assert(dns_san_len <= VMP_TLS_IDENTITY_MAX_DNS_NAME_LEN);
        GENERAL_NAMES *names = GENERAL_NAMES_new();
        GENERAL_NAME *name = GENERAL_NAME_new();
        ASN1_IA5STRING *dns = ASN1_IA5STRING_new();
        assert(names != NULL);
        assert(name != NULL);
        assert(dns != NULL);
        assert(ASN1_STRING_set(dns, dns_san, (int)dns_san_len) == 1);
        GENERAL_NAME_set0_value(name, GEN_DNS, dns);
        dns = NULL;
        assert(sk_GENERAL_NAME_push(names, name) != 0);
        name = NULL;
        assert(X509_add1_ext_i2d(certificate, NID_subject_alt_name, names, 0,
                                 X509V3_ADD_DEFAULT) == 1);
        ASN1_IA5STRING_free(dns);
        GENERAL_NAME_free(name);
        GENERAL_NAMES_free(names);
    }
    assert(X509_sign(certificate, key, EVP_sha256()) > 0);

    BIO *certificate_bio = BIO_new(BIO_s_mem());
    BIO *private_key_bio = BIO_new(BIO_s_mem());
    assert(certificate_bio != NULL);
    assert(private_key_bio != NULL);
    assert(PEM_write_bio_X509(certificate_bio, certificate) == 1);
    assert(PEM_write_bio_PrivateKey(private_key_bio, key, NULL, NULL, 0,
                                    NULL, NULL) == 1);
    copy_bio_contents(certificate_bio, &fixture.certificate_pem,
                      &fixture.certificate_pem_len);
    copy_bio_contents(private_key_bio, &fixture.private_key_pem,
                      &fixture.private_key_pem_len);
    sha256_certificate_and_spki(certificate, fixture.certificate_sha256,
                                fixture.spki_sha256);

    BIO_free(private_key_bio);
    BIO_free(certificate_bio);
    X509_free(certificate);
    EVP_PKEY_free(key);
    return fixture;
}

static void fixture_wipe(test_identity_fixture_t *fixture)
{
    if (fixture->private_key_pem != NULL) {
        OPENSSL_cleanse(fixture->private_key_pem,
                        fixture->private_key_pem_len);
        OPENSSL_free(fixture->private_key_pem);
    }
    if (fixture->certificate_pem != NULL) {
        OPENSSL_cleanse(fixture->certificate_pem,
                        fixture->certificate_pem_len);
        OPENSSL_free(fixture->certificate_pem);
    }
    OPENSSL_cleanse(fixture, sizeof(*fixture));
}

static vmp_tls_identity_inputs_t make_inputs(
    const test_identity_fixture_t *fixture, const char *dns_name,
    int64_t effective_now)
{
    vmp_tls_identity_inputs_t inputs;
    OPENSSL_cleanse(&inputs, sizeof(inputs));
    inputs.certificate_pem = fixture->certificate_pem;
    inputs.certificate_pem_len = fixture->certificate_pem_len;
    inputs.private_key_pem = fixture->private_key_pem;
    inputs.private_key_pem_len = fixture->private_key_pem_len;
    inputs.expected_dns_name = dns_name;
    inputs.expected_dns_name_len = strlen(dns_name);
    inputs.effective_now_unix_seconds = effective_now;
    inputs.route_expiry_unix_seconds = effective_now;
    memcpy(inputs.certificate_sha256, fixture->certificate_sha256,
           sizeof(inputs.certificate_sha256));
    memcpy(inputs.exit_spki_sha256, fixture->spki_sha256,
           sizeof(inputs.exit_spki_sha256));
    return inputs;
}

static uint8_t *concatenate(const uint8_t *first, size_t first_len,
                            const uint8_t *second, size_t second_len)
{
    assert(first_len <= SIZE_MAX - second_len);
    uint8_t *combined = OPENSSL_malloc(first_len + second_len);
    assert(combined != NULL);
    memcpy(combined, first, first_len);
    memcpy(&combined[first_len], second, second_len);
    return combined;
}

static uint8_t *certificate_pem_with_trailing_der_byte(
    const test_identity_fixture_t *fixture, size_t *out_len)
{
    BIO *source = BIO_new_mem_buf(fixture->certificate_pem,
                                  (ossl_ssize_t)fixture->certificate_pem_len);
    assert(source != NULL);
    X509 *certificate = PEM_read_bio_X509(source, NULL, NULL, NULL);
    assert(certificate != NULL);

    const int der_length = i2d_X509(certificate, NULL);
    assert(der_length > 0);
    uint8_t *der = OPENSSL_malloc((size_t)der_length + 1U);
    assert(der != NULL);
    uint8_t *cursor = der;
    assert(i2d_X509(certificate, &cursor) == der_length);
    assert(cursor == &der[(size_t)der_length]);
    der[(size_t)der_length] = 0xa5U;

    BIO *output = BIO_new(BIO_s_mem());
    assert(output != NULL);
    assert(PEM_write_bio(output, PEM_STRING_X509, "", der,
                         (long)der_length + 1L) > 0);
    uint8_t *pem = NULL;
    copy_bio_contents(output, &pem, out_len);

    BIO_free(output);
    OPENSSL_cleanse(der, (size_t)der_length + 1U);
    OPENSSL_free(der);
    X509_free(certificate);
    BIO_free(source);
    return pem;
}

static uint8_t *certificate_pem_with_nonminimal_signature_length(
    const test_identity_fixture_t *fixture, size_t *out_len)
{
    BIO *source = BIO_new_mem_buf(fixture->certificate_pem,
                                  (ossl_ssize_t)fixture->certificate_pem_len);
    assert(source != NULL);
    X509 *certificate = PEM_read_bio_X509(source, NULL, NULL, NULL);
    assert(certificate != NULL);

    const int der_length = i2d_X509(certificate, NULL);
    assert(der_length > 3);
    uint8_t *der = OPENSSL_malloc((size_t)der_length);
    assert(der != NULL);
    uint8_t *cursor = der;
    assert(i2d_X509(certificate, &cursor) == der_length);
    assert(cursor == &der[(size_t)der_length]);
    CBS encoded;
    CBS certificate_contents;
    CBS tbs_certificate;
    CBS signature_algorithm;
    CBS signature_value;
    CBS_init(&encoded, der, (size_t)der_length);
    assert(CBS_get_asn1(&encoded, &certificate_contents,
                        CBS_ASN1_SEQUENCE) == 1);
    assert(CBS_len(&encoded) == 0U);
    assert(CBS_get_asn1_element(&certificate_contents, &tbs_certificate,
                                CBS_ASN1_SEQUENCE) == 1);
    assert(CBS_get_asn1_element(&certificate_contents, &signature_algorithm,
                                CBS_ASN1_SEQUENCE) == 1);
    const uint8_t *signature_start = CBS_data(&certificate_contents);
    assert(CBS_get_asn1_element(&certificate_contents, &signature_value,
                                CBS_ASN1_BITSTRING) == 1);
    assert(CBS_len(&certificate_contents) == 0U);
    const size_t signature_offset = (size_t)(signature_start - der);
    assert(signature_offset + 2U < (size_t)der_length);
    assert(der[signature_offset] == 0x03U);
    assert(der[signature_offset + 1U] < 0x80U);

    assert(der[0] == 0x30U);
    assert((der[1] & 0x80U) != 0U);
    const size_t outer_length_octets = (size_t)(der[1] & 0x7fU);
    assert(outer_length_octets > 0U && outer_length_octets < 0x7eU);
    assert(2U + outer_length_octets < signature_offset);

    uint8_t *nonminimal = OPENSSL_malloc((size_t)der_length + 1U);
    assert(nonminimal != NULL);
    memcpy(nonminimal, der, signature_offset + 1U);
    nonminimal[signature_offset + 1U] = 0x81U;
    nonminimal[signature_offset + 2U] = der[signature_offset + 1U];
    memcpy(&nonminimal[signature_offset + 3U],
           &der[signature_offset + 2U],
           (size_t)der_length - signature_offset - 2U);

    unsigned int carry = 1U;
    for (size_t index = 0U; index < outer_length_octets; ++index) {
        const size_t position = 1U + outer_length_octets - index;
        const unsigned int value =
            (unsigned int)nonminimal[position] + carry;
        nonminimal[position] = (uint8_t)value;
        carry = value >> 8U;
    }
    assert(carry == 0U);

    /* The pinned BoringSSL parser deliberately accepts this historical BER
     * exception in the signature BIT STRING. The production verifier must add
     * the stricter raw-DER/canonical-i2d equality check itself. */
    const uint8_t *nonminimal_cursor = nonminimal;
    X509 *nonminimal_certificate =
        d2i_X509(NULL, &nonminimal_cursor, (long)der_length + 1L);
    assert(nonminimal_certificate != NULL);
    assert(nonminimal_cursor == &nonminimal[(size_t)der_length + 1U]);
    X509_free(nonminimal_certificate);

    BIO *output = BIO_new(BIO_s_mem());
    assert(output != NULL);
    assert(PEM_write_bio(output, PEM_STRING_X509, "", nonminimal,
                         (long)der_length + 1L) > 0);
    uint8_t *pem = NULL;
    copy_bio_contents(output, &pem, out_len);

    BIO_free(output);
    OPENSSL_cleanse(nonminimal, (size_t)der_length + 1U);
    OPENSSL_free(nonminimal);
    OPENSSL_cleanse(der, (size_t)der_length);
    OPENSSL_free(der);
    X509_free(certificate);
    BIO_free(source);
    return pem;
}

static void test_valid_identity_and_argument_bounds(
    const test_identity_fixture_t *valid)
{
    vmp_tls_identity_inputs_t inputs =
        make_inputs(valid, "exit.volparossa.test", TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) == VMP_TLS_IDENTITY_OK);
    inputs.effective_now_unix_seconds = TEST_NOT_BEFORE;
    inputs.route_expiry_unix_seconds = TEST_NOT_AFTER;
    assert(vmp_tls_identity_verify(&inputs) == VMP_TLS_IDENTITY_OK);
    assert(vmp_tls_identity_verify(NULL) == VMP_TLS_IDENTITY_INVALID_ARGUMENT);

    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.route_expiry_unix_seconds = TEST_VERIFICATION_TIME - 1;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_INVALID_ARGUMENT);

    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.certificate_pem_len =
        VMP_TLS_IDENTITY_MAX_CERTIFICATE_PEM_LEN + 1U;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_CERTIFICATE_TOO_LARGE);
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.private_key_pem_len =
        VMP_TLS_IDENTITY_MAX_PRIVATE_KEY_PEM_LEN + 1U;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_PRIVATE_KEY_TOO_LARGE);
    inputs = make_inputs(valid, "*.volparossa.test",
                         TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_NAME_INVALID);
    inputs = make_inputs(valid, "Exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_NAME_INVALID);
    inputs = make_inputs(valid, "localhost", TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_NAME_INVALID);
    inputs = make_inputs(valid, "127.0.0.1", TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_NAME_INVALID);
    inputs = make_inputs(valid, "-exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_NAME_INVALID);
    inputs = make_inputs(valid, "exit-.volparossa.test",
                         TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_NAME_INVALID);
    inputs = make_inputs(valid, "exit..volparossa.test",
                         TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_NAME_INVALID);

    char oversized_name[VMP_TLS_IDENTITY_MAX_DNS_NAME_LEN + 2U];
    memset(oversized_name, 'a', sizeof(oversized_name));
    oversized_name[sizeof(oversized_name) - 1U] = '\0';
    inputs = make_inputs(valid, oversized_name, TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_NAME_INVALID);

    char oversized_label[sizeof(".test") + 64U];
    memset(oversized_label, 'a', 64U);
    memcpy(&oversized_label[64U], ".test", sizeof(".test"));
    inputs = make_inputs(valid, oversized_label, TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_NAME_INVALID);
}

static void test_key_san_and_digest_fail_closed(
    const test_identity_fixture_t *valid,
    const test_identity_fixture_t *other_key,
    const test_identity_fixture_t *wildcard,
    const test_identity_fixture_t *common_name_only)
{
    vmp_tls_identity_inputs_t inputs =
        make_inputs(valid, "exit.volparossa.test", TEST_VERIFICATION_TIME);
    inputs.private_key_pem = other_key->private_key_pem;
    inputs.private_key_pem_len = other_key->private_key_pem_len;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_PRIVATE_KEY_MISMATCH);

    inputs = make_inputs(valid, "wrong.volparossa.test",
                         TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_SAN_MISMATCH);
    inputs = make_inputs(wildcard, "node.volparossa.test",
                         TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_SAN_MISMATCH);
    inputs = make_inputs(common_name_only, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_SAN_MISMATCH);

    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.certificate_sha256[0] ^= 1U;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_CERTIFICATE_DIGEST_MISMATCH);
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.exit_spki_sha256[0] ^= 1U;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_SPKI_DIGEST_MISMATCH);
}

static void test_explicit_validity_interval(void)
{
    test_identity_fixture_t expired = make_fixture(
        "exit.volparossa.test", "exit.volparossa.test", INT64_C(1500000000),
        INT64_C(1600000000));
    test_identity_fixture_t not_yet_valid = make_fixture(
        "exit.volparossa.test", "exit.volparossa.test", INT64_C(1900000000),
        INT64_C(2000000000));
    vmp_tls_identity_inputs_t inputs =
        make_inputs(&expired, "exit.volparossa.test", TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) == VMP_TLS_IDENTITY_EXPIRED);
    inputs = make_inputs(&not_yet_valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_NOT_YET_VALID);

    test_identity_fixture_t interval = make_fixture(
        "exit.volparossa.test", "exit.volparossa.test", TEST_NOT_BEFORE,
        TEST_NOT_AFTER);
    inputs = make_inputs(&interval, "exit.volparossa.test", TEST_NOT_BEFORE);
    inputs.route_expiry_unix_seconds = TEST_NOT_AFTER;
    assert(vmp_tls_identity_verify(&inputs) == VMP_TLS_IDENTITY_OK);
    inputs.effective_now_unix_seconds = TEST_NOT_BEFORE - 1;
    inputs.route_expiry_unix_seconds = TEST_VERIFICATION_TIME;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_NOT_YET_VALID);
    inputs.effective_now_unix_seconds = TEST_VERIFICATION_TIME;
    inputs.route_expiry_unix_seconds = TEST_NOT_AFTER + 1;
    assert(vmp_tls_identity_verify(&inputs) == VMP_TLS_IDENTITY_EXPIRED);

    test_identity_fixture_t malformed = make_fixture(
        "exit.volparossa.test", "exit.volparossa.test", TEST_NOT_AFTER,
        TEST_NOT_BEFORE);
    inputs = make_inputs(&malformed, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_VALIDITY_MALFORMED);
    fixture_wipe(&malformed);
    fixture_wipe(&interval);
    fixture_wipe(&not_yet_valid);
    fixture_wipe(&expired);
}

static void test_certificate_chain_and_malformed_material(
    const test_identity_fixture_t *valid,
    const test_identity_fixture_t *chain_element)
{
    static const uint8_t malformed[] = "not PEM";
    static const uint8_t junk[] = "JUNK";
    static const uint8_t malformed_certificate[] =
        "-----BEGIN CERTIFICATE-----\n"
        "QUFBQQ==\n"
        "-----END CERTIFICATE-----\n";
    vmp_tls_identity_inputs_t inputs =
        make_inputs(valid, "exit.volparossa.test", TEST_VERIFICATION_TIME);
    inputs.certificate_pem = malformed;
    inputs.certificate_pem_len = sizeof(malformed) - 1U;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_CERTIFICATE_MALFORMED);

    size_t trailing_der_leaf_len = 0U;
    uint8_t *trailing_der_leaf = certificate_pem_with_trailing_der_byte(
        valid, &trailing_der_leaf_len);
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.certificate_pem = trailing_der_leaf;
    inputs.certificate_pem_len = trailing_der_leaf_len;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_CERTIFICATE_MALFORMED);
    OPENSSL_cleanse(trailing_der_leaf, trailing_der_leaf_len);
    OPENSSL_free(trailing_der_leaf);

    size_t nonminimal_der_leaf_len = 0U;
    uint8_t *nonminimal_der_leaf =
        certificate_pem_with_nonminimal_signature_length(
            valid, &nonminimal_der_leaf_len);
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.certificate_pem = nonminimal_der_leaf;
    inputs.certificate_pem_len = nonminimal_der_leaf_len;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_CERTIFICATE_MALFORMED);
    OPENSSL_cleanse(nonminimal_der_leaf, nonminimal_der_leaf_len);
    OPENSSL_free(nonminimal_der_leaf);

    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.private_key_pem = malformed;
    inputs.private_key_pem_len = sizeof(malformed) - 1U;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_PRIVATE_KEY_MALFORMED);

    uint8_t *embedded_nul = OPENSSL_malloc(valid->certificate_pem_len);
    assert(embedded_nul != NULL);
    memcpy(embedded_nul, valid->certificate_pem,
           valid->certificate_pem_len);
    embedded_nul[sizeof("-----BEGIN CERTIFICATE-----") + 4U] = 0U;
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.certificate_pem = embedded_nul;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_CERTIFICATE_MALFORMED);
    OPENSSL_cleanse(embedded_nul, valid->certificate_pem_len);
    OPENSSL_free(embedded_nul);

    embedded_nul = OPENSSL_malloc(valid->private_key_pem_len);
    assert(embedded_nul != NULL);
    memcpy(embedded_nul, valid->private_key_pem,
           valid->private_key_pem_len);
    embedded_nul[sizeof("-----BEGIN PRIVATE KEY-----") + 4U] = 0U;
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.private_key_pem = embedded_nul;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_PRIVATE_KEY_MALFORMED);
    OPENSSL_cleanse(embedded_nul, valid->private_key_pem_len);
    OPENSSL_free(embedded_nul);

    static const char dns_with_nul[] = "exit\0.volparossa.test";
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.expected_dns_name = dns_with_nul;
    inputs.expected_dns_name_len = sizeof(dns_with_nul) - 1U;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_DNS_NAME_INVALID);

    uint8_t *combined = concatenate(
        valid->certificate_pem, valid->certificate_pem_len,
        chain_element->certificate_pem, chain_element->certificate_pem_len);
    const size_t chain_length = valid->certificate_pem_len +
                                chain_element->certificate_pem_len;
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.certificate_pem = combined;
    inputs.certificate_pem_len = chain_length;
    assert(vmp_tls_identity_verify(&inputs) == VMP_TLS_IDENTITY_OK);

    memcpy(inputs.certificate_sha256, chain_element->certificate_sha256,
           sizeof(inputs.certificate_sha256));
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_CERTIFICATE_DIGEST_MISMATCH);
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.certificate_pem = combined;
    inputs.certificate_pem_len = chain_length;
    memcpy(inputs.exit_spki_sha256, chain_element->spki_sha256,
           sizeof(inputs.exit_spki_sha256));
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_SPKI_DIGEST_MISMATCH);
    OPENSSL_cleanse(combined, chain_length);
    OPENSSL_free(combined);

    combined = concatenate(valid->certificate_pem,
                           valid->certificate_pem_len, junk,
                           sizeof(junk) - 1U);
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.certificate_pem = combined;
    inputs.certificate_pem_len = valid->certificate_pem_len +
                                 sizeof(junk) - 1U;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_CERTIFICATE_TRAILING_DATA);
    OPENSSL_cleanse(combined, inputs.certificate_pem_len);
    OPENSSL_free(combined);

    combined = concatenate(valid->certificate_pem,
                           valid->certificate_pem_len,
                           malformed_certificate,
                           sizeof(malformed_certificate) - 1U);
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.certificate_pem = combined;
    inputs.certificate_pem_len = valid->certificate_pem_len +
                                 sizeof(malformed_certificate) - 1U;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_CERTIFICATE_TRAILING_DATA);
    OPENSSL_cleanse(combined, inputs.certificate_pem_len);
    OPENSSL_free(combined);

    combined = concatenate(valid->certificate_pem,
                           valid->certificate_pem_len,
                           valid->private_key_pem,
                           valid->private_key_pem_len);
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.certificate_pem = combined;
    inputs.certificate_pem_len = valid->certificate_pem_len +
                                 valid->private_key_pem_len;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_CERTIFICATE_TRAILING_DATA);
    OPENSSL_cleanse(combined, inputs.certificate_pem_len);
    OPENSSL_free(combined);

    combined = concatenate(valid->private_key_pem, valid->private_key_pem_len,
                           valid->private_key_pem,
                           valid->private_key_pem_len);
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.private_key_pem = combined;
    inputs.private_key_pem_len = valid->private_key_pem_len * 2U;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_PRIVATE_KEY_TRAILING_DATA);
    OPENSSL_cleanse(combined, inputs.private_key_pem_len);
    OPENSSL_free(combined);

    combined = concatenate(valid->certificate_pem,
                           valid->certificate_pem_len,
                           valid->private_key_pem,
                           valid->private_key_pem_len);
    inputs = make_inputs(valid, "exit.volparossa.test",
                         TEST_VERIFICATION_TIME);
    inputs.private_key_pem = combined;
    inputs.private_key_pem_len = valid->certificate_pem_len +
                                 valid->private_key_pem_len;
    assert(vmp_tls_identity_verify(&inputs) ==
           VMP_TLS_IDENTITY_PRIVATE_KEY_MALFORMED);
    OPENSSL_cleanse(combined, inputs.private_key_pem_len);
    OPENSSL_free(combined);
}

int main(void)
{
    test_identity_fixture_t valid = make_fixture(
        "ignored-cn.volparossa.test", "exit.volparossa.test",
        TEST_NOT_BEFORE, TEST_NOT_AFTER);
    test_identity_fixture_t other_key = make_fixture(
        "other.volparossa.test", "other.volparossa.test", TEST_NOT_BEFORE,
        TEST_NOT_AFTER);
    test_identity_fixture_t wildcard = make_fixture(
        "ignored-cn.volparossa.test", "*.volparossa.test", TEST_NOT_BEFORE,
        TEST_NOT_AFTER);
    test_identity_fixture_t common_name_only = make_fixture(
        "exit.volparossa.test", NULL, TEST_NOT_BEFORE, TEST_NOT_AFTER);

    test_valid_identity_and_argument_bounds(&valid);
    test_key_san_and_digest_fail_closed(&valid, &other_key, &wildcard,
                                        &common_name_only);
    test_explicit_validity_interval();
    test_certificate_chain_and_malformed_material(&valid, &other_key);

    fixture_wipe(&common_name_only);
    fixture_wipe(&wildcard);
    fixture_wipe(&other_key);
    fixture_wipe(&valid);
    puts("TLS identity tests passed");
    return 0;
}
