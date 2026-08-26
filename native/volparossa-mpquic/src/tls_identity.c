// SPDX-License-Identifier: GPL-3.0-only

#include "tls_identity.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <stdbool.h>
#include <string.h>

_Static_assert(VMP_CERTIFICATE_SHA256_LEN == VMP_SPKI_SHA256_LEN,
               "certificate and SPKI digests must have equal lengths");

static const uint8_t VMP_CERTIFICATE_PEM_BEGIN[] =
    "-----BEGIN CERTIFICATE-----";
static const uint8_t VMP_PRIVATE_KEY_PEM_BEGIN[] =
    "-----BEGIN PRIVATE KEY-----";
static const uint8_t VMP_RSA_PRIVATE_KEY_PEM_BEGIN[] =
    "-----BEGIN RSA PRIVATE KEY-----";
static const uint8_t VMP_EC_PRIVATE_KEY_PEM_BEGIN[] =
    "-----BEGIN EC PRIVATE KEY-----";

static bool marshal_certificate(const X509 *certificate, uint8_t **out_der,
                                size_t *out_der_len);

static bool is_pem_whitespace(uint8_t byte)
{
    return byte == (uint8_t)' ' || byte == (uint8_t)'\t' ||
           byte == (uint8_t)'\r' || byte == (uint8_t)'\n';
}

static bool starts_with_after_whitespace(const uint8_t *bytes, size_t length,
                                         const uint8_t *prefix,
                                         size_t prefix_length)
{
    size_t offset = 0U;
    while (offset < length && is_pem_whitespace(bytes[offset])) ++offset;
    return prefix_length <= length - offset &&
           memcmp(&bytes[offset], prefix, prefix_length) == 0;
}

static bool starts_with_private_key(const uint8_t *bytes, size_t length)
{
    return starts_with_after_whitespace(
               bytes, length, VMP_PRIVATE_KEY_PEM_BEGIN,
               sizeof(VMP_PRIVATE_KEY_PEM_BEGIN) - 1U) ||
           starts_with_after_whitespace(
               bytes, length, VMP_RSA_PRIVATE_KEY_PEM_BEGIN,
               sizeof(VMP_RSA_PRIVATE_KEY_PEM_BEGIN) - 1U) ||
           starts_with_after_whitespace(
               bytes, length, VMP_EC_PRIVATE_KEY_PEM_BEGIN,
               sizeof(VMP_EC_PRIVATE_KEY_PEM_BEGIN) - 1U);
}

static bool bio_remainder_is_whitespace(BIO *bio)
{
    uint8_t buffer[128];
    bool valid = true;
    while (BIO_ctrl_pending(bio) > 0U) {
        const int read_count = BIO_read(bio, buffer, (int)sizeof(buffer));
        if (read_count <= 0) {
            valid = false;
            break;
        }
        for (int index = 0; index < read_count; ++index) {
            if (!is_pem_whitespace(buffer[(size_t)index])) valid = false;
        }
    }
    OPENSSL_cleanse(buffer, sizeof(buffer));
    return valid;
}

static X509 *read_exact_certificate(BIO *bio)
{
    char *pem_name = NULL;
    char *pem_header = NULL;
    uint8_t *der = NULL;
    long der_length = 0;
    X509 *certificate = NULL;

    if (PEM_read_bio(bio, &pem_name, &pem_header, &der, &der_length) != 1 ||
        pem_name == NULL || pem_header == NULL || der == NULL ||
        der_length <= 0 || strcmp(pem_name, PEM_STRING_X509) != 0 ||
        pem_header[0] != '\0') {
        goto cleanup;
    }

    const uint8_t *cursor = der;
    certificate = d2i_X509(NULL, &cursor, der_length);
    uint8_t *canonical_der = NULL;
    size_t canonical_der_len = 0U;
    const bool canonical =
        certificate != NULL && cursor == &der[(size_t)der_length] &&
        marshal_certificate(certificate, &canonical_der,
                            &canonical_der_len) &&
        canonical_der_len == (size_t)der_length &&
        CRYPTO_memcmp(canonical_der, der, canonical_der_len) == 0;
    if (canonical_der != NULL) {
        OPENSSL_cleanse(canonical_der, canonical_der_len);
        OPENSSL_free(canonical_der);
    }
    if (!canonical) {
        X509_free(certificate);
        certificate = NULL;
    }

cleanup:
    if (der != NULL) {
        const size_t wipe_length = der_length > 0 ? (size_t)der_length : 0U;
        OPENSSL_cleanse(der, wipe_length);
        OPENSSL_free(der);
    }
    if (pem_header != NULL) {
        OPENSSL_cleanse(pem_header, strlen(pem_header));
        OPENSSL_free(pem_header);
    }
    OPENSSL_free(pem_name);
    return certificate;
}

static bool certificate_chain_remainder_is_valid(BIO *bio)
{
    for (;;) {
        const uint8_t *remaining = NULL;
        size_t remaining_length = 0U;
        if (BIO_mem_contents(bio, &remaining, &remaining_length) != 1) {
            return false;
        }
        if (remaining_length > 0U && remaining == NULL) return false;
        size_t offset = 0U;
        while (offset < remaining_length &&
               is_pem_whitespace(remaining[offset])) {
            ++offset;
        }
        if (offset == remaining_length) return true;
        if (!starts_with_after_whitespace(
                remaining, remaining_length, VMP_CERTIFICATE_PEM_BEGIN,
                sizeof(VMP_CERTIFICATE_PEM_BEGIN) - 1U)) {
            return false;
        }

        const size_t before = remaining_length;
        X509 *chain_certificate = read_exact_certificate(bio);
        if (chain_certificate == NULL) return false;
        X509_free(chain_certificate);
        if (BIO_ctrl_pending(bio) >= before) return false;
    }
}

static bool dns_name_is_ipv4_literal(const char *name, size_t length)
{
    size_t index = 0U;
    unsigned int component_count = 0U;

    while (index < length) {
        const size_t component_start = index;
        unsigned int value = 0U;
        while (index < length && name[index] != '.') {
            const uint8_t byte = (uint8_t)name[index];
            if (byte < (uint8_t)'0' || byte > (uint8_t)'9' ||
                index - component_start >= 3U) {
                return false;
            }
            value = (value * 10U) + (unsigned int)(byte - (uint8_t)'0');
            ++index;
        }
        const size_t component_length = index - component_start;
        if (component_length == 0U || value > 255U ||
            (component_length > 1U && name[component_start] == '0')) {
            return false;
        }
        ++component_count;
        if (index == length) break;
        ++index;
    }
    return component_count == 4U;
}

static bool dns_name_is_valid(const char *name, size_t length)
{
    if (name == NULL || length == 0U ||
        length > VMP_TLS_IDENTITY_MAX_DNS_NAME_LEN) {
        return false;
    }
    size_t label_length = 0U;
    bool contains_dot = false;
    for (size_t index = 0U; index < length; ++index) {
        const uint8_t byte = (uint8_t)name[index];
        if (byte == (uint8_t)'.') {
            if (label_length == 0U || label_length > 63U ||
                name[index - 1U] == '-') {
                return false;
            }
            contains_dot = true;
            label_length = 0U;
            continue;
        }
        const bool alpha =
            byte >= (uint8_t)'a' && byte <= (uint8_t)'z';
        const bool digit = byte >= (uint8_t)'0' && byte <= (uint8_t)'9';
        if ((!alpha && !digit && byte != (uint8_t)'-') ||
            (label_length == 0U && byte == (uint8_t)'-')) {
            return false;
        }
        ++label_length;
        if (label_length > 63U) return false;
    }
    return contains_dot && label_length > 0U && name[length - 1U] != '-' &&
           !dns_name_is_ipv4_literal(name, length);
}

static bool sha256_bytes(const uint8_t *bytes, size_t length,
                         uint8_t out[VMP_TLS_IDENTITY_SHA256_LEN])
{
    SHA256_CTX context;
    OPENSSL_cleanse(&context, sizeof(context));
    const bool ok = SHA256_Init(&context) == 1 &&
                    SHA256_Update(&context, bytes, length) == 1 &&
                    SHA256_Final(out, &context) == 1;
    OPENSSL_cleanse(&context, sizeof(context));
    if (!ok) OPENSSL_cleanse(out, VMP_TLS_IDENTITY_SHA256_LEN);
    return ok;
}

static bool marshal_certificate(const X509 *certificate, uint8_t **out_der,
                                size_t *out_der_len)
{
    *out_der = NULL;
    *out_der_len = 0U;
    const int encoded_length = i2d_X509(certificate, NULL);
    if (encoded_length <= 0) return false;
    uint8_t *der = OPENSSL_malloc((size_t)encoded_length);
    if (der == NULL) return false;
    uint8_t *cursor = der;
    const int written = i2d_X509(certificate, &cursor);
    if (written != encoded_length ||
        cursor != &der[(size_t)encoded_length]) {
        OPENSSL_cleanse(der, (size_t)encoded_length);
        OPENSSL_free(der);
        return false;
    }
    *out_der = der;
    *out_der_len = (size_t)encoded_length;
    return true;
}

static bool marshal_spki(const X509 *certificate, uint8_t **out_der,
                         size_t *out_der_len)
{
    *out_der = NULL;
    *out_der_len = 0U;
    const EVP_PKEY *public_key = X509_get0_pubkey(certificate);
    if (public_key == NULL) return false;
    const int encoded_length = i2d_PUBKEY(public_key, NULL);
    if (encoded_length <= 0) return false;
    uint8_t *der = OPENSSL_malloc((size_t)encoded_length);
    if (der == NULL) return false;
    uint8_t *cursor = der;
    const int written = i2d_PUBKEY(public_key, &cursor);
    if (written != encoded_length ||
        cursor != &der[(size_t)encoded_length]) {
        OPENSSL_cleanse(der, (size_t)encoded_length);
        OPENSSL_free(der);
        return false;
    }
    *out_der = der;
    *out_der_len = (size_t)encoded_length;
    return true;
}

static int reject_password(char *buffer, int size, int read_write,
                           void *userdata)
{
    (void)read_write;
    (void)userdata;
    if (buffer != NULL && size > 0) OPENSSL_cleanse(buffer, (size_t)size);
    return 0;
}

vmp_tls_identity_result_t vmp_tls_identity_verify(
    const vmp_tls_identity_inputs_t *inputs)
{
    const bool error_mark_set = ERR_set_mark() == 1;
    vmp_tls_identity_result_t result = VMP_TLS_IDENTITY_INVALID_ARGUMENT;
    uint8_t *certificate_copy = NULL;
    uint8_t *private_key_copy = NULL;
    BIO *certificate_bio = NULL;
    BIO *private_key_bio = NULL;
    X509 *certificate = NULL;
    EVP_PKEY *private_key = NULL;
    uint8_t *certificate_der = NULL;
    size_t certificate_der_len = 0U;
    uint8_t *spki_der = NULL;
    size_t spki_der_len = 0U;
    uint8_t actual_digest[VMP_TLS_IDENTITY_SHA256_LEN];
    OPENSSL_cleanse(actual_digest, sizeof(actual_digest));

    if (inputs == NULL || inputs->certificate_pem == NULL ||
        inputs->certificate_pem_len == 0U ||
        inputs->private_key_pem == NULL ||
        inputs->private_key_pem_len == 0U ||
        inputs->effective_now_unix_seconds >
            inputs->route_expiry_unix_seconds) {
        goto cleanup;
    }
    if (inputs->certificate_pem_len >
        VMP_TLS_IDENTITY_MAX_CERTIFICATE_PEM_LEN) {
        result = VMP_TLS_IDENTITY_CERTIFICATE_TOO_LARGE;
        goto cleanup;
    }
    if (inputs->private_key_pem_len >
        VMP_TLS_IDENTITY_MAX_PRIVATE_KEY_PEM_LEN) {
        result = VMP_TLS_IDENTITY_PRIVATE_KEY_TOO_LARGE;
        goto cleanup;
    }
    if (!dns_name_is_valid(inputs->expected_dns_name,
                           inputs->expected_dns_name_len)) {
        result = VMP_TLS_IDENTITY_DNS_NAME_INVALID;
        goto cleanup;
    }

    certificate_copy = OPENSSL_malloc(inputs->certificate_pem_len);
    private_key_copy = OPENSSL_malloc(inputs->private_key_pem_len);
    if (certificate_copy == NULL || private_key_copy == NULL) {
        result = VMP_TLS_IDENTITY_OUT_OF_MEMORY;
        goto cleanup;
    }
    memcpy(certificate_copy, inputs->certificate_pem,
           inputs->certificate_pem_len);
    memcpy(private_key_copy, inputs->private_key_pem,
           inputs->private_key_pem_len);

    if (!starts_with_after_whitespace(
            certificate_copy, inputs->certificate_pem_len,
            VMP_CERTIFICATE_PEM_BEGIN,
            sizeof(VMP_CERTIFICATE_PEM_BEGIN) - 1U)) {
        result = VMP_TLS_IDENTITY_CERTIFICATE_MALFORMED;
        goto cleanup;
    }
    certificate_bio = BIO_new_mem_buf(
        certificate_copy, (ossl_ssize_t)inputs->certificate_pem_len);
    if (certificate_bio == NULL) {
        result = VMP_TLS_IDENTITY_OUT_OF_MEMORY;
        goto cleanup;
    }
    certificate = read_exact_certificate(certificate_bio);
    if (certificate == NULL) {
        result = VMP_TLS_IDENTITY_CERTIFICATE_MALFORMED;
        goto cleanup;
    }
    if (!certificate_chain_remainder_is_valid(certificate_bio)) {
        result = VMP_TLS_IDENTITY_CERTIFICATE_TRAILING_DATA;
        goto cleanup;
    }

    if (!starts_with_private_key(private_key_copy,
                                 inputs->private_key_pem_len)) {
        result = VMP_TLS_IDENTITY_PRIVATE_KEY_MALFORMED;
        goto cleanup;
    }
    private_key_bio = BIO_new_mem_buf(
        private_key_copy, (ossl_ssize_t)inputs->private_key_pem_len);
    if (private_key_bio == NULL) {
        result = VMP_TLS_IDENTITY_OUT_OF_MEMORY;
        goto cleanup;
    }
    private_key = PEM_read_bio_PrivateKey(private_key_bio, NULL,
                                          reject_password, NULL);
    if (private_key == NULL) {
        result = VMP_TLS_IDENTITY_PRIVATE_KEY_MALFORMED;
        goto cleanup;
    }
    if (!bio_remainder_is_whitespace(private_key_bio)) {
        result = VMP_TLS_IDENTITY_PRIVATE_KEY_TRAILING_DATA;
        goto cleanup;
    }
    if (X509_check_private_key(certificate, private_key) != 1) {
        result = VMP_TLS_IDENTITY_PRIVATE_KEY_MISMATCH;
        goto cleanup;
    }

    const unsigned int hostname_flags =
        X509_CHECK_FLAG_NO_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT;
    if (X509_check_host(certificate, inputs->expected_dns_name,
                        inputs->expected_dns_name_len, hostname_flags,
                        NULL) != 1) {
        result = VMP_TLS_IDENTITY_DNS_SAN_MISMATCH;
        goto cleanup;
    }

    const ASN1_TIME *not_before_time = X509_get0_notBefore(certificate);
    const ASN1_TIME *not_after_time = X509_get0_notAfter(certificate);
    int64_t not_before = 0;
    int64_t not_after = 0;
    if (not_before_time == NULL || not_after_time == NULL ||
        ASN1_TIME_to_posix(not_before_time, &not_before) != 1 ||
        ASN1_TIME_to_posix(not_after_time, &not_after) != 1 ||
        not_before > not_after) {
        result = VMP_TLS_IDENTITY_VALIDITY_MALFORMED;
        goto cleanup;
    }
    if (inputs->effective_now_unix_seconds < not_before) {
        result = VMP_TLS_IDENTITY_NOT_YET_VALID;
        goto cleanup;
    }
    if (inputs->route_expiry_unix_seconds > not_after) {
        result = VMP_TLS_IDENTITY_EXPIRED;
        goto cleanup;
    }

    if (!marshal_certificate(certificate, &certificate_der,
                             &certificate_der_len) ||
        !sha256_bytes(certificate_der, certificate_der_len, actual_digest)) {
        result = VMP_TLS_IDENTITY_CRYPTO_FAILURE;
        goto cleanup;
    }
    if (CRYPTO_memcmp(actual_digest, inputs->certificate_sha256,
                      sizeof(actual_digest)) != 0) {
        result = VMP_TLS_IDENTITY_CERTIFICATE_DIGEST_MISMATCH;
        goto cleanup;
    }
    OPENSSL_cleanse(actual_digest, sizeof(actual_digest));

    if (!marshal_spki(certificate, &spki_der, &spki_der_len) ||
        !sha256_bytes(spki_der, spki_der_len, actual_digest)) {
        result = VMP_TLS_IDENTITY_CRYPTO_FAILURE;
        goto cleanup;
    }
    if (CRYPTO_memcmp(actual_digest, inputs->exit_spki_sha256,
                      sizeof(actual_digest)) != 0) {
        result = VMP_TLS_IDENTITY_SPKI_DIGEST_MISMATCH;
        goto cleanup;
    }
    result = VMP_TLS_IDENTITY_OK;

cleanup:
    OPENSSL_cleanse(actual_digest, sizeof(actual_digest));
    if (spki_der != NULL) {
        OPENSSL_cleanse(spki_der, spki_der_len);
        OPENSSL_free(spki_der);
    }
    if (certificate_der != NULL) {
        OPENSSL_cleanse(certificate_der, certificate_der_len);
        OPENSSL_free(certificate_der);
    }
    EVP_PKEY_free(private_key);
    X509_free(certificate);
    BIO_free(private_key_bio);
    BIO_free(certificate_bio);
    if (private_key_copy != NULL) {
        OPENSSL_cleanse(private_key_copy, inputs->private_key_pem_len);
        OPENSSL_free(private_key_copy);
    }
    if (certificate_copy != NULL) {
        OPENSSL_cleanse(certificate_copy, inputs->certificate_pem_len);
        OPENSSL_free(certificate_copy);
    }
    if (error_mark_set) {
        (void)ERR_pop_to_mark();
    } else {
        ERR_clear_error();
    }
    return result;
}
