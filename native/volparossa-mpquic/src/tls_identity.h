// SPDX-License-Identifier: GPL-3.0-only

#ifndef VOLPAROSSA_MPQUIC_TLS_IDENTITY_H
#define VOLPAROSSA_MPQUIC_TLS_IDENTITY_H

#include "volparossa_mpquic_protocol.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMP_TLS_IDENTITY_SHA256_LEN VMP_CERTIFICATE_SHA256_LEN
#define VMP_TLS_IDENTITY_MAX_CERTIFICATE_PEM_LEN \
    VMP_MAX_TLS_CERTIFICATE_PEM
#define VMP_TLS_IDENTITY_MAX_PRIVATE_KEY_PEM_LEN \
    VMP_MAX_TLS_PRIVATE_KEY_PEM
#define VMP_TLS_IDENTITY_MAX_DNS_NAME_LEN VMP_MAX_TLS_SERVER_NAME

typedef enum vmp_tls_identity_result {
    VMP_TLS_IDENTITY_OK = 0,
    VMP_TLS_IDENTITY_INVALID_ARGUMENT,
    VMP_TLS_IDENTITY_CERTIFICATE_TOO_LARGE,
    VMP_TLS_IDENTITY_PRIVATE_KEY_TOO_LARGE,
    VMP_TLS_IDENTITY_DNS_NAME_INVALID,
    VMP_TLS_IDENTITY_OUT_OF_MEMORY,
    VMP_TLS_IDENTITY_CERTIFICATE_MALFORMED,
    VMP_TLS_IDENTITY_CERTIFICATE_TRAILING_DATA,
    VMP_TLS_IDENTITY_PRIVATE_KEY_MALFORMED,
    VMP_TLS_IDENTITY_PRIVATE_KEY_TRAILING_DATA,
    VMP_TLS_IDENTITY_PRIVATE_KEY_MISMATCH,
    VMP_TLS_IDENTITY_DNS_SAN_MISMATCH,
    VMP_TLS_IDENTITY_VALIDITY_MALFORMED,
    VMP_TLS_IDENTITY_NOT_YET_VALID,
    VMP_TLS_IDENTITY_EXPIRED,
    VMP_TLS_IDENTITY_CERTIFICATE_DIGEST_MISMATCH,
    VMP_TLS_IDENTITY_SPKI_DIGEST_MISMATCH,
    VMP_TLS_IDENTITY_CRYPTO_FAILURE,
} vmp_tls_identity_result_t;

typedef struct vmp_tls_identity_inputs {
    const uint8_t *certificate_pem;
    size_t certificate_pem_len;
    const uint8_t *private_key_pem;
    size_t private_key_pem_len;
    const char *expected_dns_name;
    size_t expected_dns_name_len;
    int64_t effective_now_unix_seconds;
    int64_t route_expiry_unix_seconds;
    uint8_t certificate_sha256[VMP_TLS_IDENTITY_SHA256_LEN];
    uint8_t exit_spki_sha256[VMP_TLS_IDENTITY_SHA256_LEN];
} vmp_tls_identity_inputs_t;

/* Verifies one bounded, in-memory certificate chain and its leaf consistency.
 * The first certificate is the leaf used for the key, exact non-wildcard DNS
 * hostname match, validity, canonical complete-DER digest, and DER-SPKI digest
 * checks. DNS comparison follows X.509 hostname semantics and is therefore
 * case-insensitive even though the expected input must be canonical lowercase.
 * Every remaining object must be a fully parsed canonical-DER CERTIFICATE;
 * this function does not claim chain trust validation. The caller-supplied
 * trusted interval is used instead of wall-clock time: the leaf must already
 * be valid at effective_now and remain valid through route_expiry. This lets
 * callers bind both instants to their authenticated control request and keeps
 * tests deterministic. No input is retained. */
vmp_tls_identity_result_t vmp_tls_identity_verify(
    const vmp_tls_identity_inputs_t *inputs);

#ifdef __cplusplus
}
#endif

#endif
