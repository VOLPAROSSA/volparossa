// SPDX-License-Identifier: GPL-3.0-only

#include "request_binding.h"

#include <openssl/mem.h>
#include <openssl/sha.h>

#include <string.h>

static const uint8_t vmp_add_path_binding_domain[] =
    "VOLPAROSSA-MPQUIC-ADD-PATH-FD-V6";
static const uint8_t vmp_start_exit_binding_domain[] =
    "VOLPAROSSA-MPQUIC-START-EXIT-FD-V6";
static const uint8_t vmp_request_digest_domain[] =
    "VOLPAROSSA-MPQUIC-REQUEST-V6";
static const uint8_t vmp_auth_commitment_domain[] =
    "VOLPAROSSA-NATIVE-ROUTE-AUTH-COMMITMENT-V4";

static bool sha256_domain_request(
    const uint8_t *domain, size_t domain_len,
    const uint8_t *canonical_request, size_t canonical_request_len,
    uint8_t out[VMP_REQUEST_SHA256_LEN])
{
    if (domain == NULL || domain_len == 0U || out == NULL) return false;
    memset(out, 0, VMP_REQUEST_SHA256_LEN);
    if (canonical_request == NULL || canonical_request_len == 0U ||
        canonical_request_len > VMP_MAX_CONTROL_FRAME) {
        return false;
    }
    const uint32_t length = (uint32_t)canonical_request_len;
    const uint8_t encoded_length[4] = {
        (uint8_t)(length >> 24U),
        (uint8_t)(length >> 16U),
        (uint8_t)(length >> 8U),
        (uint8_t)length,
    };
    SHA256_CTX digest;
    OPENSSL_cleanse(&digest, sizeof(digest));
    const bool ok =
        SHA256_Init(&digest) == 1 &&
        SHA256_Update(&digest, domain, domain_len) == 1 &&
        SHA256_Update(&digest, encoded_length, sizeof(encoded_length)) == 1 &&
        SHA256_Update(&digest, canonical_request, canonical_request_len) == 1 &&
        SHA256_Final(out, &digest) == 1;
    OPENSSL_cleanse(&digest, sizeof(digest));
    if (!ok) memset(out, 0, VMP_REQUEST_SHA256_LEN);
    return ok;
}

bool vmp_sha256_request_binding(
    void *context, vmp_operation_t operation, const uint8_t *canonical_request,
    size_t canonical_request_len, uint8_t out[VMP_FD_BINDING_LEN])
{
    (void)context;
    if (out == NULL) return false;
    memset(out, 0, VMP_FD_BINDING_LEN);
    const uint8_t *domain = NULL;
    size_t domain_len = 0U;
    if (operation == VMP_OPERATION_ADD_PATH) {
        domain = vmp_add_path_binding_domain;
        domain_len = sizeof(vmp_add_path_binding_domain);
    } else if (operation == VMP_OPERATION_START_EXIT_SESSION) {
        domain = vmp_start_exit_binding_domain;
        domain_len = sizeof(vmp_start_exit_binding_domain);
    } else {
        return false;
    }
    return sha256_domain_request(domain, domain_len, canonical_request,
                                 canonical_request_len, out);
}

bool vmp_sha256_request_digest(
    void *context, const uint8_t *canonical_request,
    size_t canonical_request_len, uint8_t out[VMP_REQUEST_SHA256_LEN])
{
    (void)context;
    return sha256_domain_request(
        vmp_request_digest_domain, sizeof(vmp_request_digest_domain),
        canonical_request, canonical_request_len, out);
}

bool vmp_sha256_auth_commitment(
    void *context, const uint8_t *auth_secret, size_t auth_secret_len,
    uint8_t out[VMP_AUTH_COMMITMENT_LEN])
{
    (void)context;
    if (out == NULL) return false;
    memset(out, 0, VMP_AUTH_COMMITMENT_LEN);
    if (auth_secret == NULL || auth_secret_len != VMP_AUTH_SECRET_LEN) {
        return false;
    }
    SHA256_CTX digest;
    OPENSSL_cleanse(&digest, sizeof(digest));
    const bool ok =
        SHA256_Init(&digest) == 1 &&
        SHA256_Update(&digest, vmp_auth_commitment_domain,
                      sizeof(vmp_auth_commitment_domain)) == 1 &&
        SHA256_Update(&digest, auth_secret, auth_secret_len) == 1 &&
        SHA256_Final(out, &digest) == 1;
    OPENSSL_cleanse(&digest, sizeof(digest));
    if (!ok) memset(out, 0, VMP_AUTH_COMMITMENT_LEN);
    return ok;
}
