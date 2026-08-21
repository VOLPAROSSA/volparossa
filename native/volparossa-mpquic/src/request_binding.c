// SPDX-License-Identifier: GPL-3.0-only

#include "request_binding.h"

#include <openssl/sha.h>

#include <string.h>

static const uint8_t vmp_add_path_binding_domain[] =
    "VOLPAROSSA-MPQUIC-ADD-PATH-FD-V4";

bool vmp_sha256_request_binding(
    void *context, const uint8_t *canonical_request,
    size_t canonical_request_len, uint8_t out[VMP_FD_BINDING_LEN])
{
    (void)context;
    if (canonical_request == NULL || canonical_request_len == 0U ||
        canonical_request_len > VMP_MAX_CONTROL_FRAME || out == NULL) {
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
    memset(&digest, 0, sizeof(digest));
    const bool ok =
        SHA256_Init(&digest) == 1 &&
        SHA256_Update(&digest, vmp_add_path_binding_domain,
                      sizeof(vmp_add_path_binding_domain)) == 1 &&
        SHA256_Update(&digest, encoded_length, sizeof(encoded_length)) == 1 &&
        SHA256_Update(&digest, canonical_request, canonical_request_len) == 1 &&
        SHA256_Final(out, &digest) == 1;
    memset(&digest, 0, sizeof(digest));
    if (!ok) {
        memset(out, 0, VMP_FD_BINDING_LEN);
    }
    return ok;
}
