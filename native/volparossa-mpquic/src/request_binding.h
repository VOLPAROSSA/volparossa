// SPDX-License-Identifier: GPL-3.0-only

#ifndef VOLPAROSSA_MPQUIC_REQUEST_BINDING_H
#define VOLPAROSSA_MPQUIC_REQUEST_BINDING_H

#include "volparossa_mpquic_server.h"

#ifdef __cplusplus
extern "C" {
#endif

bool vmp_sha256_request_binding(
    void *context, const uint8_t *canonical_request,
    size_t canonical_request_len, uint8_t out[VMP_FD_BINDING_LEN]);

#ifdef __cplusplus
}
#endif

#endif
