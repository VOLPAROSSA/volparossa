// SPDX-License-Identifier: GPL-3.0-only

#include "volparossa_mpquic_protocol.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    vmp_request_t request;
    (void)vmp_decode_request(data, size, &request);
    return 0;
}
