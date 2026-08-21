// SPDX-License-Identifier: GPL-3.0-only

#include "request_binding.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_fixed_domain_sha256(void)
{
    static const uint8_t request[] = {
        0x08U, 0x04U, 0x12U, 0x10U, 0x01U, 0x02U, 0x03U, 0x04U,
        0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU,
        0x0dU, 0x0eU, 0x0fU, 0x10U,
    };
    static const uint8_t expected[VMP_FD_BINDING_LEN] = {
        0x1eU, 0x34U, 0xb1U, 0x12U, 0x1dU, 0x33U, 0x25U, 0x49U,
        0xf3U, 0xb8U, 0x96U, 0x11U, 0x94U, 0x1aU, 0x4cU, 0x5fU,
        0x2bU, 0xe4U, 0x88U, 0x73U, 0x2aU, 0x00U, 0x83U, 0x4cU,
        0xedU, 0x92U, 0x5aU, 0x1aU, 0xc8U, 0xbfU, 0xd4U, 0xa1U,
    };
    uint8_t actual[VMP_FD_BINDING_LEN];
    memset(actual, 0xa5, sizeof(actual));
    assert(vmp_sha256_request_binding(NULL, request, sizeof(request), actual));
    assert(memcmp(actual, expected, sizeof(expected)) == 0);

    memset(actual, 0xa5, sizeof(actual));
    assert(!vmp_sha256_request_binding(NULL, NULL, sizeof(request), actual));
    for (size_t index = 0U; index < sizeof(actual); ++index) {
        assert(actual[index] == 0xa5U);
    }
    assert(!vmp_sha256_request_binding(NULL, request, 0U, actual));
}

int main(void)
{
    test_fixed_domain_sha256();
    puts("request binding tests passed");
    return 0;
}
