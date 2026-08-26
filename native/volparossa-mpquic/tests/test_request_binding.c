// SPDX-License-Identifier: GPL-3.0-only

#include "request_binding.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_fixed_domain_sha256(void)
{
    static const uint8_t request[] = {
        0x08U, 0x05U, 0x12U, 0x10U, 0x01U, 0x02U, 0x03U, 0x04U,
        0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU,
        0x0dU, 0x0eU, 0x0fU, 0x10U,
    };
    static const uint8_t expected_add_path[VMP_FD_BINDING_LEN] = {
        0x5bU, 0xa2U, 0xc3U, 0xd7U, 0xa3U, 0x4fU, 0x18U, 0x49U,
        0x71U, 0x7fU, 0xecU, 0x63U, 0xe1U, 0x7aU, 0xbaU, 0xdcU,
        0xd5U, 0x85U, 0x43U, 0x67U, 0x08U, 0xcdU, 0xeaU, 0xf3U,
        0xaaU, 0x2aU, 0x32U, 0x0fU, 0xc2U, 0xf8U, 0xbdU, 0x2aU,
    };
    static const uint8_t expected_start_exit[VMP_FD_BINDING_LEN] = {
        0xa0U, 0x84U, 0x23U, 0x57U, 0x90U, 0x93U, 0x3aU, 0xb2U,
        0x85U, 0x8fU, 0xa4U, 0xceU, 0xa1U, 0x8eU, 0x7fU, 0x64U,
        0x69U, 0xacU, 0x21U, 0x0eU, 0xd7U, 0x83U, 0x0fU, 0x6fU,
        0xd3U, 0x1fU, 0x86U, 0x45U, 0x1aU, 0x41U, 0xd1U, 0xccU,
    };
    uint8_t actual[VMP_FD_BINDING_LEN];
    memset(actual, 0xa5, sizeof(actual));
    assert(vmp_sha256_request_binding(NULL, VMP_OPERATION_ADD_PATH, request,
                                      sizeof(request), actual));
    assert(memcmp(actual, expected_add_path, sizeof(expected_add_path)) == 0);

    assert(vmp_sha256_request_binding(NULL,
                                      VMP_OPERATION_START_EXIT_SESSION,
                                      request, sizeof(request), actual));
    assert(memcmp(actual, expected_start_exit,
                  sizeof(expected_start_exit)) == 0);
    assert(memcmp(expected_add_path, expected_start_exit,
                  sizeof(expected_add_path)) != 0);

    memset(actual, 0xa5, sizeof(actual));
    assert(!vmp_sha256_request_binding(NULL, VMP_OPERATION_ADD_PATH, NULL,
                                       sizeof(request), actual));
    for (size_t index = 0U; index < sizeof(actual); ++index) {
        assert(actual[index] == 0U);
    }
    assert(!vmp_sha256_request_binding(NULL, VMP_OPERATION_ADD_PATH, request,
                                       0U, actual));
    assert(!vmp_sha256_request_binding(NULL, VMP_OPERATION_GET_STATUS, request,
                                       sizeof(request), actual));
}

int main(void)
{
    test_fixed_domain_sha256();
    puts("request binding tests passed");
    return 0;
}
