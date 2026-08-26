// SPDX-License-Identifier: GPL-3.0-only

#include "request_binding.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_fixed_domain_sha256(void)
{
    static const uint8_t request[] = {
        0x08U, 0x06U, 0x12U, 0x10U, 0x07U, 0x07U, 0x07U, 0x07U,
        0x07U, 0x07U, 0x07U, 0x07U, 0x07U, 0x07U, 0x07U, 0x07U,
        0x07U, 0x07U, 0x07U, 0x07U, 0x1aU, 0x20U, 0x09U, 0x09U,
        0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x09U,
        0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x09U,
        0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x09U,
        0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x09U, 0x72U, 0x12U,
        0x0aU, 0x10U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U,
        0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U,
        0x01U, 0x01U,
    };
    static const uint8_t expected_add_path[VMP_FD_BINDING_LEN] = {
        0x2dU, 0xacU, 0xd7U, 0x22U, 0xbeU, 0x6fU, 0x87U, 0x3aU,
        0xe4U, 0xa9U, 0x27U, 0x27U, 0xadU, 0x74U, 0xd4U, 0x66U,
        0x1dU, 0x2eU, 0x4cU, 0x5aU, 0xc8U, 0x60U, 0x0eU, 0xcaU,
        0xa1U, 0xbeU, 0x1dU, 0x91U, 0x81U, 0xa1U, 0xa9U, 0xbdU,
    };
    static const uint8_t expected_start_exit[VMP_FD_BINDING_LEN] = {
        0x6fU, 0x6dU, 0x88U, 0xc3U, 0x8fU, 0x60U, 0xacU, 0x2bU,
        0xa7U, 0x7fU, 0x3fU, 0x17U, 0xf6U, 0xe4U, 0x36U, 0xc1U,
        0x6eU, 0x8eU, 0xf1U, 0x63U, 0x64U, 0x57U, 0x59U, 0x77U,
        0xabU, 0x7dU, 0x1fU, 0xfdU, 0xfcU, 0xe1U, 0x16U, 0xf0U,
    };
    static const uint8_t expected_request[VMP_REQUEST_SHA256_LEN] = {
        0x3dU, 0xa7U, 0x5bU, 0xacU, 0xc9U, 0x56U, 0xf3U, 0x7fU,
        0x48U, 0x91U, 0xabU, 0xbdU, 0xfcU, 0xf9U, 0x2bU, 0x78U,
        0x8bU, 0x16U, 0x61U, 0xabU, 0xa8U, 0x14U, 0x6bU, 0xe6U,
        0xbcU, 0x7fU, 0x88U, 0x13U, 0x75U, 0x23U, 0x5fU, 0xfdU,
    };
    static const uint8_t auth_secret[VMP_AUTH_SECRET_LEN] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static const uint8_t expected_commitment[VMP_AUTH_COMMITMENT_LEN] = {
        0x2bU, 0x80U, 0x72U, 0x70U, 0xdbU, 0xd6U, 0x15U, 0x73U,
        0xccU, 0x59U, 0x14U, 0x25U, 0x11U, 0x62U, 0x1eU, 0xd6U,
        0xf3U, 0xc3U, 0x3dU, 0xd1U, 0x40U, 0x77U, 0x4cU, 0xc2U,
        0x4aU, 0x04U, 0x12U, 0x71U, 0xc6U, 0x31U, 0x08U, 0x85U,
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

    assert(vmp_sha256_request_digest(NULL, request, sizeof(request), actual));
    assert(memcmp(actual, expected_request, sizeof(expected_request)) == 0);
    assert(vmp_sha256_auth_commitment(NULL, auth_secret,
                                      sizeof(auth_secret), actual));
    assert(memcmp(actual, expected_commitment,
                  sizeof(expected_commitment)) == 0);

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
    assert(!vmp_sha256_request_digest(NULL, request, 0U, actual));
    for (size_t index = 0U; index < sizeof(actual); ++index) {
        assert(actual[index] == 0U);
    }
    assert(!vmp_sha256_auth_commitment(NULL, auth_secret,
                                       sizeof(auth_secret) - 1U, actual));
    for (size_t index = 0U; index < sizeof(actual); ++index) {
        assert(actual[index] == 0U);
    }
}

int main(void)
{
    test_fixed_domain_sha256();
    puts("request binding tests passed");
    return 0;
}
