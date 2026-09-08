// SPDX-License-Identifier: GPL-3.0-only

#include "request_binding.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_fixed_domain_sha256(void)
{
    static const uint8_t request[] = {
        0x08U, 0x07U, 0x12U, 0x10U, 0x07U, 0x07U, 0x07U, 0x07U,
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
        0x95U, 0x3eU, 0x0bU, 0xc1U, 0x66U, 0x8dU, 0x94U, 0x9fU,
        0xa4U, 0x16U, 0xd3U, 0x03U, 0x96U, 0x55U, 0xc2U, 0x8aU,
        0x44U, 0x07U, 0xcdU, 0x49U, 0x7eU, 0x9eU, 0x03U, 0x0eU,
        0x6bU, 0xb5U, 0xa0U, 0xc9U, 0x36U, 0x20U, 0xabU, 0xfbU,
    };
    static const uint8_t expected_start_exit[VMP_FD_BINDING_LEN] = {
        0x11U, 0xa5U, 0x4dU, 0x14U, 0xc1U, 0x4eU, 0x1eU, 0x21U,
        0x54U, 0x33U, 0x63U, 0x0fU, 0x45U, 0x18U, 0xc5U, 0xf6U,
        0x78U, 0xc2U, 0x33U, 0xc6U, 0x18U, 0xfbU, 0x37U, 0x4eU,
        0x39U, 0x26U, 0x5eU, 0xacU, 0x0cU, 0xbfU, 0x09U, 0xcdU,
    };
    static const uint8_t expected_request[VMP_REQUEST_SHA256_LEN] = {
        0x02U, 0xa6U, 0x39U, 0xcbU, 0xa5U, 0xbfU, 0x85U, 0x1aU,
        0xe2U, 0x73U, 0x0dU, 0x9bU, 0xdcU, 0xf2U, 0x4fU, 0xd1U,
        0xbaU, 0xedU, 0x64U, 0xd7U, 0xbbU, 0x7fU, 0x7aU, 0x9aU,
        0xcbU, 0x97U, 0x10U, 0x5aU, 0x6fU, 0x3fU, 0xa1U, 0xb1U,
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
