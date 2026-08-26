// SPDX-License-Identifier: GPL-3.0-only

#include "volparossa_mpquic_protocol.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct test_encoder {
    uint8_t *cursor;
    uint8_t *end;
} test_encoder_t;

static const uint8_t test_auth_secret[VMP_AUTH_SECRET_LEN] =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static void put_varint(test_encoder_t *encoder, uint64_t value)
{
    do {
        assert(encoder->cursor != encoder->end);
        uint8_t byte = (uint8_t)(value & UINT64_C(0x7f));
        value >>= 7;
        if (value != 0) byte |= UINT8_C(0x80);
        *encoder->cursor++ = byte;
    } while (value != 0);
}

static void put_key(test_encoder_t *encoder, uint32_t field, uint8_t wire)
{
    put_varint(encoder, ((uint64_t)field << 3) | wire);
}

static void put_uint(test_encoder_t *encoder, uint32_t field, uint64_t value)
{
    put_key(encoder, field, 0);
    put_varint(encoder, value);
}

static void put_bytes(test_encoder_t *encoder, uint32_t field, const uint8_t *value,
                      size_t len)
{
    put_key(encoder, field, 2);
    put_varint(encoder, len);
    assert((size_t)(encoder->end - encoder->cursor) >= len);
    memcpy(encoder->cursor, value, len);
    encoder->cursor += len;
}

static size_t make_start(uint8_t *out, size_t capacity, uint32_t minimum_paths,
                         uint64_t masque_context_id,
                         vmp_transport_mode_t transport_mode,
                         bool unknown_nested, bool duplicate_operation)
{
    uint8_t nested[256];
    test_encoder_t child = {.cursor = nested, .end = nested + sizeof(nested)};
    uint8_t context[VMP_CONTEXT_ID_LEN];
    uint8_t pin[VMP_SPKI_SHA256_LEN];
    memset(context, 0x11, sizeof(context));
    memset(pin, 0x22, sizeof(pin));
    put_bytes(&child, 1, context, sizeof(context));
    put_bytes(&child, 2, pin, sizeof(pin));
    put_uint(&child, 3, minimum_paths);
    put_uint(&child, 4, masque_context_id);
    put_uint(&child, 5, (uint64_t)transport_mode);
    static const uint8_t tls_server_name[] = "exit.example";
    put_bytes(&child, 6, test_auth_secret, sizeof(test_auth_secret));
    put_bytes(&child, 7, tls_server_name, sizeof(tls_server_name) - 1U);
    put_uint(&child, 8, UINT64_C(1060000));
    if (unknown_nested) put_uint(&child, 9, 1);

    test_encoder_t encoder = {.cursor = out, .end = out + capacity};
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    memset(nonce, 0x33, sizeof(nonce));
    put_uint(&encoder, 1, VMP_API_VERSION);
    put_bytes(&encoder, 2, nonce, sizeof(nonce));
    put_bytes(&encoder, VMP_OPERATION_START_SESSION, nested,
              (size_t)(child.cursor - nested));
    if (duplicate_operation)
        put_bytes(&encoder, VMP_OPERATION_START_SESSION, nested,
                  (size_t)(child.cursor - nested));
    return (size_t)(encoder.cursor - out);
}

static size_t make_old_v2_start(uint8_t *out, size_t capacity)
{
    uint8_t nested[128];
    test_encoder_t child = {.cursor = nested, .end = nested + sizeof(nested)};
    uint8_t context[VMP_CONTEXT_ID_LEN];
    uint8_t pin[VMP_SPKI_SHA256_LEN];
    memset(context, 0x11, sizeof(context));
    memset(pin, 0x22, sizeof(pin));
    put_bytes(&child, 1, context, sizeof(context));
    put_bytes(&child, 2, pin, sizeof(pin));
    put_uint(&child, 3, 2U);
    put_uint(&child, 4, 9U);
    put_uint(&child, 5, VMP_TRANSPORT_MODE_MULTIPATH_QUIC);

    test_encoder_t encoder = {.cursor = out, .end = out + capacity};
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    memset(nonce, 0x33, sizeof(nonce));
    put_uint(&encoder, 1, VMP_API_VERSION);
    put_bytes(&encoder, 2, nonce, sizeof(nonce));
    put_bytes(&encoder, VMP_OPERATION_START_SESSION, nested,
              (size_t)(child.cursor - nested));
    return (size_t)(encoder.cursor - out);
}

static size_t make_start_exit(uint8_t *out, size_t capacity)
{
    static const uint8_t tls_name[] = "exit.example";
    static const uint8_t certificate[] =
        "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";
    static const uint8_t private_key[] =
        "-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n";
    uint8_t nested[512];
    test_encoder_t child = {.cursor = nested, .end = nested + sizeof(nested)};
    uint8_t context[VMP_CONTEXT_ID_LEN];
    uint8_t spki[VMP_SPKI_SHA256_LEN];
    uint8_t reservation[VMP_RESERVATION_HASH_LEN];
    uint8_t expected_client_ip[16] = {
        0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x61U, 0x11U, 0x11U,
        0x22U, 0x22U, 0U,    1U,    0x33U, 0x33U, 0U,    1U,
    };
    uint8_t listener_ip[16];
    memset(context, 0x44, sizeof(context));
    memset(spki, 0x45, sizeof(spki));
    memset(reservation, 0x46, sizeof(reservation));
    memcpy(listener_ip, expected_client_ip, sizeof(listener_ip));
    listener_ip[15] = 4U;
    put_bytes(&child, 1, context, sizeof(context));
    put_bytes(&child, 2, test_auth_secret, sizeof(test_auth_secret));
    put_uint(&child, 3, UINT64_C(1060000));
    put_uint(&child, 4, 1U);
    put_uint(&child, 5, 19U);
    put_uint(&child, 6, VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP);
    put_bytes(&child, 7, spki, sizeof(spki));
    put_bytes(&child, 8, tls_name, sizeof(tls_name) - 1U);
    put_uint(&child, 9, 1U);
    put_bytes(&child, 10, listener_ip, sizeof(listener_ip));
    put_uint(&child, 11, 443U);
    put_bytes(&child, 12, expected_client_ip, sizeof(expected_client_ip));
    put_uint(&child, 13, UINT16_C(51820));
    put_bytes(&child, 14, reservation, sizeof(reservation));
    put_bytes(&child, 15, certificate, sizeof(certificate) - 1U);
    put_bytes(&child, 16, private_key, sizeof(private_key) - 1U);

    test_encoder_t encoder = {.cursor = out, .end = out + capacity};
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    memset(nonce, 0x55, sizeof(nonce));
    put_uint(&encoder, 1, VMP_API_VERSION);
    put_bytes(&encoder, 2, nonce, sizeof(nonce));
    put_bytes(&encoder, VMP_OPERATION_START_EXIT_SESSION, nested,
              (size_t)(child.cursor - nested));
    return (size_t)(encoder.cursor - out);
}

static size_t make_old_v4_start_exit(uint8_t *out, size_t capacity)
{
    uint8_t nested[128];
    uint8_t context[VMP_CONTEXT_ID_LEN];
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    memset(context, 0x44, sizeof(context));
    memset(nonce, 0x55, sizeof(nonce));
    test_encoder_t child = {.cursor = nested, .end = nested + sizeof(nested)};
    put_bytes(&child, 1U, context, sizeof(context));
    put_bytes(&child, 2U, test_auth_secret, sizeof(test_auth_secret));
    put_uint(&child, 3U, UINT64_C(1060000));
    put_uint(&child, 4U, 1U);
    put_uint(&child, 5U, 19U);
    put_uint(&child, 6U, VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP);
    test_encoder_t encoder = {.cursor = out, .end = out + capacity};
    put_uint(&encoder, 1U, VMP_API_VERSION);
    put_bytes(&encoder, 2U, nonce, sizeof(nonce));
    put_bytes(&encoder, VMP_OPERATION_START_EXIT_SESSION, nested,
              (size_t)(child.cursor - nested));
    return (size_t)(encoder.cursor - out);
}

typedef enum test_path_shape {
    TEST_PATH_VALID = 0,
    TEST_PATH_IPV4,
    TEST_PATH_PUBLIC_PREFIX,
    TEST_PATH_WRONG_EMBEDDED_ID,
    TEST_PATH_DIFFERENT_PREFIX,
    TEST_PATH_WRONG_HOSTS,
} test_path_shape_t;

static size_t make_add_path(uint8_t *out, size_t capacity,
                            uint16_t local_port, bool old_v3_shape,
                            test_path_shape_t shape)
{
    uint8_t nested[160];
    test_encoder_t child = {.cursor = nested, .end = nested + sizeof(nested)};
    uint8_t context[VMP_CONTEXT_ID_LEN];
    uint8_t local[16] = {0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x61U,
                         0x11U, 0x11U, 0x22U, 0x22U, 0U,    1U,
                         0x33U, 0x33U, 0U,    1U};
    uint8_t remote[16];
    uint8_t reservation[VMP_RESERVATION_HASH_LEN];
    size_t ip_len = sizeof(local);
    memset(context, 0x11, sizeof(context));
    memcpy(remote, local, sizeof(remote));
    remote[15] = 4U;
    memset(reservation, 0x44, sizeof(reservation));
    switch (shape) {
    case TEST_PATH_VALID:
        break;
    case TEST_PATH_IPV4:
        local[0] = 127U;
        local[1] = 0U;
        local[2] = 0U;
        local[3] = 1U;
        remote[0] = 192U;
        remote[1] = 0U;
        remote[2] = 2U;
        remote[3] = 4U;
        ip_len = 4U;
        break;
    case TEST_PATH_PUBLIC_PREFIX:
        local[0] = 0x20U;
        remote[0] = 0x20U;
        break;
    case TEST_PATH_WRONG_EMBEDDED_ID:
        local[11] = 2U;
        remote[11] = 2U;
        break;
    case TEST_PATH_DIFFERENT_PREFIX:
        remote[13] ^= 1U;
        break;
    case TEST_PATH_WRONG_HOSTS:
        local[15] = 2U;
        remote[15] = 3U;
        break;
    }
    put_bytes(&child, 1, context, sizeof(context));
    put_uint(&child, 2, 1);
    if (old_v3_shape) put_uint(&child, 3, 17U);
    put_bytes(&child, 4, local, ip_len);
    put_bytes(&child, 5, remote, ip_len);
    put_uint(&child, 6, 443);
    put_bytes(&child, 7, reservation, sizeof(reservation));
    if (!old_v3_shape) put_uint(&child, 8, local_port);

    test_encoder_t encoder = {.cursor = out, .end = out + capacity};
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    memset(nonce, 0x33, sizeof(nonce));
    put_uint(&encoder, 1, VMP_API_VERSION);
    put_bytes(&encoder, 2, nonce, sizeof(nonce));
    put_bytes(&encoder, VMP_OPERATION_ADD_PATH, nested,
              (size_t)(child.cursor - nested));
    return (size_t)(encoder.cursor - out);
}

static size_t make_datagram(uint8_t *out, size_t capacity, uint8_t *packet,
                            size_t packet_len)
{
    uint8_t *nested = malloc(packet_len + 64U);
    assert(nested != NULL);
    test_encoder_t child = {
        .cursor = nested,
        .end = nested + packet_len + 64U,
    };
    uint8_t context[VMP_CONTEXT_ID_LEN];
    memset(context, 0x11, sizeof(context));
    put_bytes(&child, 1, context, sizeof(context));
    put_bytes(&child, 2, packet, packet_len);
    put_uint(&child, 3, 9U);
    const size_t nested_len = (size_t)(child.cursor - nested);

    test_encoder_t encoder = {.cursor = out, .end = out + capacity};
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    memset(nonce, 0x33, sizeof(nonce));
    put_uint(&encoder, 1, VMP_API_VERSION);
    put_bytes(&encoder, 2, nonce, sizeof(nonce));
    put_bytes(&encoder, VMP_OPERATION_SEND_DATAGRAM, nested, nested_len);
    const size_t encoded_len = (size_t)(encoder.cursor - out);
    free(nested);
    return encoded_len;
}

static size_t make_receive(uint8_t *out, size_t capacity,
                           uint64_t masque_context_id)
{
    uint8_t nested[64];
    test_encoder_t child = {.cursor = nested, .end = nested + sizeof(nested)};
    uint8_t context[VMP_CONTEXT_ID_LEN];
    memset(context, 0x11, sizeof(context));
    put_bytes(&child, 1, context, sizeof(context));
    put_uint(&child, 2, masque_context_id);

    test_encoder_t encoder = {.cursor = out, .end = out + capacity};
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    memset(nonce, 0x33, sizeof(nonce));
    put_uint(&encoder, 1, VMP_API_VERSION);
    put_bytes(&encoder, 2, nonce, sizeof(nonce));
    put_bytes(&encoder, VMP_OPERATION_RECEIVE_DATAGRAM, nested,
              (size_t)(child.cursor - nested));
    return (size_t)(encoder.cursor - out);
}

static void test_start_round_trip_shape(void)
{
    uint8_t payload[256];
    const size_t len = make_start(payload, sizeof(payload), 2U, 9U,
                                  VMP_TRANSPORT_MODE_MULTIPATH_QUIC,
                                  false, false);
    vmp_request_t request;
    assert(vmp_decode_request(payload, len, &request) == VMP_PROTOCOL_OK);
    assert(request.api_version == VMP_API_VERSION);
    assert(request.operation == VMP_OPERATION_START_SESSION);
    assert(request.body.start_session.minimum_paths == 2);
    assert(request.body.start_session.masque_context_id == 9);
    assert(request.body.start_session.transport_mode ==
           VMP_TRANSPORT_MODE_MULTIPATH_QUIC);
    assert(request.body.start_session.route_context_id[0] == 0x11);
    assert(request.body.start_session.exit_spki_sha256[0] == 0x22);
    assert(request.body.start_session.auth_secret.len == VMP_AUTH_SECRET_LEN);
    assert(memcmp(request.body.start_session.auth_secret.data,
                  test_auth_secret, VMP_AUTH_SECRET_LEN) == 0);
    assert(request.body.start_session.tls_server_name.len == 12U);
    assert(memcmp(request.body.start_session.tls_server_name.data,
                  "exit.example", 12U) == 0);
    assert(request.body.start_session.expires_at_ms == UINT64_C(1060000));

    uint8_t *decoded_secret =
        (uint8_t *)(uintptr_t)request.body.start_session.auth_secret.data;
    decoded_secret[0] = (uint8_t)'!';
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
}

static void test_v2_start_shape_and_start_exit_boundary(void)
{
    uint8_t payload[1024];
    vmp_request_t request;
    size_t len = make_old_v2_start(payload, sizeof(payload));
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);

    len = make_old_v4_start_exit(payload, sizeof(payload));
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);

    len = make_start_exit(payload, sizeof(payload));
    assert(vmp_decode_request(payload, len, &request) == VMP_PROTOCOL_OK);
    assert(request.operation == VMP_OPERATION_START_EXIT_SESSION);
    assert(request.body.start_exit_session.route_context_id[0] == 0x44U);
    assert(request.body.start_exit_session.auth_secret.len ==
           VMP_AUTH_SECRET_LEN);
    assert(request.body.start_exit_session.expires_at_ms == UINT64_C(1060000));
    assert(request.body.start_exit_session.minimum_paths == 1U);
    assert(request.body.start_exit_session.masque_context_id == 19U);
    assert(request.body.start_exit_session.transport_mode ==
           VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP);
    assert(request.body.start_exit_session.exit_spki_sha256[0] == 0x45U);
    assert(request.body.start_exit_session.tls_server_name.len == 12U);
    assert(request.body.start_exit_session.path_id == 1U);
    assert(request.body.start_exit_session.listener_ip[15] == 4U);
    assert(request.body.start_exit_session.listener_port == 443U);
    assert(request.body.start_exit_session.expected_client_ip[15] == 1U);
    assert(request.body.start_exit_session.expected_client_port == 51820U);
    assert(request.body.start_exit_session.reservation_hash[0] == 0x46U);
    assert(request.body.start_exit_session.tls_certificate_pem.len != 0U);
    assert(request.body.start_exit_session.tls_private_key_pem.len != 0U);
    assert(vmp_start_exit_is_valid(&request.body.start_exit_session));

    const vmp_start_exit_session_t valid = request.body.start_exit_session;
    vmp_start_exit_session_t invalid = valid;
    invalid.auth_secret.len = VMP_AUTH_SECRET_LEN - 1U;
    assert(!vmp_start_exit_is_valid(&invalid));
    uint8_t noncanonical_auth[VMP_AUTH_SECRET_LEN];
    memcpy(noncanonical_auth, test_auth_secret, sizeof(noncanonical_auth));
    noncanonical_auth[VMP_AUTH_SECRET_LEN - 1U] = (uint8_t)'B';
    invalid = valid;
    invalid.auth_secret.data = noncanonical_auth;
    assert(!vmp_start_exit_is_valid(&invalid));
    invalid = valid;
    invalid.transport_mode = VMP_TRANSPORT_MODE_MULTIPATH_QUIC;
    assert(!vmp_start_exit_is_valid(&invalid));
    invalid = valid;
    invalid.listener_ip[15] = 5U;
    assert(!vmp_start_exit_is_valid(&invalid));
    invalid = valid;
    invalid.expected_client_port = 0U;
    assert(!vmp_start_exit_is_valid(&invalid));
    invalid = valid;
    memset(invalid.reservation_hash, 0, sizeof(invalid.reservation_hash));
    assert(!vmp_start_exit_is_valid(&invalid));
    invalid = valid;
    invalid.tls_certificate_pem.len = VMP_MAX_TLS_CERTIFICATE_PEM + 1U;
    assert(!vmp_start_exit_is_valid(&invalid));
    invalid = valid;
    invalid.tls_private_key_pem.len = VMP_MAX_TLS_PRIVATE_KEY_PEM + 1U;
    assert(!vmp_start_exit_is_valid(&invalid));
}

static void test_old_unknown_version_and_zero_nonce_are_rejected(void)
{
    uint8_t payload[256];
    const size_t len = make_start(payload, sizeof(payload), 2U, 9U,
                                  VMP_TRANSPORT_MODE_MULTIPATH_QUIC,
                                  false, false);
    vmp_request_t request;
    assert(payload[0] == 0x08U && payload[1] == VMP_API_VERSION);
    payload[1] = 1U;
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
    payload[1] = 2U;
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
    payload[1] = 3U;
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
    payload[1] = 4U;
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
    payload[1] = 99U;
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
    payload[1] = VMP_API_VERSION;
    assert(payload[2] == 0x12U &&
           payload[3] == VMP_REQUEST_NONCE_LEN);
    memset(payload + 4U, 0, VMP_REQUEST_NONCE_LEN);
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
}

static void test_noncanonical_wire_forms_are_rejected(void)
{
    uint8_t payload[320];
    uint8_t reordered[320];
    vmp_request_t request;
    size_t len = make_start(payload, sizeof(payload), 2U, 9U,
                            VMP_TRANSPORT_MODE_MULTIPATH_QUIC,
                            false, false);
    assert(payload[0] == 0x08U && payload[1] == VMP_API_VERSION);
    memmove(payload + 3U, payload + 2U, len - 2U);
    payload[1] = VMP_API_VERSION | UINT8_C(0x80);
    payload[2] = 0U;
    assert(vmp_decode_request(payload, len + 1U, &request) ==
           VMP_PROTOCOL_VARINT);

    len = make_start(payload, sizeof(payload), 2U, 9U,
                     VMP_TRANSPORT_MODE_MULTIPATH_QUIC,
                     false, false);
    const size_t nonce_field_len = 2U + VMP_REQUEST_NONCE_LEN;
    memcpy(reordered, payload + 2U, nonce_field_len);
    memcpy(reordered + nonce_field_len, payload, 2U);
    memcpy(reordered + nonce_field_len + 2U,
           payload + 2U + nonce_field_len,
           len - 2U - nonce_field_len);
    assert(vmp_decode_request(reordered, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
}

static void test_receive_is_context_correlated(void)
{
    uint8_t payload[128];
    vmp_request_t request;
    size_t len = make_receive(payload, sizeof(payload), 9U);
    assert(vmp_decode_request(payload, len, &request) == VMP_PROTOCOL_OK);
    assert(request.operation == VMP_OPERATION_RECEIVE_DATAGRAM);
    assert(request.body.receive_datagram.route_context_id[0] == 0x11U);
    assert(request.body.receive_datagram.masque_context_id == 9U);
    len = make_receive(payload, sizeof(payload), 0U);
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
    len = make_receive(payload, sizeof(payload),
                       VMP_MAX_MASQUE_CONTEXT_ID + 1U);
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
}

static void test_nonzero_masque_context_is_required(void)
{
    uint8_t payload[256];
    vmp_request_t request;
    size_t len = make_start(payload, sizeof(payload), 2U, 0U,
                            VMP_TRANSPORT_MODE_MULTIPATH_QUIC,
                            false, false);
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
    len = make_start(payload, sizeof(payload), 2U,
                     VMP_MAX_MASQUE_CONTEXT_ID + 1U,
                     VMP_TRANSPORT_MODE_MULTIPATH_QUIC, false, false);
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
}

static void test_single_path_and_extensions_fail_closed(void)
{
    uint8_t payload[320];
    vmp_request_t request;
    size_t len = make_start(
        payload, sizeof(payload), 1U, 9U,
        VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP, false, false);
    assert(vmp_decode_request(payload, len, &request) == VMP_PROTOCOL_OK);
    len = make_start(payload, sizeof(payload), 1U, 9U,
                     VMP_TRANSPORT_MODE_MULTIPATH_QUIC, false, false);
    assert(vmp_decode_request(payload, len, &request) == VMP_PROTOCOL_INVALID_VALUE);
    len = make_start(
        payload, sizeof(payload), 2U, 9U,
        VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP, false, false);
    assert(vmp_decode_request(payload, len, &request) == VMP_PROTOCOL_INVALID_VALUE);
    len = make_start(payload, sizeof(payload), 2U, 9U,
                     VMP_TRANSPORT_MODE_MULTIPATH_QUIC, true, false);
    assert(vmp_decode_request(payload, len, &request) == VMP_PROTOCOL_UNKNOWN_FIELD);
    len = make_start(payload, sizeof(payload), 2U, 9U,
                     VMP_TRANSPORT_MODE_MULTIPATH_QUIC, false, true);
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_DUPLICATE_FIELD);
}

static void test_path_is_typed_fd_bound_and_rejects_v3_shape(void)
{
    uint8_t payload[320];
    vmp_request_t request;
    size_t len = make_add_path(payload, sizeof(payload), 51820U, false,
                               TEST_PATH_VALID);
    assert(vmp_decode_request(payload, len, &request) == VMP_PROTOCOL_OK);
    assert(request.operation == VMP_OPERATION_ADD_PATH);
    assert(request.body.add_path.local_port == 51820U);
    assert(request.body.add_path.ip_len == 16);
    assert(request.body.add_path.remote_port == 443);
    assert(vmp_add_path_is_valid(&request.body.add_path));

    len = make_add_path(payload, sizeof(payload), 0U, false,
                        TEST_PATH_VALID);
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
    len = make_add_path(payload, sizeof(payload), 51820U, true,
                        TEST_PATH_VALID);
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_UNKNOWN_FIELD);

    const test_path_shape_t rejected_shapes[] = {
        TEST_PATH_IPV4,
        TEST_PATH_PUBLIC_PREFIX,
        TEST_PATH_WRONG_EMBEDDED_ID,
        TEST_PATH_DIFFERENT_PREFIX,
        TEST_PATH_WRONG_HOSTS,
    };
    for (size_t index = 0U;
         index < sizeof(rejected_shapes) / sizeof(rejected_shapes[0]);
         ++index) {
        len = make_add_path(payload, sizeof(payload), 51820U, false,
                            rejected_shapes[index]);
        assert(vmp_decode_request(payload, len, &request) ==
               VMP_PROTOCOL_INVALID_VALUE);
    }
}

static void test_complete_ip_datagram_is_required(void)
{
    uint8_t payload[320];
    uint8_t ipv4[20] = {0};
    vmp_request_t request;
    ipv4[0] = 0x45;
    ipv4[2] = 0;
    ipv4[3] = sizeof(ipv4);
    size_t len = make_datagram(payload, sizeof(payload), ipv4, sizeof(ipv4));
    assert(vmp_decode_request(payload, len, &request) == VMP_PROTOCOL_OK);
    assert(request.body.send_datagram.inner_ip_packet.data[0] == 0x45);
    assert(request.body.send_datagram.masque_context_id == 9U);
    ipv4[3] = sizeof(ipv4) - 1;
    len = make_datagram(payload, sizeof(payload), ipv4, sizeof(ipv4));
    assert(vmp_decode_request(payload, len, &request) == VMP_PROTOCOL_INVALID_VALUE);

    len = make_datagram(payload, sizeof(payload), ipv4, 0U);
    assert(vmp_decode_request(payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);

    uint8_t *large_packet = calloc(VMP_MAX_INNER_PACKET + 1U, 1U);
    uint8_t *large_payload = malloc(VMP_MAX_INNER_PACKET + 128U);
    assert(large_packet != NULL && large_payload != NULL);
    large_packet[0] = 0x45U;
    len = make_datagram(large_payload, VMP_MAX_INNER_PACKET + 128U,
                        large_packet, VMP_MAX_INNER_PACKET + 1U);
    assert(vmp_decode_request(large_payload, len, &request) ==
           VMP_PROTOCOL_INVALID_VALUE);
    free(large_payload);
    free(large_packet);
}

static void test_response_is_compatible_and_bounded(void)
{
    vmp_response_t response;
    uint8_t frame[512];
    size_t frame_len = 0;
    memset(&response, 0, sizeof(response));
    response.api_version = VMP_API_VERSION;
    memset(response.request_nonce, 0x55, sizeof(response.request_nonce));
    response.result = VMP_RESULT_OK;
    response.diagnostic_code = "ok";
    response.diagnostic_code_len = 2;
    response.path_count = 1;
    response.paths[0].path_id = 1;
    response.paths[0].smoothed_rtt_us = 1000;
    response.paths[0].delivery_rate_bps = 8000000;
    response.paths[0].data_carrying = true;
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame), &frame_len) ==
           VMP_PROTOCOL_OK);
    assert(frame_len > 4);
    const size_t declared = ((size_t)frame[0] << 24) | ((size_t)frame[1] << 16) |
                            ((size_t)frame[2] << 8) | frame[3];
    assert(declared == frame_len - 4);

    response.diagnostic_code = "not allowed";
    response.diagnostic_code_len = strlen(response.diagnostic_code);
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame), &frame_len) ==
           VMP_PROTOCOL_INVALID_VALUE);

    response.diagnostic_code = "ok";
    response.diagnostic_code_len = 2;
    response.path_count = 2;
    response.paths[1] = response.paths[0];
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame), &frame_len) ==
           VMP_PROTOCOL_INVALID_VALUE);

    response.path_count = 0U;
    response.has_received_datagram = true;
    memset(response.received_datagram.route_context_id, 0x11,
           VMP_CONTEXT_ID_LEN);
    response.received_datagram.masque_context_id = 9U;
    response.received_datagram.inner_ip_packet_len = 20U;
    response.received_datagram.inner_ip_packet[0] = 0x45U;
    response.received_datagram.inner_ip_packet[3] = 20U;
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame),
                                     &frame_len) == VMP_PROTOCOL_OK);
    bool found_received_field = false;
    for (size_t index = 4U; index < frame_len; ++index) {
        if (frame[index] == 0x32U) found_received_field = true;
    }
    assert(found_received_field);

    memset(response.received_datagram.route_context_id, 0,
           VMP_CONTEXT_ID_LEN);
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame),
                                     &frame_len) ==
           VMP_PROTOCOL_INVALID_VALUE);
    memset(response.received_datagram.route_context_id, 0x11,
           VMP_CONTEXT_ID_LEN);
    response.received_datagram.masque_context_id = 0U;
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame),
                                     &frame_len) ==
           VMP_PROTOCOL_INVALID_VALUE);
    response.received_datagram.masque_context_id =
        VMP_MAX_MASQUE_CONTEXT_ID + 1U;
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame),
                                     &frame_len) ==
           VMP_PROTOCOL_INVALID_VALUE);
    response.received_datagram.masque_context_id = 9U;
    response.received_datagram.inner_ip_packet_len = 0U;
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame),
                                     &frame_len) ==
           VMP_PROTOCOL_INVALID_VALUE);
    response.received_datagram.inner_ip_packet_len =
        VMP_MAX_INNER_PACKET + 1U;
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame),
                                     &frame_len) ==
           VMP_PROTOCOL_INVALID_VALUE);

    response.has_received_datagram = false;
    response.result = VMP_RESULT_NO_DATAGRAM;
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame),
                                     &frame_len) == VMP_PROTOCOL_OK);
    response.result = VMP_RESULT_QUEUE_OVERFLOW;
    assert(vmp_encode_response_frame(&response, frame, sizeof(frame),
                                     &frame_len) == VMP_PROTOCOL_OK);
}

int main(void)
{
    test_start_round_trip_shape();
    test_v2_start_shape_and_start_exit_boundary();
    test_old_unknown_version_and_zero_nonce_are_rejected();
    test_noncanonical_wire_forms_are_rejected();
    test_receive_is_context_correlated();
    test_nonzero_masque_context_is_required();
    test_single_path_and_extensions_fail_closed();
    test_path_is_typed_fd_bound_and_rejects_v3_shape();
    test_complete_ip_datagram_is_required();
    test_response_is_compatible_and_bounded();
    puts("protocol tests passed");
    return 0;
}
