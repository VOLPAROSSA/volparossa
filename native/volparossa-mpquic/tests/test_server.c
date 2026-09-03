// SPDX-License-Identifier: GPL-3.0-only

#define _GNU_SOURCE

#include "volparossa_mpquic_runtime.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif

typedef struct test_encoder {
    uint8_t *cursor;
    uint8_t *end;
} test_encoder_t;

typedef struct dispatch_state {
    unsigned calls;
    vmp_operation_t operation;
    bool inject_assignment;
} dispatch_state_t;

typedef struct runtime_dispatch_state {
    vmp_runtime_t *runtime;
    unsigned calls;
    unsigned closed_descriptors;
    vmp_result_t results[2];
    char diagnostics[2][VMP_MAX_DIAGNOSTIC_CODE + 1U];
} runtime_dispatch_state_t;

typedef struct runtime_clock {
    uint64_t boottime_ms;
    uint64_t realtime_ms;
    unsigned snapshot_calls;
    unsigned boottime_calls;
} runtime_clock_t;

static int injected_recvmsg_flags;
static size_t injected_recvmsg_capacity;
static unsigned runtime_auth_calls;
static unsigned runtime_backend_calls;
static const uint8_t test_instance[VMP_NATIVE_INSTANCE_ID_LEN] = {0x61U};
static const uint8_t test_exit_listener_ip[16] = {
    0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x61U, 0x11U, 0x11U,
    0x22U, 0x22U, 0U,    1U,    0x33U, 0x33U, 0U,    4U,
};
static const uint8_t test_auth_commitment[VMP_AUTH_COMMITMENT_LEN] = {
    0x2bU, 0x80U, 0x72U, 0x70U, 0xdbU, 0xd6U, 0x15U, 0x73U,
    0xccU, 0x59U, 0x14U, 0x25U, 0x11U, 0x62U, 0x1eU, 0xd6U,
    0xf3U, 0xc3U, 0x3dU, 0xd1U, 0x40U, 0x77U, 0x4cU, 0xc2U,
    0x4aU, 0x04U, 0x12U, 0x71U, 0xc6U, 0x31U, 0x08U, 0x85U,
};

ssize_t __real_recvmsg(int socket, struct msghdr *message, int flags);

ssize_t __wrap_recvmsg(int socket, struct msghdr *message, int flags)
{
    size_t original_capacity = 0U;
    if (injected_recvmsg_capacity != 0U && message->msg_iov != NULL &&
        message->msg_iovlen == 1U &&
        message->msg_iov[0].iov_len > injected_recvmsg_capacity) {
        original_capacity = message->msg_iov[0].iov_len;
        message->msg_iov[0].iov_len = injected_recvmsg_capacity;
    }
    const ssize_t received = __real_recvmsg(socket, message, flags);
    if (original_capacity != 0U) {
        message->msg_iov[0].iov_len = original_capacity;
        if (received >= 0) injected_recvmsg_capacity = 0U;
    }
    if (received >= 0 && injected_recvmsg_flags != 0) {
        message->msg_flags |= injected_recvmsg_flags;
        injected_recvmsg_flags = 0;
    }
    return received;
}

static void put_varint(test_encoder_t *encoder, uint64_t value)
{
    do {
        assert(encoder->cursor != encoder->end);
        uint8_t byte = (uint8_t)(value & UINT64_C(0x7f));
        value >>= 7;
        if (value != 0U) byte |= UINT8_C(0x80);
        *encoder->cursor++ = byte;
    } while (value != 0U);
}

static void put_uint(test_encoder_t *encoder, uint32_t field, uint64_t value)
{
    put_varint(encoder, (uint64_t)field << 3U);
    put_varint(encoder, value);
}

static void put_bytes(test_encoder_t *encoder, uint32_t field,
                      const uint8_t *value, size_t len)
{
    put_varint(encoder, ((uint64_t)field << 3U) | UINT64_C(2));
    put_varint(encoder, len);
    assert((size_t)(encoder->end - encoder->cursor) >= len);
    memcpy(encoder->cursor, value, len);
    encoder->cursor += len;
}

static size_t finish_frame(uint8_t *frame, const test_encoder_t *parent)
{
    const size_t payload_len = (size_t)(parent->cursor - (frame + 4U));
    frame[0] = (uint8_t)(payload_len >> 24U);
    frame[1] = (uint8_t)(payload_len >> 16U);
    frame[2] = (uint8_t)(payload_len >> 8U);
    frame[3] = (uint8_t)payload_len;
    return payload_len + 4U;
}

static size_t make_status_frame(uint8_t *frame, size_t capacity)
{
    uint8_t nested[32];
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    uint8_t context[VMP_CONTEXT_ID_LEN];
    memset(nonce, 0x31, sizeof(nonce));
    memset(context, 0x41, sizeof(context));
    test_encoder_t child = {.cursor = nested, .end = nested + sizeof(nested)};
    put_bytes(&child, 1U, context, sizeof(context));
    test_encoder_t parent = {.cursor = frame + 4U, .end = frame + capacity};
    put_uint(&parent, 1U, VMP_API_VERSION);
    put_bytes(&parent, 2U, nonce, sizeof(nonce));
    put_bytes(&parent, 3U, test_instance, sizeof(test_instance));
    put_bytes(&parent, VMP_OPERATION_GET_STATUS, nested,
              (size_t)(child.cursor - nested));
    return finish_frame(frame, &parent);
}

static size_t make_start_frame(uint8_t *frame, size_t capacity)
{
    static const uint8_t auth[VMP_AUTH_SECRET_LEN] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static const uint8_t tls_name[] = "exit.example";
    uint8_t nested[512];
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    uint8_t context[VMP_CONTEXT_ID_LEN];
    uint8_t spki[VMP_SPKI_SHA256_LEN];
    uint8_t reservation_id[VMP_RESERVATION_ID_LEN];
    uint8_t finalize_id[VMP_FINALIZE_ID_LEN];
    uint8_t auth_commitment[VMP_AUTH_COMMITMENT_LEN];
    uint8_t certificate_sha256[VMP_CERTIFICATE_SHA256_LEN];
    uint8_t exit_instance[VMP_NATIVE_INSTANCE_ID_LEN];
    memset(nonce, 0x30, sizeof(nonce));
    memset(context, 0x40, sizeof(context));
    memset(spki, 0x41, sizeof(spki));
    memset(reservation_id, 0x42, sizeof(reservation_id));
    memset(finalize_id, 0x43, sizeof(finalize_id));
    memcpy(auth_commitment, test_auth_commitment,
           sizeof(auth_commitment));
    memset(certificate_sha256, 0x45, sizeof(certificate_sha256));
    memset(exit_instance, 0x46, sizeof(exit_instance));
    test_encoder_t child = {.cursor = nested, .end = nested + sizeof(nested)};
    put_bytes(&child, 1U, context, sizeof(context));
    put_bytes(&child, 2U, spki, sizeof(spki));
    put_uint(&child, 3U, 1U);
    put_uint(&child, 4U, 9U);
    put_uint(&child, 5U, VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP);
    put_bytes(&child, 6U, auth, sizeof(auth));
    put_bytes(&child, 7U, tls_name, sizeof(tls_name) - 1U);
    put_uint(&child, 8U, UINT64_C(1060000));
    put_bytes(&child, 9U, reservation_id, sizeof(reservation_id));
    put_bytes(&child, 10U, finalize_id, sizeof(finalize_id));
    put_bytes(&child, 11U, auth_commitment, sizeof(auth_commitment));
    put_bytes(&child, 12U, certificate_sha256,
              sizeof(certificate_sha256));
    put_bytes(&child, 13U, test_instance, sizeof(test_instance));
    put_bytes(&child, 14U, exit_instance, sizeof(exit_instance));
    test_encoder_t parent = {.cursor = frame + 4U, .end = frame + capacity};
    put_uint(&parent, 1U, VMP_API_VERSION);
    put_bytes(&parent, 2U, nonce, sizeof(nonce));
    put_bytes(&parent, 3U, test_instance, sizeof(test_instance));
    put_bytes(&parent, VMP_OPERATION_START_SESSION, nested,
              (size_t)(child.cursor - nested));
    return finish_frame(frame, &parent);
}

static size_t make_add_path_frame_for(uint8_t *frame, size_t capacity,
                                      uint16_t local_port,
                                      bool public_overlay)
{
    uint8_t nested[160];
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    uint8_t context[VMP_CONTEXT_ID_LEN];
    uint8_t reservation[VMP_RESERVATION_HASH_LEN];
    uint8_t local[16] = {
        0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x61U, 0x11U, 0x11U,
        0x22U, 0x22U, 0U,    1U,    0x33U, 0x33U, 0U,    1U,
    };
    uint8_t remote[16];
    memset(nonce, 0x32, sizeof(nonce));
    memset(context, 0x42, sizeof(context));
    memset(reservation, 0x43, sizeof(reservation));
    memcpy(remote, local, sizeof(remote));
    remote[15] = 4U;
    if (public_overlay) {
        local[0] = 0x20U;
        remote[0] = 0x20U;
    }
    test_encoder_t child = {.cursor = nested, .end = nested + sizeof(nested)};
    put_bytes(&child, 1U, context, sizeof(context));
    put_uint(&child, 2U, 1U);
    put_bytes(&child, 4U, local, sizeof(local));
    put_bytes(&child, 5U, remote, sizeof(remote));
    put_uint(&child, 6U, 443U);
    put_bytes(&child, 7U, reservation, sizeof(reservation));
    put_uint(&child, 8U, local_port);
    test_encoder_t parent = {.cursor = frame + 4U, .end = frame + capacity};
    put_uint(&parent, 1U, VMP_API_VERSION);
    put_bytes(&parent, 2U, nonce, sizeof(nonce));
    put_bytes(&parent, 3U, test_instance, sizeof(test_instance));
    put_bytes(&parent, VMP_OPERATION_ADD_PATH, nested,
              (size_t)(child.cursor - nested));
    return finish_frame(frame, &parent);
}

static size_t make_add_path_frame(uint8_t *frame, size_t capacity)
{
    return make_add_path_frame_for(frame, capacity, UINT16_C(51820), false);
}

static size_t make_start_exit_frame_for(uint8_t *frame, size_t capacity,
                                        uint8_t nonce_byte,
                                        uint16_t listener_port)
{
    static const uint8_t auth[VMP_AUTH_SECRET_LEN] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static const uint8_t tls_name[] = "exit.example";
    static const uint8_t certificate[] =
        "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";
    static const uint8_t private_key[] =
        "-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n";
    uint8_t nested[768];
    uint8_t nonce[VMP_REQUEST_NONCE_LEN];
    uint8_t context[VMP_CONTEXT_ID_LEN];
    uint8_t spki[VMP_SPKI_SHA256_LEN];
    uint8_t reservation[VMP_RESERVATION_HASH_LEN];
    uint8_t client_ip[16] = {
        0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x61U, 0x11U, 0x11U,
        0x22U, 0x22U, 0U,    1U,    0x33U, 0x33U, 0U,    1U,
    };
    memset(nonce, nonce_byte, sizeof(nonce));
    memset(context, 0x44, sizeof(context));
    memset(spki, 0x45, sizeof(spki));
    memset(reservation, 0x46, sizeof(reservation));
    test_encoder_t child = {.cursor = nested, .end = nested + sizeof(nested)};
    put_bytes(&child, 1U, context, sizeof(context));
    put_bytes(&child, 2U, auth, sizeof(auth));
    put_uint(&child, 3U, UINT64_C(1060000));
    put_uint(&child, 4U, 1U);
    put_uint(&child, 5U, 19U);
    put_uint(&child, 6U, VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP);
    put_bytes(&child, 7U, spki, sizeof(spki));
    put_bytes(&child, 8U, tls_name, sizeof(tls_name) - 1U);
    put_uint(&child, 9U, 1U);
    put_bytes(&child, 10U, test_exit_listener_ip,
              sizeof(test_exit_listener_ip));
    put_uint(&child, 11U, listener_port);
    put_bytes(&child, 12U, client_ip, sizeof(client_ip));
    put_uint(&child, 13U, UINT16_C(51820));
    put_bytes(&child, 14U, reservation, sizeof(reservation));
    put_bytes(&child, 15U, certificate, sizeof(certificate) - 1U);
    put_bytes(&child, 16U, private_key, sizeof(private_key) - 1U);
    uint8_t reservation_id[VMP_RESERVATION_ID_LEN];
    uint8_t finalize_id[VMP_FINALIZE_ID_LEN];
    uint8_t auth_commitment[VMP_AUTH_COMMITMENT_LEN];
    uint8_t certificate_sha256[VMP_CERTIFICATE_SHA256_LEN];
    uint8_t client_instance[VMP_NATIVE_INSTANCE_ID_LEN];
    memset(reservation_id, 0x51, sizeof(reservation_id));
    memset(finalize_id, 0x52, sizeof(finalize_id));
    memcpy(auth_commitment, test_auth_commitment,
           sizeof(auth_commitment));
    memset(certificate_sha256, 0x54, sizeof(certificate_sha256));
    memset(client_instance, 0x55, sizeof(client_instance));
    put_bytes(&child, 17U, reservation_id, sizeof(reservation_id));
    put_bytes(&child, 18U, finalize_id, sizeof(finalize_id));
    put_bytes(&child, 19U, auth_commitment, sizeof(auth_commitment));
    put_bytes(&child, 20U, certificate_sha256,
              sizeof(certificate_sha256));
    put_bytes(&child, 21U, client_instance, sizeof(client_instance));
    put_bytes(&child, 22U, test_instance, sizeof(test_instance));
    test_encoder_t parent = {.cursor = frame + 4U, .end = frame + capacity};
    put_uint(&parent, 1U, VMP_API_VERSION);
    put_bytes(&parent, 2U, nonce, sizeof(nonce));
    put_bytes(&parent, 3U, test_instance, sizeof(test_instance));
    put_bytes(&parent, VMP_OPERATION_START_EXIT_SESSION, nested,
              (size_t)(child.cursor - nested));
    return finish_frame(frame, &parent);
}

static size_t make_start_exit_frame(uint8_t *frame, size_t capacity)
{
    return make_start_exit_frame_for(frame, capacity, 0x34U, 443U);
}

static bool test_request_binding(void *context, vmp_operation_t operation,
                                 const uint8_t *request,
                                 size_t request_len,
                                 uint8_t out[VMP_FD_BINDING_LEN])
{
    (void)context;
    if ((operation != VMP_OPERATION_ADD_PATH &&
         operation != VMP_OPERATION_START_EXIT_SESSION) ||
        request == NULL || request_len == 0U || out == NULL) {
        return false;
    }
    for (size_t index = 0U; index < VMP_FD_BINDING_LEN; ++index) {
        out[index] = (uint8_t)(UINT8_C(0xa5) ^ (uint8_t)index);
    }
    out[1] ^= (uint8_t)operation;
    out[0] ^= (uint8_t)request_len;
    for (size_t index = 0U; index < request_len; ++index) {
        out[index % VMP_FD_BINDING_LEN] ^= request[index];
    }
    return true;
}

static bool test_request_digest(void *context, const uint8_t *request,
                                size_t request_len,
                                uint8_t out[VMP_REQUEST_SHA256_LEN])
{
    (void)context;
    if (request == NULL || request_len == 0U || out == NULL) return false;
    for (size_t index = 0U; index < VMP_REQUEST_SHA256_LEN; ++index) {
        out[index] = (uint8_t)(UINT8_C(0x6d) ^ (uint8_t)index);
    }
    out[0] ^= (uint8_t)request_len;
    for (size_t index = 0U; index < request_len; ++index) {
        out[index % VMP_REQUEST_SHA256_LEN] ^= request[index];
    }
    return true;
}

static bool reject_request_digest(void *context, const uint8_t *request,
                                  size_t request_len,
                                  uint8_t out[VMP_REQUEST_SHA256_LEN])
{
    (void)context;
    (void)request;
    (void)request_len;
    memset(out, 0, VMP_REQUEST_SHA256_LEN);
    return false;
}

static void binding_for_frame(const uint8_t *frame, size_t frame_len,
                              vmp_operation_t operation,
                              uint8_t out[VMP_FD_BINDING_LEN])
{
    assert(frame_len > 4U);
    assert(test_request_binding(NULL, operation, frame + 4U,
                                frame_len - 4U, out));
}

static vmp_server_error_t test_dispatch(void *context,
                                        const vmp_request_t *request,
                                        vmp_response_t *response,
                                        int request_fd)
{
    dispatch_state_t *state = context;
    ++state->calls;
    state->operation = request->operation;
    if (request->operation == VMP_OPERATION_ADD_PATH ||
        request->operation == VMP_OPERATION_START_EXIT_SESSION) {
        assert(request_fd >= 0);
        const int flags = fcntl(request_fd, F_GETFD);
        assert(flags >= 0 && (flags & FD_CLOEXEC) != 0);
        assert(close(request_fd) == 0);
    } else {
        assert(request_fd == -1);
    }
    response->result = VMP_RESULT_OK;
    response->diagnostic_code = "ok";
    response->diagnostic_code_len = 2U;
    response->native_process_identity.role =
        request->operation == VMP_OPERATION_START_EXIT_SESSION
            ? VMP_NATIVE_ROLE_EXIT
            : VMP_NATIVE_ROLE_CLIENT;
    memcpy(response->native_process_identity.native_instance_id,
           test_instance, sizeof(test_instance));
    if (request->operation == VMP_OPERATION_GET_STATUS) {
        response->path_count = 1U;
        response->paths[0].path_id = 1U;
        response->paths[0].smoothed_rtt_us = 5000U;
    }
    if (state->inject_assignment) {
        response->has_tunnel_assignment = true;
        response->tunnel_assignment.assigned_ipv4[0] = 10U;
        response->tunnel_assignment.assigned_ipv4[1] = 76U;
        response->tunnel_assignment.assigned_ipv4[3] = 2U;
        response->tunnel_assignment.assigned_prefix_v4 = 32U;
        response->tunnel_assignment.server_ipv4[0] = 10U;
        response->tunnel_assignment.server_ipv4[1] = 76U;
        response->tunnel_assignment.server_ipv4[3] = 1U;
        response->tunnel_assignment.server_prefix_v4 = 32U;
        response->tunnel_assignment.mtu = 1280U;
    }
    return VMP_SERVER_OK;
}

static vmp_transport_error_t reject_transport_create(
    void *factory_context, const vmp_transport_create_params_t *params,
    void **out_session)
{
    (void)factory_context;
    (void)params;
    assert(out_session != NULL);
    *out_session = NULL;
    ++runtime_backend_calls;
    return VMP_TRANSPORT_ENGINE;
}

static void reject_transport_destroy(void *session)
{
    (void)session;
    ++runtime_backend_calls;
}

static vmp_transport_error_t reject_transport_add(
    void *session, const vmp_add_path_t *path, int path_fd,
    int64_t *out_handle)
{
    (void)session;
    (void)path;
    (void)out_handle;
    if (path_fd >= 0) assert(close(path_fd) == 0);
    ++runtime_backend_calls;
    return VMP_TRANSPORT_ENGINE;
}

static vmp_transport_error_t reject_transport_remove(void *session,
                                                     int64_t handle)
{
    (void)session;
    (void)handle;
    ++runtime_backend_calls;
    return VMP_TRANSPORT_ENGINE;
}

static vmp_transport_error_t reject_transport_pump(void *session)
{
    (void)session;
    ++runtime_backend_calls;
    return VMP_TRANSPORT_ENGINE;
}

static vmp_transport_error_t reject_transport_snapshot(
    void *session, vmp_transport_path_snapshot_t *out, size_t capacity,
    size_t *out_count, bool *out_tunnel_ready, bool *out_has_assignment,
    vmp_tunnel_assignment_t *out_assignment)
{
    (void)session;
    (void)out;
    (void)capacity;
    (void)out_count;
    (void)out_tunnel_ready;
    (void)out_has_assignment;
    (void)out_assignment;
    ++runtime_backend_calls;
    return VMP_TRANSPORT_ENGINE;
}

static vmp_transport_error_t reject_transport_send(
    void *session, uint64_t masque_context_id, const uint8_t *packet,
    size_t packet_len)
{
    (void)session;
    (void)masque_context_id;
    (void)packet;
    (void)packet_len;
    ++runtime_backend_calls;
    return VMP_TRANSPORT_ENGINE;
}

static vmp_transport_error_t reject_transport_receive(
    void *session, uint64_t masque_context_id, uint8_t *out,
    size_t out_capacity, size_t *out_len)
{
    (void)session;
    (void)masque_context_id;
    (void)out;
    (void)out_capacity;
    (void)out_len;
    ++runtime_backend_calls;
    return VMP_TRANSPORT_ENGINE;
}

static vmp_transport_error_t reject_exit_create(
    void *factory_context, const vmp_start_exit_session_t *start,
    void **out_session)
{
    (void)factory_context;
    (void)start;
    (void)out_session;
    ++runtime_backend_calls;
    return VMP_TRANSPORT_ENGINE;
}

static vmp_transport_error_t reject_exit_add(
    void *session, const vmp_start_exit_session_t *path, int listener_fd,
    int64_t *out_handle)
{
    (void)session;
    (void)path;
    (void)out_handle;
    if (listener_fd >= 0) (void)close(listener_fd);
    ++runtime_backend_calls;
    return VMP_TRANSPORT_ENGINE;
}

static vmp_transport_error_t reject_exit_snapshot(
    void *session, vmp_exit_transport_snapshot_t *out)
{
    (void)session;
    (void)out;
    ++runtime_backend_calls;
    return VMP_TRANSPORT_ENGINE;
}

static const vmp_transport_ops_t REJECT_TRANSPORT_OPS = {
    .create = reject_transport_create,
    .destroy = reject_transport_destroy,
    .add_path = reject_transport_add,
    .remove_path = reject_transport_remove,
    .pump = reject_transport_pump,
    .snapshot = reject_transport_snapshot,
    .send_inner = reject_transport_send,
    .receive_inner = reject_transport_receive,
    .exit_create = reject_exit_create,
    .exit_destroy = reject_transport_destroy,
    .exit_add_listener = reject_exit_add,
    .exit_start = reject_transport_pump,
    .exit_pump = reject_transport_pump,
    .exit_snapshot = reject_exit_snapshot,
    .exit_send_inner = reject_transport_send,
    .exit_receive_inner = reject_transport_receive,
};

static bool runtime_clock_snapshot(void *context, uint64_t *out_boottime_ms,
                                   uint64_t *out_realtime_ms)
{
    runtime_clock_t *clock = context;
    assert(clock != NULL && out_boottime_ms != NULL &&
           out_realtime_ms != NULL);
    ++clock->snapshot_calls;
    *out_boottime_ms = clock->boottime_ms;
    *out_realtime_ms = clock->realtime_ms;
    return true;
}

static bool runtime_boottime(void *context, uint64_t *out_boottime_ms)
{
    runtime_clock_t *clock = context;
    assert(clock != NULL && out_boottime_ms != NULL);
    ++clock->boottime_calls;
    *out_boottime_ms = clock->boottime_ms;
    return true;
}

static bool runtime_auth_commitment(
    void *context, const uint8_t *auth_secret, size_t auth_secret_len,
    uint8_t out[VMP_AUTH_COMMITMENT_LEN])
{
    static const uint8_t expected_secret[VMP_AUTH_SECRET_LEN] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    (void)context;
    ++runtime_auth_calls;
    if (auth_secret == NULL || out == NULL ||
        auth_secret_len != sizeof(expected_secret) ||
        memcmp(auth_secret, expected_secret, sizeof(expected_secret)) != 0) {
        return false;
    }
    memcpy(out, test_auth_commitment, VMP_AUTH_COMMITMENT_LEN);
    return true;
}

static vmp_server_error_t runtime_dispatch_capture(
    void *context, const vmp_request_t *request, vmp_response_t *response,
    int request_fd)
{
    runtime_dispatch_state_t *state = context;
    assert(state != NULL && state->runtime != NULL && state->calls < 2U);
    const vmp_server_error_t error =
        vmp_runtime_dispatch(state->runtime, request, response, request_fd);
    if (request_fd >= 0) {
        errno = 0;
        assert(fcntl(request_fd, F_GETFD) == -1 && errno == EBADF);
        ++state->closed_descriptors;
    }
    const unsigned index = state->calls++;
    state->results[index] = response->result;
    assert(response->diagnostic_code != NULL);
    assert(response->diagnostic_code_len <= VMP_MAX_DIAGNOSTIC_CODE);
    memcpy(state->diagnostics[index], response->diagnostic_code,
           response->diagnostic_code_len);
    state->diagnostics[index][response->diagnostic_code_len] = '\0';
    return error;
}

static vmp_server_error_t count_pump(void *context)
{
    unsigned *calls = context;
    ++*calls;
    return VMP_SERVER_OK;
}

static vmp_server_options_t options(void)
{
    vmp_server_options_t value = {
        .expected_peer_uid = getuid(),
        .frame_timeout_ms = 1000U,
        .max_requests = VMP_MAX_REQUESTS_PER_CONNECTION,
        .request_binding = test_request_binding,
        .request_digest = test_request_digest,
    };
    return value;
}

static void write_exact_test(int fd, const uint8_t *buffer, size_t len)
{
    size_t offset = 0U;
    while (offset < len) {
        const ssize_t written = write(fd, buffer + offset, len - offset);
        assert(written > 0);
        offset += (size_t)written;
    }
}

static void read_exact_test(int fd, uint8_t *buffer, size_t len)
{
    size_t offset = 0U;
    while (offset < len) {
        const ssize_t received = read(fd, buffer + offset, len - offset);
        assert(received > 0);
        offset += (size_t)received;
    }
}

static size_t open_descriptor_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    assert(directory != NULL);
    size_t count = 0U;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            ++count;
        }
    }
    assert(closedir(directory) == 0);
    return count;
}

static int make_bound_exit_listener(uint16_t *out_port)
{
    assert(out_port != NULL);
    const int descriptor =
        socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
               IPPROTO_UDP);
    assert(descriptor >= 0);
    const int enabled = 1;
    assert(setsockopt(descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &enabled,
                      sizeof(enabled)) == 0);
    assert(setsockopt(descriptor, IPPROTO_IPV6, IPV6_FREEBIND, &enabled,
                      sizeof(enabled)) == 0);
    struct sockaddr_in6 local;
    memset(&local, 0, sizeof(local));
    local.sin6_family = AF_INET6;
    memcpy(&local.sin6_addr, test_exit_listener_ip,
           sizeof(test_exit_listener_ip));
    assert(bind(descriptor, (const struct sockaddr *)&local,
                sizeof(local)) == 0);
    socklen_t local_len = sizeof(local);
    assert(getsockname(descriptor, (struct sockaddr *)&local,
                       &local_len) == 0);
    assert(local_len == sizeof(local) && local.sin6_port != 0U);
    *out_port = ntohs(local.sin6_port);
    return descriptor;
}

static void send_with_fds(int fd, const uint8_t *buffer, size_t len,
                          const int *descriptors, size_t descriptor_count)
{
    assert(buffer != NULL && len > 0U && descriptor_count <= 3U);
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(3U * sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));
    struct iovec vector = {.iov_base = (void *)buffer, .iov_len = len};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    if (descriptor_count > 0U) {
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(descriptor_count * sizeof(int));
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        assert(header != NULL);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(descriptor_count * sizeof(int));
        memcpy(CMSG_DATA(header), descriptors, descriptor_count * sizeof(int));
    }
    assert(sendmsg(fd, &message, MSG_NOSIGNAL) == (ssize_t)len);
}

static void send_binding(int fd, const uint8_t binding[VMP_FD_BINDING_LEN],
                         const int *descriptors, size_t descriptor_count)
{
    send_with_fds(fd, binding, VMP_FD_BINDING_LEN, descriptors,
                  descriptor_count);
}

static void close_pair(int sockets[2])
{
    assert(close(sockets[0]) == 0);
    assert(close(sockets[1]) == 0);
}

static void serve_runtime_exit_frame(runtime_dispatch_state_t *state,
                                     uint8_t nonce_byte)
{
    const size_t baseline = open_descriptor_count();
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    uint16_t listener_port = 0U;
    const int listener = make_bound_exit_listener(&listener_port);
    uint8_t request[1024];
    uint8_t binding[VMP_FD_BINDING_LEN];
    const size_t request_len = make_start_exit_frame_for(
        request, sizeof(request), nonce_byte, listener_port);
    binding_for_frame(request, request_len,
                      VMP_OPERATION_START_EXIT_SESSION, binding);
    send_binding(sockets[0], binding, &listener, 1U);
    assert(close(listener) == 0);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);

    const vmp_server_options_t configuration = options();
    assert(vmp_serve_connection(sockets[1], &configuration,
                                runtime_dispatch_capture,
                                state) == VMP_SERVER_OK);
    assert(open_descriptor_count() == baseline + 2U);
    close_pair(sockets);
    assert(open_descriptor_count() == baseline);
}

static void expect_protocol(int sockets[2], dispatch_state_t *state)
{
    const vmp_server_options_t configuration = options();
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                state) == VMP_SERVER_PROTOCOL);
    assert(state->calls == 0U);
}

static void reject_one_fd_and_assert_closed(const uint8_t *request,
                                            size_t request_len,
                                            bool correct_binding)
{
    int sockets[2];
    int pipe_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    const size_t baseline = open_descriptor_count();
    uint8_t binding[VMP_FD_BINDING_LEN];
    if (correct_binding) {
        binding_for_frame(request, request_len, VMP_OPERATION_ADD_PATH,
                          binding);
    } else {
        memset(binding, 0x5a, sizeof(binding));
    }
    send_binding(sockets[0], binding, &pipe_fds[0], 1U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    dispatch_state_t state = {0};
    expect_protocol(sockets, &state);
    assert(open_descriptor_count() == baseline);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);
}

static void reject_descriptor_count_and_assert_closed(size_t descriptor_count)
{
    assert(descriptor_count == 2U || descriptor_count == 3U);
    int sockets[2];
    int pipes[3][2];
    int descriptors[3];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    for (size_t index = 0U; index < descriptor_count; ++index) {
        assert(pipe(pipes[index]) == 0);
        descriptors[index] = pipes[index][0];
    }
    const size_t baseline = open_descriptor_count();
    uint8_t request[256];
    uint8_t binding[VMP_FD_BINDING_LEN];
    const size_t request_len = make_add_path_frame(request, sizeof(request));
    binding_for_frame(request, request_len, VMP_OPERATION_ADD_PATH, binding);
    send_binding(sockets[0], binding, descriptors, descriptor_count);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    dispatch_state_t state = {0};
    expect_protocol(sockets, &state);
    assert(open_descriptor_count() == baseline);
    for (size_t index = 0U; index < descriptor_count; ++index) {
        assert(close(pipes[index][0]) == 0);
        assert(close(pipes[index][1]) == 0);
    }
    close_pair(sockets);
}

static void test_rejected_descriptors_are_closed_on_every_boundary(void)
{
    uint8_t request[256];
    size_t request_len = make_add_path_frame(request, sizeof(request));
    reject_one_fd_and_assert_closed(request, request_len, false);

    assert(request[4] == 0x08U && request[5] == VMP_API_VERSION);
    request[5] = 3U;
    reject_one_fd_and_assert_closed(request, request_len, true);

    request_len = make_add_path_frame_for(request, sizeof(request), 0U, false);
    reject_one_fd_and_assert_closed(request, request_len, true);
    request_len = make_add_path_frame_for(request, sizeof(request),
                                          UINT16_C(51820), true);
    reject_one_fd_and_assert_closed(request, request_len, true);

    reject_descriptor_count_and_assert_closed(2U);
    reject_descriptor_count_and_assert_closed(3U);

    const uint8_t binding[VMP_FD_BINDING_LEN] = {0};
    request_len = make_status_frame(request, sizeof(request));
    for (unsigned late_descriptor = 0U; late_descriptor < 2U;
         ++late_descriptor) {
        int sockets[2];
        int pipe_fds[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
        assert(pipe(pipe_fds) == 0);
        const size_t baseline = open_descriptor_count();
        if (late_descriptor == 0U) {
            send_binding(sockets[0], binding, &pipe_fds[0], 1U);
            write_exact_test(sockets[0], request, request_len);
        } else {
            send_binding(sockets[0], binding, NULL, 0U);
            send_with_fds(sockets[0], request, request_len, &pipe_fds[0],
                          1U);
        }
        assert(shutdown(sockets[0], SHUT_WR) == 0);
        dispatch_state_t state = {0};
        expect_protocol(sockets, &state);
        assert(open_descriptor_count() == baseline);
        assert(close(pipe_fds[0]) == 0);
        assert(close(pipe_fds[1]) == 0);
        close_pair(sockets);
    }
}

static void test_authenticated_framed_exchange(void)
{
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    uint8_t request[128];
    const size_t request_len = make_status_frame(request, sizeof(request));
    const uint8_t binding[VMP_FD_BINDING_LEN] = {0};
    send_binding(sockets[0], binding, NULL, 0U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    dispatch_state_t state = {0};
    const vmp_server_options_t configuration = options();
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_OK);
    assert(state.calls == 1U && state.operation == VMP_OPERATION_GET_STATUS);
    uint8_t prefix[4];
    read_exact_test(sockets[0], prefix, sizeof(prefix));
    const size_t response_len = ((size_t)prefix[0] << 24U) |
                                ((size_t)prefix[1] << 16U) |
                                ((size_t)prefix[2] << 8U) | prefix[3];
    assert(response_len > 0U && response_len < 256U);
    uint8_t response[256];
    read_exact_test(sockets[0], response, response_len);
    uint8_t expected_digest[VMP_REQUEST_SHA256_LEN];
    assert(test_request_digest(NULL, request + 4U, request_len - 4U,
                               expected_digest));
    bool found_digest = false;
    for (size_t index = 0U;
         index + 2U + VMP_REQUEST_SHA256_LEN <= response_len; ++index) {
        if (response[index] == 0x42U &&
            response[index + 1U] == VMP_REQUEST_SHA256_LEN &&
            memcmp(response + index + 2U, expected_digest,
                   VMP_REQUEST_SHA256_LEN) == 0) {
            found_digest = true;
        }
    }
    assert(found_digest);
    close_pair(sockets);
}

static void test_request_digest_and_assignment_shape_fail_closed(void)
{
    const uint8_t binding[VMP_FD_BINDING_LEN] = {0};
    uint8_t request[1024];
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    size_t request_len = make_status_frame(request, sizeof(request));
    send_binding(sockets[0], binding, NULL, 0U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    dispatch_state_t state = {0};
    vmp_server_options_t configuration = options();
    configuration.request_digest = reject_request_digest;
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_BACKEND);
    assert(state.calls == 0U);
    close_pair(sockets);

    int pipe_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    const size_t baseline = open_descriptor_count();
    uint8_t descriptor_binding[VMP_FD_BINDING_LEN];
    request_len = make_add_path_frame(request, sizeof(request));
    binding_for_frame(request, request_len, VMP_OPERATION_ADD_PATH,
                      descriptor_binding);
    send_binding(sockets[0], descriptor_binding, &pipe_fds[0], 1U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    state = (dispatch_state_t){0};
    configuration = options();
    configuration.request_digest = reject_request_digest;
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_BACKEND);
    assert(state.calls == 0U);
    assert(open_descriptor_count() == baseline);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    request_len = make_start_frame(request, sizeof(request));
    send_binding(sockets[0], binding, NULL, 0U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    state = (dispatch_state_t){0};
    configuration = options();
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_BACKEND);
    assert(state.calls == 1U &&
           state.operation == VMP_OPERATION_START_SESSION);
    close_pair(sockets);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    request_len = make_status_frame(request, sizeof(request));
    send_binding(sockets[0], binding, NULL, 0U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    state = (dispatch_state_t){.inject_assignment = true};
    configuration = options();
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_BACKEND);
    assert(state.calls == 1U &&
           state.operation == VMP_OPERATION_GET_STATUS);
    close_pair(sockets);
}

static void reject_injected_message_flag_and_assert_closed(int message_flag)
{
    assert(message_flag == MSG_TRUNC || message_flag == MSG_CTRUNC);
    int sockets[2];
    int pipe_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    const size_t baseline = open_descriptor_count();
    uint8_t request[256];
    uint8_t binding[VMP_FD_BINDING_LEN];
    const size_t request_len = make_add_path_frame(request, sizeof(request));
    binding_for_frame(request, request_len, VMP_OPERATION_ADD_PATH, binding);
    send_binding(sockets[0], binding, &pipe_fds[0], 1U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);

    injected_recvmsg_flags = message_flag;
    dispatch_state_t state = {0};
    expect_protocol(sockets, &state);
    assert(injected_recvmsg_flags == 0);
    assert(open_descriptor_count() == baseline);

    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);
}

static void test_message_truncation_flags_are_rejected_and_closed(void)
{
    reject_injected_message_flag_and_assert_closed(MSG_TRUNC);
    reject_injected_message_flag_and_assert_closed(MSG_CTRUNC);
}

static void test_exact_add_path_fd_and_binding_succeeds(void)
{
    int sockets[2];
    int pipe_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    uint8_t request[256];
    uint8_t binding[VMP_FD_BINDING_LEN];
    const size_t request_len = make_add_path_frame(request, sizeof(request));
    binding_for_frame(request, request_len, VMP_OPERATION_ADD_PATH, binding);
    send_binding(sockets[0], binding, &pipe_fds[0], 1U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    dispatch_state_t state = {0};
    const vmp_server_options_t configuration = options();
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_OK);
    assert(state.calls == 1U && state.operation == VMP_OPERATION_ADD_PATH);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);
}

static void test_exact_start_exit_fd_uses_distinct_binding_domain(void)
{
    uint8_t request[1024];
    uint8_t binding[VMP_FD_BINDING_LEN];
    const size_t request_len = make_start_exit_frame(request, sizeof(request));

    int sockets[2];
    int pipe_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    binding_for_frame(request, request_len, VMP_OPERATION_ADD_PATH, binding);
    send_binding(sockets[0], binding, &pipe_fds[0], 1U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    dispatch_state_t state = {0};
    expect_protocol(sockets, &state);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    binding_for_frame(request, request_len,
                      VMP_OPERATION_START_EXIT_SESSION, binding);
    send_binding(sockets[0], binding, &pipe_fds[0], 1U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    state = (dispatch_state_t){0};
    const vmp_server_options_t configuration = options();
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_OK);
    assert(state.calls == 1U &&
           state.operation == VMP_OPERATION_START_EXIT_SESSION);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);
}

static void test_framed_exit_authorization_replay_is_consumed_once(void)
{
    runtime_auth_calls = 0U;
    runtime_backend_calls = 0U;
    runtime_clock_t clock = {
        .boottime_ms = UINT64_C(500000),
        .realtime_ms = UINT64_C(1000000),
    };
    vmp_runtime_t *runtime = vmp_runtime_create(
        VMP_RUNTIME_EXIT, test_instance, &REJECT_TRANSPORT_OPS, NULL,
        runtime_auth_commitment, NULL, runtime_clock_snapshot,
        runtime_boottime, &clock);
    assert(runtime != NULL);
    assert(clock.snapshot_calls == 1U && clock.boottime_calls == 0U);

    runtime_dispatch_state_t state = {.runtime = runtime};
    serve_runtime_exit_frame(&state, 0x71U);
    assert(state.calls == 1U && state.closed_descriptors == 1U);
    assert(state.results[0] == VMP_RESULT_TRANSPORT);
    assert(strcmp(state.diagnostics[0],
                  "exit_transport_create_failed") == 0);
    assert(runtime_auth_calls == 1U && runtime_backend_calls == 1U);

    serve_runtime_exit_frame(&state, 0x72U);
    assert(state.calls == 2U && state.closed_descriptors == 2U);
    assert(state.results[1] == VMP_RESULT_UNAUTHORISED);
    assert(strcmp(state.diagnostics[1], "authorization_replay") == 0);
    assert(runtime_auth_calls == 2U && runtime_backend_calls == 1U);
    assert(clock.snapshot_calls == 3U && clock.boottime_calls == 0U);

    vmp_runtime_destroy(runtime);
    assert(runtime_backend_calls == 1U);
}

static void test_fragmented_binding_recvmsg_is_reassembled(void)
{
    int sockets[2];
    int pipe_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    uint8_t request[256];
    uint8_t binding[VMP_FD_BINDING_LEN];
    const size_t request_len = make_add_path_frame(request, sizeof(request));
    binding_for_frame(request, request_len, VMP_OPERATION_ADD_PATH, binding);
    send_binding(sockets[0], binding, &pipe_fds[0], 1U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    injected_recvmsg_capacity = VMP_FD_BINDING_LEN / 2U;
    dispatch_state_t state = {0};
    const vmp_server_options_t configuration = options();
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_OK);
    assert(injected_recvmsg_capacity == 0U);
    assert(state.calls == 1U && state.operation == VMP_OPERATION_ADD_PATH);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);
}

static void test_incomplete_binding_is_rejected_and_fd_closed(void)
{
    int sockets[2];
    int pipe_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    const size_t baseline = open_descriptor_count();
    uint8_t partial[VMP_FD_BINDING_LEN / 2U];
    memset(partial, 0x5a, sizeof(partial));
    send_with_fds(sockets[0], partial, sizeof(partial), &pipe_fds[0], 1U);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    dispatch_state_t state = {0};
    const vmp_server_options_t configuration = options();
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) != VMP_SERVER_OK);
    assert(state.calls == 0U);
    assert(open_descriptor_count() == baseline);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);
}

static void test_missing_extra_and_wrong_binding_fds_are_rejected(void)
{
    uint8_t request[256];
    uint8_t binding[VMP_FD_BINDING_LEN];
    const size_t request_len = make_add_path_frame(request, sizeof(request));
    binding_for_frame(request, request_len, VMP_OPERATION_ADD_PATH, binding);

    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    send_binding(sockets[0], binding, NULL, 0U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    dispatch_state_t state = {0};
    expect_protocol(sockets, &state);
    close_pair(sockets);

    int pipe_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    send_binding(sockets[0], binding, pipe_fds, 2U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    state = (dispatch_state_t){0};
    expect_protocol(sockets, &state);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    memset(binding, 0x5a, sizeof(binding));
    send_binding(sockets[0], binding, &pipe_fds[0], 1U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    state = (dispatch_state_t){0};
    expect_protocol(sockets, &state);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);
}

static void test_non_add_path_fd_and_frame_ancillary_are_rejected(void)
{
    uint8_t request[128];
    const size_t request_len = make_status_frame(request, sizeof(request));
    const uint8_t binding[VMP_FD_BINDING_LEN] = {0};
    int sockets[2];
    int pipe_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    send_binding(sockets[0], binding, &pipe_fds[0], 1U);
    write_exact_test(sockets[0], request, request_len);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    dispatch_state_t state = {0};
    expect_protocol(sockets, &state);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    send_binding(sockets[0], binding, NULL, 0U);
    send_with_fds(sockets[0], request, request_len, &pipe_fds[0], 1U);
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    state = (dispatch_state_t){0};
    expect_protocol(sockets, &state);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);
}

static void test_truncated_ancillary_and_trailing_request_are_rejected(void)
{
    int sockets[2];
    int pipes[3][2];
    int descriptors[3];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    for (size_t index = 0U; index < 3U; ++index) {
        assert(pipe(pipes[index]) == 0);
        descriptors[index] = pipes[index][0];
    }
    const uint8_t binding[VMP_FD_BINDING_LEN] = {0};
    send_binding(sockets[0], binding, descriptors, 3U);
    dispatch_state_t state = {0};
    expect_protocol(sockets, &state);
    for (size_t index = 0U; index < 3U; ++index) {
        assert(close(pipes[index][0]) == 0);
        assert(close(pipes[index][1]) == 0);
    }
    close_pair(sockets);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    uint8_t request[128];
    const size_t request_len = make_status_frame(request, sizeof(request));
    send_binding(sockets[0], binding, NULL, 0U);
    write_exact_test(sockets[0], request, request_len);
    const uint8_t trailing = 0x08U;
    write_exact_test(sockets[0], &trailing, sizeof(trailing));
    assert(shutdown(sockets[0], SHUT_WR) == 0);
    state = (dispatch_state_t){0};
    expect_protocol(sockets, &state);
    close_pair(sockets);
}

static void test_wrong_peer_and_non_unix_are_rejected(void)
{
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    vmp_server_options_t configuration = options();
    configuration.expected_peer_uid = getuid() == 0U ? 1U : 0U;
    dispatch_state_t state = {0};
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_PEER_REJECTED);
    assert(state.calls == 0U);
    close_pair(sockets);

    int descriptors[2];
    assert(pipe(descriptors) == 0);
    configuration = options();
    assert(vmp_serve_connection(descriptors[0], &configuration, test_dispatch,
                                &state) == VMP_SERVER_PEER_REJECTED);
    assert(close(descriptors[0]) == 0);
    assert(close(descriptors[1]) == 0);
}

static void test_oversize_and_partial_frame_are_bounded(void)
{
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    const uint8_t binding[VMP_FD_BINDING_LEN] = {0};
    send_binding(sockets[0], binding, NULL, 0U);
    const uint32_t too_large = VMP_MAX_CONTROL_FRAME + 1U;
    const uint8_t prefix[4] = {
        (uint8_t)(too_large >> 24U), (uint8_t)(too_large >> 16U),
        (uint8_t)(too_large >> 8U), (uint8_t)too_large};
    write_exact_test(sockets[0], prefix, sizeof(prefix));
    dispatch_state_t state = {0};
    expect_protocol(sockets, &state);
    close_pair(sockets);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    send_binding(sockets[0], binding, NULL, 0U);
    const uint8_t incomplete[] = {0U, 0U, 0U, 2U, 0x08U};
    write_exact_test(sockets[0], incomplete, sizeof(incomplete));
    unsigned pump_calls = 0U;
    vmp_server_options_t configuration = options();
    configuration.frame_timeout_ms = 20U;
    configuration.pump_interval_ms = 1U;
    configuration.pump = count_pump;
    configuration.pump_context = &pump_calls;
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_TIMEOUT);
    assert(state.calls == 0U && pump_calls > 0U);
    close_pair(sockets);

    int pipe_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pipe(pipe_fds) == 0);
    const size_t baseline = open_descriptor_count();
    uint8_t request[256];
    uint8_t descriptor_binding[VMP_FD_BINDING_LEN];
    const size_t request_len = make_add_path_frame(request, sizeof(request));
    binding_for_frame(request, request_len, VMP_OPERATION_ADD_PATH,
                      descriptor_binding);
    send_binding(sockets[0], descriptor_binding, &pipe_fds[0], 1U);
    state = (dispatch_state_t){0};
    configuration = options();
    configuration.frame_timeout_ms = 20U;
    assert(vmp_serve_connection(sockets[1], &configuration, test_dispatch,
                                &state) == VMP_SERVER_TIMEOUT);
    assert(state.calls == 0U);
    assert(open_descriptor_count() == baseline);
    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    close_pair(sockets);
}

static void test_secret_fd_is_bounded_and_wiped(void)
{
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    static const uint8_t secret[VMP_AUTH_SECRET_LEN] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    write_exact_test(descriptors[1], secret, sizeof(secret));
    assert(close(descriptors[1]) == 0);
    uint8_t output[VMP_AUTH_SECRET_LEN] = {0};
    size_t output_len = 0U;
    assert(vmp_read_auth_secret(descriptors[0], output, sizeof(output),
                                &output_len) == VMP_SERVER_OK);
    assert(output_len == sizeof(secret));
    assert(memcmp(output, secret, output_len) == 0);
    vmp_wipe_secret(output, output_len);
    for (size_t index = 0U; index < output_len; ++index) {
        assert(output[index] == 0U);
    }
    assert(close(descriptors[0]) == 0);

    assert(pipe(descriptors) == 0);
    uint8_t noncanonical[VMP_AUTH_SECRET_LEN];
    memcpy(noncanonical, secret, sizeof(noncanonical));
    noncanonical[VMP_AUTH_SECRET_LEN - 1U] = (uint8_t)'B';
    write_exact_test(descriptors[1], noncanonical, sizeof(noncanonical));
    assert(close(descriptors[1]) == 0);
    memset(output, 0xa5, sizeof(output));
    output_len = 99U;
    assert(vmp_read_auth_secret(descriptors[0], output, sizeof(output),
                                &output_len) == VMP_SERVER_PROTOCOL);
    assert(output_len == 0U);
    for (size_t index = 0U; index < sizeof(output); ++index) {
        assert(output[index] == 0U);
    }
    assert(close(descriptors[0]) == 0);

    assert(pipe(descriptors) == 0);
    const uint8_t ambiguous[] = "secret\n";
    write_exact_test(descriptors[1], ambiguous, sizeof(ambiguous) - 1U);
    assert(close(descriptors[1]) == 0);
    memset(output, 0xa5, sizeof(output));
    output_len = 99U;
    assert(vmp_read_auth_secret(descriptors[0], output, sizeof(output),
                                &output_len) == VMP_SERVER_PROTOCOL);
    assert(output_len == 0U);
    for (size_t index = 0U; index < sizeof(output); ++index) {
        assert(output[index] == 0U);
    }
    assert(close(descriptors[0]) == 0);
}

int main(void)
{
    test_authenticated_framed_exchange();
    test_request_digest_and_assignment_shape_fail_closed();
    test_exact_add_path_fd_and_binding_succeeds();
    test_exact_start_exit_fd_uses_distinct_binding_domain();
    test_framed_exit_authorization_replay_is_consumed_once();
    test_fragmented_binding_recvmsg_is_reassembled();
    test_incomplete_binding_is_rejected_and_fd_closed();
    test_rejected_descriptors_are_closed_on_every_boundary();
    test_message_truncation_flags_are_rejected_and_closed();
    test_missing_extra_and_wrong_binding_fds_are_rejected();
    test_non_add_path_fd_and_frame_ancillary_are_rejected();
    test_truncated_ancillary_and_trailing_request_are_rejected();
    test_wrong_peer_and_non_unix_are_rejected();
    test_oversize_and_partial_frame_are_bounded();
    test_secret_fd_is_bounded_and_wiped();
    puts("server boundary tests passed");
    return 0;
}
