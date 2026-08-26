// SPDX-License-Identifier: GPL-3.0-only

#define _GNU_SOURCE

#include "volparossa_mpquic_runtime.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif

typedef struct mock_transport {
    unsigned create_calls;
    unsigned destroy_calls;
    unsigned add_calls;
    unsigned remove_calls;
    unsigned pump_calls;
    unsigned send_calls;
    unsigned receive_calls;
    uint64_t create_masque_context_id;
    uint64_t send_masque_context_id;
    uint64_t receive_masque_context_id;
    vmp_transport_mode_t create_transport_mode;
    vmp_transport_error_t receive_result;
    uint8_t receive_packet[64];
    size_t receive_packet_len;
    bool ready;
    bool pump_fails;
    vmp_transport_path_snapshot_t paths[VMP_MAX_PATHS];
    size_t path_count;
} mock_transport_t;

typedef struct mock_clock {
    uint64_t now_ms;
} mock_clock_t;

static const uint8_t TEST_SECRET[VMP_AUTH_SECRET_LEN] =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const uint8_t TEST_TLS_SERVER_NAME[] = "exit.example";
static const uint8_t TEST_TLS_CERTIFICATE[] =
    "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";
static const uint8_t TEST_TLS_PRIVATE_KEY[] =
    "-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n";
#define TEST_NOW_MS UINT64_C(1000000)
#define TEST_EXPIRY_MS (TEST_NOW_MS + UINT64_C(60000))

static void init_mock(mock_transport_t *mock)
{
    memset(mock, 0, sizeof(*mock));
    mock->receive_result = VMP_TRANSPORT_EMPTY;
}

static vmp_transport_error_t mock_create(
    void *factory_context, const vmp_transport_create_params_t *params,
    void **out_session)
{
    mock_transport_t *mock = factory_context;
    assert(params != NULL);
    assert(params->auth_secret_len == VMP_AUTH_SECRET_LEN);
    assert(memcmp(params->auth_secret, TEST_SECRET,
                  VMP_AUTH_SECRET_LEN) == 0);
    assert(strcmp(params->tls_server_name, "exit.example") == 0);
    assert(params->exit_spki_sha256[0] == 0x22U);
    assert(params->ip_len == 16U);
    assert(params->remote_ip[15] == 4U);
    assert(params->remote_port == 443U);
    mock->create_masque_context_id = params->masque_context_id;
    mock->create_transport_mode = params->transport_mode;
    ++mock->create_calls;
    *out_session = mock;
    return VMP_TRANSPORT_OK;
}

static void mock_destroy(void *session)
{
    mock_transport_t *mock = session;
    ++mock->destroy_calls;
}

static vmp_transport_error_t mock_add(void *session,
                                      const vmp_add_path_t *path,
                                      int path_fd,
                                      int64_t *out_handle)
{
    mock_transport_t *mock = session;
    assert(path_fd >= 0);
    assert(close(path_fd) == 0);
    assert(mock->path_count < VMP_MAX_PATHS);
    const int64_t handle = INT64_C(100) + (int64_t)path->path_id;
    vmp_transport_path_snapshot_t *snapshot =
        &mock->paths[mock->path_count++];
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->handle = handle;
    snapshot->state = VMP_TRANSPORT_PATH_PENDING;
    *out_handle = handle;
    ++mock->add_calls;
    return VMP_TRANSPORT_OK;
}

static vmp_transport_error_t mock_remove(void *session, int64_t handle)
{
    mock_transport_t *mock = session;
    size_t found = mock->path_count;
    for (size_t index = 0; index < mock->path_count; ++index) {
        if (mock->paths[index].handle == handle) {
            found = index;
            break;
        }
    }
    if (found == mock->path_count) return VMP_TRANSPORT_INVALID;
    for (size_t index = found + 1U; index < mock->path_count; ++index) {
        mock->paths[index - 1U] = mock->paths[index];
    }
    --mock->path_count;
    memset(&mock->paths[mock->path_count], 0,
           sizeof(mock->paths[mock->path_count]));
    ++mock->remove_calls;
    return VMP_TRANSPORT_OK;
}

static vmp_transport_error_t mock_pump(void *session)
{
    mock_transport_t *mock = session;
    ++mock->pump_calls;
    return mock->pump_fails ? VMP_TRANSPORT_ENGINE : VMP_TRANSPORT_OK;
}

static vmp_transport_error_t mock_snapshot(
    void *session, vmp_transport_path_snapshot_t *out, size_t capacity,
    size_t *out_count, bool *out_tunnel_ready)
{
    mock_transport_t *mock = session;
    if (capacity < mock->path_count) return VMP_TRANSPORT_RESOURCE;
    memcpy(out, mock->paths, mock->path_count * sizeof(*out));
    *out_count = mock->path_count;
    *out_tunnel_ready = mock->ready;
    return VMP_TRANSPORT_OK;
}

static vmp_transport_error_t mock_send(void *session,
                                       uint64_t masque_context_id,
                                       const uint8_t *packet,
                                       size_t packet_len)
{
    mock_transport_t *mock = session;
    assert(packet != NULL);
    assert(packet_len > 0U);
    mock->send_masque_context_id = masque_context_id;
    ++mock->send_calls;
    return VMP_TRANSPORT_OK;
}

static vmp_transport_error_t mock_receive(void *session,
                                          uint64_t masque_context_id,
                                          uint8_t *out,
                                          size_t out_capacity,
                                          size_t *out_len)
{
    mock_transport_t *mock = session;
    assert(out != NULL);
    assert(out_len != NULL);
    mock->receive_masque_context_id = masque_context_id;
    ++mock->receive_calls;
    *out_len = 0U;
    if (mock->receive_result != VMP_TRANSPORT_OK) {
        return mock->receive_result;
    }
    if (out_capacity < mock->receive_packet_len) {
        return VMP_TRANSPORT_RESOURCE;
    }
    memcpy(out, mock->receive_packet, mock->receive_packet_len);
    *out_len = mock->receive_packet_len;
    return VMP_TRANSPORT_OK;
}

static const vmp_transport_ops_t MOCK_OPS = {
    .create = mock_create,
    .destroy = mock_destroy,
    .add_path = mock_add,
    .remove_path = mock_remove,
    .pump = mock_pump,
    .snapshot = mock_snapshot,
    .send_inner = mock_send,
    .receive_inner = mock_receive,
};

static uint64_t mock_now_ms(void *context)
{
    const mock_clock_t *clock = context;
    return clock->now_ms;
}

static vmp_runtime_t *create_runtime(vmp_runtime_mode_t mode,
                                     mock_transport_t *mock,
                                     mock_clock_t *clock)
{
    return vmp_runtime_create(mode, &MOCK_OPS, mock, mock_now_ms, clock);
}

static vmp_request_t start_request(uint8_t context_byte, uint64_t masque,
                                   vmp_transport_mode_t transport_mode,
                                   uint32_t minimum_paths)
{
    vmp_request_t request;
    memset(&request, 0, sizeof(request));
    request.api_version = VMP_API_VERSION;
    request.operation = VMP_OPERATION_START_SESSION;
    memset(request.body.start_session.route_context_id, context_byte,
           VMP_CONTEXT_ID_LEN);
    memset(request.body.start_session.exit_spki_sha256, 0x22,
           VMP_SPKI_SHA256_LEN);
    request.body.start_session.minimum_paths = minimum_paths;
    request.body.start_session.masque_context_id = masque;
    request.body.start_session.transport_mode = transport_mode;
    request.body.start_session.auth_secret.data = TEST_SECRET;
    request.body.start_session.auth_secret.len = sizeof(TEST_SECRET);
    request.body.start_session.tls_server_name.data = TEST_TLS_SERVER_NAME;
    request.body.start_session.tls_server_name.len =
        sizeof(TEST_TLS_SERVER_NAME) - 1U;
    request.body.start_session.expires_at_ms = TEST_EXPIRY_MS;
    return request;
}

static vmp_request_t start_exit_request(
    uint8_t context_byte, uint64_t masque,
    vmp_transport_mode_t transport_mode, uint32_t minimum_paths)
{
    vmp_request_t request;
    memset(&request, 0, sizeof(request));
    request.api_version = VMP_API_VERSION;
    request.operation = VMP_OPERATION_START_EXIT_SESSION;
    memset(request.body.start_exit_session.route_context_id, context_byte,
           VMP_CONTEXT_ID_LEN);
    request.body.start_exit_session.auth_secret.data = TEST_SECRET;
    request.body.start_exit_session.auth_secret.len = sizeof(TEST_SECRET);
    request.body.start_exit_session.expires_at_ms = TEST_EXPIRY_MS;
    request.body.start_exit_session.minimum_paths = minimum_paths;
    request.body.start_exit_session.masque_context_id = masque;
    request.body.start_exit_session.transport_mode = transport_mode;
    memset(request.body.start_exit_session.exit_spki_sha256, 0x22,
           VMP_SPKI_SHA256_LEN);
    request.body.start_exit_session.tls_server_name.data =
        TEST_TLS_SERVER_NAME;
    request.body.start_exit_session.tls_server_name.len =
        sizeof(TEST_TLS_SERVER_NAME) - 1U;
    request.body.start_exit_session.path_id = 1U;
    uint8_t *listener_ip = request.body.start_exit_session.listener_ip;
    listener_ip[0] = 0xfdU;
    listener_ip[1] = 0x76U;
    listener_ip[2] = 0x6fU;
    listener_ip[3] = 0x6cU;
    listener_ip[4] = 0x70U;
    listener_ip[5] = 0x61U;
    listener_ip[6] = context_byte;
    listener_ip[10] = 0U;
    listener_ip[11] = 1U;
    listener_ip[13] = context_byte;
    listener_ip[15] = 4U;
    memcpy(request.body.start_exit_session.expected_client_ip, listener_ip,
           sizeof(request.body.start_exit_session.expected_client_ip));
    request.body.start_exit_session.expected_client_ip[15] = 1U;
    request.body.start_exit_session.listener_port = 45443U;
    request.body.start_exit_session.expected_client_port = 51820U;
    memset(request.body.start_exit_session.reservation_hash, 0x33,
           VMP_RESERVATION_HASH_LEN);
    request.body.start_exit_session.tls_certificate_pem.data =
        TEST_TLS_CERTIFICATE;
    request.body.start_exit_session.tls_certificate_pem.len =
        sizeof(TEST_TLS_CERTIFICATE) - 1U;
    request.body.start_exit_session.tls_private_key_pem.data =
        TEST_TLS_PRIVATE_KEY;
    request.body.start_exit_session.tls_private_key_pem.len =
        sizeof(TEST_TLS_PRIVATE_KEY) - 1U;
    return request;
}

static vmp_request_t add_request(uint8_t context_byte, uint32_t path_id,
                                 uint32_t port_seed)
{
    static const uint8_t overlay_prefix[6] = {
        0xfdU, 0x76U, 0x6fU, 0x6cU, 0x70U, 0x61U,
    };
    vmp_request_t request;
    memset(&request, 0, sizeof(request));
    request.api_version = VMP_API_VERSION;
    request.operation = VMP_OPERATION_ADD_PATH;
    vmp_add_path_t *path = &request.body.add_path;
    memset(path->route_context_id, context_byte, VMP_CONTEXT_ID_LEN);
    path->path_id = path_id;
    path->local_port = (uint16_t)(UINT16_C(10000) + port_seed);
    path->ip_len = 16U;
    memcpy(path->local_ip, overlay_prefix, sizeof(overlay_prefix));
    path->local_ip[6] = context_byte;
    path->local_ip[8] = (uint8_t)port_seed;
    path->local_ip[10] = (uint8_t)(path_id >> 8U);
    path->local_ip[11] = (uint8_t)path_id;
    path->local_ip[12] = 0x33U;
    path->local_ip[13] = context_byte;
    path->local_ip[15] = 1U;
    memcpy(path->remote_ip, path->local_ip, sizeof(path->remote_ip));
    path->remote_ip[15] = 4U;
    path->remote_port = 443U;
    memset(path->reservation_hash, (int)(0x30U + path_id),
           VMP_RESERVATION_HASH_LEN);
    return request;
}

static int make_exit_listener(const vmp_start_exit_session_t *start)
{
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
    local.sin6_port = htons(start->listener_port);
    memcpy(&local.sin6_addr, start->listener_ip,
           sizeof(start->listener_ip));
    assert(bind(descriptor, (const struct sockaddr *)&local,
                sizeof(local)) == 0);
    return descriptor;
}

static vmp_response_t dispatch_with_fd(vmp_runtime_t *runtime,
                                       const vmp_request_t *request,
                                       int request_fd)
{
    vmp_response_t response;
    memset(&response, 0, sizeof(response));
    response.api_version = VMP_API_VERSION;
    assert(vmp_runtime_dispatch(runtime, request, &response, request_fd) ==
           VMP_SERVER_OK);
    if (request_fd >= 0) {
        errno = 0;
        assert(fcntl(request_fd, F_GETFD) == -1);
        assert(errno == EBADF);
    }
    assert(response.diagnostic_code != NULL);
    assert(response.diagnostic_code_len <= VMP_MAX_DIAGNOSTIC_CODE);
    return response;
}

static vmp_response_t dispatch(vmp_runtime_t *runtime,
                               const vmp_request_t *request)
{
    int request_fd = -1;
    if (request->operation == VMP_OPERATION_ADD_PATH) {
        int descriptors[2];
        assert(pipe(descriptors) == 0);
        assert(close(descriptors[1]) == 0);
        request_fd = descriptors[0];
    } else if (request->operation == VMP_OPERATION_START_EXIT_SESSION) {
        request_fd = make_exit_listener(&request->body.start_exit_session);
    }
    return dispatch_with_fd(runtime, request, request_fd);
}

static vmp_request_t context_request(vmp_operation_t operation,
                                     uint8_t context_byte)
{
    vmp_request_t request;
    memset(&request, 0, sizeof(request));
    request.api_version = VMP_API_VERSION;
    request.operation = operation;
    if (operation == VMP_OPERATION_GET_STATUS) {
        memset(request.body.get_status.route_context_id, context_byte,
               VMP_CONTEXT_ID_LEN);
    } else {
        memset(request.body.stop_session.route_context_id, context_byte,
               VMP_CONTEXT_ID_LEN);
    }
    return request;
}

static vmp_request_t send_request(uint8_t context_byte,
                                  uint64_t masque_context_id,
                                  const uint8_t *packet, size_t packet_len)
{
    vmp_request_t request;
    memset(&request, 0, sizeof(request));
    request.api_version = VMP_API_VERSION;
    request.operation = VMP_OPERATION_SEND_DATAGRAM;
    memset(request.body.send_datagram.route_context_id, context_byte,
           VMP_CONTEXT_ID_LEN);
    request.body.send_datagram.masque_context_id = masque_context_id;
    request.body.send_datagram.inner_ip_packet.data = packet;
    request.body.send_datagram.inner_ip_packet.len = packet_len;
    return request;
}

static vmp_request_t receive_request(uint8_t context_byte,
                                     uint64_t masque_context_id)
{
    vmp_request_t request;
    memset(&request, 0, sizeof(request));
    request.api_version = VMP_API_VERSION;
    request.operation = VMP_OPERATION_RECEIVE_DATAGRAM;
    memset(request.body.receive_datagram.route_context_id, context_byte,
           VMP_CONTEXT_ID_LEN);
    request.body.receive_datagram.masque_context_id = masque_context_id;
    return request;
}

static void test_required_multipath_and_honest_failures(void)
{
    mock_transport_t mock;
    init_mock(&mock);
    mock_clock_t clock = {.now_ms = TEST_NOW_MS};
    vmp_runtime_t *runtime =
        create_runtime(VMP_RUNTIME_CLIENT, &mock, &clock);
    assert(runtime != NULL);

    vmp_request_t start =
        start_request(0x11U, 7U, VMP_TRANSPORT_MODE_MULTIPATH_QUIC, 2U);
    vmp_response_t response = dispatch(runtime, &start);
    assert(response.result == VMP_RESULT_INSUFFICIENT_PATHS);
    assert(mock.create_calls == 0U);

    vmp_request_t first = add_request(0x11U, 1U, 10U);
    response = dispatch(runtime, &first);
    assert(response.result == VMP_RESULT_OK);
    assert(mock.create_calls == 1U && mock.add_calls == 1U);
    assert(mock.create_masque_context_id == 7U);
    assert(mock.create_transport_mode == VMP_TRANSPORT_MODE_MULTIPATH_QUIC);

    vmp_request_t forged_overlay = add_request(0x11U, 2U, 11U);
    forged_overlay.body.add_path.local_ip[11] = 1U;
    forged_overlay.body.add_path.remote_ip[11] = 1U;
    response = dispatch(runtime, &forged_overlay);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code, "path_overlay_shape") == 0);
    assert(mock.add_calls == 1U);

    vmp_request_t second = add_request(0x11U, 2U, 11U);
    response = dispatch(runtime, &second);
    assert(response.result == VMP_RESULT_OK);
    response = dispatch(runtime, &start);
    assert(response.result == VMP_RESULT_INSUFFICIENT_PATHS);

    mock.ready = true;
    mock.paths[0].state = VMP_TRANSPORT_PATH_ACTIVE;
    mock.paths[1].state = VMP_TRANSPORT_PATH_ACTIVE;
    response = dispatch(runtime, &start);
    assert(response.result == VMP_RESULT_OK);

    uint8_t packet[20] = {0x45U};
    packet[3] = (uint8_t)sizeof(packet);
    vmp_request_t send =
        send_request(0x11U, 7U, packet, sizeof(packet));
    response = dispatch(runtime, &send);
    assert(response.result == VMP_RESULT_OK);
    assert(mock.send_calls == 1U);
    assert(mock.send_masque_context_id == 7U);

    vmp_request_t wrong_context =
        send_request(0x11U, 8U, packet, sizeof(packet));
    response = dispatch(runtime, &wrong_context);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code, "masque_context_mismatch") == 0);
    assert(mock.send_calls == 1U);

    vmp_request_t status =
        context_request(VMP_OPERATION_GET_STATUS, 0x11U);
    response = dispatch(runtime, &status);
    assert(response.result == VMP_RESULT_TRANSPORT);
    assert(strcmp(response.diagnostic_code,
                  "unique_delivery_metric_unsupported") == 0);
    assert(response.path_count == 0U);

    vmp_request_t remove;
    memset(&remove, 0, sizeof(remove));
    remove.api_version = VMP_API_VERSION;
    remove.operation = VMP_OPERATION_REMOVE_PATH;
    memset(remove.body.remove_path.route_context_id, 0x11,
           VMP_CONTEXT_ID_LEN);
    remove.body.remove_path.path_id = 2U;
    response = dispatch(runtime, &remove);
    assert(response.result == VMP_RESULT_OK);
    assert(mock.remove_calls == 1U);
    response = dispatch(runtime, &send);
    assert(response.result == VMP_RESULT_INSUFFICIENT_PATHS);

    vmp_request_t stop =
        context_request(VMP_OPERATION_STOP_SESSION, 0x11U);
    response = dispatch(runtime, &stop);
    assert(response.result == VMP_RESULT_OK);
    assert(mock.destroy_calls == 1U);
    response = dispatch(runtime, &status);
    assert(response.result == VMP_RESULT_NOT_FOUND);
    vmp_runtime_destroy(runtime);
    assert(mock.destroy_calls == 1U);
}

static void test_explicit_modes_and_contexts(void)
{
    mock_transport_t mock;
    init_mock(&mock);
    mock_clock_t clock = {.now_ms = TEST_NOW_MS};
    assert(vmp_runtime_create(VMP_RUNTIME_CLIENT, &MOCK_OPS, &mock,
                              NULL, &clock) == NULL);

    vmp_runtime_t *client =
        create_runtime(VMP_RUNTIME_CLIENT, &mock, &clock);
    assert(client != NULL);
    static const uint8_t invalid_tls_name[] = "-bad.example";
    vmp_request_t invalid =
        start_request(0x44U, 7U, VMP_TRANSPORT_MODE_MULTIPATH_QUIC, 2U);
    invalid.body.start_session.tls_server_name.data = invalid_tls_name;
    invalid.body.start_session.tls_server_name.len =
        sizeof(invalid_tls_name) - 1U;
    vmp_response_t response = dispatch(client, &invalid);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    invalid =
        start_request(0x44U, 0U, VMP_TRANSPORT_MODE_MULTIPATH_QUIC, 2U);
    response = dispatch(client, &invalid);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    invalid = start_request(0x44U, VMP_MAX_MASQUE_CONTEXT_ID + 1U,
                            VMP_TRANSPORT_MODE_MULTIPATH_QUIC, 2U);
    response = dispatch(client, &invalid);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    invalid =
        start_request(0x44U, 7U, VMP_TRANSPORT_MODE_UNSPECIFIED, 1U);
    response = dispatch(client, &invalid);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);

    vmp_request_t single =
        start_request(0x44U, 7U,
                      VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP, 1U);
    response = dispatch(client, &single);
    assert(response.result == VMP_RESULT_INSUFFICIENT_PATHS);
    vmp_request_t first = add_request(0x44U, 1U, 30U);
    response = dispatch(client, &first);
    assert(response.result == VMP_RESULT_OK);
    assert(mock.create_masque_context_id == 7U);
    assert(mock.create_transport_mode ==
           VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP);
    vmp_request_t second = add_request(0x44U, 2U, 31U);
    response = dispatch(client, &second);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code, "path_count_for_mode") == 0);

    mock.ready = true;
    mock.paths[0].state = VMP_TRANSPORT_PATH_ACTIVE;
    response = dispatch(client, &single);
    assert(response.result == VMP_RESULT_OK);
    vmp_request_t changed =
        start_request(0x44U, 7U, VMP_TRANSPORT_MODE_MULTIPATH_QUIC, 2U);
    response = dispatch(client, &changed);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);

    uint8_t packet[20] = {0x45U};
    packet[3] = (uint8_t)sizeof(packet);
    vmp_request_t send =
        send_request(0x44U, 8U, packet, sizeof(packet));
    response = dispatch(client, &send);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    send = send_request(0x44U, 7U, packet, sizeof(packet));
    response = dispatch(client, &send);
    assert(response.result == VMP_RESULT_OK);

    vmp_request_t wrong_role = start_exit_request(
        0x44U, 7U, VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP, 1U);
    response = dispatch(client, &wrong_role);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code, "operation_for_role") == 0);

    vmp_request_t stop =
        context_request(VMP_OPERATION_STOP_SESSION, 0x44U);
    assert(dispatch(client, &stop).result == VMP_RESULT_OK);
    vmp_runtime_destroy(client);

    vmp_runtime_t *exit_runtime =
        create_runtime(VMP_RUNTIME_EXIT, &mock, &clock);
    assert(exit_runtime != NULL);
    vmp_request_t start =
        start_request(0x55U, 9U, VMP_TRANSPORT_MODE_MULTIPATH_QUIC, 2U);
    response = dispatch(exit_runtime, &start);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code, "operation_for_role") == 0);

    vmp_request_t start_exit = start_exit_request(
        0x55U, 9U, VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP, 1U);
    vmp_request_t rejected_exit = start_exit;
    rejected_exit.api_version = 4U;
    response = dispatch(exit_runtime, &rejected_exit);
    assert(response.result == VMP_RESULT_VERSION);
    rejected_exit = start_exit;
    rejected_exit.body.start_exit_session.listener_ip[15] = 5U;
    response = dispatch(exit_runtime, &rejected_exit);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    rejected_exit = start_exit;
    rejected_exit.body.start_exit_session.expires_at_ms = clock.now_ms;
    response = dispatch(exit_runtime, &rejected_exit);
    assert(response.result == VMP_RESULT_UNAUTHORISED);
    int invalid_descriptors[2];
    assert(pipe(invalid_descriptors) == 0);
    assert(close(invalid_descriptors[1]) == 0);
    response = dispatch_with_fd(exit_runtime, &start_exit,
                                invalid_descriptors[0]);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code,
                  "exit_listener_descriptor") == 0);

    int mismatched_tuple = make_exit_listener(
        &start_exit.body.start_exit_session);
    rejected_exit = start_exit;
    ++rejected_exit.body.start_exit_session.listener_port;
    response = dispatch_with_fd(exit_runtime, &rejected_exit,
                                mismatched_tuple);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code,
                  "exit_listener_descriptor") == 0);

    int blocking_listener = make_exit_listener(
        &start_exit.body.start_exit_session);
    const int status_flags = fcntl(blocking_listener, F_GETFL);
    assert(status_flags >= 0);
    assert(fcntl(blocking_listener, F_SETFL,
                 status_flags & ~O_NONBLOCK) == 0);
    response = dispatch_with_fd(exit_runtime, &start_exit,
                                blocking_listener);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code,
                  "exit_listener_descriptor") == 0);

    int reusable_listener = make_exit_listener(
        &start_exit.body.start_exit_session);
    const int enabled = 1;
    assert(setsockopt(reusable_listener, SOL_SOCKET, SO_REUSEADDR, &enabled,
                      sizeof(enabled)) == 0);
    response = dispatch_with_fd(exit_runtime, &start_exit,
                                reusable_listener);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code,
                  "exit_listener_descriptor") == 0);

    response = dispatch(exit_runtime, &start_exit);
    assert(response.result == VMP_RESULT_TRANSPORT);
    assert(strcmp(response.diagnostic_code,
                  "exit_listener_orchestration_unavailable") == 0);
    vmp_runtime_destroy(exit_runtime);
}

static void test_reverse_receive_and_overflow(void)
{
    mock_transport_t mock;
    init_mock(&mock);
    mock_clock_t clock = {.now_ms = TEST_NOW_MS};
    vmp_runtime_t *runtime =
        create_runtime(VMP_RUNTIME_CLIENT, &mock, &clock);
    assert(runtime != NULL);
    vmp_request_t start =
        start_request(0x22U, 11U, VMP_TRANSPORT_MODE_MULTIPATH_QUIC, 2U);
    assert(dispatch(runtime, &start).result ==
           VMP_RESULT_INSUFFICIENT_PATHS);
    vmp_request_t first = add_request(0x22U, 1U, 40U);
    vmp_request_t second = add_request(0x22U, 2U, 41U);
    assert(dispatch(runtime, &first).result == VMP_RESULT_OK);
    assert(dispatch(runtime, &second).result == VMP_RESULT_OK);
    mock.ready = true;
    mock.paths[0].state = VMP_TRANSPORT_PATH_ACTIVE;
    mock.paths[1].state = VMP_TRANSPORT_PATH_ACTIVE;
    assert(dispatch(runtime, &start).result == VMP_RESULT_OK);

    vmp_request_t receive = receive_request(0x22U, 11U);
    vmp_response_t response = dispatch(runtime, &receive);
    assert(response.result == VMP_RESULT_NO_DATAGRAM);
    assert(!response.has_received_datagram);
    assert(mock.receive_calls == 1U);

    vmp_request_t wrong = receive_request(0x22U, 12U);
    response = dispatch(runtime, &wrong);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(mock.receive_calls == 1U);

    memset(mock.receive_packet, 0, sizeof(mock.receive_packet));
    mock.receive_packet[0] = 0x45U;
    mock.receive_packet[3] = 20U;
    mock.receive_packet_len = 20U;
    mock.receive_result = VMP_TRANSPORT_OK;
    response = dispatch(runtime, &receive);
    assert(response.result == VMP_RESULT_OK);
    assert(response.has_received_datagram);
    assert(response.received_datagram.masque_context_id == 11U);
    assert(response.received_datagram.route_context_id[0] == 0x22U);
    assert(response.received_datagram.inner_ip_packet_len == 20U);
    assert(memcmp(response.received_datagram.inner_ip_packet,
                  mock.receive_packet, 20U) == 0);
    assert(mock.receive_masque_context_id == 11U);

    mock.receive_result = VMP_TRANSPORT_OVERFLOW;
    response = dispatch(runtime, &receive);
    assert(response.result == VMP_RESULT_QUEUE_OVERFLOW);
    assert(!response.has_received_datagram);
    const unsigned calls_at_overflow = mock.receive_calls;
    response = dispatch(runtime, &receive);
    assert(response.result == VMP_RESULT_QUEUE_OVERFLOW);
    assert(mock.receive_calls == calls_at_overflow);

    vmp_request_t send =
        send_request(0x22U, 11U, mock.receive_packet, 20U);
    assert(dispatch(runtime, &send).result == VMP_RESULT_QUEUE_OVERFLOW);
    vmp_request_t stop =
        context_request(VMP_OPERATION_STOP_SESSION, 0x22U);
    assert(dispatch(runtime, &stop).result == VMP_RESULT_OK);
    vmp_runtime_destroy(runtime);
}

static void test_session_credentials_versions_and_expiry(void)
{
    mock_transport_t mock;
    init_mock(&mock);
    mock_clock_t clock = {.now_ms = TEST_NOW_MS};
    vmp_runtime_t *runtime =
        create_runtime(VMP_RUNTIME_CLIENT, &mock, &clock);
    assert(runtime != NULL);

    uint8_t auth_secret[VMP_AUTH_SECRET_LEN] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint8_t tls_server_name[] = "exit.example";
    vmp_request_t start = start_request(
        0x77U, 17U, VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP, 1U);
    start.body.start_session.auth_secret.data = auth_secret;
    start.body.start_session.auth_secret.len = sizeof(auth_secret);
    start.body.start_session.tls_server_name.data = tls_server_name;
    start.body.start_session.tls_server_name.len =
        sizeof(tls_server_name) - 1U;
    start.body.start_session.expires_at_ms = clock.now_ms + UINT64_C(1000);

    const uint32_t rejected_versions[] = {1U, 2U, 3U, 4U, 99U};
    for (size_t index = 0U;
         index < sizeof(rejected_versions) / sizeof(rejected_versions[0]);
         ++index) {
        start.api_version = rejected_versions[index];
        vmp_response_t rejected = dispatch(runtime, &start);
        assert(rejected.result == VMP_RESULT_VERSION);
        assert(strcmp(rejected.diagnostic_code, "api_version") == 0);
    }
    start.api_version = VMP_API_VERSION;
    uint8_t noncanonical_secret[VMP_AUTH_SECRET_LEN];
    memcpy(noncanonical_secret, auth_secret, sizeof(noncanonical_secret));
    noncanonical_secret[VMP_AUTH_SECRET_LEN - 1U] = (uint8_t)'B';
    vmp_request_t noncanonical = start;
    noncanonical.body.start_session.auth_secret.data = noncanonical_secret;
    vmp_response_t response = dispatch(runtime, &noncanonical);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code, "session_parameters") == 0);

    response = dispatch(runtime, &start);
    assert(response.result == VMP_RESULT_INSUFFICIENT_PATHS);

    uint8_t other_secret[VMP_AUTH_SECRET_LEN];
    memcpy(other_secret, TEST_SECRET, sizeof(other_secret));
    other_secret[0] = (uint8_t)'B';
    vmp_request_t changed = start;
    changed.body.start_session.auth_secret.data = other_secret;
    changed.body.start_session.auth_secret.len = sizeof(other_secret);
    response = dispatch(runtime, &changed);
    assert(response.result == VMP_RESULT_INVALID_REQUEST);
    assert(strcmp(response.diagnostic_code,
                  "session_parameters_changed") == 0);

    memset(auth_secret, 0xa5, sizeof(auth_secret));
    memset(tls_server_name, 0x5a, sizeof(tls_server_name));
    vmp_request_t path = add_request(0x77U, 1U, 50U);
    response = dispatch(runtime, &path);
    assert(response.result == VMP_RESULT_OK);
    assert(mock.create_calls == 1U);

    clock.now_ms = start.body.start_session.expires_at_ms;
    uint8_t packet[20] = {0x45U};
    packet[3] = (uint8_t)sizeof(packet);
    vmp_request_t send =
        send_request(0x77U, 17U, packet, sizeof(packet));
    response = dispatch(runtime, &send);
    assert(response.result == VMP_RESULT_UNAUTHORISED);
    assert(strcmp(response.diagnostic_code, "session_expired") == 0);
    assert(mock.destroy_calls == 1U);

    vmp_request_t status =
        context_request(VMP_OPERATION_GET_STATUS, 0x77U);
    assert(dispatch(runtime, &status).result == VMP_RESULT_NOT_FOUND);

    vmp_request_t expired = start_request(
        0x77U, 17U, VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP, 1U);
    expired.body.start_session.expires_at_ms = clock.now_ms;
    assert(dispatch(runtime, &expired).result == VMP_RESULT_UNAUTHORISED);
    expired.body.start_session.expires_at_ms =
        clock.now_ms + VMP_MAX_AUTHORIZATION_FUTURE_MS + UINT64_C(1);
    assert(dispatch(runtime, &expired).result == VMP_RESULT_UNAUTHORISED);

    vmp_runtime_destroy(runtime);
    assert(mock.destroy_calls == 1U);
}

static void test_pump_failure_is_session_scoped(void)
{
    mock_transport_t mock;
    init_mock(&mock);
    mock_clock_t clock = {.now_ms = TEST_NOW_MS};
    vmp_runtime_t *runtime =
        create_runtime(VMP_RUNTIME_CLIENT, &mock, &clock);
    assert(runtime != NULL);
    vmp_request_t start =
        start_request(0x66U, 13U, VMP_TRANSPORT_MODE_MULTIPATH_QUIC, 2U);
    assert(dispatch(runtime, &start).result ==
           VMP_RESULT_INSUFFICIENT_PATHS);
    vmp_request_t add = add_request(0x66U, 1U, 20U);
    assert(dispatch(runtime, &add).result == VMP_RESULT_OK);
    mock.pump_fails = true;
    assert(vmp_runtime_pump(runtime) == VMP_SERVER_OK);
    assert(mock.pump_calls == 1U);
    assert(dispatch(runtime, &start).result == VMP_RESULT_TRANSPORT);
    vmp_runtime_destroy(runtime);
}

int main(void)
{
    test_required_multipath_and_honest_failures();
    test_explicit_modes_and_contexts();
    test_reverse_receive_and_overflow();
    test_session_credentials_versions_and_expiry();
    test_pump_failure_is_session_scoped();
    puts("runtime gate tests passed");
    return 0;
}
