// SPDX-License-Identifier: GPL-3.0-only

#define _GNU_SOURCE

#include "volparossa_mpquic_runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct runtime_path {
    bool used;
    int64_t transport_handle;
    vmp_add_path_t request;
} runtime_path_t;

typedef struct runtime_session {
    bool used;
    bool failed;
    bool started;
    bool reverse_overflow;
    vmp_start_session_t start;
    uint8_t auth_secret[VMP_MAX_AUTH_SECRET];
    char tls_server_name[VMP_MAX_TLS_SERVER_NAME + 1U];
    void *transport_session;
    runtime_path_t paths[VMP_MAX_PATHS];
} runtime_session_t;

struct vmp_runtime {
    vmp_runtime_mode_t mode;
    uint8_t native_instance_id[VMP_NATIVE_INSTANCE_ID_LEN];
    vmp_transport_ops_t transport;
    void *factory_context;
    vmp_auth_commitment_fn auth_commitment;
    void *auth_commitment_context;
    vmp_now_ms_fn now_ms;
    void *clock_context;
    runtime_session_t sessions[VMP_MAX_SESSIONS];
};

static bool all_zero(const uint8_t *bytes, size_t len)
{
    uint8_t combined = 0U;
    for (size_t index = 0U; index < len; ++index) {
        combined |= bytes[index];
    }
    return combined == 0U;
}

static void secure_zero(void *memory, size_t len)
{
    volatile uint8_t *bytes = memory;
    while (len > 0U) {
        *bytes++ = 0;
        --len;
    }
}

static bool canonical_base64url_final(uint8_t value)
{
    switch (value) {
    case (uint8_t)'A':
    case (uint8_t)'E':
    case (uint8_t)'I':
    case (uint8_t)'M':
    case (uint8_t)'Q':
    case (uint8_t)'U':
    case (uint8_t)'Y':
    case (uint8_t)'c':
    case (uint8_t)'g':
    case (uint8_t)'k':
    case (uint8_t)'o':
    case (uint8_t)'s':
    case (uint8_t)'w':
    case (uint8_t)'0':
    case (uint8_t)'4':
    case (uint8_t)'8': return true;
    default: return false;
    }
}

static bool valid_secret(const uint8_t *secret, size_t len)
{
    if (secret == NULL || len != VMP_AUTH_SECRET_LEN) {
        return false;
    }
    for (size_t index = 0; index < len; ++index) {
        const uint8_t value = secret[index];
        const bool alphanumeric =
            (value >= (uint8_t)'A' && value <= (uint8_t)'Z') ||
            (value >= (uint8_t)'a' && value <= (uint8_t)'z') ||
            (value >= (uint8_t)'0' && value <= (uint8_t)'9');
        if (!alphanumeric && value != (uint8_t)'_' &&
            value != (uint8_t)'-') {
            return false;
        }
    }
    return canonical_base64url_final(secret[len - 1U]);
}

static bool exact_exit_listener(int listener_fd,
                                const vmp_start_exit_session_t *start)
{
    if (listener_fd < 0 || start == NULL) return false;

    const int descriptor_flags = fcntl(listener_fd, F_GETFD);
    const int status_flags = fcntl(listener_fd, F_GETFL);
    if (descriptor_flags < 0 || status_flags < 0 ||
        (descriptor_flags & FD_CLOEXEC) == 0 ||
        (status_flags & O_NONBLOCK) == 0) {
        return false;
    }

    int socket_type = 0;
    int protocol = 0;
    int accepting = 0;
    int socket_error = 0;
    int only_v6 = 0;
    int reuse_address = 0;
    int reuse_port = 0;
    socklen_t option_len = sizeof(int);
    if (getsockopt(listener_fd, SOL_SOCKET, SO_TYPE, &socket_type,
                   &option_len) != 0 ||
        option_len != sizeof(int) || socket_type != SOCK_DGRAM) {
        return false;
    }
    option_len = sizeof(int);
    if (getsockopt(listener_fd, SOL_SOCKET, SO_PROTOCOL, &protocol,
                   &option_len) != 0 ||
        option_len != sizeof(int) || protocol != IPPROTO_UDP) {
        return false;
    }
    option_len = sizeof(int);
    if (getsockopt(listener_fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting,
                   &option_len) != 0 ||
        option_len != sizeof(int) || accepting != 0) {
        return false;
    }
    option_len = sizeof(int);
    if (getsockopt(listener_fd, SOL_SOCKET, SO_ERROR, &socket_error,
                   &option_len) != 0 ||
        option_len != sizeof(int) || socket_error != 0) {
        return false;
    }
    option_len = sizeof(int);
    if (getsockopt(listener_fd, IPPROTO_IPV6, IPV6_V6ONLY, &only_v6,
                   &option_len) != 0 ||
        option_len != sizeof(int) || only_v6 != 1) {
        return false;
    }
    option_len = sizeof(int);
    if (getsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address,
                   &option_len) != 0 ||
        option_len != sizeof(int) || reuse_address != 0) {
        return false;
    }
    option_len = sizeof(int);
    if (getsockopt(listener_fd, SOL_SOCKET, SO_REUSEPORT, &reuse_port,
                   &option_len) != 0 ||
        option_len != sizeof(int) || reuse_port != 0) {
        return false;
    }

    struct sockaddr_in6 local;
    memset(&local, 0, sizeof(local));
    socklen_t local_len = sizeof(local);
    if (getsockname(listener_fd, (struct sockaddr *)&local, &local_len) != 0 ||
        local_len != sizeof(local) || local.sin6_family != AF_INET6 ||
        ntohs(local.sin6_port) != start->listener_port ||
        memcmp(&local.sin6_addr, start->listener_ip,
               sizeof(start->listener_ip)) != 0) {
        return false;
    }

    struct sockaddr_in6 peer;
    memset(&peer, 0, sizeof(peer));
    socklen_t peer_len = sizeof(peer);
    errno = 0;
    if (getpeername(listener_fd, (struct sockaddr *)&peer, &peer_len) == 0 ||
        errno != ENOTCONN) {
        return false;
    }
    return true;
}

static bool constant_time_secret_equal(const vmp_bytes_view_t *left,
                                       const vmp_bytes_view_t *right)
{
    size_t difference = left->len ^ right->len;
    for (size_t index = 0U; index < VMP_MAX_AUTH_SECRET; ++index) {
        const uint8_t left_byte = index < left->len ? left->data[index] : 0U;
        const uint8_t right_byte =
            index < right->len ? right->data[index] : 0U;
        difference |= (size_t)(left_byte ^ right_byte);
    }
    return difference == 0U;
}

static bool valid_auth_commitment(
    const vmp_runtime_t *runtime, const vmp_bytes_view_t *secret,
    const uint8_t expected[VMP_AUTH_COMMITMENT_LEN])
{
    uint8_t actual[VMP_AUTH_COMMITMENT_LEN];
    memset(actual, 0, sizeof(actual));
    if (!runtime->auth_commitment(runtime->auth_commitment_context,
                                  secret->data, secret->len, actual)) {
        secure_zero(actual, sizeof(actual));
        return false;
    }
    uint8_t difference = 0U;
    for (size_t index = 0U; index < VMP_AUTH_COMMITMENT_LEN; ++index) {
        difference |= actual[index] ^ expected[index];
    }
    secure_zero(actual, sizeof(actual));
    return difference == 0U;
}

static bool valid_tls_name(const char *name)
{
    if (name == NULL) return false;
    const size_t len = strlen(name);
    if (len == 0U || len > VMP_MAX_TLS_SERVER_NAME || name[0] == '.' ||
        name[len - 1U] == '.') {
        return false;
    }
    size_t label_len = 0U;
    for (size_t index = 0; index < len; ++index) {
        const unsigned char value = (unsigned char)name[index];
        if (value == (unsigned char)'.') {
            if (label_len == 0U || label_len > 63U ||
                name[index - 1U] == '-') {
                return false;
            }
            label_len = 0U;
            continue;
        }
        const bool alpha = (value >= (unsigned char)'A' &&
                            value <= (unsigned char)'Z') ||
                           (value >= (unsigned char)'a' &&
                            value <= (unsigned char)'z');
        const bool digit =
            value >= (unsigned char)'0' && value <= (unsigned char)'9';
        if (!alpha && !digit && value != (unsigned char)'-') return false;
        if (label_len == 0U && value == (unsigned char)'-') return false;
        ++label_len;
    }
    return label_len > 0U && label_len <= 63U && name[len - 1U] != '-';
}

static bool copy_tls_name(const vmp_bytes_view_t *view,
                          char out[VMP_MAX_TLS_SERVER_NAME + 1U])
{
    if (view->data == NULL || view->len == 0U ||
        view->len > VMP_MAX_TLS_SERVER_NAME) {
        return false;
    }
    memcpy(out, view->data, view->len);
    out[view->len] = 0;
    if (!valid_tls_name(out)) {
        secure_zero(out, VMP_MAX_TLS_SERVER_NAME + 1U);
        return false;
    }
    return true;
}

static bool valid_mode(uint32_t minimum_paths,
                       vmp_transport_mode_t transport_mode)
{
    return (transport_mode == VMP_TRANSPORT_MODE_MULTIPATH_QUIC &&
            minimum_paths >= 2U && minimum_paths <= VMP_MAX_PATHS) ||
           (transport_mode == VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP &&
            minimum_paths == 1U);
}

static bool valid_authorization_window(const vmp_runtime_t *runtime,
                                       uint64_t expires_at_ms)
{
    const uint64_t now_ms = runtime->now_ms(runtime->clock_context);
    return expires_at_ms > now_ms &&
           expires_at_ms - now_ms <= VMP_MAX_AUTHORIZATION_FUTURE_MS;
}

static bool valid_transport(const vmp_transport_ops_t *transport)
{
    return transport != NULL && transport->create != NULL &&
           transport->destroy != NULL && transport->add_path != NULL &&
           transport->remove_path != NULL && transport->pump != NULL &&
           transport->snapshot != NULL && transport->send_inner != NULL &&
           transport->receive_inner != NULL;
}

static void set_result(vmp_response_t *response, vmp_result_t result,
                       const char *diagnostic)
{
    response->result = result;
    response->diagnostic_code = diagnostic;
    response->diagnostic_code_len = strlen(diagnostic);
    response->path_count = 0U;
    response->has_received_datagram = false;
    secure_zero(&response->received_datagram,
                sizeof(response->received_datagram));
    response->has_tunnel_assignment = false;
    secure_zero(&response->tunnel_assignment,
                sizeof(response->tunnel_assignment));
}

static bool valid_inner_packet(const uint8_t *packet, size_t packet_len)
{
    if (packet == NULL || packet_len < 20U ||
        packet_len > VMP_MAX_INNER_PACKET) {
        return false;
    }
    const uint8_t version = packet[0] >> 4U;
    if (version == 4U) {
        const size_t header_len =
            (size_t)(packet[0] & UINT8_C(0x0f)) * 4U;
        const size_t total_len =
            ((size_t)packet[2] << 8U) | (size_t)packet[3];
        return header_len >= 20U && header_len <= packet_len &&
               total_len == packet_len;
    }
    if (version == 6U && packet_len >= 40U) {
        const size_t payload_len =
            ((size_t)packet[4] << 8U) | (size_t)packet[5];
        return payload_len != 0U && payload_len + 40U == packet_len;
    }
    return false;
}

static runtime_session_t *find_session(vmp_runtime_t *runtime,
                                       const uint8_t context[VMP_CONTEXT_ID_LEN])
{
    for (size_t index = 0; index < VMP_MAX_SESSIONS; ++index) {
        runtime_session_t *session = &runtime->sessions[index];
        if (session->used &&
            memcmp(session->start.route_context_id, context,
                   VMP_CONTEXT_ID_LEN) == 0) {
            return session;
        }
    }
    return NULL;
}

static runtime_session_t *free_session(vmp_runtime_t *runtime)
{
    for (size_t index = 0; index < VMP_MAX_SESSIONS; ++index) {
        if (!runtime->sessions[index].used) return &runtime->sessions[index];
    }
    return NULL;
}

static runtime_path_t *find_path(runtime_session_t *session, uint32_t path_id)
{
    for (size_t index = 0; index < VMP_MAX_PATHS; ++index) {
        if (session->paths[index].used &&
            session->paths[index].request.path_id == path_id) {
            return &session->paths[index];
        }
    }
    return NULL;
}

static runtime_path_t *free_path(runtime_session_t *session)
{
    for (size_t index = 0; index < VMP_MAX_PATHS; ++index) {
        if (!session->paths[index].used) return &session->paths[index];
    }
    return NULL;
}

static bool start_matches(const runtime_session_t *session,
                          const vmp_start_session_t *start)
{
    return memcmp(session->start.route_context_id, start->route_context_id,
                  VMP_CONTEXT_ID_LEN) == 0 &&
           memcmp(session->start.exit_spki_sha256, start->exit_spki_sha256,
                  VMP_SPKI_SHA256_LEN) == 0 &&
           session->start.minimum_paths == start->minimum_paths &&
           session->start.masque_context_id == start->masque_context_id &&
           session->start.transport_mode == start->transport_mode &&
           session->start.expires_at_ms == start->expires_at_ms &&
           memcmp(session->start.reservation_id, start->reservation_id,
                  VMP_RESERVATION_ID_LEN) == 0 &&
           memcmp(session->start.finalize_id, start->finalize_id,
                  VMP_FINALIZE_ID_LEN) == 0 &&
           memcmp(session->start.auth_commitment, start->auth_commitment,
                  VMP_AUTH_COMMITMENT_LEN) == 0 &&
           memcmp(session->start.certificate_sha256,
                  start->certificate_sha256,
                  VMP_CERTIFICATE_SHA256_LEN) == 0 &&
           memcmp(session->start.client_native_instance_id,
                  start->client_native_instance_id,
                  VMP_NATIVE_INSTANCE_ID_LEN) == 0 &&
           memcmp(session->start.exit_native_instance_id,
                  start->exit_native_instance_id,
                  VMP_NATIVE_INSTANCE_ID_LEN) == 0 &&
           constant_time_secret_equal(&session->start.auth_secret,
                                      &start->auth_secret) &&
           session->start.tls_server_name.len == start->tls_server_name.len &&
           memcmp(session->start.tls_server_name.data,
                  start->tls_server_name.data,
                  start->tls_server_name.len) == 0;
}

static bool session_expired(const vmp_runtime_t *runtime,
                            const runtime_session_t *session)
{
    return runtime->now_ms(runtime->clock_context) >=
           session->start.expires_at_ms;
}

static void copy_start(runtime_session_t *session,
                       const vmp_start_session_t *start,
                       const char tls_server_name[VMP_MAX_TLS_SERVER_NAME + 1U])
{
    memset(session, 0, sizeof(*session));
    session->used = true;
    memcpy(session->start.route_context_id, start->route_context_id,
           VMP_CONTEXT_ID_LEN);
    memcpy(session->start.exit_spki_sha256, start->exit_spki_sha256,
           VMP_SPKI_SHA256_LEN);
    session->start.minimum_paths = start->minimum_paths;
    session->start.masque_context_id = start->masque_context_id;
    session->start.transport_mode = start->transport_mode;
    session->start.expires_at_ms = start->expires_at_ms;
    memcpy(session->start.reservation_id, start->reservation_id,
           VMP_RESERVATION_ID_LEN);
    memcpy(session->start.finalize_id, start->finalize_id,
           VMP_FINALIZE_ID_LEN);
    memcpy(session->start.auth_commitment, start->auth_commitment,
           VMP_AUTH_COMMITMENT_LEN);
    memcpy(session->start.certificate_sha256, start->certificate_sha256,
           VMP_CERTIFICATE_SHA256_LEN);
    memcpy(session->start.client_native_instance_id,
           start->client_native_instance_id,
           VMP_NATIVE_INSTANCE_ID_LEN);
    memcpy(session->start.exit_native_instance_id,
           start->exit_native_instance_id,
           VMP_NATIVE_INSTANCE_ID_LEN);
    memcpy(session->auth_secret, start->auth_secret.data,
           start->auth_secret.len);
    session->start.auth_secret.data = session->auth_secret;
    session->start.auth_secret.len = start->auth_secret.len;
    memcpy(session->tls_server_name, tls_server_name,
           start->tls_server_name.len + 1U);
    session->start.tls_server_name.data =
        (const uint8_t *)session->tls_server_name;
    session->start.tls_server_name.len = start->tls_server_name.len;
}

static bool path_tuple_conflicts(const runtime_session_t *session,
                                 const vmp_add_path_t *candidate)
{
    for (size_t index = 0; index < VMP_MAX_PATHS; ++index) {
        const runtime_path_t *existing = &session->paths[index];
        if (!existing->used) continue;
        const vmp_add_path_t *path = &existing->request;
        if ((path->ip_len == candidate->ip_len &&
             path->local_port == candidate->local_port &&
             memcmp(path->local_ip, candidate->local_ip,
                    candidate->ip_len) == 0) ||
            (path->ip_len == candidate->ip_len &&
             path->remote_port == candidate->remote_port &&
             memcmp(path->remote_ip, candidate->remote_ip,
                    candidate->ip_len) == 0)) {
            return true;
        }
    }
    return false;
}

static size_t path_count(const runtime_session_t *session)
{
    size_t count = 0U;
    for (size_t index = 0; index < VMP_MAX_PATHS; ++index) {
        if (session->paths[index].used) ++count;
    }
    return count;
}

static bool known_handle(const runtime_session_t *session, int64_t handle,
                         bool observed[VMP_MAX_PATHS])
{
    for (size_t index = 0; index < VMP_MAX_PATHS; ++index) {
        if (session->paths[index].used &&
            session->paths[index].transport_handle == handle) {
            if (observed[index]) return false;
            observed[index] = true;
            return true;
        }
    }
    return false;
}

static vmp_transport_error_t snapshot_active(vmp_runtime_t *runtime,
                                             runtime_session_t *session,
                                             size_t *out_active,
                                             bool *out_ready,
                                             bool *out_has_assignment,
                                             vmp_tunnel_assignment_t
                                                 *out_assignment)
{
    *out_active = 0U;
    *out_ready = false;
    *out_has_assignment = false;
    memset(out_assignment, 0, sizeof(*out_assignment));
    if (session->failed) return VMP_TRANSPORT_ENGINE;
    if (session->transport_session == NULL) return VMP_TRANSPORT_OK;

    vmp_transport_path_snapshot_t snapshots[VMP_MAX_PATHS];
    memset(snapshots, 0, sizeof(snapshots));
    size_t count = 0U;
    bool ready = false;
    bool has_assignment = false;
    vmp_tunnel_assignment_t assignment;
    memset(&assignment, 0, sizeof(assignment));
    const vmp_transport_error_t error = runtime->transport.snapshot(
        session->transport_session, snapshots, VMP_MAX_PATHS, &count, &ready,
        &has_assignment, &assignment);
    if (error != VMP_TRANSPORT_OK || count > VMP_MAX_PATHS ||
        (has_assignment && !vmp_tunnel_assignment_is_valid(&assignment)) ||
        (ready && !has_assignment)) {
        session->failed = true;
        secure_zero(&assignment, sizeof(assignment));
        return VMP_TRANSPORT_ENGINE;
    }

    bool observed[VMP_MAX_PATHS] = {false};
    for (size_t index = 0; index < count; ++index) {
        if (!known_handle(session, snapshots[index].handle, observed) ||
            snapshots[index].state > VMP_TRANSPORT_PATH_CLOSED) {
            session->failed = true;
            secure_zero(&assignment, sizeof(assignment));
            return VMP_TRANSPORT_ENGINE;
        }
        if (snapshots[index].state == VMP_TRANSPORT_PATH_ACTIVE) {
            ++*out_active;
        }
    }
    if (count != path_count(session)) {
        session->failed = true;
        secure_zero(&assignment, sizeof(assignment));
        return VMP_TRANSPORT_ENGINE;
    }
    *out_ready = ready;
    *out_has_assignment = has_assignment;
    if (has_assignment) memcpy(out_assignment, &assignment, sizeof(assignment));
    secure_zero(&assignment, sizeof(assignment));
    if (!ready || *out_active < session->start.minimum_paths) {
        session->started = false;
    }
    return VMP_TRANSPORT_OK;
}

static void destroy_session(vmp_runtime_t *runtime, runtime_session_t *session)
{
    if (session->transport_session != NULL) {
        runtime->transport.destroy(session->transport_session);
    }
    secure_zero(session, sizeof(*session));
}

static bool require_live(vmp_runtime_t *runtime, runtime_session_t *session,
                         vmp_response_t *response)
{
    if (!session_expired(runtime, session)) return true;
    destroy_session(runtime, session);
    set_result(response, VMP_RESULT_UNAUTHORISED, "session_expired");
    return false;
}

vmp_runtime_t *vmp_runtime_create(vmp_runtime_mode_t mode,
                                  const uint8_t native_instance_id
                                      [VMP_NATIVE_INSTANCE_ID_LEN],
                                  const vmp_transport_ops_t *transport,
                                  void *factory_context,
                                  vmp_auth_commitment_fn auth_commitment,
                                  void *auth_commitment_context,
                                  vmp_now_ms_fn now_ms,
                                  void *clock_context)
{
    if ((mode != VMP_RUNTIME_CLIENT && mode != VMP_RUNTIME_EXIT) ||
        native_instance_id == NULL ||
        all_zero(native_instance_id, VMP_NATIVE_INSTANCE_ID_LEN) ||
        !valid_transport(transport) || auth_commitment == NULL ||
        now_ms == NULL) {
        return NULL;
    }
    vmp_runtime_t *runtime = calloc(1U, sizeof(*runtime));
    if (runtime == NULL) return NULL;
    runtime->mode = mode;
    memcpy(runtime->native_instance_id, native_instance_id,
           VMP_NATIVE_INSTANCE_ID_LEN);
    runtime->transport = *transport;
    runtime->factory_context = factory_context;
    runtime->auth_commitment = auth_commitment;
    runtime->auth_commitment_context = auth_commitment_context;
    runtime->now_ms = now_ms;
    runtime->clock_context = clock_context;
    return runtime;
}

void vmp_runtime_destroy(vmp_runtime_t *runtime)
{
    if (runtime == NULL) return;
    for (size_t index = 0; index < VMP_MAX_SESSIONS; ++index) {
        if (runtime->sessions[index].used) {
            destroy_session(runtime, &runtime->sessions[index]);
        }
    }
    secure_zero(runtime, sizeof(*runtime));
    free(runtime);
}

vmp_server_error_t vmp_runtime_pump(void *context)
{
    vmp_runtime_t *runtime = context;
    if (runtime == NULL) return VMP_SERVER_BACKEND;
    for (size_t index = 0; index < VMP_MAX_SESSIONS; ++index) {
        runtime_session_t *session = &runtime->sessions[index];
        if (!session->used) continue;
        if (session_expired(runtime, session)) {
            destroy_session(runtime, session);
            continue;
        }
        if (session->failed || session->transport_session == NULL) continue;
        if (runtime->transport.pump(session->transport_session) !=
            VMP_TRANSPORT_OK) {
            session->failed = true;
            session->started = false;
        }
    }
    return VMP_SERVER_OK;
}

static void dispatch_start(vmp_runtime_t *runtime,
                           const vmp_start_session_t *start,
                           vmp_response_t *response)
{
    if (runtime->mode != VMP_RUNTIME_CLIENT) {
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "operation_for_role");
        return;
    }

    runtime_session_t *session =
        find_session(runtime, start->route_context_id);
    if (session != NULL && session_expired(runtime, session)) {
        destroy_session(runtime, session);
        session = NULL;
    }

    char tls_server_name[VMP_MAX_TLS_SERVER_NAME + 1U];
    memset(tls_server_name, 0, sizeof(tls_server_name));
    if (!valid_mode(start->minimum_paths, start->transport_mode) ||
        start->masque_context_id == 0U ||
        start->masque_context_id > VMP_MAX_MASQUE_CONTEXT_ID ||
        !valid_secret(start->auth_secret.data, start->auth_secret.len) ||
        all_zero(start->reservation_id, VMP_RESERVATION_ID_LEN) ||
        all_zero(start->finalize_id, VMP_FINALIZE_ID_LEN) ||
        all_zero(start->auth_commitment, VMP_AUTH_COMMITMENT_LEN) ||
        all_zero(start->certificate_sha256,
                 VMP_CERTIFICATE_SHA256_LEN) ||
        all_zero(start->exit_native_instance_id,
                 VMP_NATIVE_INSTANCE_ID_LEN) ||
        !copy_tls_name(&start->tls_server_name, tls_server_name)) {
        secure_zero(tls_server_name, sizeof(tls_server_name));
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "session_parameters");
        return;
    }
    if (!valid_auth_commitment(runtime, &start->auth_secret,
                               start->auth_commitment)) {
        secure_zero(tls_server_name, sizeof(tls_server_name));
        set_result(response, VMP_RESULT_UNAUTHORISED,
                   "auth_commitment_mismatch");
        return;
    }
    if (!valid_authorization_window(runtime, start->expires_at_ms)) {
        secure_zero(tls_server_name, sizeof(tls_server_name));
        set_result(response, VMP_RESULT_UNAUTHORISED,
                   "authorization_window");
        return;
    }

    if (session == NULL) {
        session = free_session(runtime);
        if (session == NULL) {
            secure_zero(tls_server_name, sizeof(tls_server_name));
            set_result(response, VMP_RESULT_TRANSPORT, "session_limit");
            return;
        }
        copy_start(session, start, tls_server_name);
        secure_zero(tls_server_name, sizeof(tls_server_name));
        set_result(response, VMP_RESULT_INSUFFICIENT_PATHS,
                   "required_paths_not_active");
        return;
    }
    if (!start_matches(session, start)) {
        secure_zero(tls_server_name, sizeof(tls_server_name));
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "session_parameters_changed");
        return;
    }
    secure_zero(tls_server_name, sizeof(tls_server_name));
    if (session->reverse_overflow) {
        set_result(response, VMP_RESULT_QUEUE_OVERFLOW,
                   "reverse_queue_overflow");
        return;
    }

    size_t active = 0U;
    bool ready = false;
    bool has_assignment = false;
    vmp_tunnel_assignment_t assignment;
    memset(&assignment, 0, sizeof(assignment));
    if (snapshot_active(runtime, session, &active, &ready,
                        &has_assignment, &assignment) !=
        VMP_TRANSPORT_OK) {
        secure_zero(&assignment, sizeof(assignment));
        set_result(response, VMP_RESULT_TRANSPORT, "native_transport_failed");
        return;
    }
    if (!ready || !has_assignment ||
        active < session->start.minimum_paths) {
        secure_zero(&assignment, sizeof(assignment));
        set_result(response, VMP_RESULT_INSUFFICIENT_PATHS,
                   "required_paths_not_active");
        return;
    }
    session->started = true;
    set_result(response, VMP_RESULT_OK, "ok");
    response->has_tunnel_assignment = true;
    memcpy(&response->tunnel_assignment, &assignment, sizeof(assignment));
    secure_zero(&assignment, sizeof(assignment));
}

static void dispatch_add_path(vmp_runtime_t *runtime,
                              const vmp_add_path_t *request,
                              vmp_response_t *response,
                              int path_fd)
{
    if (!vmp_add_path_is_valid(request)) {
        (void)close(path_fd);
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "path_overlay_shape");
        return;
    }
    runtime_session_t *session =
        find_session(runtime, request->route_context_id);
    if (session == NULL) {
        (void)close(path_fd);
        set_result(response, VMP_RESULT_NOT_FOUND, "session_not_found");
        return;
    }
    if (!require_live(runtime, session, response)) {
        (void)close(path_fd);
        return;
    }
    if (session->failed) {
        (void)close(path_fd);
        set_result(response, VMP_RESULT_TRANSPORT, "native_transport_failed");
        return;
    }
    if (session->start.transport_mode ==
            VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP &&
        path_count(session) >= 1U) {
        (void)close(path_fd);
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "path_count_for_mode");
        return;
    }
    if (find_path(session, request->path_id) != NULL) {
        (void)close(path_fd);
        set_result(response, VMP_RESULT_INVALID_REQUEST, "path_id_exists");
        return;
    }
    if (path_tuple_conflicts(session, request)) {
        (void)close(path_fd);
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "path_tuple_not_unique");
        return;
    }
    runtime_path_t *path = free_path(session);
    if (path == NULL) {
        (void)close(path_fd);
        set_result(response, VMP_RESULT_INVALID_REQUEST, "path_limit");
        return;
    }

    bool created = false;
    if (session->transport_session == NULL) {
        vmp_transport_create_params_t params;
        memset(&params, 0, sizeof(params));
        memcpy(params.exit_spki_sha256, session->start.exit_spki_sha256,
               VMP_SPKI_SHA256_LEN);
        params.auth_secret = session->start.auth_secret.data;
        params.auth_secret_len = session->start.auth_secret.len;
        params.tls_server_name = session->tls_server_name;
        memcpy(params.remote_ip, request->remote_ip, request->ip_len);
        params.ip_len = request->ip_len;
        params.remote_port = request->remote_port;
        params.masque_context_id = session->start.masque_context_id;
        params.transport_mode = session->start.transport_mode;
        const vmp_transport_error_t create_error = runtime->transport.create(
            runtime->factory_context, &params,
            &session->transport_session);
        secure_zero(&params, sizeof(params));
        if (create_error != VMP_TRANSPORT_OK ||
            session->transport_session == NULL) {
            (void)close(path_fd);
            session->transport_session = NULL;
            set_result(response, VMP_RESULT_TRANSPORT,
                       "native_transport_create_failed");
            return;
        }
        created = true;
    }

    int64_t handle = -1;
    const vmp_transport_error_t add_error = runtime->transport.add_path(
        session->transport_session, request, path_fd, &handle);
    if (add_error != VMP_TRANSPORT_OK || handle < 0) {
        if (created) {
            runtime->transport.destroy(session->transport_session);
            session->transport_session = NULL;
        }
        set_result(response, VMP_RESULT_TRANSPORT, "path_activation_failed");
        return;
    }
    memset(path, 0, sizeof(*path));
    path->used = true;
    path->transport_handle = handle;
    path->request = *request;
    set_result(response, VMP_RESULT_OK, "path_registered");
}

static void dispatch_remove_path(vmp_runtime_t *runtime,
                                 const vmp_remove_path_t *request,
                                 vmp_response_t *response)
{
    runtime_session_t *session =
        find_session(runtime, request->route_context_id);
    if (session == NULL) {
        set_result(response, VMP_RESULT_NOT_FOUND, "session_not_found");
        return;
    }
    if (!require_live(runtime, session, response)) return;
    runtime_path_t *path = find_path(session, request->path_id);
    if (path == NULL) {
        set_result(response, VMP_RESULT_NOT_FOUND, "path_not_found");
        return;
    }
    if (session->failed ||
        runtime->transport.remove_path(session->transport_session,
                                       path->transport_handle) !=
            VMP_TRANSPORT_OK) {
        session->failed = true;
        session->started = false;
        set_result(response, VMP_RESULT_TRANSPORT, "path_removal_failed");
        return;
    }
    secure_zero(path, sizeof(*path));
    session->started = false;
    set_result(response, VMP_RESULT_OK, "ok");
}

static bool require_active(vmp_runtime_t *runtime, runtime_session_t *session,
                           vmp_response_t *response)
{
    size_t active = 0U;
    bool ready = false;
    bool has_assignment = false;
    vmp_tunnel_assignment_t assignment;
    memset(&assignment, 0, sizeof(assignment));
    if (snapshot_active(runtime, session, &active, &ready,
                        &has_assignment, &assignment) !=
        VMP_TRANSPORT_OK) {
        secure_zero(&assignment, sizeof(assignment));
        set_result(response, VMP_RESULT_TRANSPORT, "native_transport_failed");
        return false;
    }
    secure_zero(&assignment, sizeof(assignment));
    if (!session->started || !ready || !has_assignment ||
        active < session->start.minimum_paths) {
        set_result(response, VMP_RESULT_INSUFFICIENT_PATHS,
                   "required_paths_not_active");
        return false;
    }
    return true;
}

static void dispatch_send(vmp_runtime_t *runtime,
                          const vmp_send_datagram_t *request,
                          vmp_response_t *response)
{
    runtime_session_t *session =
        find_session(runtime, request->route_context_id);
    if (session == NULL) {
        set_result(response, VMP_RESULT_NOT_FOUND, "session_not_found");
        return;
    }
    if (!require_live(runtime, session, response)) return;
    if (session->reverse_overflow) {
        set_result(response, VMP_RESULT_QUEUE_OVERFLOW,
                   "reverse_queue_overflow");
        return;
    }
    if (request->masque_context_id != session->start.masque_context_id) {
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "masque_context_mismatch");
        return;
    }
    if (!require_active(runtime, session, response)) return;

    const vmp_transport_error_t error = runtime->transport.send_inner(
        session->transport_session, request->masque_context_id,
        request->inner_ip_packet.data, request->inner_ip_packet.len);
    if (error == VMP_TRANSPORT_OK) {
        set_result(response, VMP_RESULT_OK, "ok");
    } else if (error == VMP_TRANSPORT_RESOURCE) {
        set_result(response, VMP_RESULT_TRANSPORT, "send_backpressure");
    } else if (error == VMP_TRANSPORT_OVERFLOW) {
        session->reverse_overflow = true;
        session->failed = true;
        session->started = false;
        set_result(response, VMP_RESULT_QUEUE_OVERFLOW,
                   "reverse_queue_overflow");
    } else {
        session->failed = true;
        session->started = false;
        set_result(response, VMP_RESULT_TRANSPORT,
                   "native_transport_failed");
    }
}

static void dispatch_receive(vmp_runtime_t *runtime,
                             const vmp_receive_datagram_t *request,
                             vmp_response_t *response)
{
    runtime_session_t *session =
        find_session(runtime, request->route_context_id);
    if (session == NULL) {
        set_result(response, VMP_RESULT_NOT_FOUND, "session_not_found");
        return;
    }
    if (!require_live(runtime, session, response)) return;
    if (session->reverse_overflow) {
        set_result(response, VMP_RESULT_QUEUE_OVERFLOW,
                   "reverse_queue_overflow");
        return;
    }
    if (request->masque_context_id != session->start.masque_context_id) {
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "masque_context_mismatch");
        return;
    }
    if (!require_active(runtime, session, response)) return;

    set_result(response, VMP_RESULT_OK, "datagram");
    size_t packet_len = 0U;
    const vmp_transport_error_t error = runtime->transport.receive_inner(
        session->transport_session, request->masque_context_id,
        response->received_datagram.inner_ip_packet,
        sizeof(response->received_datagram.inner_ip_packet), &packet_len);
    if (error == VMP_TRANSPORT_EMPTY) {
        set_result(response, VMP_RESULT_NO_DATAGRAM, "no_datagram");
        return;
    }
    if (error == VMP_TRANSPORT_OVERFLOW) {
        session->reverse_overflow = true;
        session->failed = true;
        session->started = false;
        set_result(response, VMP_RESULT_QUEUE_OVERFLOW,
                   "reverse_queue_overflow");
        return;
    }
    if (error != VMP_TRANSPORT_OK ||
        !valid_inner_packet(response->received_datagram.inner_ip_packet,
                            packet_len)) {
        session->failed = true;
        session->started = false;
        set_result(response, VMP_RESULT_TRANSPORT,
                   "native_transport_failed");
        return;
    }
    response->has_received_datagram = true;
    memcpy(response->received_datagram.route_context_id,
           request->route_context_id, VMP_CONTEXT_ID_LEN);
    response->received_datagram.masque_context_id =
        request->masque_context_id;
    response->received_datagram.inner_ip_packet_len = packet_len;
}

static void dispatch_status(vmp_runtime_t *runtime,
                            const vmp_context_request_t *request,
                            vmp_response_t *response)
{
    runtime_session_t *session =
        find_session(runtime, request->route_context_id);
    if (session == NULL) {
        set_result(response, VMP_RESULT_NOT_FOUND, "session_not_found");
        return;
    }
    if (!require_live(runtime, session, response)) return;
    if (!require_active(runtime, session, response)) return;

    /* xquic's exposed delivered counter is ACKed QUIC transport bytes and can
     * include retransmissions and framing. NativePathStatus requires unique
     * delivered payload bytes, so returning zero or relabelling that counter
     * would be false telemetry. */
    set_result(response, VMP_RESULT_TRANSPORT,
               "unique_delivery_metric_unsupported");
}

static void dispatch_start_exit(vmp_runtime_t *runtime,
                                const vmp_start_exit_session_t *start,
                                vmp_response_t *response,
                                int listener_fd)
{
    if (runtime->mode != VMP_RUNTIME_EXIT) {
        if (listener_fd >= 0) (void)close(listener_fd);
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "operation_for_role");
        return;
    }
    const bool valid_listener = exact_exit_listener(listener_fd, start);
    if (listener_fd >= 0) (void)close(listener_fd);
    if (!vmp_start_exit_is_valid(start) || !valid_listener) {
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   valid_listener ? "session_parameters"
                                  : "exit_listener_descriptor");
        return;
    }
    if (!valid_auth_commitment(runtime, &start->auth_secret,
                               start->auth_commitment)) {
        set_result(response, VMP_RESULT_UNAUTHORISED,
                   "auth_commitment_mismatch");
        return;
    }
    if (!valid_authorization_window(runtime, start->expires_at_ms)) {
        set_result(response, VMP_RESULT_UNAUTHORISED,
                   "authorization_window");
        return;
    }

    /* API v6 has consumed a UDP descriptor whose current tuple and flags match
     * the route request. Helper origin, assigned-address state and exact
     * network namespace remain unproven. Bounded certificate/key candidate PEM
     * is carried in memory, but this process boundary still has no reviewed
     * exit transport factory. Starting a replacement host-local listener,
     * reading secret paths, or falling back is forbidden. */
    set_result(response, VMP_RESULT_TRANSPORT,
               "exit_listener_orchestration_unavailable");
}

static void dispatch_stop(vmp_runtime_t *runtime,
                          const vmp_context_request_t *request,
                          vmp_response_t *response)
{
    runtime_session_t *session =
        find_session(runtime, request->route_context_id);
    if (session == NULL) {
        set_result(response, VMP_RESULT_NOT_FOUND, "session_not_found");
        return;
    }
    destroy_session(runtime, session);
    set_result(response, VMP_RESULT_OK, "ok");
}

vmp_server_error_t vmp_runtime_dispatch(void *context,
                                        const vmp_request_t *request,
                                        vmp_response_t *response,
                                        int request_fd)
{
    vmp_runtime_t *runtime = context;
    if (runtime == NULL || request == NULL || response == NULL) {
        if (request_fd >= 0) (void)close(request_fd);
        return VMP_SERVER_BACKEND;
    }
    response->native_process_identity.role =
        runtime->mode == VMP_RUNTIME_CLIENT ? VMP_NATIVE_ROLE_CLIENT
                                            : VMP_NATIVE_ROLE_EXIT;
    memcpy(response->native_process_identity.native_instance_id,
           runtime->native_instance_id, VMP_NATIVE_INSTANCE_ID_LEN);
    const bool descriptor_operation =
        request->operation == VMP_OPERATION_ADD_PATH ||
        request->operation == VMP_OPERATION_START_EXIT_SESSION;
    if ((descriptor_operation && request_fd < 0) ||
        (!descriptor_operation && request_fd >= 0)) {
        if (request_fd >= 0) (void)close(request_fd);
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "descriptor_for_operation");
        return VMP_SERVER_OK;
    }
    if (request->api_version != VMP_API_VERSION) {
        if (request_fd >= 0) (void)close(request_fd);
        set_result(response, VMP_RESULT_VERSION, "api_version");
        return VMP_SERVER_OK;
    }
    if (request->operation == VMP_OPERATION_PREFLIGHT) {
        if (!all_zero(request->target_native_instance_id,
                      VMP_NATIVE_INSTANCE_ID_LEN)) {
            set_result(response, VMP_RESULT_INVALID_REQUEST,
                       "preflight_target");
        } else if (request->body.preflight.expected_role !=
            response->native_process_identity.role) {
            set_result(response, VMP_RESULT_INVALID_REQUEST,
                       "role_mismatch");
        } else {
            set_result(response, VMP_RESULT_OK, "ok");
        }
        return VMP_SERVER_OK;
    }
    if (memcmp(request->target_native_instance_id,
               runtime->native_instance_id,
               VMP_NATIVE_INSTANCE_ID_LEN) != 0) {
        if (request_fd >= 0) (void)close(request_fd);
        set_result(response, VMP_RESULT_STALE_INSTANCE,
                   "stale_instance");
        return VMP_SERVER_OK;
    }
    if ((request->operation == VMP_OPERATION_START_SESSION &&
         memcmp(request->body.start_session.client_native_instance_id,
                runtime->native_instance_id,
                VMP_NATIVE_INSTANCE_ID_LEN) != 0) ||
        (request->operation == VMP_OPERATION_START_EXIT_SESSION &&
         memcmp(request->body.start_exit_session.exit_native_instance_id,
                runtime->native_instance_id,
                VMP_NATIVE_INSTANCE_ID_LEN) != 0)) {
        if (request_fd >= 0) (void)close(request_fd);
        set_result(response, VMP_RESULT_STALE_INSTANCE,
                   "signed_instance_mismatch");
        return VMP_SERVER_OK;
    }

    switch (request->operation) {
    case VMP_OPERATION_START_SESSION:
        dispatch_start(runtime, &request->body.start_session, response);
        break;
    case VMP_OPERATION_START_EXIT_SESSION:
        dispatch_start_exit(runtime, &request->body.start_exit_session,
                            response, request_fd);
        break;
    case VMP_OPERATION_ADD_PATH:
        dispatch_add_path(runtime, &request->body.add_path, response,
                          request_fd);
        break;
    case VMP_OPERATION_REMOVE_PATH:
        dispatch_remove_path(runtime, &request->body.remove_path, response);
        break;
    case VMP_OPERATION_SEND_DATAGRAM:
        dispatch_send(runtime, &request->body.send_datagram, response);
        break;
    case VMP_OPERATION_RECEIVE_DATAGRAM:
        dispatch_receive(runtime, &request->body.receive_datagram,
                         response);
        break;
    case VMP_OPERATION_GET_STATUS:
        dispatch_status(runtime, &request->body.get_status, response);
        break;
    case VMP_OPERATION_STOP_SESSION:
        dispatch_stop(runtime, &request->body.stop_session, response);
        break;
    case VMP_OPERATION_PREFLIGHT:
        /* Handled before target-instance validation. */
        set_result(response, VMP_RESULT_INVALID_REQUEST, "operation");
        break;
    case VMP_OPERATION_NONE:
    default:
        set_result(response, VMP_RESULT_INVALID_REQUEST, "operation");
        break;
    }
    return VMP_SERVER_OK;
}
