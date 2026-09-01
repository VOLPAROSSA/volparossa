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

typedef enum runtime_authorization_state {
    RUNTIME_AUTHORIZATION_UNUSED = 0,
    RUNTIME_AUTHORIZATION_ACTIVE,
    RUNTIME_AUTHORIZATION_TOMBSTONE,
} runtime_authorization_state_t;

typedef struct runtime_authorization {
    runtime_authorization_state_t state;
    uint8_t reservation_id[VMP_RESERVATION_ID_LEN];
    uint8_t finalize_id[VMP_FINALIZE_ID_LEN];
    uint64_t deadline_boottime_ms;
} runtime_authorization_t;

typedef struct runtime_session {
    bool used;
    bool failed;
    bool started;
    bool reverse_overflow;
    vmp_start_session_t start;
    uint8_t auth_secret[VMP_MAX_AUTH_SECRET];
    char tls_server_name[VMP_MAX_TLS_SERVER_NAME + 1U];
    uint64_t authorization_deadline_boottime_ms;
    size_t authorization_index;
    void *transport_session;
    runtime_path_t paths[VMP_MAX_PATHS];
} runtime_session_t;

typedef struct runtime_exit_path {
    bool used;
    int64_t transport_handle;
    uint32_t path_id;
    uint8_t listener_ip[16];
    uint16_t listener_port;
    uint8_t expected_client_ip[16];
    uint16_t expected_client_port;
    uint8_t reservation_hash[VMP_RESERVATION_HASH_LEN];
} runtime_exit_path_t;

typedef struct runtime_exit_session {
    bool used;
    bool failed;
    bool started;
    vmp_start_exit_session_t start;
    uint8_t auth_secret[VMP_MAX_AUTH_SECRET];
    char tls_server_name[VMP_MAX_TLS_SERVER_NAME + 1U];
    uint64_t authorization_deadline_boottime_ms;
    size_t authorization_index;
    void *transport_session;
    runtime_exit_path_t paths[VMP_MAX_PATHS];
} runtime_exit_session_t;

struct vmp_runtime {
    vmp_runtime_mode_t mode;
    uint8_t native_instance_id[VMP_NATIVE_INSTANCE_ID_LEN];
    vmp_transport_ops_t transport;
    void *factory_context;
    vmp_auth_commitment_fn auth_commitment;
    void *auth_commitment_context;
    vmp_clock_snapshot_fn clock_snapshot;
    vmp_boottime_ms_fn boottime_now;
    void *clock_context;
    uint64_t wall_anchor_boottime_ms;
    uint64_t wall_anchor_realtime_ms;
    uint64_t last_boottime_ms;
    runtime_session_t sessions[VMP_MAX_SESSIONS];
    runtime_exit_session_t exit_sessions[VMP_MAX_SESSIONS];
    runtime_authorization_t
        authorizations[VMP_MAX_AUTHORIZATION_RECORDS];
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

static bool valid_transport(const vmp_transport_ops_t *transport)
{
    return transport != NULL && transport->create != NULL &&
           transport->destroy != NULL && transport->add_path != NULL &&
           transport->remove_path != NULL && transport->pump != NULL &&
           transport->snapshot != NULL && transport->send_inner != NULL &&
           transport->receive_inner != NULL &&
           transport->exit_create != NULL &&
           transport->exit_destroy != NULL &&
           transport->exit_add_listener != NULL &&
           transport->exit_start != NULL &&
           transport->exit_pump != NULL &&
           transport->exit_snapshot != NULL &&
           transport->exit_send_inner != NULL &&
           transport->exit_receive_inner != NULL;
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

static bool read_boottime(vmp_runtime_t *runtime, uint64_t *out_now_ms)
{
    uint64_t now_ms = 0U;
    if (!runtime->boottime_now(runtime->clock_context, &now_ms) ||
        now_ms == UINT64_MAX || now_ms < runtime->last_boottime_ms) {
        return false;
    }
    runtime->last_boottime_ms = now_ms;
    *out_now_ms = now_ms;
    return true;
}

static bool read_admission_clock(vmp_runtime_t *runtime,
                                 uint64_t *out_boottime_ms,
                                 uint64_t *out_effective_realtime_ms)
{
    uint64_t boottime_ms = 0U;
    uint64_t realtime_ms = 0U;
    if (!runtime->clock_snapshot(runtime->clock_context, &boottime_ms,
                                 &realtime_ms) ||
        boottime_ms == UINT64_MAX || realtime_ms == UINT64_MAX ||
        boottime_ms < runtime->last_boottime_ms ||
        boottime_ms < runtime->wall_anchor_boottime_ms) {
        return false;
    }

    const uint64_t elapsed_ms =
        boottime_ms - runtime->wall_anchor_boottime_ms;
    if (runtime->wall_anchor_realtime_ms > UINT64_MAX - elapsed_ms) {
        return false;
    }
    const uint64_t floor_realtime_ms =
        runtime->wall_anchor_realtime_ms + elapsed_ms;
    const uint64_t effective_realtime_ms =
        realtime_ms > floor_realtime_ms ? realtime_ms : floor_realtime_ms;

    runtime->last_boottime_ms = boottime_ms;
    runtime->wall_anchor_boottime_ms = boottime_ms;
    runtime->wall_anchor_realtime_ms = effective_realtime_ms;
    *out_boottime_ms = boottime_ms;
    *out_effective_realtime_ms = effective_realtime_ms;
    return true;
}

typedef enum authorization_lookup {
    AUTHORIZATION_LOOKUP_NONE = 0,
    AUTHORIZATION_LOOKUP_EXACT,
    AUTHORIZATION_LOOKUP_COLLISION,
} authorization_lookup_t;

static authorization_lookup_t find_authorization(
    vmp_runtime_t *runtime,
    const uint8_t reservation_id[VMP_RESERVATION_ID_LEN],
    const uint8_t finalize_id[VMP_FINALIZE_ID_LEN], size_t *out_index)
{
    bool collision = false;
    for (size_t index = 0U; index < VMP_MAX_AUTHORIZATION_RECORDS;
         ++index) {
        const runtime_authorization_t *authorization =
            &runtime->authorizations[index];
        if (authorization->state == RUNTIME_AUTHORIZATION_UNUSED) continue;
        const bool reservation_matches =
            memcmp(authorization->reservation_id, reservation_id,
                   VMP_RESERVATION_ID_LEN) == 0;
        const bool finalize_matches =
            memcmp(authorization->finalize_id, finalize_id,
                   VMP_FINALIZE_ID_LEN) == 0;
        if (reservation_matches && finalize_matches) {
            *out_index = index;
            return AUTHORIZATION_LOOKUP_EXACT;
        }
        collision = collision || reservation_matches || finalize_matches;
    }
    return collision ? AUTHORIZATION_LOOKUP_COLLISION
                     : AUTHORIZATION_LOOKUP_NONE;
}

static runtime_authorization_t *free_authorization(vmp_runtime_t *runtime,
                                                    size_t *out_index)
{
    for (size_t index = 0U; index < VMP_MAX_AUTHORIZATION_RECORDS;
         ++index) {
        if (runtime->authorizations[index].state ==
            RUNTIME_AUTHORIZATION_UNUSED) {
            *out_index = index;
            return &runtime->authorizations[index];
        }
    }
    return NULL;
}

static void store_authorization(
    runtime_authorization_t *authorization,
    runtime_authorization_state_t state,
    const uint8_t reservation_id[VMP_RESERVATION_ID_LEN],
    const uint8_t finalize_id[VMP_FINALIZE_ID_LEN],
    uint64_t deadline_boottime_ms)
{
    memset(authorization, 0, sizeof(*authorization));
    authorization->state = state;
    memcpy(authorization->reservation_id, reservation_id,
           VMP_RESERVATION_ID_LEN);
    memcpy(authorization->finalize_id, finalize_id, VMP_FINALIZE_ID_LEN);
    authorization->deadline_boottime_ms = deadline_boottime_ms;
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

static void copy_start(runtime_session_t *session,
                       const vmp_start_session_t *start,
                       const char tls_server_name[VMP_MAX_TLS_SERVER_NAME + 1U],
                       uint64_t authorization_deadline_boottime_ms,
                       size_t authorization_index)
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
    session->authorization_deadline_boottime_ms =
        authorization_deadline_boottime_ms;
    session->authorization_index = authorization_index;
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

static runtime_exit_session_t *find_exit_session(
    vmp_runtime_t *runtime, const uint8_t context[VMP_CONTEXT_ID_LEN])
{
    for (size_t index = 0U; index < VMP_MAX_SESSIONS; ++index) {
        runtime_exit_session_t *session = &runtime->exit_sessions[index];
        if (session->used &&
            memcmp(session->start.route_context_id, context,
                   VMP_CONTEXT_ID_LEN) == 0) {
            return session;
        }
    }
    return NULL;
}

static runtime_exit_session_t *free_exit_session(vmp_runtime_t *runtime)
{
    for (size_t index = 0U; index < VMP_MAX_SESSIONS; ++index) {
        if (!runtime->exit_sessions[index].used) {
            return &runtime->exit_sessions[index];
        }
    }
    return NULL;
}

static size_t exit_path_count(const runtime_exit_session_t *session)
{
    size_t count = 0U;
    for (size_t index = 0U; index < VMP_MAX_PATHS; ++index) {
        if (session->paths[index].used) ++count;
    }
    return count;
}

static runtime_exit_path_t *free_exit_path(runtime_exit_session_t *session)
{
    for (size_t index = 0U; index < VMP_MAX_PATHS; ++index) {
        if (!session->paths[index].used) return &session->paths[index];
    }
    return NULL;
}

static bool exit_start_matches(const runtime_exit_session_t *session,
                               const vmp_start_exit_session_t *start)
{
    return memcmp(session->start.route_context_id, start->route_context_id,
                  VMP_CONTEXT_ID_LEN) == 0 &&
           session->start.expires_at_ms == start->expires_at_ms &&
           session->start.minimum_paths == start->minimum_paths &&
           session->start.masque_context_id == start->masque_context_id &&
           session->start.transport_mode == start->transport_mode &&
           memcmp(session->start.exit_spki_sha256,
                  start->exit_spki_sha256, VMP_SPKI_SHA256_LEN) == 0 &&
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

static bool exit_path_conflicts(const runtime_exit_session_t *session,
                                const vmp_start_exit_session_t *candidate)
{
    for (size_t index = 0U; index < VMP_MAX_PATHS; ++index) {
        const runtime_exit_path_t *path = &session->paths[index];
        if (!path->used) continue;
        if (path->path_id == candidate->path_id ||
            (path->listener_port == candidate->listener_port &&
             memcmp(path->listener_ip, candidate->listener_ip, 16U) == 0) ||
            (path->expected_client_port == candidate->expected_client_port &&
             memcmp(path->expected_client_ip,
                    candidate->expected_client_ip, 16U) == 0)) {
            return true;
        }
    }
    return false;
}

static void copy_exit_start(runtime_exit_session_t *session,
                            const vmp_start_exit_session_t *start,
                            const char tls_server_name
                                [VMP_MAX_TLS_SERVER_NAME + 1U],
                            uint64_t deadline_boottime_ms,
                            size_t authorization_index)
{
    memset(session, 0, sizeof(*session));
    session->used = true;
    session->start = *start;
    memcpy(session->auth_secret, start->auth_secret.data,
           start->auth_secret.len);
    session->start.auth_secret.data = session->auth_secret;
    memcpy(session->tls_server_name, tls_server_name,
           start->tls_server_name.len + 1U);
    session->start.tls_server_name.data =
        (const uint8_t *)session->tls_server_name;
    /* PEM views are used only synchronously by exit_create and must not be
     * reachable after the request frame is retired. */
    session->start.tls_certificate_pem.data = NULL;
    session->start.tls_certificate_pem.len = 0U;
    session->start.tls_private_key_pem.data = NULL;
    session->start.tls_private_key_pem.len = 0U;
    session->authorization_deadline_boottime_ms = deadline_boottime_ms;
    session->authorization_index = authorization_index;
}

static bool exit_authorization_matches(
    const vmp_runtime_t *runtime, const runtime_exit_session_t *session)
{
    if (session->authorization_index >= VMP_MAX_AUTHORIZATION_RECORDS) {
        return false;
    }
    const runtime_authorization_t *authorization =
        &runtime->authorizations[session->authorization_index];
    return authorization->state == RUNTIME_AUTHORIZATION_ACTIVE &&
           authorization->deadline_boottime_ms ==
               session->authorization_deadline_boottime_ms &&
           memcmp(authorization->reservation_id,
                  session->start.reservation_id,
                  VMP_RESERVATION_ID_LEN) == 0 &&
           memcmp(authorization->finalize_id,
                  session->start.finalize_id,
                  VMP_FINALIZE_ID_LEN) == 0;
}

static void destroy_exit_session(vmp_runtime_t *runtime,
                                 runtime_exit_session_t *session)
{
    if (session->used && exit_authorization_matches(runtime, session)) {
        runtime->authorizations[session->authorization_index].state =
            RUNTIME_AUTHORIZATION_TOMBSTONE;
    }
    if (session->transport_session != NULL) {
        runtime->transport.exit_destroy(session->transport_session);
    }
    secure_zero(session, sizeof(*session));
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
    if (error == VMP_TRANSPORT_OVERFLOW) {
        session->reverse_overflow = true;
        session->failed = true;
        session->started = false;
        secure_zero(&assignment, sizeof(assignment));
        return VMP_TRANSPORT_OVERFLOW;
    }
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

static bool session_authorization_matches(
    const vmp_runtime_t *runtime, const runtime_session_t *session)
{
    if (session->authorization_index >= VMP_MAX_AUTHORIZATION_RECORDS) {
        return false;
    }
    const runtime_authorization_t *authorization =
        &runtime->authorizations[session->authorization_index];
    return authorization->state == RUNTIME_AUTHORIZATION_ACTIVE &&
           authorization->deadline_boottime_ms ==
               session->authorization_deadline_boottime_ms &&
           memcmp(authorization->reservation_id,
                  session->start.reservation_id,
                  VMP_RESERVATION_ID_LEN) == 0 &&
           memcmp(authorization->finalize_id, session->start.finalize_id,
                  VMP_FINALIZE_ID_LEN) == 0;
}

static void destroy_session(vmp_runtime_t *runtime, runtime_session_t *session)
{
    if (session->used && session_authorization_matches(runtime, session)) {
        runtime->authorizations[session->authorization_index].state =
            RUNTIME_AUTHORIZATION_TOMBSTONE;
    }
    if (session->transport_session != NULL) {
        runtime->transport.destroy(session->transport_session);
    }
    secure_zero(session, sizeof(*session));
}

static void destroy_all_sessions(vmp_runtime_t *runtime)
{
    for (size_t index = 0U; index < VMP_MAX_SESSIONS; ++index) {
        if (runtime->sessions[index].used) {
            destroy_session(runtime, &runtime->sessions[index]);
        }
        if (runtime->exit_sessions[index].used) {
            destroy_exit_session(runtime, &runtime->exit_sessions[index]);
        }
    }
}

static void expire_sessions_at(vmp_runtime_t *runtime, uint64_t now_ms)
{
    for (size_t index = 0U; index < VMP_MAX_SESSIONS; ++index) {
        runtime_session_t *session = &runtime->sessions[index];
        if (session->used &&
            now_ms >= session->authorization_deadline_boottime_ms) {
            destroy_session(runtime, session);
        }
        runtime_exit_session_t *exit_session =
            &runtime->exit_sessions[index];
        if (exit_session->used &&
            now_ms >= exit_session->authorization_deadline_boottime_ms) {
            destroy_exit_session(runtime, exit_session);
        }
    }
}

static void purge_authorizations_at(vmp_runtime_t *runtime,
                                    uint64_t now_ms)
{
    for (size_t index = 0U; index < VMP_MAX_AUTHORIZATION_RECORDS;
         ++index) {
        runtime_authorization_t *authorization =
            &runtime->authorizations[index];
        if (authorization->state == RUNTIME_AUTHORIZATION_TOMBSTONE &&
            now_ms >= authorization->deadline_boottime_ms) {
            secure_zero(authorization, sizeof(*authorization));
        }
    }
}

typedef enum authorization_admission {
    AUTHORIZATION_ADMISSION_OK = 0,
    AUTHORIZATION_ADMISSION_CLOCK,
    AUTHORIZATION_ADMISSION_WINDOW,
} authorization_admission_t;

static authorization_admission_t authorization_deadline(
    vmp_runtime_t *runtime, uint64_t expires_at_ms,
    uint64_t *out_deadline_boottime_ms)
{
    uint64_t boottime_ms = 0U;
    uint64_t effective_realtime_ms = 0U;
    if (!read_admission_clock(runtime, &boottime_ms,
                              &effective_realtime_ms)) {
        return AUTHORIZATION_ADMISSION_CLOCK;
    }
    expire_sessions_at(runtime, boottime_ms);
    purge_authorizations_at(runtime, boottime_ms);

    if (expires_at_ms <= effective_realtime_ms) {
        return AUTHORIZATION_ADMISSION_WINDOW;
    }
    const uint64_t remaining_ms = expires_at_ms - effective_realtime_ms;
    if (remaining_ms > VMP_MAX_AUTHORIZATION_FUTURE_MS ||
        boottime_ms > UINT64_MAX - remaining_ms) {
        return AUTHORIZATION_ADMISSION_WINDOW;
    }
    *out_deadline_boottime_ms = boottime_ms + remaining_ms;
    return AUTHORIZATION_ADMISSION_OK;
}

static bool require_live(vmp_runtime_t *runtime, runtime_session_t *session,
                         vmp_response_t *response)
{
    uint64_t now_ms = 0U;
    if (!read_boottime(runtime, &now_ms)) {
        destroy_session(runtime, session);
        set_result(response, VMP_RESULT_UNAUTHORISED,
                   "authorization_clock");
        return false;
    }
    if (now_ms >= session->authorization_deadline_boottime_ms) {
        destroy_session(runtime, session);
        purge_authorizations_at(runtime, now_ms);
        set_result(response, VMP_RESULT_UNAUTHORISED, "session_expired");
        return false;
    }
    if (!session_authorization_matches(runtime, session)) {
        destroy_session(runtime, session);
        set_result(response, VMP_RESULT_TRANSPORT, "authorization_state");
        return false;
    }
    return true;
}

static bool require_exit_live(vmp_runtime_t *runtime,
                              runtime_exit_session_t *session,
                              vmp_response_t *response)
{
    uint64_t now_ms = 0U;
    if (!read_boottime(runtime, &now_ms)) {
        destroy_exit_session(runtime, session);
        set_result(response, VMP_RESULT_UNAUTHORISED,
                   "authorization_clock");
        return false;
    }
    if (now_ms >= session->authorization_deadline_boottime_ms) {
        destroy_exit_session(runtime, session);
        purge_authorizations_at(runtime, now_ms);
        set_result(response, VMP_RESULT_UNAUTHORISED, "session_expired");
        return false;
    }
    if (!exit_authorization_matches(runtime, session)) {
        destroy_exit_session(runtime, session);
        set_result(response, VMP_RESULT_TRANSPORT, "authorization_state");
        return false;
    }
    return true;
}

vmp_runtime_t *vmp_runtime_create(vmp_runtime_mode_t mode,
                                  const uint8_t native_instance_id
                                      [VMP_NATIVE_INSTANCE_ID_LEN],
                                  const vmp_transport_ops_t *transport,
                                  void *factory_context,
                                  vmp_auth_commitment_fn auth_commitment,
                                  void *auth_commitment_context,
                                  vmp_clock_snapshot_fn clock_snapshot,
                                  vmp_boottime_ms_fn boottime_now,
                                  void *clock_context)
{
    if ((mode != VMP_RUNTIME_CLIENT && mode != VMP_RUNTIME_EXIT) ||
        native_instance_id == NULL ||
        all_zero(native_instance_id, VMP_NATIVE_INSTANCE_ID_LEN) ||
        !valid_transport(transport) || auth_commitment == NULL ||
        clock_snapshot == NULL || boottime_now == NULL) {
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
    runtime->clock_snapshot = clock_snapshot;
    runtime->boottime_now = boottime_now;
    runtime->clock_context = clock_context;
    uint64_t boottime_ms = 0U;
    uint64_t realtime_ms = 0U;
    if (!clock_snapshot(clock_context, &boottime_ms, &realtime_ms) ||
        boottime_ms == UINT64_MAX || realtime_ms == UINT64_MAX) {
        secure_zero(runtime, sizeof(*runtime));
        free(runtime);
        return NULL;
    }
    runtime->wall_anchor_boottime_ms = boottime_ms;
    runtime->wall_anchor_realtime_ms = realtime_ms;
    runtime->last_boottime_ms = boottime_ms;
    return runtime;
}

void vmp_runtime_destroy(vmp_runtime_t *runtime)
{
    if (runtime == NULL) return;
    destroy_all_sessions(runtime);
    secure_zero(runtime, sizeof(*runtime));
    free(runtime);
}

vmp_server_error_t vmp_runtime_pump(void *context)
{
    vmp_runtime_t *runtime = context;
    if (runtime == NULL) return VMP_SERVER_BACKEND;
    uint64_t now_ms = 0U;
    if (!read_boottime(runtime, &now_ms)) {
        destroy_all_sessions(runtime);
        return VMP_SERVER_BACKEND;
    }
    expire_sessions_at(runtime, now_ms);
    purge_authorizations_at(runtime, now_ms);
    for (size_t index = 0; index < VMP_MAX_SESSIONS; ++index) {
        runtime_session_t *session = &runtime->sessions[index];
        if (session->used && !session->failed &&
            session->transport_session != NULL) {
            const vmp_transport_error_t error =
                runtime->transport.pump(session->transport_session);
            if (error != VMP_TRANSPORT_OK) {
                if (error == VMP_TRANSPORT_OVERFLOW) {
                    session->reverse_overflow = true;
                }
                session->failed = true;
                session->started = false;
            }
        }
        runtime_exit_session_t *exit_session =
            &runtime->exit_sessions[index];
        if (!exit_session->used || exit_session->failed ||
            exit_session->transport_session == NULL) {
            continue;
        }
        const vmp_transport_error_t exit_error =
            runtime->transport.exit_pump(exit_session->transport_session);
        if (exit_error != VMP_TRANSPORT_OK) {
            exit_session->failed = true;
            exit_session->started = false;
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

    if (session != NULL) {
        if (!require_live(runtime, session, response)) {
            secure_zero(tls_server_name, sizeof(tls_server_name));
            return;
        }
        if (!start_matches(session, start)) {
            secure_zero(tls_server_name, sizeof(tls_server_name));
            set_result(response, VMP_RESULT_INVALID_REQUEST,
                       "session_parameters_changed");
            return;
        }
    } else {
        uint64_t deadline_boottime_ms = 0U;
        const authorization_admission_t admission = authorization_deadline(
            runtime, start->expires_at_ms, &deadline_boottime_ms);
        if (admission != AUTHORIZATION_ADMISSION_OK) {
            secure_zero(tls_server_name, sizeof(tls_server_name));
            set_result(response, VMP_RESULT_UNAUTHORISED,
                       admission == AUTHORIZATION_ADMISSION_CLOCK
                           ? "authorization_clock"
                           : "authorization_window");
            return;
        }

        size_t authorization_index = 0U;
        const authorization_lookup_t lookup = find_authorization(
            runtime, start->reservation_id, start->finalize_id,
            &authorization_index);
        if (lookup != AUTHORIZATION_LOOKUP_NONE) {
            secure_zero(tls_server_name, sizeof(tls_server_name));
            set_result(response, VMP_RESULT_UNAUTHORISED,
                       lookup == AUTHORIZATION_LOOKUP_EXACT
                           ? "authorization_replay"
                           : "authorization_scope_reuse");
            return;
        }

        session = free_session(runtime);
        if (session == NULL) {
            secure_zero(tls_server_name, sizeof(tls_server_name));
            set_result(response, VMP_RESULT_TRANSPORT, "session_limit");
            return;
        }
        runtime_authorization_t *authorization =
            free_authorization(runtime, &authorization_index);
        if (authorization == NULL) {
            secure_zero(tls_server_name, sizeof(tls_server_name));
            set_result(response, VMP_RESULT_TRANSPORT,
                       "authorization_capacity");
            return;
        }
        store_authorization(authorization, RUNTIME_AUTHORIZATION_ACTIVE,
                            start->reservation_id, start->finalize_id,
                            deadline_boottime_ms);
        copy_start(session, start, tls_server_name, deadline_boottime_ms,
                   authorization_index);
        secure_zero(tls_server_name, sizeof(tls_server_name));
        set_result(response, VMP_RESULT_INSUFFICIENT_PATHS,
                   "required_paths_not_active");
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
    const vmp_transport_error_t snapshot_error = snapshot_active(
        runtime, session, &active, &ready, &has_assignment, &assignment);
    if (snapshot_error != VMP_TRANSPORT_OK) {
        secure_zero(&assignment, sizeof(assignment));
        set_result(response,
                   snapshot_error == VMP_TRANSPORT_OVERFLOW
                       ? VMP_RESULT_QUEUE_OVERFLOW
                       : VMP_RESULT_TRANSPORT,
                   snapshot_error == VMP_TRANSPORT_OVERFLOW
                       ? "reverse_queue_overflow"
                       : "native_transport_failed");
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
    if (session->reverse_overflow) {
        (void)close(path_fd);
        set_result(response, VMP_RESULT_QUEUE_OVERFLOW,
                   "reverse_queue_overflow");
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
        if (add_error == VMP_TRANSPORT_OVERFLOW) {
            session->reverse_overflow = true;
            session->failed = true;
            session->started = false;
        }
        if (created) {
            runtime->transport.destroy(session->transport_session);
            session->transport_session = NULL;
        }
        set_result(response,
                   add_error == VMP_TRANSPORT_OVERFLOW
                       ? VMP_RESULT_QUEUE_OVERFLOW
                       : VMP_RESULT_TRANSPORT,
                   add_error == VMP_TRANSPORT_OVERFLOW
                       ? "reverse_queue_overflow"
                       : "path_activation_failed");
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
    if (session->reverse_overflow) {
        set_result(response, VMP_RESULT_QUEUE_OVERFLOW,
                   "reverse_queue_overflow");
        return;
    }
    if (session->failed) {
        set_result(response, VMP_RESULT_TRANSPORT,
                   "native_transport_failed");
        return;
    }
    const vmp_transport_error_t remove_error =
        runtime->transport.remove_path(session->transport_session,
                                       path->transport_handle);
    if (remove_error != VMP_TRANSPORT_OK) {
        if (remove_error == VMP_TRANSPORT_OVERFLOW) {
            session->reverse_overflow = true;
        }
        session->failed = true;
        session->started = false;
        set_result(response,
                   remove_error == VMP_TRANSPORT_OVERFLOW
                       ? VMP_RESULT_QUEUE_OVERFLOW
                       : VMP_RESULT_TRANSPORT,
                   remove_error == VMP_TRANSPORT_OVERFLOW
                       ? "reverse_queue_overflow"
                       : "path_removal_failed");
        return;
    }
    secure_zero(path, sizeof(*path));
    session->started = false;
    set_result(response, VMP_RESULT_OK, "ok");
}

static bool require_active(vmp_runtime_t *runtime, runtime_session_t *session,
                           vmp_response_t *response)
{
    if (session->reverse_overflow) {
        set_result(response, VMP_RESULT_QUEUE_OVERFLOW,
                   "reverse_queue_overflow");
        return false;
    }
    size_t active = 0U;
    bool ready = false;
    bool has_assignment = false;
    vmp_tunnel_assignment_t assignment;
    memset(&assignment, 0, sizeof(assignment));
    const vmp_transport_error_t snapshot_error = snapshot_active(
        runtime, session, &active, &ready, &has_assignment, &assignment);
    if (snapshot_error != VMP_TRANSPORT_OK) {
        secure_zero(&assignment, sizeof(assignment));
        set_result(response,
                   snapshot_error == VMP_TRANSPORT_OVERFLOW
                       ? VMP_RESULT_QUEUE_OVERFLOW
                       : VMP_RESULT_TRANSPORT,
                   snapshot_error == VMP_TRANSPORT_OVERFLOW
                       ? "reverse_queue_overflow"
                       : "native_transport_failed");
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
    if (runtime->mode == VMP_RUNTIME_EXIT) {
        runtime_exit_session_t *exit_session =
            find_exit_session(runtime, request->route_context_id);
        if (exit_session == NULL) {
            set_result(response, VMP_RESULT_NOT_FOUND, "session_not_found");
            return;
        }
        if (!require_exit_live(runtime, exit_session, response)) return;
        if (request->masque_context_id !=
            exit_session->start.masque_context_id) {
            set_result(response, VMP_RESULT_INVALID_REQUEST,
                       "masque_context_mismatch");
            return;
        }
        vmp_exit_transport_snapshot_t snapshot;
        memset(&snapshot, 0, sizeof(snapshot));
        if (!exit_session->started || exit_session->failed ||
            runtime->transport.exit_snapshot(
                exit_session->transport_session, &snapshot) !=
                VMP_TRANSPORT_OK ||
            !snapshot.listening || !snapshot.connected ||
            snapshot.retained_paths < exit_session->start.minimum_paths) {
            set_result(response, VMP_RESULT_INSUFFICIENT_PATHS,
                       "exit_session_not_connected");
            return;
        }
        const vmp_transport_error_t exit_error =
            runtime->transport.exit_send_inner(
                exit_session->transport_session,
                request->masque_context_id,
                request->inner_ip_packet.data,
                request->inner_ip_packet.len);
        if (exit_error == VMP_TRANSPORT_OK) {
            set_result(response, VMP_RESULT_OK, "ok");
        } else {
            exit_session->failed = exit_error != VMP_TRANSPORT_RESOURCE;
            set_result(response, VMP_RESULT_TRANSPORT,
                       exit_error == VMP_TRANSPORT_RESOURCE
                           ? "send_backpressure"
                           : "native_transport_failed");
        }
        return;
    }
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
    if (runtime->mode == VMP_RUNTIME_EXIT) {
        runtime_exit_session_t *exit_session =
            find_exit_session(runtime, request->route_context_id);
        if (exit_session == NULL) {
            set_result(response, VMP_RESULT_NOT_FOUND, "session_not_found");
            return;
        }
        if (!require_exit_live(runtime, exit_session, response)) return;
        if (request->masque_context_id !=
            exit_session->start.masque_context_id) {
            set_result(response, VMP_RESULT_INVALID_REQUEST,
                       "masque_context_mismatch");
            return;
        }
        vmp_exit_transport_snapshot_t snapshot;
        memset(&snapshot, 0, sizeof(snapshot));
        if (!exit_session->started || exit_session->failed ||
            runtime->transport.exit_snapshot(
                exit_session->transport_session, &snapshot) !=
                VMP_TRANSPORT_OK ||
            !snapshot.listening || !snapshot.connected ||
            snapshot.retained_paths < exit_session->start.minimum_paths) {
            set_result(response, VMP_RESULT_INSUFFICIENT_PATHS,
                       "exit_session_not_connected");
            return;
        }
        set_result(response, VMP_RESULT_OK, "datagram");
        size_t packet_len = 0U;
        const vmp_transport_error_t exit_error =
            runtime->transport.exit_receive_inner(
                exit_session->transport_session,
                request->masque_context_id,
                response->received_datagram.inner_ip_packet,
                sizeof(response->received_datagram.inner_ip_packet),
                &packet_len);
        if (exit_error == VMP_TRANSPORT_EMPTY) {
            set_result(response, VMP_RESULT_NO_DATAGRAM, "no_datagram");
            return;
        }
        if (exit_error != VMP_TRANSPORT_OK ||
            !valid_inner_packet(
                response->received_datagram.inner_ip_packet,
                packet_len)) {
            exit_session->failed = true;
            exit_session->started = false;
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
        return;
    }
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
    if (!vmp_start_exit_is_valid(start) || !valid_listener) {
        if (listener_fd >= 0) (void)close(listener_fd);
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   valid_listener ? "session_parameters"
                                  : "exit_listener_descriptor");
        return;
    }
    if (!valid_auth_commitment(runtime, &start->auth_secret,
                               start->auth_commitment)) {
        (void)close(listener_fd);
        set_result(response, VMP_RESULT_UNAUTHORISED,
                   "auth_commitment_mismatch");
        return;
    }
    runtime_exit_session_t *session =
        find_exit_session(runtime, start->route_context_id);
    if (session == NULL) {
        uint64_t deadline_boottime_ms = 0U;
        const authorization_admission_t admission = authorization_deadline(
            runtime, start->expires_at_ms, &deadline_boottime_ms);
        if (admission != AUTHORIZATION_ADMISSION_OK) {
            (void)close(listener_fd);
            set_result(response, VMP_RESULT_UNAUTHORISED,
                       admission == AUTHORIZATION_ADMISSION_CLOCK
                           ? "authorization_clock"
                           : "authorization_window");
            return;
        }
        size_t authorization_index = 0U;
        const authorization_lookup_t lookup = find_authorization(
            runtime, start->reservation_id, start->finalize_id,
            &authorization_index);
        if (lookup != AUTHORIZATION_LOOKUP_NONE) {
            (void)close(listener_fd);
            set_result(response, VMP_RESULT_UNAUTHORISED,
                       lookup == AUTHORIZATION_LOOKUP_EXACT
                           ? "authorization_replay"
                           : "authorization_scope_reuse");
            return;
        }
        session = free_exit_session(runtime);
        runtime_authorization_t *authorization =
            free_authorization(runtime, &authorization_index);
        char tls_server_name[VMP_MAX_TLS_SERVER_NAME + 1U];
        memset(tls_server_name, 0, sizeof(tls_server_name));
        if (session == NULL || authorization == NULL ||
            !copy_tls_name(&start->tls_server_name, tls_server_name)) {
            (void)close(listener_fd);
            secure_zero(tls_server_name, sizeof(tls_server_name));
            set_result(response, VMP_RESULT_TRANSPORT,
                       session == NULL ? "session_limit"
                                       : "authorization_capacity");
            return;
        }
        store_authorization(authorization, RUNTIME_AUTHORIZATION_ACTIVE,
                            start->reservation_id, start->finalize_id,
                            deadline_boottime_ms);
        void *transport_session = NULL;
        const vmp_transport_error_t create_error =
            runtime->transport.exit_create(runtime->factory_context, start,
                                           &transport_session);
        if (create_error != VMP_TRANSPORT_OK || transport_session == NULL) {
            authorization->state = RUNTIME_AUTHORIZATION_TOMBSTONE;
            (void)close(listener_fd);
            secure_zero(tls_server_name, sizeof(tls_server_name));
            set_result(response, VMP_RESULT_TRANSPORT,
                       "exit_transport_create_failed");
            return;
        }
        copy_exit_start(session, start, tls_server_name,
                        deadline_boottime_ms, authorization_index);
        session->transport_session = transport_session;
        secure_zero(tls_server_name, sizeof(tls_server_name));
    } else if (!require_exit_live(runtime, session, response) ||
               !exit_start_matches(session, start)) {
        (void)close(listener_fd);
        if (response->result == VMP_RESULT_OK) {
            set_result(response, VMP_RESULT_INVALID_REQUEST,
                       "session_parameters_changed");
        }
        return;
    }

    runtime_exit_path_t *path = free_exit_path(session);
    if (session->failed || path == NULL ||
        exit_path_conflicts(session, start)) {
        (void)close(listener_fd);
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   exit_path_conflicts(session, start)
                       ? "exit_path_conflict"
                       : "exit_path_capacity");
        return;
    }
    int64_t handle = -1;
    const vmp_transport_error_t add_error =
        runtime->transport.exit_add_listener(
            session->transport_session, start, listener_fd, &handle);
    if (add_error != VMP_TRANSPORT_OK || handle < 0) {
        session->failed = true;
        session->started = false;
        set_result(response, VMP_RESULT_TRANSPORT,
                   "exit_listener_activation_failed");
        return;
    }
    memset(path, 0, sizeof(*path));
    path->used = true;
    path->transport_handle = handle;
    path->path_id = start->path_id;
    memcpy(path->listener_ip, start->listener_ip, 16U);
    path->listener_port = start->listener_port;
    memcpy(path->expected_client_ip, start->expected_client_ip, 16U);
    path->expected_client_port = start->expected_client_port;
    memcpy(path->reservation_hash, start->reservation_hash,
           VMP_RESERVATION_HASH_LEN);

    if (exit_path_count(session) < session->start.minimum_paths) {
        set_result(response, VMP_RESULT_INSUFFICIENT_PATHS,
                   "required_exit_listeners_not_retained");
        return;
    }
    if (!session->started) {
        if (runtime->transport.exit_start(session->transport_session) !=
            VMP_TRANSPORT_OK) {
            session->failed = true;
            set_result(response, VMP_RESULT_TRANSPORT,
                       "exit_transport_start_failed");
            return;
        }
        session->started = true;
    }
    vmp_exit_transport_snapshot_t snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    if (runtime->transport.exit_snapshot(session->transport_session,
                                         &snapshot) != VMP_TRANSPORT_OK ||
        !snapshot.listening ||
        snapshot.retained_paths < session->start.minimum_paths) {
        session->failed = true;
        session->started = false;
        set_result(response, VMP_RESULT_TRANSPORT,
                   "exit_transport_not_listening");
        return;
    }
    set_result(response, VMP_RESULT_OK, "exit_listeners_ready");
}

static void dispatch_stop(vmp_runtime_t *runtime,
                          const vmp_context_request_t *request,
                          vmp_response_t *response)
{
    if (runtime->mode == VMP_RUNTIME_EXIT) {
        runtime_exit_session_t *exit_session =
            find_exit_session(runtime, request->route_context_id);
        if (exit_session == NULL) {
            set_result(response, VMP_RESULT_NOT_FOUND, "session_not_found");
            return;
        }
        destroy_exit_session(runtime, exit_session);
        set_result(response, VMP_RESULT_OK, "ok");
        return;
    }
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
