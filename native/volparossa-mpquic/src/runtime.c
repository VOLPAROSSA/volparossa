// SPDX-License-Identifier: GPL-3.0-only

#include "volparossa_mpquic_runtime.h"

#include <stdlib.h>
#include <string.h>
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
    vmp_transport_ops_t transport;
    void *factory_context;
    vmp_now_ms_fn now_ms;
    void *clock_context;
    runtime_session_t sessions[VMP_MAX_SESSIONS];
};

static void secure_zero(void *memory, size_t len)
{
    volatile uint8_t *bytes = memory;
    while (len > 0U) {
        *bytes++ = 0;
        --len;
    }
}

static bool valid_secret(const uint8_t *secret, size_t len)
{
    if (secret == NULL || len == 0U || len > VMP_MAX_AUTH_SECRET) {
        return false;
    }
    for (size_t index = 0; index < len; ++index) {
        if (secret[index] == 0U || secret[index] == (uint8_t)'\n' ||
            secret[index] == (uint8_t)'\r') {
            return false;
        }
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
                                             bool *out_ready)
{
    *out_active = 0U;
    *out_ready = false;
    if (session->failed) return VMP_TRANSPORT_ENGINE;
    if (session->transport_session == NULL) return VMP_TRANSPORT_OK;

    vmp_transport_path_snapshot_t snapshots[VMP_MAX_PATHS];
    memset(snapshots, 0, sizeof(snapshots));
    size_t count = 0U;
    bool ready = false;
    const vmp_transport_error_t error = runtime->transport.snapshot(
        session->transport_session, snapshots, VMP_MAX_PATHS, &count, &ready);
    if (error != VMP_TRANSPORT_OK || count > VMP_MAX_PATHS) {
        session->failed = true;
        return VMP_TRANSPORT_ENGINE;
    }

    bool observed[VMP_MAX_PATHS] = {false};
    for (size_t index = 0; index < count; ++index) {
        if (!known_handle(session, snapshots[index].handle, observed) ||
            snapshots[index].state > VMP_TRANSPORT_PATH_CLOSED) {
            session->failed = true;
            return VMP_TRANSPORT_ENGINE;
        }
        if (snapshots[index].state == VMP_TRANSPORT_PATH_ACTIVE) {
            ++*out_active;
        }
    }
    if (count != path_count(session)) {
        session->failed = true;
        return VMP_TRANSPORT_ENGINE;
    }
    *out_ready = ready;
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
                                  const vmp_transport_ops_t *transport,
                                  void *factory_context,
                                  vmp_now_ms_fn now_ms,
                                  void *clock_context)
{
    if ((mode != VMP_RUNTIME_CLIENT && mode != VMP_RUNTIME_EXIT) ||
        !valid_transport(transport) || now_ms == NULL) {
        return NULL;
    }
    vmp_runtime_t *runtime = calloc(1U, sizeof(*runtime));
    if (runtime == NULL) return NULL;
    runtime->mode = mode;
    runtime->transport = *transport;
    runtime->factory_context = factory_context;
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
        !copy_tls_name(&start->tls_server_name, tls_server_name)) {
        secure_zero(tls_server_name, sizeof(tls_server_name));
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "session_parameters");
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
    if (snapshot_active(runtime, session, &active, &ready) !=
        VMP_TRANSPORT_OK) {
        set_result(response, VMP_RESULT_TRANSPORT, "native_transport_failed");
        return;
    }
    if (!ready || active < session->start.minimum_paths) {
        set_result(response, VMP_RESULT_INSUFFICIENT_PATHS,
                   "required_paths_not_active");
        return;
    }
    session->started = true;
    set_result(response, VMP_RESULT_OK, "ok");
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
    if (snapshot_active(runtime, session, &active, &ready) !=
        VMP_TRANSPORT_OK) {
        set_result(response, VMP_RESULT_TRANSPORT, "native_transport_failed");
        return false;
    }
    if (!session->started || !ready ||
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
                                vmp_response_t *response)
{
    if (runtime->mode != VMP_RUNTIME_EXIT) {
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "operation_for_role");
        return;
    }
    if (!valid_mode(start->minimum_paths, start->transport_mode) ||
        start->masque_context_id == 0U ||
        start->masque_context_id > VMP_MAX_MASQUE_CONTEXT_ID ||
        !valid_secret(start->auth_secret.data, start->auth_secret.len)) {
        set_result(response, VMP_RESULT_INVALID_REQUEST,
                   "session_parameters");
        return;
    }
    if (!valid_authorization_window(runtime, start->expires_at_ms)) {
        set_result(response, VMP_RESULT_UNAUTHORISED,
                   "authorization_window");
        return;
    }

    /* The pinned mqvpn patch exposes session-correlated server delivery, but
     * this process boundary has no exit transport factory and the privileged
     * helper does not yet hand it a route-scoped listener socket plus TLS
     * certificate/key descriptors. Starting a host-local listener or reading
     * secret paths here would violate the product privilege boundary. */
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
    const bool add_path = request->operation == VMP_OPERATION_ADD_PATH;
    if ((add_path && request_fd < 0) || (!add_path && request_fd >= 0)) {
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

    switch (request->operation) {
    case VMP_OPERATION_START_SESSION:
        dispatch_start(runtime, &request->body.start_session, response);
        break;
    case VMP_OPERATION_START_EXIT_SESSION:
        dispatch_start_exit(runtime, &request->body.start_exit_session,
                            response);
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
    case VMP_OPERATION_NONE:
    default:
        set_result(response, VMP_RESULT_INVALID_REQUEST, "operation");
        break;
    }
    return VMP_SERVER_OK;
}
