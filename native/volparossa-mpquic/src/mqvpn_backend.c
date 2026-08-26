// SPDX-License-Identifier: GPL-3.0-only

#define _GNU_SOURCE

#include "volparossa_mpquic_runtime.h"

#include "libmqvpn.h"
#include "mqvpn_backend_state.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define VMP_OUTER_PACKET_CAPACITY 65536U
#define VMP_MAX_OUTER_READS_PER_PUMP 64U

typedef struct mqvpn_backend_path {
    bool used;
    int fd;
    mqvpn_path_handle_t handle;
    struct sockaddr_storage remote;
    socklen_t remote_len;
} mqvpn_backend_path_t;

typedef struct mqvpn_backend {
    mqvpn_client_t *client;
    mqvpn_backend_path_t paths[VMP_MAX_PATHS];
    uint64_t masque_context_id;
    vmp_transport_mode_t transport_mode;
    uint64_t netns_cookie;
    bool have_netns_cookie;
    vmp_mqvpn_backend_state_t lifecycle;

    bool connected;
    mqvpn_client_state_t state;
} mqvpn_backend_t;

static void backend_zero(void *memory, size_t len)
{
    volatile uint8_t *bytes = memory;
    while (len > 0U) {
        *bytes++ = 0U;
        --len;
    }
}

static void backend_mark_terminal(
    mqvpn_backend_t *backend, vmp_mqvpn_backend_terminal_t reason)
{
    if (backend == NULL) return;
    vmp_mqvpn_backend_state_enter_terminal(&backend->lifecycle, reason);
}

static vmp_transport_error_t backend_terminal_error(
    const mqvpn_backend_t *backend)
{
    if (backend == NULL) return VMP_TRANSPORT_ENGINE;
    switch (backend->lifecycle.terminal) {
    case VMP_MQVPN_TERMINAL_NONE:
        return VMP_TRANSPORT_OK;
    case VMP_MQVPN_TERMINAL_OVERFLOW:
        return VMP_TRANSPORT_OVERFLOW;
    case VMP_MQVPN_TERMINAL_ENGINE:
    default:
        return VMP_TRANSPORT_ENGINE;
    }
}

static bool copy_tunnel_assignment(const mqvpn_tunnel_info_t *info,
                                   vmp_tunnel_assignment_t *out)
{
    if (info == NULL || out == NULL || info->struct_size != sizeof(*info) ||
        info->mtu < 0 || (info->has_v6 != 0 && info->has_v6 != 1)) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->assigned_ipv4, info->assigned_ip,
           sizeof(out->assigned_ipv4));
    out->assigned_prefix_v4 = info->assigned_prefix;
    memcpy(out->server_ipv4, info->server_ip, sizeof(out->server_ipv4));
    out->server_prefix_v4 = info->server_prefix;
    out->mtu = (uint32_t)info->mtu;
    out->has_ipv6 = info->has_v6 == 1;
    memcpy(out->assigned_ipv6, info->assigned_ip6,
           sizeof(out->assigned_ipv6));
    out->assigned_prefix_v6 = info->assigned_prefix6;
    return vmp_tunnel_assignment_candidate_is_valid(out);
}

static bool map_client_phase(mqvpn_client_state_t state,
                             vmp_mqvpn_observed_phase_t *out)
{
    if (out == NULL) return false;
    switch (state) {
    case MQVPN_STATE_IDLE:
        *out = VMP_MQVPN_PHASE_IDLE;
        return true;
    case MQVPN_STATE_CONNECTING:
        *out = VMP_MQVPN_PHASE_CONNECTING;
        return true;
    case MQVPN_STATE_AUTHENTICATING:
        *out = VMP_MQVPN_PHASE_AUTHENTICATING;
        return true;
    case MQVPN_STATE_TUNNEL_READY:
        *out = VMP_MQVPN_PHASE_TUNNEL_READY;
        return true;
    case MQVPN_STATE_ESTABLISHED:
        *out = VMP_MQVPN_PHASE_ESTABLISHED;
        return true;
    case MQVPN_STATE_RECONNECTING:
        *out = VMP_MQVPN_PHASE_RECONNECTING;
        return true;
    case MQVPN_STATE_CLOSED:
        *out = VMP_MQVPN_PHASE_CLOSED;
        return true;
    default:
        return false;
    }
}

static bool backend_sample_current(
    mqvpn_backend_t *backend, vmp_mqvpn_observed_phase_t *out_phase)
{
    if (backend == NULL || backend->client == NULL) return false;
    const mqvpn_client_state_t current =
        mqvpn_client_get_state(backend->client);
    vmp_mqvpn_observed_phase_t phase = VMP_MQVPN_PHASE_IDLE;
    if (current != backend->state || !map_client_phase(current, &phase) ||
        !vmp_mqvpn_backend_state_sample_phase(&backend->lifecycle,
                                              phase)) {
        backend->state = current;
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
        return false;
    }
    if (out_phase != NULL) *out_phase = phase;
    return true;
}

static bool mqvpn_result_ok(int result)
{
    return result == MQVPN_OK || result == MQVPN_ERR_AGAIN;
}

static bool exit_overlay_address(const uint8_t *ip, uint8_t ip_len)
{
    static const uint8_t overlay_prefix[] = {
        UINT8_C(0xfd), UINT8_C(0x76), UINT8_C(0x6f),
        UINT8_C(0x6c), UINT8_C(0x70), UINT8_C(0x61),
    };
    return ip != NULL && ip_len == 16U &&
           memcmp(ip, overlay_prefix, sizeof(overlay_prefix)) == 0 &&
           ip[10] == 0U && ip[11] >= 1U && ip[11] <= VMP_MAX_PATHS &&
           ip[14] == 0U && ip[15] == 4U;
}

static bool make_address(const uint8_t *ip, uint8_t ip_len, uint16_t port,
                         struct sockaddr_storage *out, socklen_t *out_len)
{
    if (ip == NULL || ip_len != 16U || port == 0U || out == NULL ||
        out_len == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    struct sockaddr_in6 *address = (struct sockaddr_in6 *)out;
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(port);
    memcpy(&address->sin6_addr, ip, 16U);
    *out_len = (socklen_t)sizeof(*address);
    return true;
}

static bool address_tuple_equal(const struct sockaddr *left,
                                const struct sockaddr *right)
{
    if (left == NULL || right == NULL || left->sa_family != AF_INET6 ||
        right->sa_family != AF_INET6) {
        return false;
    }
    const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)left;
    const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)right;
    return a->sin6_port == b->sin6_port &&
           a->sin6_scope_id == b->sin6_scope_id &&
           memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0;
}

static bool integer_socket_option(int fd, int option, int expected)
{
    int value = 0;
    socklen_t value_len = (socklen_t)sizeof(value);
    return getsockopt(fd, SOL_SOCKET, option, &value, &value_len) == 0 &&
           value_len == (socklen_t)sizeof(value) && value == expected;
}

static bool helper_path_socket(
    mqvpn_backend_t *backend, const vmp_add_path_t *path, int fd,
    struct sockaddr_storage *local, socklen_t *local_len,
    struct sockaddr_storage *remote, socklen_t *remote_len,
    uint64_t *netns_cookie)
{
    if (backend == NULL || path == NULL || fd < 0 || local == NULL ||
        local_len == NULL || remote == NULL || remote_len == NULL ||
        netns_cookie == NULL || !vmp_add_path_is_valid(path) ||
        !make_address(path->local_ip, path->ip_len, path->local_port,
                      local, local_len) ||
        !make_address(path->remote_ip, path->ip_len, path->remote_port,
                      remote, remote_len)) {
        return false;
    }
    const int family = AF_INET6;
    const int descriptor_flags = fcntl(fd, F_GETFD);
    const int status_flags = fcntl(fd, F_GETFL);
    if (descriptor_flags < 0 || status_flags < 0 ||
        (descriptor_flags & FD_CLOEXEC) == 0 ||
        (status_flags & O_NONBLOCK) == 0 ||
        !integer_socket_option(fd, SO_DOMAIN, family) ||
        !integer_socket_option(fd, SO_TYPE, SOCK_DGRAM) ||
        !integer_socket_option(fd, SO_PROTOCOL, IPPROTO_UDP) ||
        !integer_socket_option(fd, SO_ACCEPTCONN, 0)) {
        return false;
    }

    struct sockaddr_storage actual;
    socklen_t actual_len = (socklen_t)sizeof(actual);
    memset(&actual, 0, sizeof(actual));
    if (getsockname(fd, (struct sockaddr *)&actual, &actual_len) != 0 ||
        !address_tuple_equal((const struct sockaddr *)&actual,
                             (const struct sockaddr *)local)) {
        return false;
    }
    actual_len = (socklen_t)sizeof(actual);
    errno = 0;
    if (getpeername(fd, (struct sockaddr *)&actual, &actual_len) == 0 ||
        errno != ENOTCONN) {
        return false;
    }

    int socket_error = 0;
    socklen_t socket_error_len = (socklen_t)sizeof(socket_error);
    socklen_t cookie_len = (socklen_t)sizeof(*netns_cookie);
    /* A non-zero, session-stable cookie proves namespace consistency only;
     * it does not prove that this descriptor originated at the helper. */
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                   &socket_error_len) != 0 ||
        socket_error_len != (socklen_t)sizeof(socket_error) ||
        socket_error != 0 ||
        getsockopt(fd, SOL_SOCKET, SO_NETNS_COOKIE, netns_cookie,
                   &cookie_len) != 0 ||
        cookie_len != (socklen_t)sizeof(*netns_cookie) ||
        *netns_cookie == 0U ||
        (backend->have_netns_cookie &&
         backend->netns_cookie != *netns_cookie)) {
        return false;
    }

    if (connect(fd, (const struct sockaddr *)remote, *remote_len) != 0) {
        return false;
    }
    actual_len = (socklen_t)sizeof(actual);
    memset(&actual, 0, sizeof(actual));
    if (getpeername(fd, (struct sockaddr *)&actual, &actual_len) != 0 ||
        !address_tuple_equal((const struct sockaddr *)&actual,
                             (const struct sockaddr *)remote)) {
        return false;
    }
    actual_len = (socklen_t)sizeof(actual);
    memset(&actual, 0, sizeof(actual));
    return getsockname(fd, (struct sockaddr *)&actual, &actual_len) == 0 &&
           address_tuple_equal((const struct sockaddr *)&actual,
                               (const struct sockaddr *)local);
}

static void callback_tun_output(const uint8_t *packet, size_t packet_len,
                                void *user_context)
{
    mqvpn_backend_t *backend = user_context;
    if (backend == NULL) return;
    (void)vmp_mqvpn_backend_state_enqueue_reverse(
        &backend->lifecycle, packet, packet_len);
}

static void callback_tunnel_ready(const mqvpn_tunnel_info_t *info,
                                  void *user_context)
{
    mqvpn_backend_t *backend = user_context;
    if (backend == NULL || backend->client == NULL ||
        backend_terminal_error(backend) != VMP_TRANSPORT_OK) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
        return;
    }

    vmp_tunnel_assignment_t candidate;
    memset(&candidate, 0, sizeof(candidate));
    vmp_mqvpn_observed_phase_t observed = VMP_MQVPN_PHASE_IDLE;
    if (!backend_sample_current(backend, &observed) ||
        !copy_tunnel_assignment(info, &candidate)) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
        backend_zero(&candidate, sizeof(candidate));
        return;
    }
    const vmp_mqvpn_assignment_action_t action =
        vmp_mqvpn_backend_state_offer_assignment(
            &backend->lifecycle, observed, &candidate);
    backend_zero(&candidate, sizeof(candidate));
    if (action == VMP_MQVPN_ASSIGNMENT_DUPLICATE) return;
    if (action != VMP_MQVPN_ASSIGNMENT_ACTIVATE) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
        return;
    }

    const int activation_result =
        mqvpn_client_set_tun_active(backend->client, 1, -1);
    vmp_mqvpn_observed_phase_t post_call = VMP_MQVPN_PHASE_IDLE;
    const bool sampled = backend_sample_current(backend, &post_call);
    if (!vmp_mqvpn_backend_state_finish_activation(
            &backend->lifecycle,
            activation_result == MQVPN_OK && sampled, post_call)) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
    }
}

static void callback_tunnel_closed(mqvpn_error_t reason, void *user_context)
{
    (void)reason;
    mqvpn_backend_t *backend = user_context;
    backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
}

static void callback_ready_for_tun(void *user_context)
{
    (void)user_context;
}

static void callback_state_changed(mqvpn_client_state_t old_state,
                                   mqvpn_client_state_t new_state,
                                   void *user_context)
{
    mqvpn_backend_t *backend = user_context;
    if (backend == NULL) return;
    vmp_mqvpn_observed_phase_t old_phase = VMP_MQVPN_PHASE_IDLE;
    vmp_mqvpn_observed_phase_t new_phase = VMP_MQVPN_PHASE_IDLE;
    const bool valid = old_state == backend->state &&
                       map_client_phase(old_state, &old_phase) &&
                       map_client_phase(new_state, &new_phase) &&
                       vmp_mqvpn_backend_state_observe_transition(
                           &backend->lifecycle, old_phase, new_phase);
    backend->state = new_state;
    if (!valid) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
    }
}

static vmp_transport_error_t configure_client(
    const vmp_transport_create_params_t *params, mqvpn_backend_t *backend)
{
    char host[INET6_ADDRSTRLEN];
    if (!exit_overlay_address(params->remote_ip, params->ip_len) ||
        inet_ntop(AF_INET6, params->remote_ip, host, sizeof(host)) == NULL ||
        params->auth_secret_len == 0U ||
        params->auth_secret_len > VMP_MAX_AUTH_SECRET) {
        return VMP_TRANSPORT_INVALID;
    }
    char auth[VMP_MAX_AUTH_SECRET + 1U];
    memset(auth, 0, sizeof(auth));
    memcpy(auth, params->auth_secret, params->auth_secret_len);

    mqvpn_config_t *config = mqvpn_config_new();
    if (config == NULL) {
        backend_zero(auth, sizeof(auth));
        return VMP_TRANSPORT_RESOURCE;
    }
    bool configured =
        mqvpn_config_set_server(config, host, (int)params->remote_port) ==
            MQVPN_OK &&
        mqvpn_config_set_tls_server_name(config, params->tls_server_name) ==
            MQVPN_OK &&
        mqvpn_config_set_auth_key(config, auth) == MQVPN_OK &&
        mqvpn_config_set_expected_spki_sha256(
            config, params->exit_spki_sha256) == MQVPN_OK &&
        mqvpn_config_set_insecure(config, 0) == MQVPN_OK &&
        mqvpn_config_set_multipath(
            config,
            params->transport_mode == VMP_TRANSPORT_MODE_MULTIPATH_QUIC
                ? 1
                : 0) == MQVPN_OK &&
        mqvpn_config_set_tun_mtu(config, 1420) == MQVPN_OK &&
        mqvpn_config_set_reconnect(config, 0, 5) == MQVPN_OK &&
        mqvpn_config_set_scheduler(config, MQVPN_SCHED_WLB) == MQVPN_OK &&
        mqvpn_config_set_cc(config, MQVPN_CC_BBR2) == MQVPN_OK &&
        mqvpn_config_set_reinjection(config, MQVPN_REINJ_OFF) == MQVPN_OK &&
        mqvpn_config_set_reorder_enabled(config, MQVPN_REORDER_OFF) ==
            MQVPN_OK &&
        mqvpn_config_set_hybrid_enabled(config, 0) == MQVPN_OK &&
        mqvpn_config_set_init_max_path_id(
            config,
            params->transport_mode ==
                    VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP
                ? 1
                : VMP_MAX_PATHS) ==
            MQVPN_OK &&
        mqvpn_config_set_log_level(config, MQVPN_LOG_ERROR) == MQVPN_OK;

    mqvpn_client_callbacks_t callbacks = MQVPN_CLIENT_CALLBACKS_INIT;
    callbacks.tun_output = callback_tun_output;
    callbacks.tunnel_config_ready = callback_tunnel_ready;
    callbacks.send_packet = NULL;
    callbacks.tunnel_closed = callback_tunnel_closed;
    callbacks.ready_for_tun = callback_ready_for_tun;
    callbacks.state_changed = callback_state_changed;

    if (configured) {
        backend->client = mqvpn_client_new(config, &callbacks, backend);
    }
    mqvpn_config_free(config);
    backend_zero(auth, sizeof(auth));
    if (!configured || backend->client == NULL) {
        return VMP_TRANSPORT_ENGINE;
    }

    struct sockaddr_storage server;
    socklen_t server_len = 0;
    if (!make_address(params->remote_ip, params->ip_len,
                      params->remote_port, &server, &server_len) ||
        mqvpn_client_set_server_addr(
            backend->client, (const struct sockaddr *)&server,
            server_len) != MQVPN_OK) {
        mqvpn_client_destroy(backend->client);
        backend->client = NULL;
        return VMP_TRANSPORT_ENGINE;
    }
    if (!backend_sample_current(backend, NULL)) {
        mqvpn_client_destroy(backend->client);
        backend->client = NULL;
        return VMP_TRANSPORT_ENGINE;
    }
    return VMP_TRANSPORT_OK;
}

static vmp_transport_error_t backend_create(
    void *factory_context, const vmp_transport_create_params_t *params,
    void **out_session)
{
    (void)factory_context;
    if (params == NULL || out_session == NULL ||
        !exit_overlay_address(params->remote_ip, params->ip_len) ||
        params->remote_port == 0U ||
        params->masque_context_id == 0U ||
        params->masque_context_id > VMP_MAX_MASQUE_CONTEXT_ID ||
        (params->transport_mode != VMP_TRANSPORT_MODE_MULTIPATH_QUIC &&
         params->transport_mode !=
             VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP)) {
        return VMP_TRANSPORT_INVALID;
    }
    *out_session = NULL;
    mqvpn_backend_t *backend = calloc(1U, sizeof(*backend));
    if (backend == NULL) return VMP_TRANSPORT_RESOURCE;
    backend->masque_context_id = params->masque_context_id;
    backend->transport_mode = params->transport_mode;
    backend->state = MQVPN_STATE_IDLE;
    vmp_mqvpn_backend_state_init(&backend->lifecycle);
    for (size_t index = 0; index < VMP_MAX_PATHS; ++index) {
        backend->paths[index].fd = -1;
        backend->paths[index].handle = -1;
    }
    const vmp_transport_error_t error = configure_client(params, backend);
    if (error != VMP_TRANSPORT_OK) {
        backend_zero(backend, sizeof(*backend));
        free(backend);
        return error;
    }
    *out_session = backend;
    return VMP_TRANSPORT_OK;
}

static mqvpn_backend_path_t *backend_free_path(mqvpn_backend_t *backend)
{
    for (size_t index = 0; index < VMP_MAX_PATHS; ++index) {
        if (!backend->paths[index].used) return &backend->paths[index];
    }
    return NULL;
}

static mqvpn_backend_path_t *backend_find_path(mqvpn_backend_t *backend,
                                               int64_t handle)
{
    for (size_t index = 0; index < VMP_MAX_PATHS; ++index) {
        if (backend->paths[index].used &&
            backend->paths[index].handle == handle) {
            return &backend->paths[index];
        }
    }
    return NULL;
}

static size_t backend_path_count(const mqvpn_backend_t *backend)
{
    size_t count = 0U;
    for (size_t index = 0U; index < VMP_MAX_PATHS; ++index) {
        if (backend->paths[index].used) ++count;
    }
    return count;
}

/* mqvpn keeps removed slots until both the transport-side close and the
 * platform descriptor close have been observed. Preserve that order so a
 * recycled descriptor number can never remain reachable through a stale
 * xquic path mapping. The local descriptor is forgotten immediately after
 * close(), even when a later notification fails. */
static vmp_transport_error_t backend_retire_registered_path(
    mqvpn_backend_t *backend, mqvpn_path_handle_t handle, int *owned_fd)
{
    if (backend == NULL || backend->client == NULL || handle < 0 ||
        owned_fd == NULL || *owned_fd < 0) {
        return VMP_TRANSPORT_INVALID;
    }

    bool valid = mqvpn_client_remove_path(backend->client, handle) ==
                 MQVPN_OK;
    if (backend_terminal_error(backend) != VMP_TRANSPORT_OK) valid = false;

    const int descriptor = *owned_fd;
    *owned_fd = -1;
    if (close(descriptor) != 0) valid = false;

    if (mqvpn_client_on_platform_fd_closed(backend->client, handle) !=
        MQVPN_OK) {
        valid = false;
    }
    if (backend_terminal_error(backend) != VMP_TRANSPORT_OK) valid = false;
    if (!valid) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
    }
    return backend_terminal_error(backend);
}

static vmp_transport_error_t backend_add_path(void *session,
                                              const vmp_add_path_t *path,
                                              int path_fd,
                                              int64_t *out_handle)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL || path == NULL || out_handle == NULL ||
        path_fd < 0 || !vmp_add_path_is_valid(path) ||
        backend->client == NULL) {
        if (path_fd >= 0) close(path_fd);
        return VMP_TRANSPORT_INVALID;
    }
    const vmp_transport_error_t before = backend_terminal_error(backend);
    if (before != VMP_TRANSPORT_OK) {
        close(path_fd);
        return before;
    }
    if (backend->transport_mode ==
            VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP &&
        backend_path_count(backend) >= 1U) {
        close(path_fd);
        return VMP_TRANSPORT_INVALID;
    }
    mqvpn_backend_path_t *slot = backend_free_path(backend);
    if (slot == NULL) {
        close(path_fd);
        return VMP_TRANSPORT_RESOURCE;
    }

    struct sockaddr_storage local;
    struct sockaddr_storage remote;
    socklen_t local_len = 0;
    socklen_t remote_len = 0;
    uint64_t netns_cookie = 0U;
    if (!helper_path_socket(backend, path, path_fd, &local, &local_len,
                            &remote, &remote_len, &netns_cookie)) {
        close(path_fd);
        return VMP_TRANSPORT_ENGINE;
    }

    mqvpn_path_desc_t descriptor;
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.struct_size = sizeof(descriptor);
    descriptor.fd = path_fd;
    if ((size_t)local_len > sizeof(descriptor.local_addr) ||
        (size_t)remote_len > sizeof(descriptor.remote_addr)) {
        close(path_fd);
        return VMP_TRANSPORT_INVALID;
    }
    memcpy(descriptor.local_addr, &local, (size_t)local_len);
    descriptor.local_addr_len = (uint32_t)local_len;
    memcpy(descriptor.remote_addr, &remote, (size_t)remote_len);
    descriptor.remote_addr_len = (uint32_t)remote_len;

    mqvpn_add_path_outcome_t outcome = MQVPN_ADD_PATH_PERMANENT_FAIL;
    const mqvpn_path_handle_t handle =
        mqvpn_client_add_path_fd_with_outcome(backend->client, path_fd,
                                              &descriptor, &outcome);
    const vmp_transport_error_t add_terminal =
        backend_terminal_error(backend);
    if (handle < 0 || outcome != MQVPN_ADD_PATH_OK ||
        add_terminal != VMP_TRANSPORT_OK) {
        if (handle >= 0) {
            (void)backend_retire_registered_path(
                backend, handle, &path_fd);
        } else {
            (void)close(path_fd);
            path_fd = -1;
        }
        const vmp_transport_error_t failed =
            backend_terminal_error(backend);
        return failed == VMP_TRANSPORT_OK ? VMP_TRANSPORT_ENGINE
                                          : failed;
    }

    if (!backend->connected) {
        const int connect_result = mqvpn_client_connect(backend->client);
        const vmp_transport_error_t connect_terminal =
            backend_terminal_error(backend);
        if (connect_result != MQVPN_OK ||
            connect_terminal != VMP_TRANSPORT_OK) {
            if (connect_result != MQVPN_OK) {
                backend_mark_terminal(backend,
                                      VMP_MQVPN_TERMINAL_ENGINE);
            }
            (void)backend_retire_registered_path(
                backend, handle, &path_fd);
            const vmp_transport_error_t failed =
                backend_terminal_error(backend);
            return failed == VMP_TRANSPORT_OK ? VMP_TRANSPORT_ENGINE
                                              : failed;
        }
        backend->connected = true;
    }

    if (!backend_sample_current(backend, NULL)) {
        (void)backend_retire_registered_path(
            backend, handle, &path_fd);
        return backend_terminal_error(backend);
    }

    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    slot->fd = path_fd;
    slot->handle = handle;
    slot->remote = remote;
    slot->remote_len = remote_len;
    if (!backend->have_netns_cookie) {
        backend->netns_cookie = netns_cookie;
        backend->have_netns_cookie = true;
    }
    *out_handle = handle;
    return VMP_TRANSPORT_OK;
}

static vmp_transport_error_t backend_remove_path(void *session, int64_t handle)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL || backend->client == NULL) {
        return VMP_TRANSPORT_INVALID;
    }
    const vmp_transport_error_t before = backend_terminal_error(backend);
    if (before != VMP_TRANSPORT_OK) return before;
    mqvpn_backend_path_t *path = backend_find_path(backend, handle);
    if (path == NULL) return VMP_TRANSPORT_INVALID;
    const mqvpn_path_handle_t retained_handle = path->handle;
    const vmp_transport_error_t retired =
        backend_retire_registered_path(backend, retained_handle, &path->fd);
    backend_zero(path, sizeof(*path));
    path->fd = -1;
    path->handle = -1;
    if (retired != VMP_TRANSPORT_OK) return retired;
    const vmp_transport_error_t terminal = backend_terminal_error(backend);
    if (terminal != VMP_TRANSPORT_OK) return terminal;
    if (!backend_sample_current(backend, NULL)) {
        return backend_terminal_error(backend);
    }
    return VMP_TRANSPORT_OK;
}

static vmp_transport_error_t backend_pump(void *session)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL || backend->client == NULL) {
        return VMP_TRANSPORT_ENGINE;
    }
    vmp_transport_error_t terminal = backend_terminal_error(backend);
    if (terminal != VMP_TRANSPORT_OK) return terminal;
    const int first_tick = mqvpn_client_tick(backend->client);
    if (!mqvpn_result_ok(first_tick)) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
    }
    terminal = backend_terminal_error(backend);
    if (terminal != VMP_TRANSPORT_OK) return terminal;

    uint8_t packet[VMP_OUTER_PACKET_CAPACITY];
    unsigned int budget = VMP_MAX_OUTER_READS_PER_PUMP;
    bool received_any = false;
    for (size_t index = 0; index < VMP_MAX_PATHS && budget > 0U; ++index) {
        mqvpn_backend_path_t *path = &backend->paths[index];
        if (!path->used || path->fd < 0) continue;
        while (budget > 0U) {
            --budget;
            struct sockaddr_storage peer;
            socklen_t peer_len = (socklen_t)sizeof(peer);
            const ssize_t received =
                recvfrom(path->fd, packet, sizeof(packet), MSG_DONTWAIT,
                         (struct sockaddr *)&peer, &peer_len);
            if (received < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                backend_mark_terminal(backend,
                                      VMP_MQVPN_TERMINAL_ENGINE);
                return VMP_TRANSPORT_ENGINE;
            }
            if (received == 0 ||
                !address_tuple_equal((const struct sockaddr *)&peer,
                                     (const struct sockaddr *)&path->remote)) {
                backend_mark_terminal(backend,
                                      VMP_MQVPN_TERMINAL_ENGINE);
                return VMP_TRANSPORT_ENGINE;
            }
            const int receive_result = mqvpn_client_on_socket_recv(
                backend->client, path->handle, packet, (size_t)received,
                (const struct sockaddr *)&peer, peer_len);
            if (!mqvpn_result_ok(receive_result)) {
                backend_mark_terminal(backend,
                                      VMP_MQVPN_TERMINAL_ENGINE);
            }
            terminal = backend_terminal_error(backend);
            if (terminal != VMP_TRANSPORT_OK) return terminal;
            received_any = true;
        }
    }
    if (received_any) {
        const int second_tick = mqvpn_client_tick(backend->client);
        if (!mqvpn_result_ok(second_tick)) {
            backend_mark_terminal(backend,
                                  VMP_MQVPN_TERMINAL_ENGINE);
        }
        terminal = backend_terminal_error(backend);
        if (terminal != VMP_TRANSPORT_OK) return terminal;
    }
    if (!backend_sample_current(backend, NULL)) {
        return backend_terminal_error(backend);
    }
    return backend_terminal_error(backend);
}

static bool normalize_path_state(mqvpn_path_status_t state,
                                 vmp_mqvpn_path_state_t *out)
{
    if (out == NULL) return false;
    switch (state) {
    case MQVPN_PATH_ACTIVE:
        *out = VMP_MQVPN_PATH_ACTIVE;
        return true;
    case MQVPN_PATH_STANDBY:
    case MQVPN_PATH_PENDING:
        *out = VMP_MQVPN_PATH_PENDING;
        return true;
    case MQVPN_PATH_DEGRADED:
        *out = VMP_MQVPN_PATH_DEGRADED;
        return true;
    case MQVPN_PATH_CLOSED:
        *out = VMP_MQVPN_PATH_CLOSED;
        return true;
    default:
        return false;
    }
}

static bool publish_path_state(vmp_mqvpn_path_state_t state,
                               vmp_transport_path_state_t *out)
{
    if (out == NULL) return false;
    switch (state) {
    case VMP_MQVPN_PATH_PENDING:
        *out = VMP_TRANSPORT_PATH_PENDING;
        return true;
    case VMP_MQVPN_PATH_ACTIVE:
        *out = VMP_TRANSPORT_PATH_ACTIVE;
        return true;
    case VMP_MQVPN_PATH_DEGRADED:
        *out = VMP_TRANSPORT_PATH_DEGRADED;
        return true;
    case VMP_MQVPN_PATH_CLOSED:
        *out = VMP_TRANSPORT_PATH_CLOSED;
        return true;
    default:
        return false;
    }
}

static vmp_transport_error_t backend_snapshot(
    void *session, vmp_transport_path_snapshot_t *out, size_t capacity,
    size_t *out_count, bool *out_tunnel_ready, bool *out_has_assignment,
    vmp_tunnel_assignment_t *out_assignment)
{
    mqvpn_backend_t *backend = session;
    if (out_count != NULL) *out_count = 0U;
    if (out_tunnel_ready != NULL) *out_tunnel_ready = false;
    if (out_has_assignment != NULL) *out_has_assignment = false;
    if (out_assignment != NULL) {
        memset(out_assignment, 0, sizeof(*out_assignment));
    }
    if (out != NULL && capacity <= VMP_MAX_PATHS) {
        memset(out, 0, capacity * sizeof(*out));
    }
    if (backend == NULL || out == NULL || out_count == NULL ||
        out_tunnel_ready == NULL || out_has_assignment == NULL ||
        out_assignment == NULL || capacity > VMP_MAX_PATHS ||
        backend->client == NULL) {
        return VMP_TRANSPORT_INVALID;
    }
    const vmp_transport_error_t terminal = backend_terminal_error(backend);
    if (terminal != VMP_TRANSPORT_OK) return terminal;
    const size_t expected_count = backend_path_count(backend);
    if (capacity < expected_count) return VMP_TRANSPORT_RESOURCE;

    mqvpn_path_info_t info[MQVPN_MAX_PATHS];
    memset(info, 0, sizeof(info));
    int info_count = 0;
    if (mqvpn_client_get_paths(backend->client, info, MQVPN_MAX_PATHS,
                               &info_count) != MQVPN_OK ||
        info_count < 0 || info_count > MQVPN_MAX_PATHS) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
        return VMP_TRANSPORT_ENGINE;
    }
    const uint64_t supported_metric_flags =
        (uint64_t)MQVPN_PATH_METRIC_SRTT |
        (uint64_t)MQVPN_PATH_METRIC_LOSS |
        (uint64_t)MQVPN_PATH_METRIC_CWND |
        (uint64_t)MQVPN_PATH_METRIC_INFLIGHT |
        (uint64_t)MQVPN_PATH_METRIC_ESTIMATED_RATE |
        (uint64_t)MQVPN_PATH_METRIC_ACKED_TRANSPORT;
    const uint64_t known_metric_flags =
        supported_metric_flags |
        (uint64_t)MQVPN_PATH_METRIC_XQUIC_STATE;

    vmp_mqvpn_path_record_t observed[VMP_MAX_PATHS];
    vmp_mqvpn_path_record_t projected[VMP_MAX_PATHS];
    int64_t expected_handles[VMP_MAX_PATHS];
    memset(observed, 0, sizeof(observed));
    memset(projected, 0, sizeof(projected));
    memset(expected_handles, 0, sizeof(expected_handles));
    for (int info_index = 0; info_index < info_count; ++info_index) {
        vmp_mqvpn_path_record_t *record = &observed[info_index];
        if (info[info_index].struct_size != sizeof(info[info_index]) ||
            (info[info_index].metrics_valid & ~known_metric_flags) != 0U ||
            !normalize_path_state(info[info_index].status,
                                  &record->state)) {
            backend_mark_terminal(backend,
                                  VMP_MQVPN_TERMINAL_ENGINE);
            return VMP_TRANSPORT_ENGINE;
        }
        record->handle = info[info_index].handle;
        record->metrics_valid =
            info[info_index].metrics_valid & supported_metric_flags;
        if ((record->metrics_valid &
             (uint64_t)MQVPN_PATH_METRIC_SRTT) != 0U) {
            record->smoothed_rtt_us = info[info_index].srtt_us;
        }
        if ((record->metrics_valid &
             (uint64_t)MQVPN_PATH_METRIC_LOSS) != 0U) {
            record->packets_lost = info[info_index].packets_lost;
        }
        if ((record->metrics_valid &
             (uint64_t)MQVPN_PATH_METRIC_CWND) != 0U) {
            record->congestion_window_bytes =
                info[info_index].congestion_window_bytes;
        }
        if ((record->metrics_valid &
             (uint64_t)MQVPN_PATH_METRIC_INFLIGHT) != 0U) {
            record->bytes_in_flight = info[info_index].bytes_in_flight;
        }
        if ((record->metrics_valid &
             (uint64_t)MQVPN_PATH_METRIC_ESTIMATED_RATE) != 0U) {
            record->estimated_rate_bytes_per_sec =
                info[info_index].estimated_rate_bytes_per_sec;
        }
        if ((record->metrics_valid &
             (uint64_t)MQVPN_PATH_METRIC_ACKED_TRANSPORT) != 0U) {
            record->acked_transport_bytes =
                info[info_index].acked_transport_bytes;
        }
    }

    size_t handle_count = 0U;
    for (size_t path_index = 0; path_index < VMP_MAX_PATHS; ++path_index) {
        const mqvpn_backend_path_t *path = &backend->paths[path_index];
        if (!path->used) continue;
        expected_handles[handle_count++] = path->handle;
    }
    size_t projected_count = 0U;
    if (handle_count != expected_count ||
        !vmp_mqvpn_backend_select_current_paths(
            expected_handles, expected_count, observed,
            (size_t)info_count, projected, VMP_MAX_PATHS,
            &projected_count) ||
        projected_count != expected_count ||
        !backend_sample_current(backend, NULL)) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
        return VMP_TRANSPORT_ENGINE;
    }

    vmp_tunnel_assignment_t assignment;
    memset(&assignment, 0, sizeof(assignment));
    bool tunnel_ready = false;
    bool has_assignment = false;
    if (!vmp_mqvpn_backend_state_snapshot(
            &backend->lifecycle, &tunnel_ready, &has_assignment,
            &assignment)) {
        backend_zero(&assignment, sizeof(assignment));
        return backend_terminal_error(backend);
    }

    vmp_transport_path_snapshot_t snapshots[VMP_MAX_PATHS];
    memset(snapshots, 0, sizeof(snapshots));
    for (size_t index = 0U; index < projected_count; ++index) {
        const vmp_mqvpn_path_record_t *record = &projected[index];
        vmp_transport_path_snapshot_t *snapshot = &snapshots[index];
        snapshot->handle = record->handle;
        if (!publish_path_state(record->state, &snapshot->state)) {
            backend_zero(&assignment, sizeof(assignment));
            backend_mark_terminal(backend,
                                  VMP_MQVPN_TERMINAL_ENGINE);
            return VMP_TRANSPORT_ENGINE;
        }
        snapshot->metrics_valid = record->metrics_valid;
        snapshot->smoothed_rtt_us = record->smoothed_rtt_us;
        snapshot->packets_lost = record->packets_lost;
        snapshot->congestion_window_bytes =
            record->congestion_window_bytes;
        snapshot->bytes_in_flight = record->bytes_in_flight;
        snapshot->estimated_rate_bytes_per_sec =
            record->estimated_rate_bytes_per_sec;
        snapshot->acked_transport_bytes =
            record->acked_transport_bytes;
    }

    memcpy(out, snapshots, projected_count * sizeof(*out));
    *out_count = projected_count;
    *out_tunnel_ready = tunnel_ready;
    *out_has_assignment = has_assignment;
    if (has_assignment) {
        memcpy(out_assignment, &assignment, sizeof(*out_assignment));
    }
    backend_zero(&assignment, sizeof(assignment));
    return VMP_TRANSPORT_OK;
}

static vmp_transport_error_t backend_send_inner(void *session,
                                                uint64_t masque_context_id,
                                                const uint8_t *packet,
                                                size_t packet_len)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL || backend->client == NULL || packet == NULL ||
        packet_len == 0U || packet_len > VMP_MAX_INNER_PACKET ||
        masque_context_id != backend->masque_context_id) {
        return VMP_TRANSPORT_INVALID;
    }
    const vmp_transport_error_t before = backend_terminal_error(backend);
    if (before != VMP_TRANSPORT_OK) return before;
    if (!backend_sample_current(backend, NULL)) {
        return backend_terminal_error(backend);
    }
    if (backend->state != MQVPN_STATE_ESTABLISHED ||
        backend->lifecycle.lifecycle != VMP_MQVPN_BACKEND_ACTIVE) {
        return VMP_TRANSPORT_INVALID;
    }
    if (!vmp_tunnel_assignment_packet_source_is_owned(
            &backend->lifecycle.assignment, packet, packet_len)) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
        return VMP_TRANSPORT_ENGINE;
    }
    const int result =
        mqvpn_client_on_tun_packet(backend->client, packet, packet_len);
    if (result != MQVPN_OK && result != MQVPN_ERR_AGAIN) {
        backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
    }
    const vmp_transport_error_t after = backend_terminal_error(backend);
    if (after != VMP_TRANSPORT_OK) return after;
    if (result == MQVPN_ERR_AGAIN) return VMP_TRANSPORT_RESOURCE;
    return VMP_TRANSPORT_OK;
}

static vmp_transport_error_t backend_receive_inner(
    void *session, uint64_t masque_context_id, uint8_t *out,
    size_t out_capacity, size_t *out_len)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL || out == NULL || out_len == NULL ||
        masque_context_id != backend->masque_context_id ||
        backend->client == NULL) {
        return VMP_TRANSPORT_INVALID;
    }
    *out_len = 0U;
    const vmp_transport_error_t terminal = backend_terminal_error(backend);
    if (terminal != VMP_TRANSPORT_OK) return terminal;
    if (!backend_sample_current(backend, NULL)) {
        return backend_terminal_error(backend);
    }
    switch (vmp_mqvpn_backend_state_dequeue_reverse(
        &backend->lifecycle, out, out_capacity, out_len)) {
    case VMP_MQVPN_RESULT_NONE:
        return VMP_TRANSPORT_OK;
    case VMP_MQVPN_RESULT_EMPTY:
        return VMP_TRANSPORT_EMPTY;
    case VMP_MQVPN_RESULT_RESOURCE:
        return VMP_TRANSPORT_RESOURCE;
    case VMP_MQVPN_RESULT_OVERFLOW:
        return VMP_TRANSPORT_OVERFLOW;
    case VMP_MQVPN_RESULT_ENGINE:
    default:
        return VMP_TRANSPORT_ENGINE;
    }
}

static void backend_destroy(void *session)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL) return;
    backend_mark_terminal(backend, VMP_MQVPN_TERMINAL_ENGINE);
    if (backend->client != NULL) {
        if (backend->connected) {
            (void)mqvpn_client_disconnect(backend->client);
        }
        mqvpn_client_destroy(backend->client);
        backend->client = NULL;
    }
    for (size_t index = 0; index < VMP_MAX_PATHS; ++index) {
        if (backend->paths[index].fd >= 0) {
            close(backend->paths[index].fd);
        }
    }
    backend_zero(backend, sizeof(*backend));
    free(backend);
}

const vmp_transport_ops_t *vmp_mqvpn_transport_ops(void)
{
    static const vmp_transport_ops_t operations = {
        .create = backend_create,
        .destroy = backend_destroy,
        .add_path = backend_add_path,
        .remove_path = backend_remove_path,
        .pump = backend_pump,
        .snapshot = backend_snapshot,
        .send_inner = backend_send_inner,
        .receive_inner = backend_receive_inner,
    };
    return &operations;
}
