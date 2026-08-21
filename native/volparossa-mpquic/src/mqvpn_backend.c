// SPDX-License-Identifier: GPL-3.0-only

#define _GNU_SOURCE

#include "volparossa_mpquic_runtime.h"

#include "libmqvpn.h"

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
#define VMP_REVERSE_QUEUE_MAX_PACKETS 8U
#define VMP_REVERSE_QUEUE_MAX_BYTES (256U * 1024U)

typedef struct mqvpn_backend_path {
    bool used;
    int fd;
    mqvpn_path_handle_t handle;
    struct sockaddr_storage remote;
    socklen_t remote_len;
} mqvpn_backend_path_t;

typedef struct mqvpn_reverse_packet {
    uint8_t bytes[VMP_MAX_INNER_PACKET];
    size_t len;
} mqvpn_reverse_packet_t;

typedef struct mqvpn_backend {
    mqvpn_client_t *client;
    mqvpn_backend_path_t paths[VMP_MAX_PATHS];
    mqvpn_reverse_packet_t reverse_queue[VMP_REVERSE_QUEUE_MAX_PACKETS];
    size_t reverse_head;
    size_t reverse_tail;
    size_t reverse_count;
    size_t reverse_bytes;
    uint64_t masque_context_id;
    vmp_transport_mode_t transport_mode;
    uint64_t netns_cookie;
    bool have_netns_cookie;

    bool connected;
    bool tunnel_configured;
    bool reverse_overflow;
    bool fatal;
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

static void wipe_reverse_queue(mqvpn_backend_t *backend)
{
    backend_zero(backend->reverse_queue, sizeof(backend->reverse_queue));
    backend->reverse_head = 0U;
    backend->reverse_tail = 0U;
    backend->reverse_count = 0U;
    backend->reverse_bytes = 0U;
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
    if (packet == NULL || packet_len == 0U ||
        packet_len > VMP_MAX_INNER_PACKET) {
        wipe_reverse_queue(backend);
        backend->fatal = true;
        return;
    }
    if (backend->reverse_overflow) return;
    if (backend->reverse_count >= VMP_REVERSE_QUEUE_MAX_PACKETS ||
        packet_len > VMP_REVERSE_QUEUE_MAX_BYTES - backend->reverse_bytes) {
        wipe_reverse_queue(backend);
        backend->reverse_overflow = true;
        return;
    }

    mqvpn_reverse_packet_t *entry =
        &backend->reverse_queue[backend->reverse_tail];
    memcpy(entry->bytes, packet, packet_len);
    entry->len = packet_len;
    backend->reverse_tail =
        (backend->reverse_tail + 1U) % VMP_REVERSE_QUEUE_MAX_PACKETS;
    ++backend->reverse_count;
    backend->reverse_bytes += packet_len;
}

static void callback_tunnel_ready(const mqvpn_tunnel_info_t *info,
                                  void *user_context)
{
    mqvpn_backend_t *backend = user_context;
    if (backend == NULL || info == NULL ||
        info->struct_size != sizeof(*info) || backend->client == NULL ||
        mqvpn_client_set_tun_active(backend->client, 1, -1) != MQVPN_OK) {
        if (backend != NULL) backend->fatal = true;
        return;
    }
    backend->tunnel_configured = true;
}

static void callback_tunnel_closed(mqvpn_error_t reason, void *user_context)
{
    (void)reason;
    mqvpn_backend_t *backend = user_context;
    if (backend != NULL) backend->fatal = true;
}

static void callback_ready_for_tun(void *user_context)
{
    (void)user_context;
}

static void callback_state_changed(mqvpn_client_state_t old_state,
                                   mqvpn_client_state_t new_state,
                                   void *user_context)
{
    (void)old_state;
    mqvpn_backend_t *backend = user_context;
    if (backend == NULL) return;
    backend->state = new_state;
    if (new_state == MQVPN_STATE_CLOSED ||
        new_state == MQVPN_STATE_RECONNECTING) {
        backend->fatal = true;
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
    backend->state = mqvpn_client_get_state(backend->client);
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

static vmp_transport_error_t backend_add_path(void *session,
                                              const vmp_add_path_t *path,
                                              int path_fd,
                                              int64_t *out_handle)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL || path == NULL || out_handle == NULL ||
        path_fd < 0 || !vmp_add_path_is_valid(path) || backend->fatal ||
        backend->client == NULL) {
        if (path_fd >= 0) close(path_fd);
        return VMP_TRANSPORT_INVALID;
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
    if (handle < 0 || outcome != MQVPN_ADD_PATH_OK) {
        if (handle >= 0) {
            (void)mqvpn_client_remove_path(backend->client, handle);
        }
        close(path_fd);
        return VMP_TRANSPORT_ENGINE;
    }

    if (!backend->connected) {
        const int connect_result = mqvpn_client_connect(backend->client);
        if (connect_result != MQVPN_OK) {
            (void)mqvpn_client_remove_path(backend->client, handle);
            close(path_fd);
            return VMP_TRANSPORT_ENGINE;
        }
        backend->connected = true;
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
    mqvpn_backend_path_t *path = backend_find_path(backend, handle);
    if (path == NULL) return VMP_TRANSPORT_INVALID;
    if (mqvpn_client_remove_path(backend->client, path->handle) != MQVPN_OK) {
        return VMP_TRANSPORT_ENGINE;
    }
    if (path->fd >= 0) close(path->fd);
    backend_zero(path, sizeof(*path));
    path->fd = -1;
    path->handle = -1;
    return VMP_TRANSPORT_OK;
}

static vmp_transport_error_t backend_pump(void *session)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL || backend->client == NULL || backend->fatal) {
        return VMP_TRANSPORT_ENGINE;
    }
    if (!mqvpn_result_ok(mqvpn_client_tick(backend->client))) {
        return VMP_TRANSPORT_ENGINE;
    }

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
                return VMP_TRANSPORT_ENGINE;
            }
            if (received == 0 ||
                !address_tuple_equal((const struct sockaddr *)&peer,
                                     (const struct sockaddr *)&path->remote) ||
                !mqvpn_result_ok(mqvpn_client_on_socket_recv(
                    backend->client, path->handle, packet, (size_t)received,
                    (const struct sockaddr *)&peer, peer_len))) {
                return VMP_TRANSPORT_ENGINE;
            }
            received_any = true;
        }
    }
    if (received_any &&
        !mqvpn_result_ok(mqvpn_client_tick(backend->client))) {
        return VMP_TRANSPORT_ENGINE;
    }
    backend->state = mqvpn_client_get_state(backend->client);
    return backend->fatal ? VMP_TRANSPORT_ENGINE : VMP_TRANSPORT_OK;
}

static vmp_transport_path_state_t map_path_state(mqvpn_path_status_t state)
{
    switch (state) {
    case MQVPN_PATH_ACTIVE:
    case MQVPN_PATH_STANDBY:
        return state == MQVPN_PATH_ACTIVE ? VMP_TRANSPORT_PATH_ACTIVE
                                          : VMP_TRANSPORT_PATH_PENDING;
    case MQVPN_PATH_DEGRADED:
        return VMP_TRANSPORT_PATH_DEGRADED;
    case MQVPN_PATH_CLOSED:
        return VMP_TRANSPORT_PATH_CLOSED;
    case MQVPN_PATH_PENDING:
    default:
        return VMP_TRANSPORT_PATH_PENDING;
    }
}

static vmp_transport_error_t backend_snapshot(
    void *session, vmp_transport_path_snapshot_t *out, size_t capacity,
    size_t *out_count, bool *out_tunnel_ready)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL || out == NULL || out_count == NULL ||
        out_tunnel_ready == NULL || capacity > VMP_MAX_PATHS ||
        backend->client == NULL || backend->fatal) {
        return VMP_TRANSPORT_INVALID;
    }
    mqvpn_path_info_t info[MQVPN_MAX_PATHS];
    memset(info, 0, sizeof(info));
    int info_count = 0;
    if (mqvpn_client_get_paths(backend->client, info, MQVPN_MAX_PATHS,
                               &info_count) != MQVPN_OK ||
        info_count < 0 || info_count > MQVPN_MAX_PATHS) {
        return VMP_TRANSPORT_ENGINE;
    }

    size_t written = 0U;
    for (size_t path_index = 0; path_index < VMP_MAX_PATHS; ++path_index) {
        const mqvpn_backend_path_t *path = &backend->paths[path_index];
        if (!path->used) continue;
        if (written == capacity) return VMP_TRANSPORT_RESOURCE;
        const mqvpn_path_info_t *match = NULL;
        for (int info_index = 0; info_index < info_count; ++info_index) {
            if (info[info_index].handle == path->handle) {
                if (match != NULL) return VMP_TRANSPORT_ENGINE;
                match = &info[info_index];
            }
        }
        if (match == NULL) return VMP_TRANSPORT_ENGINE;
        vmp_transport_path_snapshot_t *snapshot = &out[written++];
        memset(snapshot, 0, sizeof(*snapshot));
        snapshot->handle = match->handle;
        snapshot->state = map_path_state(match->status);
        snapshot->metrics_valid = match->metrics_valid;
        snapshot->smoothed_rtt_us = match->srtt_us;
        snapshot->packets_lost = match->packets_lost;
        snapshot->congestion_window_bytes =
            match->congestion_window_bytes;
        snapshot->bytes_in_flight = match->bytes_in_flight;
        snapshot->estimated_rate_bytes_per_sec =
            match->estimated_rate_bytes_per_sec;
        snapshot->acked_transport_bytes = match->acked_transport_bytes;
    }
    backend->state = mqvpn_client_get_state(backend->client);
    *out_count = written;
    *out_tunnel_ready =
        backend->tunnel_configured &&
        backend->state == MQVPN_STATE_ESTABLISHED && !backend->fatal;
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
        masque_context_id != backend->masque_context_id || backend->fatal ||
        backend->state != MQVPN_STATE_ESTABLISHED) {
        return VMP_TRANSPORT_INVALID;
    }
    if (backend->reverse_overflow) return VMP_TRANSPORT_OVERFLOW;
    const int result =
        mqvpn_client_on_tun_packet(backend->client, packet, packet_len);
    if (result == MQVPN_ERR_AGAIN) return VMP_TRANSPORT_RESOURCE;
    return result == MQVPN_OK ? VMP_TRANSPORT_OK : VMP_TRANSPORT_ENGINE;
}

static vmp_transport_error_t backend_receive_inner(
    void *session, uint64_t masque_context_id, uint8_t *out,
    size_t out_capacity, size_t *out_len)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL || out == NULL || out_len == NULL ||
        masque_context_id != backend->masque_context_id ||
        backend->client == NULL || backend->fatal ||
        backend->state != MQVPN_STATE_ESTABLISHED) {
        return VMP_TRANSPORT_INVALID;
    }
    *out_len = 0U;
    if (backend->reverse_overflow) return VMP_TRANSPORT_OVERFLOW;
    if (backend->reverse_count == 0U) return VMP_TRANSPORT_EMPTY;

    mqvpn_reverse_packet_t *entry =
        &backend->reverse_queue[backend->reverse_head];
    if (entry->len == 0U || entry->len > VMP_MAX_INNER_PACKET) {
        wipe_reverse_queue(backend);
        backend->fatal = true;
        return VMP_TRANSPORT_ENGINE;
    }
    if (out_capacity < entry->len) return VMP_TRANSPORT_RESOURCE;

    const size_t packet_len = entry->len;
    memcpy(out, entry->bytes, packet_len);
    backend->reverse_bytes -= packet_len;
    backend_zero(entry, sizeof(*entry));
    backend->reverse_head =
        (backend->reverse_head + 1U) % VMP_REVERSE_QUEUE_MAX_PACKETS;
    --backend->reverse_count;
    *out_len = packet_len;
    return VMP_TRANSPORT_OK;
}

static void backend_destroy(void *session)
{
    mqvpn_backend_t *backend = session;
    if (backend == NULL) return;
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
