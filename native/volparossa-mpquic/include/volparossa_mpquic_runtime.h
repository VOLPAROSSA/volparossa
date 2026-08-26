// SPDX-License-Identifier: GPL-3.0-only

#ifndef VOLPAROSSA_MPQUIC_RUNTIME_H
#define VOLPAROSSA_MPQUIC_RUNTIME_H

#include "volparossa_mpquic_server.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMP_MAX_SESSIONS 32U
#define VMP_MAX_AUTHORIZATION_RECORDS 128U

typedef enum vmp_runtime_mode {
    VMP_RUNTIME_CLIENT = 1,
    VMP_RUNTIME_EXIT = 2,
} vmp_runtime_mode_t;

typedef enum vmp_transport_error {
    VMP_TRANSPORT_OK = 0,
    VMP_TRANSPORT_INVALID,
    VMP_TRANSPORT_RESOURCE,
    VMP_TRANSPORT_ENGINE,
    VMP_TRANSPORT_EMPTY,
    VMP_TRANSPORT_OVERFLOW,
} vmp_transport_error_t;

typedef enum vmp_transport_path_state {
    VMP_TRANSPORT_PATH_PENDING = 0,
    VMP_TRANSPORT_PATH_ACTIVE,
    VMP_TRANSPORT_PATH_DEGRADED,
    VMP_TRANSPORT_PATH_CLOSED,
} vmp_transport_path_state_t;

typedef struct vmp_transport_create_params {
    uint8_t exit_spki_sha256[VMP_SPKI_SHA256_LEN];
    const uint8_t *auth_secret;
    size_t auth_secret_len;
    const char *tls_server_name;
    uint8_t remote_ip[16];
    uint8_t ip_len;
    uint16_t remote_port;
    uint64_t masque_context_id;
    vmp_transport_mode_t transport_mode;
} vmp_transport_create_params_t;

typedef struct vmp_transport_path_snapshot {
    int64_t handle;
    vmp_transport_path_state_t state;
    uint64_t metrics_valid;
    uint64_t smoothed_rtt_us;
    uint64_t packets_lost;
    uint64_t congestion_window_bytes;
    uint64_t bytes_in_flight;
    uint64_t estimated_rate_bytes_per_sec;
    uint64_t acked_transport_bytes;
} vmp_transport_path_snapshot_t;

typedef struct vmp_transport_ops {
    vmp_transport_error_t (*create)(
        void *factory_context, const vmp_transport_create_params_t *params,
        void **out_session);
    void (*destroy)(void *session);
    /* Consumes path_fd on every return path. It is a helper-created,
     * bound, nonblocking UDP socket in the committed route namespace. */
    vmp_transport_error_t (*add_path)(void *session,
                                      const vmp_add_path_t *path,
                                      int path_fd,
                                      int64_t *out_handle);
    vmp_transport_error_t (*remove_path)(void *session, int64_t handle);
    vmp_transport_error_t (*pump)(void *session);
    vmp_transport_error_t (*snapshot)(
        void *session, vmp_transport_path_snapshot_t *out, size_t capacity,
        size_t *out_count, bool *out_tunnel_ready,
        bool *out_has_assignment,
        vmp_tunnel_assignment_t *out_assignment);
    vmp_transport_error_t (*send_inner)(
        void *session, uint64_t masque_context_id, const uint8_t *packet,
        size_t packet_len);
    vmp_transport_error_t (*receive_inner)(
        void *session, uint64_t masque_context_id, uint8_t *out,
        size_t out_capacity, size_t *out_len);
} vmp_transport_ops_t;

typedef struct vmp_runtime vmp_runtime_t;

/* A snapshot implementation samples CLOCK_BOOTTIME first and CLOCK_REALTIME
 * second. The separate BOOTTIME reader is used after admission so a wall-clock
 * change can neither extend nor revive an authorization. */
typedef bool (*vmp_clock_snapshot_fn)(void *context,
                                      uint64_t *out_boottime_ms,
                                      uint64_t *out_realtime_ms);
typedef bool (*vmp_boottime_ms_fn)(void *context,
                                   uint64_t *out_boottime_ms);
typedef bool (*vmp_auth_commitment_fn)(
    void *context, const uint8_t *auth_secret, size_t auth_secret_len,
    uint8_t out[VMP_AUTH_COMMITMENT_LEN]);

/* Creates an empty role-specific runtime. Authentication and TLS names arrive
 * only in bounded START requests and are copied into their exact route session.
 * Both injected clocks are fallible and required for short-lived
 * authorization admission and expiry. */
vmp_runtime_t *vmp_runtime_create(vmp_runtime_mode_t mode,
                                  const uint8_t native_instance_id
                                      [VMP_NATIVE_INSTANCE_ID_LEN],
                                  const vmp_transport_ops_t *transport,
                                  void *factory_context,
                                  vmp_auth_commitment_fn auth_commitment,
                                  void *auth_commitment_context,
                                  vmp_clock_snapshot_fn clock_snapshot,
                                  vmp_boottime_ms_fn boottime_now,
                                  void *clock_context);

/* Destroys every native session and wipes all copied authentication,
 * reservation, pin, and route-context material. */
void vmp_runtime_destroy(vmp_runtime_t *runtime);

/* Drives all live engines once. A failure is retained on only the affected
 * session so subsequent requests receive a structured transport failure. */
vmp_server_error_t vmp_runtime_pump(void *runtime);

/* Dispatcher for vmp_serve_connection. START is idempotent: its first call
 * creates a pending context and returns INSUFFICIENT_PATHS. Repeating the
 * identical START succeeds only after the requested number of native paths
 * are ACTIVE and the MASQUE tunnel is ready. */
vmp_server_error_t vmp_runtime_dispatch(void *runtime,
                                        const vmp_request_t *request,
                                        vmp_response_t *response,
                                        int request_fd);

/* Production mqvpn/xquic adapter. */
const vmp_transport_ops_t *vmp_mqvpn_transport_ops(void);

#ifdef __cplusplus
}
#endif

#endif
