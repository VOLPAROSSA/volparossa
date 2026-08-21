// SPDX-License-Identifier: GPL-3.0-only

#ifndef VOLPAROSSA_MPQUIC_SERVER_H
#define VOLPAROSSA_MPQUIC_SERVER_H

#include "volparossa_mpquic_protocol.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMP_MAX_REQUESTS_PER_CONNECTION UINT32_C(1)
#define VMP_MAX_AUTH_SECRET 255U

typedef enum vmp_server_error {
    VMP_SERVER_OK = 0,
    VMP_SERVER_IO,
    VMP_SERVER_TIMEOUT,
    VMP_SERVER_PEER_REJECTED,
    VMP_SERVER_PROTOCOL,
    VMP_SERVER_BACKEND,
    VMP_SERVER_LIMIT,
} vmp_server_error_t;

typedef vmp_server_error_t (*vmp_pump_fn)(void *context);

/* The server pre-populates version and echoed nonce. The dispatcher owns only
 * result, diagnostic_code, and paths. request_fd is exactly one descriptor
 * for ADD_PATH and -1 for every other operation. The dispatcher consumes
 * request_fd on every success and error path and must not retain borrowed
 * packet views after returning. */
typedef vmp_server_error_t (*vmp_dispatch_fn)(void *context,
                                              const vmp_request_t *request,
                                              vmp_response_t *response,
                                              int request_fd);

/* Computes SHA-256 over the fixed API-v4 AddPath domain, a four-byte
 * big-endian payload length, and the canonical unframed NativeRequest. */
typedef bool (*vmp_request_binding_fn)(
    void *context, const uint8_t *canonical_request,
    size_t canonical_request_len, uint8_t out[VMP_FD_BINDING_LEN]);

typedef struct vmp_server_options {
    uid_t expected_peer_uid;
    uint32_t frame_timeout_ms;
    uint32_t max_requests;
    vmp_request_binding_fn request_binding;
    void *request_binding_context;
    uint32_t pump_interval_ms;
    vmp_pump_fn pump;
    void *pump_context;
} vmp_server_options_t;

/* Serves exactly one request on a connected AF_UNIX SOCK_STREAM socket.
 * Linux SO_PEERCRED must match expected_peer_uid. Before the framed request,
 * exactly one 32-byte recvmsg record binds its ancillary state. ADD_PATH
 * requires one descriptor and the SHA-256 binding; every other operation
 * requires the all-zero binding and zero descriptors. The peer must
 * half-close after that one request. */
vmp_server_error_t vmp_serve_connection(int connection_fd,
                                        const vmp_server_options_t *options,
                                        vmp_dispatch_fn dispatch,
                                        void *dispatch_context);

/* Accepts one connection from a pre-opened AF_UNIX listening socket. Socket
 * creation/path ownership is intentionally outside this unprivileged API. */
vmp_server_error_t vmp_accept_one(int listening_fd,
                                  const vmp_server_options_t *options,
                                  vmp_dispatch_fn dispatch,
                                  void *dispatch_context);

/* Reads an opaque process credential from an already-open descriptor. The
 * credential must have no NUL/newline bytes and EOF must occur within 255
 * bytes. No file path enters this boundary. The output length is reset and
 * the usable output region is wiped before every read. */
vmp_server_error_t vmp_read_auth_secret(int secret_fd, uint8_t *out,
                                        size_t out_capacity, size_t *out_len);

void vmp_wipe_secret(void *secret, size_t len);

const char *vmp_server_error_string(vmp_server_error_t error);

#ifdef __cplusplus
}
#endif

#endif
