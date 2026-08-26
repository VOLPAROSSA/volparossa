// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2026 VOLPAROSSA contributors

#ifndef VOLPAROSSA_MPQUIC_PROTOCOL_H
#define VOLPAROSSA_MPQUIC_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMP_API_VERSION UINT32_C(6)
#define VMP_MAX_CONTROL_FRAME (UINT32_C(1024) * UINT32_C(1024))
#define VMP_CONTEXT_ID_LEN 16U
#define VMP_RESERVATION_ID_LEN 16U
#define VMP_FINALIZE_ID_LEN 16U
#define VMP_REQUEST_NONCE_LEN 16U
#define VMP_NATIVE_INSTANCE_ID_LEN 32U
#define VMP_REQUEST_SHA256_LEN 32U
#define VMP_AUTH_COMMITMENT_LEN 32U
#define VMP_CERTIFICATE_SHA256_LEN 32U
#define VMP_SPKI_SHA256_LEN 32U
#define VMP_RESERVATION_HASH_LEN 32U
#define VMP_FD_BINDING_LEN 32U
#define VMP_MAX_PATHS 8U
#define VMP_MAX_INNER_PACKET 65535U
#define VMP_MAX_DIAGNOSTIC_CODE 64U
#define VMP_AUTH_SECRET_LEN 43U
#define VMP_MAX_AUTH_SECRET VMP_AUTH_SECRET_LEN
#define VMP_MAX_TLS_SERVER_NAME 253U
#define VMP_MAX_TLS_CERTIFICATE_PEM (64U * 1024U)
#define VMP_MAX_TLS_PRIVATE_KEY_PEM (16U * 1024U)
#define VMP_MAX_AUTHORIZATION_FUTURE_MS UINT64_C(900000)
#define VMP_MAX_MASQUE_CONTEXT_ID ((UINT64_C(1) << 62) - UINT64_C(1))

typedef enum vmp_result {
    VMP_RESULT_OK = 0,
    VMP_RESULT_VERSION = 1,
    VMP_RESULT_INVALID_REQUEST = 2,
    VMP_RESULT_NOT_FOUND = 3,
    VMP_RESULT_UNAUTHORISED = 4,
    VMP_RESULT_TRANSPORT = 5,
    VMP_RESULT_INSUFFICIENT_PATHS = 6,
    VMP_RESULT_NO_DATAGRAM = 7,
    VMP_RESULT_QUEUE_OVERFLOW = 8,
    VMP_RESULT_STALE_INSTANCE = 9,
} vmp_result_t;

typedef enum vmp_operation {
    VMP_OPERATION_NONE = 0,
    VMP_OPERATION_START_SESSION = 10,
    VMP_OPERATION_ADD_PATH = 11,
    VMP_OPERATION_REMOVE_PATH = 12,
    VMP_OPERATION_SEND_DATAGRAM = 13,
    VMP_OPERATION_GET_STATUS = 14,
    VMP_OPERATION_STOP_SESSION = 15,
    VMP_OPERATION_RECEIVE_DATAGRAM = 16,
    VMP_OPERATION_START_EXIT_SESSION = 17,
    VMP_OPERATION_PREFLIGHT = 18,
} vmp_operation_t;

typedef enum vmp_native_role {
    VMP_NATIVE_ROLE_UNSPECIFIED = 0,
    VMP_NATIVE_ROLE_CLIENT = 1,
    VMP_NATIVE_ROLE_EXIT = 2,
} vmp_native_role_t;

typedef enum vmp_transport_mode {
    VMP_TRANSPORT_MODE_UNSPECIFIED = 0,
    VMP_TRANSPORT_MODE_MULTIPATH_QUIC = 1,
    VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP = 2,
} vmp_transport_mode_t;

typedef struct vmp_bytes_view {
    const uint8_t *data;
    size_t len;
} vmp_bytes_view_t;

typedef struct vmp_start_session {
    uint8_t route_context_id[VMP_CONTEXT_ID_LEN];
    uint8_t exit_spki_sha256[VMP_SPKI_SHA256_LEN];
    uint32_t minimum_paths;
    uint64_t masque_context_id;
    vmp_transport_mode_t transport_mode;
    vmp_bytes_view_t auth_secret;
    vmp_bytes_view_t tls_server_name;
    uint64_t expires_at_ms;
    uint8_t reservation_id[VMP_RESERVATION_ID_LEN];
    uint8_t finalize_id[VMP_FINALIZE_ID_LEN];
    uint8_t auth_commitment[VMP_AUTH_COMMITMENT_LEN];
    uint8_t certificate_sha256[VMP_CERTIFICATE_SHA256_LEN];
    uint8_t client_native_instance_id[VMP_NATIVE_INSTANCE_ID_LEN];
    uint8_t exit_native_instance_id[VMP_NATIVE_INSTANCE_ID_LEN];
} vmp_start_session_t;

typedef struct vmp_start_exit_session {
    uint8_t route_context_id[VMP_CONTEXT_ID_LEN];
    vmp_bytes_view_t auth_secret;
    uint64_t expires_at_ms;
    uint32_t minimum_paths;
    uint64_t masque_context_id;
    vmp_transport_mode_t transport_mode;
    uint8_t exit_spki_sha256[VMP_SPKI_SHA256_LEN];
    vmp_bytes_view_t tls_server_name;
    uint32_t path_id;
    uint8_t listener_ip[16];
    uint16_t listener_port;
    uint8_t expected_client_ip[16];
    uint16_t expected_client_port;
    uint8_t reservation_hash[VMP_RESERVATION_HASH_LEN];
    vmp_bytes_view_t tls_certificate_pem;
    vmp_bytes_view_t tls_private_key_pem;
    uint8_t reservation_id[VMP_RESERVATION_ID_LEN];
    uint8_t finalize_id[VMP_FINALIZE_ID_LEN];
    uint8_t auth_commitment[VMP_AUTH_COMMITMENT_LEN];
    uint8_t certificate_sha256[VMP_CERTIFICATE_SHA256_LEN];
    uint8_t client_native_instance_id[VMP_NATIVE_INSTANCE_ID_LEN];
    uint8_t exit_native_instance_id[VMP_NATIVE_INSTANCE_ID_LEN];
} vmp_start_exit_session_t;

typedef struct vmp_preflight {
    vmp_native_role_t expected_role;
} vmp_preflight_t;

typedef struct vmp_add_path {
    uint8_t route_context_id[VMP_CONTEXT_ID_LEN];
    uint32_t path_id;
    uint8_t local_ip[16];
    uint8_t remote_ip[16];
    uint8_t ip_len;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t reservation_hash[VMP_RESERVATION_HASH_LEN];
} vmp_add_path_t;

typedef struct vmp_remove_path {
    uint8_t route_context_id[VMP_CONTEXT_ID_LEN];
    uint32_t path_id;
} vmp_remove_path_t;

typedef struct vmp_send_datagram {
    uint8_t route_context_id[VMP_CONTEXT_ID_LEN];
    vmp_bytes_view_t inner_ip_packet;
    uint64_t masque_context_id;
} vmp_send_datagram_t;

typedef struct vmp_receive_datagram {
    uint8_t route_context_id[VMP_CONTEXT_ID_LEN];
    uint64_t masque_context_id;
} vmp_receive_datagram_t;

typedef struct vmp_context_request {
    uint8_t route_context_id[VMP_CONTEXT_ID_LEN];
} vmp_context_request_t;

typedef struct vmp_request {
    uint32_t api_version;
    uint8_t request_nonce[VMP_REQUEST_NONCE_LEN];
    uint8_t target_native_instance_id[VMP_NATIVE_INSTANCE_ID_LEN];
    vmp_operation_t operation;
    union {
        vmp_start_session_t start_session;
        vmp_add_path_t add_path;
        vmp_remove_path_t remove_path;
        vmp_send_datagram_t send_datagram;
        vmp_context_request_t get_status;
        vmp_context_request_t stop_session;
        vmp_receive_datagram_t receive_datagram;
        vmp_start_exit_session_t start_exit_session;
        vmp_preflight_t preflight;
    } body;
} vmp_request_t;

typedef struct vmp_path_status {
    uint32_t path_id;
    uint64_t smoothed_rtt_us;
    uint64_t packets_lost;
    uint64_t delivered_bytes;
    uint64_t congestion_window_bytes;
    uint64_t bytes_in_flight;
    uint64_t delivery_rate_bps;
    bool data_carrying;
} vmp_path_status_t;

typedef struct vmp_received_datagram {
    uint8_t route_context_id[VMP_CONTEXT_ID_LEN];
    uint64_t masque_context_id;
    uint8_t inner_ip_packet[VMP_MAX_INNER_PACKET];
    size_t inner_ip_packet_len;
} vmp_received_datagram_t;

typedef struct vmp_native_process_identity {
    vmp_native_role_t role;
    uint8_t native_instance_id[VMP_NATIVE_INSTANCE_ID_LEN];
} vmp_native_process_identity_t;

typedef struct vmp_tunnel_assignment {
    uint8_t assigned_ipv4[4];
    uint32_t assigned_prefix_v4;
    uint8_t server_ipv4[4];
    uint32_t server_prefix_v4;
    uint32_t mtu;
    bool has_ipv6;
    uint8_t assigned_ipv6[16];
    uint32_t assigned_prefix_v6;
} vmp_tunnel_assignment_t;

typedef struct vmp_response {
    uint32_t api_version;
    uint8_t request_nonce[VMP_REQUEST_NONCE_LEN];
    vmp_result_t result;
    const char *diagnostic_code;
    size_t diagnostic_code_len;
    vmp_path_status_t paths[VMP_MAX_PATHS];
    size_t path_count;
    bool has_received_datagram;
    vmp_received_datagram_t received_datagram;
    vmp_native_process_identity_t native_process_identity;
    uint8_t request_sha256[VMP_REQUEST_SHA256_LEN];
    bool has_tunnel_assignment;
    vmp_tunnel_assignment_t tunnel_assignment;
} vmp_response_t;

typedef enum vmp_protocol_error {
    VMP_PROTOCOL_OK = 0,
    VMP_PROTOCOL_TRUNCATED,
    VMP_PROTOCOL_VARINT,
    VMP_PROTOCOL_WIRE_TYPE,
    VMP_PROTOCOL_UNKNOWN_FIELD,
    VMP_PROTOCOL_DUPLICATE_FIELD,
    VMP_PROTOCOL_MISSING_FIELD,
    VMP_PROTOCOL_INVALID_VALUE,
    VMP_PROTOCOL_TOO_LARGE,
    VMP_PROTOCOL_OUTPUT_TOO_SMALL,
} vmp_protocol_error_t;

/* Verifies the complete fail-closed AddPath overlayshape: IPv6 only,
 * fd76:6f6c:7061::/48, path ID in segment six, one shared /112, and fixed
 * client/exit host identifiers 1 and 4. */
bool vmp_add_path_is_valid(const vmp_add_path_t *path);

/* Verifies the fail-closed API-v6 single-path exit request shape, including
 * its canonical overlay tuple and bounded in-memory TLS material. This does
 * not parse or cryptographically bind the certificate, key, name, and SPKI.
 * Credential validation proves only base64url syntax and exact length; its
 * generator remains responsible for entropy. */
bool vmp_start_exit_is_valid(const vmp_start_exit_session_t *start);

/* Validates the exact API-v6 mqvpn tunnel assignment shape. The current
 * pinned backend emits /32 IPv4 endpoints, an MTU in 1280..9000, and either
 * no IPv6 assignment or one non-zero /96../126 client address. Product pool
 * policy is deliberately a separate fail-closed activation prerequisite. */
bool vmp_tunnel_assignment_is_valid(
    const vmp_tunnel_assignment_t *assignment);

/* Decodes one unframed protobuf payload without allocating. Packet views in
 * the result borrow from `payload` and remain valid only while it remains
 * alive. Unknown and duplicate fields are rejected deliberately. */
vmp_protocol_error_t vmp_decode_request(const uint8_t *payload, size_t payload_len,
                                        vmp_request_t *out);

/* Encodes one NativeResponse-compatible protobuf payload. */
vmp_protocol_error_t vmp_encode_response_payload(const vmp_response_t *response,
                                                 uint8_t *out, size_t out_capacity,
                                                 size_t *out_len);

/* Prefixes an encoded response with the four-byte big-endian frame length
 * used by volparossa-quic. */
vmp_protocol_error_t vmp_encode_response_frame(const vmp_response_t *response,
                                               uint8_t *out, size_t out_capacity,
                                               size_t *out_len);

const char *vmp_protocol_error_string(vmp_protocol_error_t error);

#ifdef __cplusplus
}
#endif

#endif
