// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2026 VOLPAROSSA contributors

#include "volparossa_mpquic_protocol.h"

#include <limits.h>
#include <string.h>

typedef struct decoder {
    const uint8_t *cursor;
    const uint8_t *end;
    uint32_t last_field;
} decoder_t;

typedef struct encoder {
    uint8_t *cursor;
    uint8_t *end;
} encoder_t;

static vmp_protocol_error_t read_varint(decoder_t *decoder, uint64_t *value)
{
    uint64_t result = 0;
    for (unsigned shift = 0; shift < 70; shift += 7) {
        if (decoder->cursor == decoder->end) {
            return VMP_PROTOCOL_TRUNCATED;
        }
        const uint8_t byte = *decoder->cursor++;
        if (shift == 63 && (byte & UINT8_C(0xfe)) != 0) {
            return VMP_PROTOCOL_VARINT;
        }
        result |= (uint64_t)(byte & UINT8_C(0x7f)) << shift;
        if ((byte & UINT8_C(0x80)) == 0) {
            if (shift != 0U && byte == 0U) return VMP_PROTOCOL_VARINT;
            *value = result;
            return VMP_PROTOCOL_OK;
        }
    }
    return VMP_PROTOCOL_VARINT;
}

static vmp_protocol_error_t read_key(decoder_t *decoder, uint32_t *field,
                                     uint8_t *wire_type)
{
    uint64_t key = 0;
    vmp_protocol_error_t error = read_varint(decoder, &key);
    if (error != VMP_PROTOCOL_OK) {
        return error;
    }
    if ((key >> 3) == 0 || (key >> 3) > UINT32_MAX) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    *field = (uint32_t)(key >> 3);
    if (*field < decoder->last_field) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    decoder->last_field = *field;
    *wire_type = (uint8_t)(key & UINT64_C(7));
    return VMP_PROTOCOL_OK;
}

static vmp_protocol_error_t expect_varint(decoder_t *decoder, uint8_t wire_type,
                                          uint64_t *value)
{
    if (wire_type != 0) {
        return VMP_PROTOCOL_WIRE_TYPE;
    }
    return read_varint(decoder, value);
}

static vmp_protocol_error_t expect_bytes(decoder_t *decoder, uint8_t wire_type,
                                         vmp_bytes_view_t *view)
{
    uint64_t length = 0;
    if (wire_type != 2) {
        return VMP_PROTOCOL_WIRE_TYPE;
    }
    vmp_protocol_error_t error = read_varint(decoder, &length);
    if (error != VMP_PROTOCOL_OK) {
        return error;
    }
    const size_t remaining = (size_t)(decoder->end - decoder->cursor);
    if (length > remaining || length > SIZE_MAX) {
        return VMP_PROTOCOL_TRUNCATED;
    }
    view->data = decoder->cursor;
    view->len = (size_t)length;
    decoder->cursor += view->len;
    return VMP_PROTOCOL_OK;
}

static vmp_protocol_error_t copy_exact(vmp_bytes_view_t view, uint8_t *out,
                                       size_t expected)
{
    if (view.len != expected) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    memcpy(out, view.data, expected);
    return VMP_PROTOCOL_OK;
}

static bool all_zero(const uint8_t *bytes, size_t len)
{
    uint8_t combined = 0;
    for (size_t index = 0; index < len; ++index) {
        combined |= bytes[index];
    }
    return combined == 0;
}

bool vmp_add_path_is_valid(const vmp_add_path_t *path)
{
    static const uint8_t overlay_prefix[] = {
        UINT8_C(0xfd), UINT8_C(0x76), UINT8_C(0x6f),
        UINT8_C(0x6c), UINT8_C(0x70), UINT8_C(0x61),
    };
    if (path == NULL || path->ip_len != 16U || path->path_id == 0U ||
        path->path_id > VMP_MAX_PATHS || path->local_port == 0U ||
        path->remote_port == 0U ||
        all_zero(path->route_context_id, VMP_CONTEXT_ID_LEN) ||
        all_zero(path->reservation_hash, VMP_RESERVATION_HASH_LEN) ||
        memcmp(path->local_ip, overlay_prefix, sizeof(overlay_prefix)) != 0 ||
        memcmp(path->remote_ip, overlay_prefix, sizeof(overlay_prefix)) != 0 ||
        memcmp(path->local_ip, path->remote_ip, 14U) != 0) {
        return false;
    }
    const uint16_t embedded_path =
        ((uint16_t)path->local_ip[10] << 8U) | path->local_ip[11];
    const uint16_t local_host =
        ((uint16_t)path->local_ip[14] << 8U) | path->local_ip[15];
    const uint16_t remote_host =
        ((uint16_t)path->remote_ip[14] << 8U) | path->remote_ip[15];
    return embedded_path == path->path_id && local_host == UINT16_C(1) &&
           remote_host == UINT16_C(4);
}

static vmp_protocol_error_t parse_context_only(decoder_t decoder,
                                               vmp_context_request_t *out)
{
    bool have_context = false;
    while (decoder.cursor != decoder.end) {
        uint32_t field = 0;
        uint8_t wire_type = 0;
        vmp_protocol_error_t error = read_key(&decoder, &field, &wire_type);
        if (error != VMP_PROTOCOL_OK) {
            return error;
        }
        if (field != 1) {
            return VMP_PROTOCOL_UNKNOWN_FIELD;
        }
        if (have_context) {
            return VMP_PROTOCOL_DUPLICATE_FIELD;
        }
        vmp_bytes_view_t value = {0};
        error = expect_bytes(&decoder, wire_type, &value);
        if (error != VMP_PROTOCOL_OK) {
            return error;
        }
        error = copy_exact(value, out->route_context_id, VMP_CONTEXT_ID_LEN);
        if (error != VMP_PROTOCOL_OK) {
            return error;
        }
        have_context = true;
    }
    if (!have_context || all_zero(out->route_context_id, VMP_CONTEXT_ID_LEN)) {
        return VMP_PROTOCOL_MISSING_FIELD;
    }
    return VMP_PROTOCOL_OK;
}

static vmp_protocol_error_t parse_start(decoder_t decoder, vmp_start_session_t *out)
{
    unsigned seen = 0U;
    while (decoder.cursor != decoder.end) {
        uint32_t field = 0U;
        uint8_t wire_type = 0U;
        vmp_protocol_error_t error = read_key(&decoder, &field, &wire_type);
        if (error != VMP_PROTOCOL_OK) return error;
        if (field < 1U || field > 8U) return VMP_PROTOCOL_UNKNOWN_FIELD;
        const unsigned bit = 1U << (field - 1U);
        if ((seen & bit) != 0U) return VMP_PROTOCOL_DUPLICATE_FIELD;
        seen |= bit;

        if (field == 1U || field == 2U || field == 6U || field == 7U) {
            vmp_bytes_view_t value = {0};
            error = expect_bytes(&decoder, wire_type, &value);
            if (error != VMP_PROTOCOL_OK) return error;
            if (field == 1U) {
                error = copy_exact(value, out->route_context_id,
                                   VMP_CONTEXT_ID_LEN);
            } else if (field == 2U) {
                error = copy_exact(value, out->exit_spki_sha256,
                                   VMP_SPKI_SHA256_LEN);
            } else if (field == 6U) {
                out->auth_secret = value;
            } else {
                out->tls_server_name = value;
            }
            if (error != VMP_PROTOCOL_OK) return error;
        } else {
            uint64_t value = 0U;
            error = expect_varint(&decoder, wire_type, &value);
            if (error != VMP_PROTOCOL_OK) return error;
            if (field == 3U) {
                if (value > UINT32_MAX) return VMP_PROTOCOL_INVALID_VALUE;
                out->minimum_paths = (uint32_t)value;
            } else if (field == 4U) {
                out->masque_context_id = value;
            } else if (field == 5U) {
                if (value >
                    (uint64_t)VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP) {
                    return VMP_PROTOCOL_INVALID_VALUE;
                }
                out->transport_mode = (vmp_transport_mode_t)value;
            } else {
                out->expires_at_ms = value;
            }
        }
    }
    const bool valid_shape =
        (out->transport_mode == VMP_TRANSPORT_MODE_MULTIPATH_QUIC &&
         out->minimum_paths >= 2U &&
         out->minimum_paths <= VMP_MAX_PATHS) ||
        (out->transport_mode ==
             VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP &&
         out->minimum_paths == 1U);
    if (seen != UINT32_C(0xff) ||
        all_zero(out->route_context_id, VMP_CONTEXT_ID_LEN) ||
        all_zero(out->exit_spki_sha256, VMP_SPKI_SHA256_LEN) ||
        out->masque_context_id == 0U ||
        out->masque_context_id > VMP_MAX_MASQUE_CONTEXT_ID ||
        out->auth_secret.len == 0U ||
        out->auth_secret.len > VMP_MAX_AUTH_SECRET ||
        out->tls_server_name.len == 0U ||
        out->tls_server_name.len > VMP_MAX_TLS_SERVER_NAME ||
        out->expires_at_ms == 0U || !valid_shape) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    for (size_t index = 0U; index < out->auth_secret.len; ++index) {
        const uint8_t value = out->auth_secret.data[index];
        if (value == 0U || value == (uint8_t)'\n' ||
            value == (uint8_t)'\r') {
            return VMP_PROTOCOL_INVALID_VALUE;
        }
    }
    for (size_t index = 0U; index < out->tls_server_name.len; ++index) {
        const uint8_t value = out->tls_server_name.data[index];
        if (value < UINT8_C(0x21) || value > UINT8_C(0x7e)) {
            return VMP_PROTOCOL_INVALID_VALUE;
        }
    }
    return VMP_PROTOCOL_OK;
}

static vmp_protocol_error_t parse_add_path(decoder_t decoder, vmp_add_path_t *out)
{
    unsigned seen = 0;
    while (decoder.cursor != decoder.end) {
        uint32_t field = 0;
        uint8_t wire_type = 0;
        vmp_protocol_error_t error = read_key(&decoder, &field, &wire_type);
        if (error != VMP_PROTOCOL_OK) {
            return error;
        }
        if (field < 1 || field > 8 || field == 3) {
            return VMP_PROTOCOL_UNKNOWN_FIELD;
        }
        const unsigned bit = 1U << (field - 1U);
        if ((seen & bit) != 0) {
            return VMP_PROTOCOL_DUPLICATE_FIELD;
        }
        seen |= bit;
        if (field == 1 || field == 4 || field == 5 || field == 7) {
            vmp_bytes_view_t value = {0};
            error = expect_bytes(&decoder, wire_type, &value);
            if (error != VMP_PROTOCOL_OK) {
                return error;
            }
            if (field == 1) {
                error = copy_exact(value, out->route_context_id,
                                   VMP_CONTEXT_ID_LEN);
            } else if (field == 7) {
                error = copy_exact(value, out->reservation_hash,
                                   VMP_RESERVATION_HASH_LEN);
            } else {
                if (value.len != 4 && value.len != 16) {
                    return VMP_PROTOCOL_INVALID_VALUE;
                }
                if (out->ip_len != 0 && out->ip_len != value.len) {
                    return VMP_PROTOCOL_INVALID_VALUE;
                }
                out->ip_len = (uint8_t)value.len;
                memcpy(field == 4 ? out->local_ip : out->remote_ip, value.data,
                       value.len);
                error = VMP_PROTOCOL_OK;
            }
            if (error != VMP_PROTOCOL_OK) {
                return error;
            }
        } else {
            uint64_t value = 0;
            error = expect_varint(&decoder, wire_type, &value);
            if (error != VMP_PROTOCOL_OK || value > UINT32_MAX) {
                return error == VMP_PROTOCOL_OK ? VMP_PROTOCOL_INVALID_VALUE : error;
            }
            if (field == 2) {
                out->path_id = (uint32_t)value;
            } else {
                if (value > UINT16_MAX) {
                    return VMP_PROTOCOL_INVALID_VALUE;
                }
                if (field == 6) {
                    out->remote_port = (uint16_t)value;
                } else {
                    out->local_port = (uint16_t)value;
                }
            }
        }
    }
    if (seen != UINT32_C(0xfb) || !vmp_add_path_is_valid(out)) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    return VMP_PROTOCOL_OK;
}

static vmp_protocol_error_t parse_remove_path(decoder_t decoder,
                                              vmp_remove_path_t *out)
{
    unsigned seen = 0;
    while (decoder.cursor != decoder.end) {
        uint32_t field = 0;
        uint8_t wire_type = 0;
        vmp_protocol_error_t error = read_key(&decoder, &field, &wire_type);
        if (error != VMP_PROTOCOL_OK) {
            return error;
        }
        if (field < 1 || field > 2) {
            return VMP_PROTOCOL_UNKNOWN_FIELD;
        }
        const unsigned bit = 1U << (field - 1U);
        if ((seen & bit) != 0) {
            return VMP_PROTOCOL_DUPLICATE_FIELD;
        }
        seen |= bit;
        if (field == 1) {
            vmp_bytes_view_t value = {0};
            error = expect_bytes(&decoder, wire_type, &value);
            if (error == VMP_PROTOCOL_OK) {
                error = copy_exact(value, out->route_context_id,
                                   VMP_CONTEXT_ID_LEN);
            }
        } else {
            uint64_t value = 0;
            error = expect_varint(&decoder, wire_type, &value);
            if (error == VMP_PROTOCOL_OK) {
                if (value > UINT32_MAX) {
                    return VMP_PROTOCOL_INVALID_VALUE;
                }
                out->path_id = (uint32_t)value;
            }
        }
        if (error != VMP_PROTOCOL_OK) {
            return error;
        }
    }
    if (seen != UINT32_C(3) ||
        all_zero(out->route_context_id, VMP_CONTEXT_ID_LEN) ||
        out->path_id == 0 || out->path_id > VMP_MAX_PATHS) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    return VMP_PROTOCOL_OK;
}

static vmp_protocol_error_t validate_ip_packet(vmp_bytes_view_t packet)
{
    if (packet.len < 20 || packet.len > VMP_MAX_INNER_PACKET) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    const uint8_t version = packet.data[0] >> 4;
    if (version == 4) {
        const size_t header_len = (size_t)(packet.data[0] & UINT8_C(0x0f)) * 4U;
        if (header_len < 20 || header_len > packet.len) {
            return VMP_PROTOCOL_INVALID_VALUE;
        }
        const size_t total_len = ((size_t)packet.data[2] << 8) | packet.data[3];
        if (total_len != packet.len) {
            return VMP_PROTOCOL_INVALID_VALUE;
        }
    } else if (version == 6) {
        if (packet.len < 40) {
            return VMP_PROTOCOL_INVALID_VALUE;
        }
        const size_t payload_len = ((size_t)packet.data[4] << 8) | packet.data[5];
        if (payload_len == 0 || payload_len + 40U != packet.len) {
            return VMP_PROTOCOL_INVALID_VALUE;
        }
    } else {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    return VMP_PROTOCOL_OK;
}

static vmp_protocol_error_t parse_send_datagram(decoder_t decoder,
                                                vmp_send_datagram_t *out)
{
    unsigned seen = 0;
    while (decoder.cursor != decoder.end) {
        uint32_t field = 0;
        uint8_t wire_type = 0;
        vmp_protocol_error_t error = read_key(&decoder, &field, &wire_type);
        if (error != VMP_PROTOCOL_OK) {
            return error;
        }
        if (field < 1 || field > 3) {
            return VMP_PROTOCOL_UNKNOWN_FIELD;
        }
        const unsigned bit = 1U << (field - 1U);
        if ((seen & bit) != 0) {
            return VMP_PROTOCOL_DUPLICATE_FIELD;
        }
        seen |= bit;
        if (field == 1 || field == 2) {
            vmp_bytes_view_t value = {0};
            error = expect_bytes(&decoder, wire_type, &value);
            if (error != VMP_PROTOCOL_OK) {
                return error;
            }
            if (field == 1) {
                error = copy_exact(value, out->route_context_id,
                                   VMP_CONTEXT_ID_LEN);
                if (error != VMP_PROTOCOL_OK) {
                    return error;
                }
            } else {
                out->inner_ip_packet = value;
            }
        } else {
            error = expect_varint(&decoder, wire_type,
                                  &out->masque_context_id);
            if (error != VMP_PROTOCOL_OK) {
                return error;
            }
        }
    }
    if (seen != UINT32_C(7) ||
        all_zero(out->route_context_id, VMP_CONTEXT_ID_LEN) ||
        out->masque_context_id == 0U ||
        out->masque_context_id > VMP_MAX_MASQUE_CONTEXT_ID) {
        return VMP_PROTOCOL_MISSING_FIELD;
    }
    return validate_ip_packet(out->inner_ip_packet);
}

static vmp_protocol_error_t parse_receive_datagram(
    decoder_t decoder, vmp_receive_datagram_t *out)
{
    unsigned seen = 0U;
    while (decoder.cursor != decoder.end) {
        uint32_t field = 0U;
        uint8_t wire_type = 0U;
        vmp_protocol_error_t error = read_key(&decoder, &field, &wire_type);
        if (error != VMP_PROTOCOL_OK) {
            return error;
        }
        if (field < 1U || field > 2U) {
            return VMP_PROTOCOL_UNKNOWN_FIELD;
        }
        const unsigned bit = 1U << (field - 1U);
        if ((seen & bit) != 0U) {
            return VMP_PROTOCOL_DUPLICATE_FIELD;
        }
        seen |= bit;
        if (field == 1U) {
            vmp_bytes_view_t value = {0};
            error = expect_bytes(&decoder, wire_type, &value);
            if (error == VMP_PROTOCOL_OK) {
                error = copy_exact(value, out->route_context_id,
                                   VMP_CONTEXT_ID_LEN);
            }
        } else {
            error = expect_varint(&decoder, wire_type,
                                  &out->masque_context_id);
        }
        if (error != VMP_PROTOCOL_OK) {
            return error;
        }
    }
    if (seen != UINT32_C(3) ||
        all_zero(out->route_context_id, VMP_CONTEXT_ID_LEN) ||
        out->masque_context_id == 0U ||
        out->masque_context_id > VMP_MAX_MASQUE_CONTEXT_ID) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    return VMP_PROTOCOL_OK;
}

static vmp_protocol_error_t parse_start_exit(
    decoder_t decoder, vmp_start_exit_session_t *out)
{
    unsigned seen = 0U;
    while (decoder.cursor != decoder.end) {
        uint32_t field = 0U;
        uint8_t wire_type = 0U;
        vmp_protocol_error_t error = read_key(&decoder, &field, &wire_type);
        if (error != VMP_PROTOCOL_OK) return error;
        if (field < 1U || field > 6U) return VMP_PROTOCOL_UNKNOWN_FIELD;
        const unsigned bit = 1U << (field - 1U);
        if ((seen & bit) != 0U) return VMP_PROTOCOL_DUPLICATE_FIELD;
        seen |= bit;
        if (field == 1U || field == 2U) {
            vmp_bytes_view_t value = {0};
            error = expect_bytes(&decoder, wire_type, &value);
            if (error != VMP_PROTOCOL_OK) return error;
            if (field == 1U) {
                error = copy_exact(value, out->route_context_id,
                                   VMP_CONTEXT_ID_LEN);
                if (error != VMP_PROTOCOL_OK) return error;
            } else {
                out->auth_secret = value;
            }
        } else {
            uint64_t value = 0U;
            error = expect_varint(&decoder, wire_type, &value);
            if (error != VMP_PROTOCOL_OK) return error;
            if (field == 3U) {
                out->expires_at_ms = value;
            } else if (field == 4U) {
                if (value > UINT32_MAX) return VMP_PROTOCOL_INVALID_VALUE;
                out->minimum_paths = (uint32_t)value;
            } else if (field == 5U) {
                out->masque_context_id = value;
            } else {
                if (value >
                    (uint64_t)VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP) {
                    return VMP_PROTOCOL_INVALID_VALUE;
                }
                out->transport_mode = (vmp_transport_mode_t)value;
            }
        }
    }
    const bool valid_shape =
        (out->transport_mode == VMP_TRANSPORT_MODE_MULTIPATH_QUIC &&
         out->minimum_paths >= 2U &&
         out->minimum_paths <= VMP_MAX_PATHS) ||
        (out->transport_mode ==
             VMP_TRANSPORT_MODE_SINGLE_PATH_GENERAL_UDP &&
         out->minimum_paths == 1U);
    if (seen != UINT32_C(0x3f) ||
        all_zero(out->route_context_id, VMP_CONTEXT_ID_LEN) ||
        out->auth_secret.len == 0U ||
        out->auth_secret.len > VMP_MAX_AUTH_SECRET ||
        out->expires_at_ms == 0U || out->masque_context_id == 0U ||
        out->masque_context_id > VMP_MAX_MASQUE_CONTEXT_ID ||
        !valid_shape) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    for (size_t index = 0U; index < out->auth_secret.len; ++index) {
        const uint8_t value = out->auth_secret.data[index];
        if (value == 0U || value == UINT8_C(10) || value == UINT8_C(13)) {
            return VMP_PROTOCOL_INVALID_VALUE;
        }
    }
    return VMP_PROTOCOL_OK;
}

static vmp_protocol_error_t parse_operation(vmp_operation_t operation,
                                            vmp_bytes_view_t value,
                                            vmp_request_t *out)
{
    decoder_t nested = {.cursor = value.data, .end = value.data + value.len};
    switch (operation) {
    case VMP_OPERATION_START_SESSION:
        return parse_start(nested, &out->body.start_session);
    case VMP_OPERATION_ADD_PATH:
        return parse_add_path(nested, &out->body.add_path);
    case VMP_OPERATION_REMOVE_PATH:
        return parse_remove_path(nested, &out->body.remove_path);
    case VMP_OPERATION_SEND_DATAGRAM:
        return parse_send_datagram(nested, &out->body.send_datagram);
    case VMP_OPERATION_GET_STATUS:
        return parse_context_only(nested, &out->body.get_status);
    case VMP_OPERATION_STOP_SESSION:
        return parse_context_only(nested, &out->body.stop_session);
    case VMP_OPERATION_RECEIVE_DATAGRAM:
        return parse_receive_datagram(nested,
                                      &out->body.receive_datagram);
    case VMP_OPERATION_START_EXIT_SESSION:
        return parse_start_exit(nested,
                                &out->body.start_exit_session);
    case VMP_OPERATION_NONE:
    default: return VMP_PROTOCOL_INVALID_VALUE;
    }
}

vmp_protocol_error_t vmp_decode_request(const uint8_t *payload, size_t payload_len,
                                        vmp_request_t *out)
{
    if (payload == NULL || out == NULL) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    if (payload_len == 0) {
        return VMP_PROTOCOL_TRUNCATED;
    }
    if (payload_len > VMP_MAX_CONTROL_FRAME) {
        return VMP_PROTOCOL_TOO_LARGE;
    }
    memset(out, 0, sizeof(*out));
    decoder_t decoder = {.cursor = payload, .end = payload + payload_len};
    bool have_version = false;
    bool have_nonce = false;
    bool have_operation = false;

    while (decoder.cursor != decoder.end) {
        uint32_t field = 0;
        uint8_t wire_type = 0;
        vmp_protocol_error_t error = read_key(&decoder, &field, &wire_type);
        if (error != VMP_PROTOCOL_OK) {
            return error;
        }
        if (field == 1) {
            if (have_version) {
                return VMP_PROTOCOL_DUPLICATE_FIELD;
            }
            uint64_t value = 0;
            error = expect_varint(&decoder, wire_type, &value);
            if (error != VMP_PROTOCOL_OK || value > UINT32_MAX) {
                return error == VMP_PROTOCOL_OK ? VMP_PROTOCOL_INVALID_VALUE : error;
            }
            out->api_version = (uint32_t)value;
            have_version = true;
        } else if (field == 2) {
            if (have_nonce) {
                return VMP_PROTOCOL_DUPLICATE_FIELD;
            }
            vmp_bytes_view_t value = {0};
            error = expect_bytes(&decoder, wire_type, &value);
            if (error == VMP_PROTOCOL_OK) {
                error = copy_exact(value, out->request_nonce,
                                   VMP_REQUEST_NONCE_LEN);
            }
            if (error != VMP_PROTOCOL_OK) {
                return error;
            }
            have_nonce = true;
        } else if (field >= VMP_OPERATION_START_SESSION &&
                   field <= VMP_OPERATION_START_EXIT_SESSION) {
            if (have_operation) {
                return VMP_PROTOCOL_DUPLICATE_FIELD;
            }
            vmp_bytes_view_t value = {0};
            error = expect_bytes(&decoder, wire_type, &value);
            if (error != VMP_PROTOCOL_OK) {
                return error;
            }
            out->operation = (vmp_operation_t)field;
            error = parse_operation(out->operation, value, out);
            if (error != VMP_PROTOCOL_OK) {
                return error;
            }
            have_operation = true;
        } else {
            return VMP_PROTOCOL_UNKNOWN_FIELD;
        }
    }

    if (!have_version || !have_nonce || !have_operation) {
        return VMP_PROTOCOL_MISSING_FIELD;
    }
    if (out->api_version != VMP_API_VERSION ||
        all_zero(out->request_nonce, VMP_REQUEST_NONCE_LEN)) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    return VMP_PROTOCOL_OK;
}

static size_t varint_len(uint64_t value)
{
    size_t len = 1;
    while (value >= UINT64_C(0x80)) {
        value >>= 7;
        ++len;
    }
    return len;
}

static vmp_protocol_error_t write_bytes(encoder_t *encoder, const uint8_t *bytes,
                                        size_t len)
{
    if ((size_t)(encoder->end - encoder->cursor) < len) {
        return VMP_PROTOCOL_OUTPUT_TOO_SMALL;
    }
    memcpy(encoder->cursor, bytes, len);
    encoder->cursor += len;
    return VMP_PROTOCOL_OK;
}

static vmp_protocol_error_t write_varint(encoder_t *encoder, uint64_t value)
{
    uint8_t encoded[10];
    size_t len = 0;
    do {
        uint8_t byte = (uint8_t)(value & UINT64_C(0x7f));
        value >>= 7;
        if (value != 0) {
            byte |= UINT8_C(0x80);
        }
        encoded[len++] = byte;
    } while (value != 0);
    return write_bytes(encoder, encoded, len);
}

static vmp_protocol_error_t write_key(encoder_t *encoder, uint32_t field,
                                      uint8_t wire_type)
{
    return write_varint(encoder, ((uint64_t)field << 3) | wire_type);
}

static vmp_protocol_error_t write_varint_field(encoder_t *encoder, uint32_t field,
                                               uint64_t value)
{
    vmp_protocol_error_t error = write_key(encoder, field, 0);
    return error == VMP_PROTOCOL_OK ? write_varint(encoder, value) : error;
}

static vmp_protocol_error_t write_len_field(encoder_t *encoder, uint32_t field,
                                            const uint8_t *value, size_t len)
{
    vmp_protocol_error_t error = write_key(encoder, field, 2);
    if (error == VMP_PROTOCOL_OK) {
        error = write_varint(encoder, len);
    }
    return error == VMP_PROTOCOL_OK ? write_bytes(encoder, value, len) : error;
}

static size_t encoded_path_len(const vmp_path_status_t *path)
{
    size_t len = 1 + varint_len(path->path_id);
    if (path->smoothed_rtt_us != 0) len += 1 + varint_len(path->smoothed_rtt_us);
    if (path->packets_lost != 0) len += 1 + varint_len(path->packets_lost);
    if (path->delivered_bytes != 0) len += 1 + varint_len(path->delivered_bytes);
    if (path->congestion_window_bytes != 0)
        len += 1 + varint_len(path->congestion_window_bytes);
    if (path->bytes_in_flight != 0) len += 1 + varint_len(path->bytes_in_flight);
    if (path->delivery_rate_bps != 0) len += 1 + varint_len(path->delivery_rate_bps);
    if (path->data_carrying) len += 2;
    return len;
}

static vmp_protocol_error_t write_path(encoder_t *encoder,
                                       const vmp_path_status_t *path)
{
    const size_t nested_len = encoded_path_len(path);
    vmp_protocol_error_t error = write_key(encoder, 5, 2);
    if (error == VMP_PROTOCOL_OK) error = write_varint(encoder, nested_len);
    if (error == VMP_PROTOCOL_OK) error = write_varint_field(encoder, 1, path->path_id);
    if (error == VMP_PROTOCOL_OK && path->smoothed_rtt_us != 0)
        error = write_varint_field(encoder, 2, path->smoothed_rtt_us);
    if (error == VMP_PROTOCOL_OK && path->packets_lost != 0)
        error = write_varint_field(encoder, 3, path->packets_lost);
    if (error == VMP_PROTOCOL_OK && path->delivered_bytes != 0)
        error = write_varint_field(encoder, 4, path->delivered_bytes);
    if (error == VMP_PROTOCOL_OK && path->congestion_window_bytes != 0)
        error = write_varint_field(encoder, 5, path->congestion_window_bytes);
    if (error == VMP_PROTOCOL_OK && path->bytes_in_flight != 0)
        error = write_varint_field(encoder, 6, path->bytes_in_flight);
    if (error == VMP_PROTOCOL_OK && path->delivery_rate_bps != 0)
        error = write_varint_field(encoder, 7, path->delivery_rate_bps);
    if (error == VMP_PROTOCOL_OK && path->data_carrying)
        error = write_varint_field(encoder, 8, 1);
    return error;
}

static size_t encoded_received_datagram_len(
    const vmp_received_datagram_t *datagram)
{
    return 1U + varint_len(VMP_CONTEXT_ID_LEN) + VMP_CONTEXT_ID_LEN +
           1U + varint_len(datagram->masque_context_id) +
           1U + varint_len(datagram->inner_ip_packet_len) +
           datagram->inner_ip_packet_len;
}

static vmp_protocol_error_t write_received_datagram(
    encoder_t *encoder, const vmp_received_datagram_t *datagram)
{
    const size_t nested_len = encoded_received_datagram_len(datagram);
    vmp_protocol_error_t error = write_key(encoder, 6U, 2U);
    if (error == VMP_PROTOCOL_OK) error = write_varint(encoder, nested_len);
    if (error == VMP_PROTOCOL_OK)
        error = write_len_field(encoder, 1U, datagram->route_context_id,
                                VMP_CONTEXT_ID_LEN);
    if (error == VMP_PROTOCOL_OK)
        error = write_varint_field(encoder, 2U,
                                   datagram->masque_context_id);
    if (error == VMP_PROTOCOL_OK)
        error = write_len_field(encoder, 3U, datagram->inner_ip_packet,
                                datagram->inner_ip_packet_len);
    return error;
}

static bool diagnostic_valid(const vmp_response_t *response)
{
    if (response->diagnostic_code_len == 0) {
        return true;
    }
    if (response->diagnostic_code == NULL ||
        response->diagnostic_code_len > VMP_MAX_DIAGNOSTIC_CODE) {
        return false;
    }
    for (size_t index = 0; index < response->diagnostic_code_len; ++index) {
        const unsigned char byte = (unsigned char)response->diagnostic_code[index];
        const bool valid = (byte >= 'a' && byte <= 'z') ||
                           (byte >= 'A' && byte <= 'Z') ||
                           (byte >= '0' && byte <= '9') || byte == '_' || byte == '-';
        if (!valid) {
            return false;
        }
    }
    return true;
}

vmp_protocol_error_t vmp_encode_response_payload(const vmp_response_t *response,
                                                 uint8_t *out, size_t out_capacity,
                                                 size_t *out_len)
{
    if (response == NULL || out == NULL || out_len == NULL ||
        response->api_version != VMP_API_VERSION ||
        all_zero(response->request_nonce, VMP_REQUEST_NONCE_LEN) ||
        response->result < VMP_RESULT_OK ||
        response->result > VMP_RESULT_QUEUE_OVERFLOW ||
        response->path_count > VMP_MAX_PATHS || !diagnostic_valid(response)) {
        return VMP_PROTOCOL_INVALID_VALUE;
    }
    if (response->has_received_datagram) {
        const vmp_received_datagram_t *datagram =
            &response->received_datagram;
        const vmp_bytes_view_t packet = {
            .data = datagram->inner_ip_packet,
            .len = datagram->inner_ip_packet_len,
        };
        if (response->result != VMP_RESULT_OK || response->path_count != 0U ||
            all_zero(datagram->route_context_id, VMP_CONTEXT_ID_LEN) ||
            datagram->masque_context_id == 0U ||
            datagram->masque_context_id > VMP_MAX_MASQUE_CONTEXT_ID ||
            validate_ip_packet(packet) != VMP_PROTOCOL_OK) {
            return VMP_PROTOCOL_INVALID_VALUE;
        }
    }

    encoder_t encoder = {.cursor = out, .end = out + out_capacity};
    vmp_protocol_error_t error = write_varint_field(&encoder, 1, VMP_API_VERSION);
    if (error == VMP_PROTOCOL_OK)
        error = write_len_field(&encoder, 2, response->request_nonce,
                                VMP_REQUEST_NONCE_LEN);
    if (error == VMP_PROTOCOL_OK && response->result != VMP_RESULT_OK)
        error = write_varint_field(&encoder, 3, (uint64_t)response->result);
    if (error == VMP_PROTOCOL_OK && response->diagnostic_code_len != 0)
        error = write_len_field(&encoder, 4,
                                (const uint8_t *)response->diagnostic_code,
                                response->diagnostic_code_len);
    uint16_t seen_path_ids = 0;
    for (size_t index = 0; error == VMP_PROTOCOL_OK && index < response->path_count;
         ++index) {
        const uint32_t path_id = response->paths[index].path_id;
        if (path_id == 0 || path_id > VMP_MAX_PATHS) {
            return VMP_PROTOCOL_INVALID_VALUE;
        }
        const uint16_t path_bit =
            (uint16_t)(UINT16_C(1) << (path_id - UINT32_C(1)));
        if ((seen_path_ids & path_bit) != 0) {
            return VMP_PROTOCOL_INVALID_VALUE;
        }
        seen_path_ids |= path_bit;
        error = write_path(&encoder, &response->paths[index]);
    }
    if (error == VMP_PROTOCOL_OK && response->has_received_datagram) {
        error = write_received_datagram(&encoder, &response->received_datagram);
    }
    if (error != VMP_PROTOCOL_OK) {
        return error;
    }
    *out_len = (size_t)(encoder.cursor - out);
    return *out_len <= VMP_MAX_CONTROL_FRAME ? VMP_PROTOCOL_OK
                                             : VMP_PROTOCOL_TOO_LARGE;
}

vmp_protocol_error_t vmp_encode_response_frame(const vmp_response_t *response,
                                               uint8_t *out, size_t out_capacity,
                                               size_t *out_len)
{
    if (out == NULL || out_len == NULL || out_capacity < 4) {
        return VMP_PROTOCOL_OUTPUT_TOO_SMALL;
    }
    size_t payload_len = 0;
    vmp_protocol_error_t error = vmp_encode_response_payload(
        response, out + 4, out_capacity - 4, &payload_len);
    if (error != VMP_PROTOCOL_OK) {
        return error;
    }
    if (payload_len == 0 || payload_len > UINT32_MAX) {
        return VMP_PROTOCOL_TOO_LARGE;
    }
    const uint32_t length = (uint32_t)payload_len;
    out[0] = (uint8_t)(length >> 24);
    out[1] = (uint8_t)(length >> 16);
    out[2] = (uint8_t)(length >> 8);
    out[3] = (uint8_t)length;
    *out_len = payload_len + 4;
    return VMP_PROTOCOL_OK;
}

const char *vmp_protocol_error_string(vmp_protocol_error_t error)
{
    switch (error) {
    case VMP_PROTOCOL_OK: return "ok";
    case VMP_PROTOCOL_TRUNCATED: return "truncated";
    case VMP_PROTOCOL_VARINT: return "invalid_varint";
    case VMP_PROTOCOL_WIRE_TYPE: return "wrong_wire_type";
    case VMP_PROTOCOL_UNKNOWN_FIELD: return "unknown_field";
    case VMP_PROTOCOL_DUPLICATE_FIELD: return "duplicate_field";
    case VMP_PROTOCOL_MISSING_FIELD: return "missing_field";
    case VMP_PROTOCOL_INVALID_VALUE: return "invalid_value";
    case VMP_PROTOCOL_TOO_LARGE: return "too_large";
    case VMP_PROTOCOL_OUTPUT_TOO_SMALL: return "output_too_small";
    default: return "unknown_error";
    }
}
