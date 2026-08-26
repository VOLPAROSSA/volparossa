// SPDX-License-Identifier: GPL-3.0-only

#define _GNU_SOURCE

#include "volparossa_mpquic_server.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define VMP_RESPONSE_FRAME_CAPACITY \
    (VMP_MAX_INNER_PACKET + 1024U)

typedef enum io_result {
    IO_OK = 0,
    IO_EOF,
    IO_ERROR,
    IO_TIMEOUT,
    IO_BACKEND,
    IO_PROTOCOL,
} io_result_t;

typedef struct received_descriptors {
    int values[2];
    size_t count;
} received_descriptors_t;

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

static void close_descriptors(received_descriptors_t *descriptors)
{
    if (descriptors == NULL) return;
    for (size_t index = 0U; index < descriptors->count; ++index) {
        if (descriptors->values[index] >= 0) {
            (void)close(descriptors->values[index]);
        }
    }
    memset(descriptors, 0, sizeof(*descriptors));
}

static bool monotonic_ms(uint64_t *out)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return false;
    }
    *out = (uint64_t)now.tv_sec * UINT64_C(1000) +
           (uint64_t)now.tv_nsec / UINT64_C(1000000);
    return true;
}

static int remaining_timeout(uint64_t deadline_ms)
{
    uint64_t now = 0;
    if (!monotonic_ms(&now) || now >= deadline_ms) {
        return 0;
    }
    const uint64_t remaining = deadline_ms - now;
    return remaining > (uint64_t)INT32_MAX ? INT32_MAX : (int)remaining;
}

static io_result_t wait_fd(int fd, short events, uint64_t deadline_ms,
                           bool deadline_enabled,
                           const vmp_server_options_t *options)
{
    for (;;) {
        struct pollfd descriptor = {.fd = fd, .events = events, .revents = 0};
        int timeout = deadline_enabled ? remaining_timeout(deadline_ms) : INT32_MAX;
        if (deadline_enabled && timeout == 0) {
            return IO_TIMEOUT;
        }
        if (options->pump != NULL && timeout > (int)options->pump_interval_ms) {
            timeout = (int)options->pump_interval_ms;
        }
        const int ready = poll(&descriptor, 1, timeout);
        if (ready > 0) {
            if ((descriptor.revents & events) != 0) return IO_OK;
            if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0) return IO_ERROR;
            if ((descriptor.revents & POLLHUP) != 0) return IO_EOF;
            continue;
        }
        if (ready == 0) {
            if (options->pump == NULL) return IO_TIMEOUT;
            if (options->pump(options->pump_context) != VMP_SERVER_OK) {
                return IO_BACKEND;
            }
            continue;
        }
        if (errno != EINTR) return IO_ERROR;
    }
}

static io_result_t receive_once(
    int fd, uint8_t *buffer, size_t capacity, bool allow_descriptors,
    received_descriptors_t *descriptors, size_t *out_received)
{
    if (buffer == NULL || capacity == 0U || descriptors == NULL ||
        out_received == NULL) {
        return IO_ERROR;
    }
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(2U * sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));
    struct iovec vector = {.iov_base = buffer, .iov_len = capacity};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);

    const ssize_t received =
        recvmsg(fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (received < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return IO_EOF;
        }
        return IO_ERROR;
    }

    bool unexpected = (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET ||
            header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(0U)) {
            unexpected = true;
            continue;
        }
        const size_t data_len = header->cmsg_len - CMSG_LEN(0U);
        if (data_len == 0U || data_len % sizeof(int) != 0U) {
            unexpected = true;
            continue;
        }
        const size_t count = data_len / sizeof(int);
        const int *values = (const int *)CMSG_DATA(header);
        for (size_t index = 0U; index < count; ++index) {
            if (descriptors->count ==
                sizeof(descriptors->values) / sizeof(descriptors->values[0])) {
                unexpected = true;
                (void)close(values[index]);
            } else {
                descriptors->values[descriptors->count++] = values[index];
            }
        }
    }
    if (!allow_descriptors && descriptors->count != 0U) {
        unexpected = true;
    }
    if (unexpected) {
        close_descriptors(descriptors);
        return IO_PROTOCOL;
    }
    *out_received = (size_t)received;
    return IO_OK;
}

static io_result_t receive_exact(
    int fd, uint8_t *buffer, size_t len, uint64_t deadline_ms,
    bool allow_initial_eof, bool allow_descriptors,
    received_descriptors_t *descriptors,
    const vmp_server_options_t *options)
{
    size_t offset = 0U;
    while (offset < len) {
        const io_result_t waiting =
            wait_fd(fd, POLLIN, deadline_ms, true, options);
        if (waiting != IO_OK) return waiting;
        size_t received = 0U;
        const io_result_t result =
            receive_once(fd, buffer + offset, len - offset,
                         allow_descriptors, descriptors, &received);
        if (result == IO_EOF) continue;
        if (result != IO_OK) return result;
        if (received == 0U) {
            return allow_initial_eof && offset == 0U ? IO_EOF : IO_ERROR;
        }
        offset += received;
    }
    return IO_OK;
}

static io_result_t receive_binding_record(
    int fd, uint8_t binding[VMP_FD_BINDING_LEN], uint64_t deadline_ms,
    received_descriptors_t *descriptors,
    const vmp_server_options_t *options)
{
    for (;;) {
        const io_result_t waiting =
            wait_fd(fd, POLLIN, deadline_ms, true, options);
        if (waiting != IO_OK) return waiting;
        size_t received = 0U;
        const io_result_t result =
            receive_once(fd, binding, VMP_FD_BINDING_LEN, true,
                         descriptors, &received);
        if (result == IO_EOF) continue;
        if (result != IO_OK) return result;
        if (received == 0U) return IO_PROTOCOL;
        if (received == VMP_FD_BINDING_LEN) return IO_OK;

        /* SOCK_STREAM does not preserve the sender's write boundary. The
         * descriptor, when present, must accompany the first byte; assemble
         * the remaining binding bytes while rejecting any later ancillary
         * data. */
        received_descriptors_t unexpected = {{-1, -1}, 0U};
        const io_result_t remainder = receive_exact(
            fd, binding + received, VMP_FD_BINDING_LEN - received,
            deadline_ms, false, false, &unexpected, options);
        close_descriptors(&unexpected);
        return remainder;
    }
}

static io_result_t require_write_eof(
    int fd, uint64_t deadline_ms, const vmp_server_options_t *options)
{
    uint8_t extra = 0U;
    received_descriptors_t descriptors = {{-1, -1}, 0U};
    for (;;) {
        const io_result_t waiting =
            wait_fd(fd, POLLIN, deadline_ms, true, options);
        if (waiting != IO_OK && waiting != IO_EOF) return waiting;
        size_t received = 0U;
        const io_result_t result =
            receive_once(fd, &extra, sizeof(extra), false, &descriptors,
                         &received);
        close_descriptors(&descriptors);
        if (result == IO_EOF) continue;
        if (result != IO_OK) return result;
        return received == 0U ? IO_OK : IO_PROTOCOL;
    }
}

static io_result_t write_exact(int fd, const uint8_t *buffer, size_t len,
                               uint64_t deadline_ms,
                               const vmp_server_options_t *options)
{
    size_t offset = 0;
    while (offset < len) {
        const io_result_t waiting = wait_fd(fd, POLLOUT, deadline_ms, true, options);
        if (waiting != IO_OK) return waiting;
        const ssize_t written = send(fd, buffer + offset, len - offset,
                                     MSG_DONTWAIT | MSG_NOSIGNAL);
        if (written > 0) {
            offset += (size_t)written;
        } else if (written == 0) {
            return IO_ERROR;
        } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            return IO_ERROR;
        }
    }
    return IO_OK;
}

static vmp_server_error_t map_io(io_result_t result)
{
    if (result == IO_BACKEND) return VMP_SERVER_BACKEND;
    if (result == IO_PROTOCOL) return VMP_SERVER_PROTOCOL;
    return result == IO_TIMEOUT ? VMP_SERVER_TIMEOUT : VMP_SERVER_IO;
}

static bool options_valid(const vmp_server_options_t *options)
{
    return options != NULL && options->frame_timeout_ms >= 10 &&
           options->frame_timeout_ms <= 60000 &&
           options->max_requests == VMP_MAX_REQUESTS_PER_CONNECTION &&
           options->request_binding != NULL &&
           options->request_digest != NULL &&
           ((options->pump == NULL && options->pump_interval_ms == 0) ||
            (options->pump != NULL && options->pump_interval_ms >= 1 &&
             options->pump_interval_ms <= 1000));
}

static vmp_server_error_t verify_peer(int fd, uid_t expected_uid)
{
    int domain = 0;
    int type = 0;
    socklen_t option_len = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &option_len) != 0 ||
        option_len != sizeof(domain) || domain != AF_UNIX) {
        return VMP_SERVER_PEER_REJECTED;
    }
    option_len = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &option_len) != 0 ||
        option_len != sizeof(type) || type != SOCK_STREAM) {
        return VMP_SERVER_PEER_REJECTED;
    }
    struct ucred credentials;
    socklen_t credentials_len = sizeof(credentials);
    memset(&credentials, 0, sizeof(credentials));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials,
                   &credentials_len) != 0 ||
        credentials_len != sizeof(credentials) ||
        credentials.uid != expected_uid || credentials.pid <= 0) {
        return VMP_SERVER_PEER_REJECTED;
    }
    return VMP_SERVER_OK;
}

static bool zero_binding(const uint8_t binding[VMP_FD_BINDING_LEN])
{
    uint8_t combined = 0U;
    for (size_t index = 0U; index < VMP_FD_BINDING_LEN; ++index) {
        combined |= binding[index];
    }
    return combined == 0U;
}

static bool equal_binding(
    const uint8_t left[VMP_FD_BINDING_LEN],
    const uint8_t right[VMP_FD_BINDING_LEN])
{
    uint8_t difference = 0U;
    for (size_t index = 0U; index < VMP_FD_BINDING_LEN; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0U;
}

vmp_server_error_t vmp_serve_connection(int connection_fd,
                                        const vmp_server_options_t *options,
                                        vmp_dispatch_fn dispatch,
                                        void *dispatch_context)
{
    if (connection_fd < 0 || !options_valid(options) || dispatch == NULL) {
        return VMP_SERVER_LIMIT;
    }
    vmp_server_error_t error = verify_peer(connection_fd,
                                           options->expected_peer_uid);
    if (error != VMP_SERVER_OK) return error;

    uint64_t now = 0U;
    if (!monotonic_ms(&now) ||
        now > UINT64_MAX - (uint64_t)options->frame_timeout_ms) {
        return VMP_SERVER_IO;
    }
    const uint64_t deadline = now + (uint64_t)options->frame_timeout_ms;
    uint8_t binding[VMP_FD_BINDING_LEN];
    memset(binding, 0, sizeof(binding));
    received_descriptors_t descriptors = {{-1, -1}, 0U};
    io_result_t io = receive_binding_record(
        connection_fd, binding, deadline, &descriptors, options);
    if (io != IO_OK) {
        close_descriptors(&descriptors);
        return map_io(io);
    }

    received_descriptors_t unexpected = {{-1, -1}, 0U};
    uint8_t prefix[4];
    io = receive_exact(connection_fd, prefix, sizeof(prefix), deadline, false,
                       false, &unexpected, options);
    if (io != IO_OK) {
        close_descriptors(&descriptors);
        close_descriptors(&unexpected);
        return map_io(io);
    }
    const uint32_t frame_len = ((uint32_t)prefix[0] << 24U) |
                               ((uint32_t)prefix[1] << 16U) |
                               ((uint32_t)prefix[2] << 8U) |
                               (uint32_t)prefix[3];
    if (frame_len == 0U || frame_len > VMP_MAX_CONTROL_FRAME) {
        close_descriptors(&descriptors);
        return VMP_SERVER_PROTOCOL;
    }

    uint8_t *frame = malloc(frame_len);
    if (frame == NULL) {
        close_descriptors(&descriptors);
        return VMP_SERVER_IO;
    }
    io = receive_exact(connection_fd, frame, frame_len, deadline, false,
                       false, &unexpected, options);
    if (io == IO_OK) {
        io = require_write_eof(connection_fd, deadline, options);
    }
    close_descriptors(&unexpected);
    if (io != IO_OK) {
        close_descriptors(&descriptors);
        vmp_wipe_secret(frame, frame_len);
        free(frame);
        return map_io(io);
    }

    vmp_request_t request;
    memset(&request, 0, sizeof(request));
    const vmp_protocol_error_t decode_error =
        vmp_decode_request(frame, frame_len, &request);
    if (decode_error != VMP_PROTOCOL_OK) {
        close_descriptors(&descriptors);
        vmp_wipe_secret(frame, frame_len);
        free(frame);
        return VMP_SERVER_PROTOCOL;
    }

    int request_fd = -1;
    if (request.operation == VMP_OPERATION_ADD_PATH ||
        request.operation == VMP_OPERATION_START_EXIT_SESSION) {
        uint8_t expected[VMP_FD_BINDING_LEN];
        memset(expected, 0, sizeof(expected));
        const bool valid =
            descriptors.count == 1U &&
            options->request_binding(options->request_binding_context,
                                     request.operation, frame, frame_len,
                                     expected) &&
            equal_binding(binding, expected);
        vmp_wipe_secret(expected, sizeof(expected));
        if (!valid) {
            close_descriptors(&descriptors);
            vmp_wipe_secret(&request, sizeof(request));
            vmp_wipe_secret(frame, frame_len);
            free(frame);
            return VMP_SERVER_PROTOCOL;
        }
        request_fd = descriptors.values[0];
        descriptors.values[0] = -1;
        descriptors.count = 0U;
    } else if (descriptors.count != 0U || !zero_binding(binding)) {
        close_descriptors(&descriptors);
        vmp_wipe_secret(&request, sizeof(request));
        vmp_wipe_secret(frame, frame_len);
        free(frame);
        return VMP_SERVER_PROTOCOL;
    }
    vmp_wipe_secret(binding, sizeof(binding));

    vmp_response_t response;
    memset(&response, 0, sizeof(response));
    response.api_version = VMP_API_VERSION;
    memcpy(response.request_nonce, request.request_nonce,
           VMP_REQUEST_NONCE_LEN);
    if (!options->request_digest(options->request_digest_context, frame,
                                 frame_len, response.request_sha256)) {
        vmp_wipe_secret(&request, sizeof(request));
        vmp_wipe_secret(frame, frame_len);
        free(frame);
        vmp_wipe_secret(&response, sizeof(response));
        return VMP_SERVER_BACKEND;
    }
    error = dispatch(dispatch_context, &request, &response, request_fd);
    request_fd = -1;
    if (error != VMP_SERVER_OK) {
        vmp_wipe_secret(&request, sizeof(request));
        vmp_wipe_secret(frame, frame_len);
        free(frame);
        vmp_wipe_secret(&response, sizeof(response));
        return VMP_SERVER_BACKEND;
    }
    if ((request.operation == VMP_OPERATION_START_SESSION &&
         response.result == VMP_RESULT_OK &&
         !response.has_tunnel_assignment) ||
        (request.operation != VMP_OPERATION_START_SESSION &&
         response.has_tunnel_assignment)) {
        vmp_wipe_secret(&request, sizeof(request));
        vmp_wipe_secret(frame, frame_len);
        free(frame);
        vmp_wipe_secret(&response, sizeof(response));
        return VMP_SERVER_BACKEND;
    }

    uint8_t encoded[VMP_RESPONSE_FRAME_CAPACITY];
    memset(encoded, 0, sizeof(encoded));
    size_t encoded_len = 0U;
    const vmp_protocol_error_t encode_error = vmp_encode_response_frame(
        &response, encoded, sizeof(encoded), &encoded_len);
    vmp_wipe_secret(&request, sizeof(request));
    vmp_wipe_secret(frame, frame_len);
    free(frame);
    if (encode_error != VMP_PROTOCOL_OK) {
        vmp_wipe_secret(encoded, sizeof(encoded));
        vmp_wipe_secret(&response, sizeof(response));
        return VMP_SERVER_BACKEND;
    }
    const io_result_t send_result =
        write_exact(connection_fd, encoded, encoded_len, deadline, options);
    vmp_wipe_secret(encoded, sizeof(encoded));
    vmp_wipe_secret(&response, sizeof(response));
    return send_result == IO_OK ? VMP_SERVER_OK : map_io(send_result);
}

vmp_server_error_t vmp_accept_one(int listening_fd,
                                  const vmp_server_options_t *options,
                                  vmp_dispatch_fn dispatch,
                                  void *dispatch_context)
{
    if (listening_fd < 0 || !options_valid(options) || dispatch == NULL) {
        return VMP_SERVER_LIMIT;
    }
    const int connection =
        accept4(listening_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (connection < 0) return VMP_SERVER_IO;
    const vmp_server_error_t error =
        vmp_serve_connection(connection, options, dispatch, dispatch_context);
    (void)close(connection);
    return error;
}

vmp_server_error_t vmp_read_auth_secret(int secret_fd, uint8_t *out,
                                        size_t out_capacity, size_t *out_len)
{
    if (secret_fd < 0 || out == NULL || out_len == NULL || out_capacity == 0) {
        return VMP_SERVER_LIMIT;
    }
    *out_len = 0;
    const size_t limit = out_capacity < VMP_MAX_AUTH_SECRET
                             ? out_capacity
                             : VMP_MAX_AUTH_SECRET;
    vmp_wipe_secret(out, limit);
    size_t offset = 0;
    while (offset < limit) {
        const ssize_t received = read(secret_fd, out + offset, limit - offset);
        if (received > 0) {
            for (ssize_t index = 0; index < received; ++index) {
                const uint8_t byte = out[offset + (size_t)index];
                const bool alphanumeric =
                    (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') ||
                    (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
                    (byte >= (uint8_t)'0' && byte <= (uint8_t)'9');
                if (!alphanumeric && byte != (uint8_t)'_' &&
                    byte != (uint8_t)'-') {
                    vmp_wipe_secret(out, limit);
                    return VMP_SERVER_PROTOCOL;
                }
            }
            offset += (size_t)received;
        } else if (received == 0) {
            if (offset != VMP_AUTH_SECRET_LEN ||
                !canonical_base64url_final(out[offset - 1U])) {
                vmp_wipe_secret(out, limit);
                return VMP_SERVER_PROTOCOL;
            }
            *out_len = offset;
            return VMP_SERVER_OK;
        } else if (errno != EINTR) {
            vmp_wipe_secret(out, limit);
            return VMP_SERVER_IO;
        }
    }

    uint8_t extra = 0;
    ssize_t received;
    do {
        received = read(secret_fd, &extra, 1);
    } while (received < 0 && errno == EINTR);
    if (received != 0) {
        const bool overlong = received > 0;
        vmp_wipe_secret(&extra, sizeof(extra));
        vmp_wipe_secret(out, limit);
        return overlong ? VMP_SERVER_LIMIT : VMP_SERVER_IO;
    }
    vmp_wipe_secret(&extra, sizeof(extra));
    if (offset != VMP_AUTH_SECRET_LEN ||
        !canonical_base64url_final(out[offset - 1U])) {
        vmp_wipe_secret(out, limit);
        return VMP_SERVER_PROTOCOL;
    }
    *out_len = offset;
    return VMP_SERVER_OK;
}

void vmp_wipe_secret(void *secret, size_t len)
{
    volatile uint8_t *bytes = secret;
    if (bytes == NULL) return;
    while (len > 0) {
        *bytes++ = 0;
        --len;
    }
}

const char *vmp_server_error_string(vmp_server_error_t error)
{
    switch (error) {
    case VMP_SERVER_OK: return "ok";
    case VMP_SERVER_IO: return "io";
    case VMP_SERVER_TIMEOUT: return "timeout";
    case VMP_SERVER_PEER_REJECTED: return "peer_rejected";
    case VMP_SERVER_PROTOCOL: return "protocol";
    case VMP_SERVER_BACKEND: return "backend";
    case VMP_SERVER_LIMIT: return "limit";
    default: return "unknown";
    }
}
