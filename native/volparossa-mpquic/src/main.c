// SPDX-License-Identifier: GPL-3.0-only

#define _GNU_SOURCE

#include "daemon_socket.h"
#include "request_binding.h"
#include "volparossa_mpquic_runtime.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

typedef struct daemon_arguments {
    vmp_runtime_mode_t mode;
    const char *socket_path;
    bool have_mode;
} daemon_arguments_t;

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static void print_usage(const char *program)
{
    fprintf(stderr,
            "usage: %s --mode client|exit --socket ABSOLUTE_PATH\n"
            "       %s --api-version\n",
            program, program);
}

static bool set_mode(const char *text, daemon_arguments_t *arguments)
{
    if (arguments->have_mode) return false;
    if (strcmp(text, "client") == 0) {
        arguments->mode = VMP_RUNTIME_CLIENT;
    } else if (strcmp(text, "exit") == 0) {
        arguments->mode = VMP_RUNTIME_EXIT;
    } else {
        return false;
    }
    arguments->have_mode = true;
    return true;
}

static bool parse_arguments(int argc, char **argv,
                            daemon_arguments_t *arguments)
{
    memset(arguments, 0, sizeof(*arguments));
    for (int index = 1; index < argc; ++index) {
        if (index + 1 >= argc) return false;
        const char *option = argv[index++];
        const char *value = argv[index];
        if (strcmp(option, "--mode") == 0) {
            if (!set_mode(value, arguments)) return false;
        } else if (strcmp(option, "--socket") == 0) {
            if (arguments->socket_path != NULL) return false;
            arguments->socket_path = value;
        } else {
            return false;
        }
    }
    return arguments->have_mode && arguments->socket_path != NULL;
}

static bool clock_ms(clockid_t clock_id, uint64_t *out_ms)
{
    if (out_ms == NULL) return false;
    struct timespec now;
    if (clock_gettime(clock_id, &now) != 0 || now.tv_sec < 0) return false;
    const uint64_t seconds = (uint64_t)now.tv_sec;
    const uint64_t milliseconds = (uint64_t)now.tv_nsec / UINT64_C(1000000);
    if (seconds > (UINT64_MAX - milliseconds) / UINT64_C(1000)) {
        return false;
    }
    *out_ms = seconds * UINT64_C(1000) + milliseconds;
    return true;
}

static bool clock_snapshot(void *context, uint64_t *out_boottime_ms,
                           uint64_t *out_realtime_ms)
{
    (void)context;
    /* This order converts from the preceding boot sample, so sampling delay
     * can only shorten an authorization lifetime and can never extend it. */
    return clock_ms(CLOCK_BOOTTIME, out_boottime_ms) &&
           clock_ms(CLOCK_REALTIME, out_realtime_ms);
}

static bool boottime_ms(void *context, uint64_t *out_boottime_ms)
{
    (void)context;
    return clock_ms(CLOCK_BOOTTIME, out_boottime_ms);
}

static bool random_native_instance(
    uint8_t out[VMP_NATIVE_INSTANCE_ID_LEN])
{
    memset(out, 0, VMP_NATIVE_INSTANCE_ID_LEN);
    size_t offset = 0U;
    while (offset < VMP_NATIVE_INSTANCE_ID_LEN) {
        const ssize_t received =
            getrandom(out + offset, VMP_NATIVE_INSTANCE_ID_LEN - offset, 0U);
        if (received < 0) {
            if (errno == EINTR) continue;
            vmp_wipe_secret(out, VMP_NATIVE_INSTANCE_ID_LEN);
            return false;
        }
        if (received == 0) {
            vmp_wipe_secret(out, VMP_NATIVE_INSTANCE_ID_LEN);
            return false;
        }
        offset += (size_t)received;
    }
    uint8_t combined = 0U;
    for (size_t index = 0U; index < VMP_NATIVE_INSTANCE_ID_LEN; ++index) {
        combined |= out[index];
    }
    if (combined == 0U) {
        vmp_wipe_secret(out, VMP_NATIVE_INSTANCE_ID_LEN);
        return false;
    }
    return true;
}

static bool install_signal_handlers(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    if (sigemptyset(&action.sa_mask) != 0) return false;
    return sigaction(SIGINT, &action, NULL) == 0 &&
           sigaction(SIGTERM, &action, NULL) == 0;
}

/* Development-only cumulative timing, explicitly enabled by the disposable
 * fixture. No route, peer, destination, credential, or payload is recorded.
 * The wrappers call the identical runtime operations, with no new waits. */
typedef struct daemon_timing {
    vmp_runtime_t *runtime;
    bool enabled;
    uint64_t started_ns;
    uint64_t last_report_ns;
    uint64_t pump_calls;
    uint64_t pump_ns;
    uint64_t interest_calls;
    uint64_t interest_ns;
    uint64_t accepted;
    uint64_t failed;
    uint64_t rpc_ns;
    uint64_t rpc_max_ns;
    uint64_t operation_calls[19];
    uint64_t operation_ns[19];
    uint64_t operation_results[19][10];
    bool reported_rejection[19][10];
} daemon_timing_t;

static const char *timing_failure_code(const vmp_response_t *response)
{
    /* Return our fixed enum labels, never a runtime/peer-supplied string. */
    static const struct { const char *wire; const char *label; } codes[] = {
        {"path_metrics_unavailable", "PATH_METRICS_UNAVAILABLE"},
        {"native_transport_failed", "NATIVE_TRANSPORT_FAILED"},
        {"required_paths_not_active", "REQUIRED_PATHS_NOT_ACTIVE"},
        {"reverse_queue_overflow", "REVERSE_QUEUE_OVERFLOW"},
        {"session_expired", "SESSION_EXPIRED"},
        {"session_not_found", "SESSION_NOT_FOUND"},
        {"send_backpressure", "SEND_BACKPRESSURE"},
        {"stale_instance", "STALE_INSTANCE"},
        {"exit_session_not_connected", "EXIT_SESSION_NOT_CONNECTED"},
    };
    for (size_t index = 0U; index < sizeof(codes) / sizeof(codes[0]); ++index) {
        const size_t length = strlen(codes[index].wire);
        if (response->diagnostic_code != NULL &&
            response->diagnostic_code_len == length &&
            memcmp(response->diagnostic_code, codes[index].wire, length) == 0) {
            return codes[index].label;
        }
    }
    return "OTHER_NATIVE_REJECTION";
}

static uint64_t timing_now_ns(clockid_t clock_id)
{
    struct timespec now;
    if (clock_gettime(clock_id, &now) != 0 || now.tv_sec < 0) return 0U;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
           (uint64_t)now.tv_nsec;
}

static uint64_t timing_elapsed(uint64_t started)
{
    const uint64_t now = timing_now_ns(CLOCK_MONOTONIC);
    return started != 0U && now >= started ? now - started : 0U;
}

static vmp_server_error_t timed_pump(void *context)
{
    daemon_timing_t *timing = context;
    const uint64_t started = timing->enabled
                                 ? timing_now_ns(CLOCK_MONOTONIC) : 0U;
    const vmp_server_error_t result = vmp_runtime_pump(timing->runtime);
    if (timing->enabled) {
        ++timing->pump_calls;
        timing->pump_ns += timing_elapsed(started);
    }
    return result;
}

static vmp_server_error_t timed_interest(void *context, vmp_io_interest_t *out)
{
    daemon_timing_t *timing = context;
    const uint64_t started = timing->enabled
                                 ? timing_now_ns(CLOCK_MONOTONIC) : 0U;
    const vmp_server_error_t result = vmp_runtime_interest(timing->runtime, out);
    if (timing->enabled) {
        ++timing->interest_calls;
        timing->interest_ns += timing_elapsed(started);
    }
    return result;
}

static vmp_server_error_t timed_dispatch(void *context,
                                         const vmp_request_t *request,
                                         vmp_response_t *response, int request_fd)
{
    daemon_timing_t *timing = context;
    const uint64_t started = timing->enabled
                                 ? timing_now_ns(CLOCK_MONOTONIC) : 0U;
    const vmp_server_error_t result = vmp_runtime_dispatch(
        timing->runtime, request, response, request_fd);
    if (timing->enabled && (unsigned)request->operation < 19U) {
        const unsigned operation = (unsigned)request->operation;
        ++timing->operation_calls[operation];
        timing->operation_ns[operation] += timing_elapsed(started);
        if (result == VMP_SERVER_OK && (unsigned)response->result < 10U) {
            ++timing->operation_results[operation][(unsigned)response->result];
            const unsigned rejected = (unsigned)response->result;
            if (rejected != VMP_RESULT_OK && rejected != VMP_RESULT_NO_DATAGRAM &&
                !timing->reported_rejection[operation][rejected]) {
                timing->reported_rejection[operation][rejected] = true;
                (void)fprintf(stderr,
                    "NATIVE_RPC_REJECT op=%u result=%u cause=%s\n",
                    operation, rejected, timing_failure_code(response));
            }
        }
    }
    return result;
}

static void report_timing(daemon_timing_t *timing, bool final)
{
    if (!timing->enabled) return;
    const uint64_t now = timing_now_ns(CLOCK_MONOTONIC);
    if (!final && (now < timing->last_report_ns ||
                  now - timing->last_report_ns < UINT64_C(10000000000))) return;
    timing->last_report_ns = now;
    (void)fprintf(stderr,
        "NATIVE_RPC_TIMING {\"final\":%s,\"elapsed_ns\":%" PRIu64
        ",\"process_cpu_ns\":%" PRIu64 ",\"accepted\":%" PRIu64
        ",\"failed\":%" PRIu64 ",\"rpc_ns\":%" PRIu64
        ",\"rpc_max_ns\":%" PRIu64 ",\"pump_calls\":%" PRIu64
        ",\"pump_ns\":%" PRIu64 ",\"interest_calls\":%" PRIu64
        ",\"interest_ns\":%" PRIu64 ",\"operations\":[",
        final ? "true" : "false", timing_elapsed(timing->started_ns),
        timing_now_ns(CLOCK_PROCESS_CPUTIME_ID), timing->accepted,
        timing->failed, timing->rpc_ns, timing->rpc_max_ns,
        timing->pump_calls, timing->pump_ns, timing->interest_calls,
        timing->interest_ns);
    bool first = true;
    for (unsigned operation = 10U; operation < 19U; ++operation) {
        if (timing->operation_calls[operation] == 0U) continue;
        (void)fprintf(stderr,
            "%s{\"code\":%u,\"calls\":%" PRIu64 ",\"dispatch_ns\":%" PRIu64
            ",\"results\":[", first ? "" : ",", operation,
            timing->operation_calls[operation], timing->operation_ns[operation]);
        for (unsigned result = 0U; result < 10U; ++result) {
            (void)fprintf(stderr, "%s%" PRIu64, result == 0U ? "" : ",",
                          timing->operation_results[operation][result]);
        }
        (void)fputs("]}", stderr);
        first = false;
    }
    (void)fputs("]}\n", stderr);
    (void)fflush(stderr);
}

static int serve(vmp_runtime_t *runtime, vmp_control_socket_t *control)
{
    const uid_t effective_uid = geteuid();
    const char *timing_environment = getenv("VMP_RPC_TIMING");
    daemon_timing_t timing = {
        .runtime = runtime,
        .enabled = timing_environment != NULL &&
                   strcmp(timing_environment, "1") == 0,
    };
    if (timing.enabled) {
        timing.started_ns = timing_now_ns(CLOCK_MONOTONIC);
        timing.last_report_ns = timing.started_ns;
    }
    const vmp_server_options_t options = {
        .expected_peer_uid = effective_uid,
        .frame_timeout_ms = 5000U,
        .max_requests = 1U,
        .request_binding = vmp_sha256_request_binding,
        .request_binding_context = NULL,
        .request_digest = vmp_sha256_request_digest,
        .request_digest_context = NULL,
        .pump = timed_pump,
        .pump_context = &timing,
        .interest = timed_interest,
    };

    int result = 0;
    while (!stop_requested) {
        short events = 0;
        if (vmp_wait_control(control->listening_fd, POLLIN, 1000U,
                             &options, &events) != VMP_SERVER_OK ||
            (events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            result = 1;
            break;
        }
        if ((events & POLLIN) != 0) {
            /* Every per-connection failure is bounded and isolated. Only
             * same-UID peers can reach this point; malformed frames never
             * terminate other native sessions. */
            const uint64_t started = timing.enabled
                                         ? timing_now_ns(CLOCK_MONOTONIC) : 0U;
            const vmp_server_error_t accepted = vmp_accept_one(
                control->listening_fd, &options, timed_dispatch, &timing);
            if (timing.enabled) {
                const uint64_t elapsed = timing_elapsed(started);
                ++timing.accepted;
                timing.failed += accepted != VMP_SERVER_OK ? 1U : 0U;
                timing.rpc_ns += elapsed;
                if (elapsed > timing.rpc_max_ns) timing.rpc_max_ns = elapsed;
            }
        }
        report_timing(&timing, false);
    }
    report_timing(&timing, true);
    return result;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--api-version") == 0) {
        printf("%u\n", (unsigned)VMP_API_VERSION);
        return 0;
    }

    daemon_arguments_t arguments;
    if (!parse_arguments(argc, argv, &arguments)) {
        print_usage(argv[0]);
        return 2;
    }

    uint8_t native_instance_id[VMP_NATIVE_INSTANCE_ID_LEN];
    if (!random_native_instance(native_instance_id)) {
        fputs("volparossa-mpquic: native instance generation failed\n",
              stderr);
        return 1;
    }
    vmp_runtime_t *runtime = vmp_runtime_create(
        arguments.mode, native_instance_id, vmp_mqvpn_transport_ops(), NULL,
        vmp_sha256_auth_commitment, NULL, clock_snapshot, boottime_ms, NULL);
    vmp_wipe_secret(native_instance_id, sizeof(native_instance_id));
    if (runtime == NULL) {
        fputs("volparossa-mpquic: invalid runtime configuration\n", stderr);
        return 1;
    }

    vmp_control_socket_t control;
    if (!install_signal_handlers() ||
        vmp_control_socket_open(arguments.socket_path, geteuid(), &control) !=
            0) {
        fputs("volparossa-mpquic: control socket setup failed\n", stderr);
        vmp_runtime_destroy(runtime);
        return 1;
    }

    const int result = serve(runtime, &control);
    vmp_control_socket_close(&control);
    vmp_runtime_destroy(runtime);
    return result;
}
