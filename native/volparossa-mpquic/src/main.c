// SPDX-License-Identifier: GPL-3.0-only

#define _GNU_SOURCE

#include "daemon_socket.h"
#include "request_binding.h"
#include "volparossa_mpquic_runtime.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
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

static uint64_t realtime_ms(void *context)
{
    (void)context;
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0) {
        return UINT64_MAX;
    }
    const uint64_t seconds = (uint64_t)now.tv_sec;
    const uint64_t milliseconds = (uint64_t)now.tv_nsec / UINT64_C(1000000);
    if (seconds > (UINT64_MAX - milliseconds) / UINT64_C(1000)) {
        return UINT64_MAX;
    }
    return seconds * UINT64_C(1000) + milliseconds;
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

static int serve(vmp_runtime_t *runtime, vmp_control_socket_t *control)
{
    const uid_t effective_uid = geteuid();
    const vmp_server_options_t options = {
        .expected_peer_uid = effective_uid,
        .frame_timeout_ms = 5000U,
        .max_requests = 1U,
        .request_binding = vmp_sha256_request_binding,
        .request_binding_context = NULL,
        .pump_interval_ms = 10U,
        .pump = vmp_runtime_pump,
        .pump_context = runtime,
    };

    while (!stop_requested) {
        struct pollfd descriptor = {
            .fd = control->listening_fd,
            .events = POLLIN,
            .revents = 0,
        };
        const int ready = poll(&descriptor, 1U, 10);
        if (ready < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        if (vmp_runtime_pump(runtime) != VMP_SERVER_OK) return 1;
        if (ready == 0) continue;
        if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0) return 1;
        if ((descriptor.revents & POLLIN) != 0) {
            /* Every per-connection failure is bounded and isolated. Only
             * same-UID peers can reach this point; malformed frames never
             * terminate other native sessions. */
            (void)vmp_accept_one(control->listening_fd, &options,
                                 vmp_runtime_dispatch, runtime);
        }
    }
    return 0;
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

    vmp_runtime_t *runtime = vmp_runtime_create(
        arguments.mode, vmp_mqvpn_transport_ops(), NULL, realtime_ms, NULL);
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
