// SPDX-License-Identifier: GPL-3.0-only
/* Diagnostic only: real mqvpn/xquic over two owned loopback UDP pairs.
 * No TUN, WireGuard, host changes, privileged operations, or acceptance claim.
 * A small reliable application protocol retransmits missing data explicitly;
 * that is NOT MPQUIC DATAGRAM retransmission, scheduler duplication, or FEC.
 */
#define _POSIX_C_SOURCE 200809L
#include "libmqvpn.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DATA_BYTES 1024U
#define MAX_CHUNKS 32768U
#define WINDOW 32U
#define PACKET_BYTES (44U + DATA_BYTES)
#define RETRY_MS 400U

typedef struct {
    int client_fd, server_fd;
    struct sockaddr_in client_addr, server_addr;
    mqvpn_path_handle_t handle;
    uint64_t forwarded[2], dropped[2], packets[2];
} path_t;

typedef struct {
    mqvpn_client_t *client;
    mqvpn_server_t *server;
    path_t paths[2];
    mqvpn_tunnel_info_t assignment;
    uint32_t session_id, connections, disconnections;
    bool ready, activated, failed, blocked, sender_is_client;
    unsigned blocked_path, phase, count, unique, acknowledged;
    unsigned application_sends, application_retries;
    bool seen[MAX_CHUNKS], acknowledged_chunks[MAX_CHUNKS], pending_ack[MAX_CHUNKS];
    uint64_t last_send[MAX_CHUNKS];
    uint8_t *received;
    uint8_t auth_random[32];
    char auth[65];
    uint64_t started_ms;
    const char *stage;
} probe_t;

static volatile sig_atomic_t interrupted;
static void stop_signal(int sig) { (void)sig; interrupted = 1; }

static uint64_t now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) abort();
    return (uint64_t)t.tv_sec * 1000U + (uint64_t)t.tv_nsec / 1000000U;
}

static void put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void payload(uint8_t *out, unsigned phase, unsigned sequence)
{
    /* Public deterministic test bytes; not an authentication key or nonce. */
    uint32_t value = (uint32_t)phase * 0x9e3779b9U ^ (uint32_t)sequence;
    for (unsigned i = 0; i < DATA_BYTES; ++i) {
        value = value * 1664525U + 1013904223U;
        out[i] = (uint8_t)(value >> 24);
    }
}

static size_t packet(probe_t *p, uint8_t *out, bool client, bool ack, unsigned seq)
{
    size_t n = ack ? 44U : PACKET_BYTES;
    memset(out, 0, n);
    out[0] = 0x45; out[2] = (uint8_t)(n >> 8); out[3] = (uint8_t)n;
    out[8] = 64; out[9] = 17;
    const uint8_t destination[4] = {8, 8, 8, 8};
    memcpy(out + 12, client ? p->assignment.assigned_ip : destination, 4);
    memcpy(out + 16, client ? destination : p->assignment.assigned_ip, 4);
    unsigned port = p->phase <= 2 ? 52006U : 52016U;
    out[20] = (uint8_t)((client ? port : 443U) >> 8);
    out[21] = (uint8_t)(client ? port : 443U);
    out[22] = (uint8_t)((client ? 443U : port) >> 8);
    out[23] = (uint8_t)(client ? 443U : port);
    out[24] = (uint8_t)((n - 20U) >> 8); out[25] = (uint8_t)(n - 20U);
    memcpy(out + 28, "VWP1", 4);
    put32(out + 32, p->phase); put32(out + 36, seq); put32(out + 40, ack ? 1U : 0U);
    if (!ack) payload(out + 44, p->phase, seq);
    unsigned sum = 0;
    for (unsigned i = 0; i < 20; i += 2) sum += ((unsigned)out[i] << 8) | out[i + 1];
    while (sum >> 16) sum = (sum & 65535U) + (sum >> 16);
    sum = ~sum; out[10] = (uint8_t)(sum >> 8); out[11] = (uint8_t)sum;
    return n;
}

static void receive_inner(probe_t *p, const uint8_t *data, size_t len, bool at_client)
{
    if (len < 44U || data[0] != 0x45 || data[9] != 17 || memcmp(data + 28, "VWP1", 4)) {
        p->failed = true; return;
    }
    unsigned phase = get32(data + 32), seq = get32(data + 36), ack = get32(data + 40);
    /* Old packets may still be in flight after a completed, acknowledged phase. */
    if (phase < p->phase) return;
    if (phase != p->phase || seq >= p->count || ack > 1U ||
        at_client != (ack ? p->sender_is_client : !p->sender_is_client)) {
        p->failed = true; return;
    }
    if (ack) {
        if (len != 44U) { p->failed = true; return; }
        if (!p->acknowledged_chunks[seq]) { p->acknowledged_chunks[seq] = true; ++p->acknowledged; }
        return;
    }
    uint8_t expected[DATA_BYTES]; payload(expected, phase, seq);
    if (len != PACKET_BYTES || memcmp(expected, data + 44, DATA_BYTES)) {
        p->failed = true; return;
    }
    if (!p->seen[seq]) {
        p->seen[seq] = true; ++p->unique;
        memcpy(p->received + (size_t)seq * DATA_BYTES, data + 44, DATA_BYTES);
    }
    p->pending_ack[seq] = true;
}

static void client_packet(const uint8_t *data, size_t len, void *ctx)
{ receive_inner(ctx, data, len, true); }

static void server_packet(const uint8_t *data, size_t len, uint32_t session, void *ctx)
{
    probe_t *p = ctx;
    if (session != p->session_id) { p->failed = true; return; }
    receive_inner(p, data, len, false);
}

static void unexpected_packet(const uint8_t *data, size_t len, void *ctx)
{ (void)data; (void)len; ((probe_t *)ctx)->failed = true; }
static void client_ready(const mqvpn_tunnel_info_t *info, void *ctx)
{ probe_t *p = ctx; p->assignment = *info; p->ready = true; }
static void server_ready(const mqvpn_tunnel_info_t *info, void *ctx)
{ (void)info; (void)ctx; }
static void connected(const mqvpn_tunnel_info_t *info, uint32_t session, void *ctx)
{ (void)info; probe_t *p = ctx; p->session_id = session; ++p->connections; }
static void disconnected(uint32_t session, mqvpn_error_t reason, void *ctx)
{ (void)session; (void)reason; ++((probe_t *)ctx)->disconnections; }

static bool same_address(const struct sockaddr_in *a, const struct sockaddr *b, socklen_t len)
{
    if (len != sizeof(*a) || b->sa_family != AF_INET) return false;
    const struct sockaddr_in *v = (const struct sockaddr_in *)(const void *)b;
    return a->sin_addr.s_addr == v->sin_addr.s_addr && a->sin_port == v->sin_port;
}

static void server_send(mqvpn_path_handle_t handle, const uint8_t *packet_data,
                        size_t len, const struct sockaddr *peer, socklen_t peer_len, void *ctx)
{
    (void)handle; probe_t *p = ctx;
    for (unsigned i = 0; i < 2; ++i) {
        path_t *path = &p->paths[i];
        if (same_address(&path->client_addr, peer, peer_len)) {
            if (sendto(path->server_fd, packet_data, len, 0, peer, peer_len) != (ssize_t)len)
                p->failed = true;
            return;
        }
    }
    p->failed = true;
}

static int udp_socket(struct sockaddr_in *address)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int size = 1024 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET; address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(*address);
    if (bind(fd, (const struct sockaddr *)address, len) || getsockname(fd, (struct sockaddr *)address, &len)) {
        close(fd); return -1;
    }
    return fd;
}

static void pump(probe_t *p)
{
    uint8_t data[65536];
    for (unsigned i = 0; i < 2; ++i) for (unsigned side = 0; side < 2; ++side) {
        path_t *path = &p->paths[i];
        int fd = side == 0 ? path->server_fd : path->client_fd;
        for (unsigned budget = 0; budget < 64; ++budget) {
            struct sockaddr_storage peer; socklen_t len = sizeof(peer);
            ssize_t n = recvfrom(fd, data, sizeof(data), 0, (struct sockaddr *)&peer, &len);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n <= 0 || !same_address(side == 0 ? &path->client_addr : &path->server_addr,
                                      (const struct sockaddr *)&peer, len)) { p->failed = true; break; }
            if (p->blocked && i == p->blocked_path) { path->dropped[side] += (uint64_t)n; continue; }
            path->forwarded[side] += (uint64_t)n; ++path->packets[side];
            int result = side == 0 ? mqvpn_server_on_path_socket_recv(p->server, data, (size_t)n,
                    (const struct sockaddr *)&path->server_addr, sizeof(path->server_addr),
                    (const struct sockaddr *)&peer, len)
                : mqvpn_client_on_socket_recv(p->client, path->handle, data, (size_t)n,
                    (const struct sockaddr *)&peer, len);
            if (result != MQVPN_OK) p->failed = true;
        }
    }
    if (mqvpn_client_tick(p->client) != MQVPN_OK || mqvpn_server_tick(p->server) != MQVPN_OK) p->failed = true;
}

static bool two_active(probe_t *p)
{
    mqvpn_path_info_t paths[MQVPN_MAX_PATHS]; int count = 0;
    memset(paths, 0, sizeof(paths));
    if (mqvpn_client_get_paths(p->client, paths, MQVPN_MAX_PATHS, &count) != MQVPN_OK || count != 2) return false;
    return paths[0].status == MQVPN_PATH_ACTIVE && paths[1].status == MQVPN_PATH_ACTIVE;
}

static bool common_config(mqvpn_config_t *cfg)
{
    return cfg && mqvpn_config_set_multipath(cfg, 1) == MQVPN_OK &&
        mqvpn_config_set_scheduler(cfg, MQVPN_SCHED_VOLPAROSSA_EDT) == MQVPN_OK &&
        mqvpn_config_set_cc(cfg, MQVPN_CC_BBR2) == MQVPN_OK &&
        mqvpn_config_set_reinjection(cfg, MQVPN_REINJ_OFF) == MQVPN_OK &&
        mqvpn_config_set_reorder_enabled(cfg, MQVPN_REORDER_OFF) == MQVPN_OK &&
        mqvpn_config_set_hybrid_enabled(cfg, 0) == MQVPN_OK &&
        mqvpn_config_set_tun_mtu(cfg, 1420) == MQVPN_OK &&
        mqvpn_config_set_log_level(cfg, MQVPN_LOG_ERROR) == MQVPN_OK;
}

static uint8_t *read_bounded(const char *path, size_t *len)
{
    FILE *file = fopen(path, "rb"); if (!file) return NULL;
    uint8_t *bytes = malloc(65536); if (!bytes) { fclose(file); return NULL; }
    *len = fread(bytes, 1, 65536, file);
    bool ok = *len && *len < 65536 && !ferror(file) && fgetc(file) == EOF;
    fclose(file); if (!ok) { free(bytes); return NULL; } return bytes;
}

static bool initialize(probe_t *p, const char *cert, const char *key)
{
    size_t cert_len = 0, key_len = 0;
    uint8_t *cert_bytes = read_bounded(cert, &cert_len), *key_bytes = read_bounded(key, &key_len);
    mqvpn_config_t *s = mqvpn_config_new(), *c = mqvpn_config_new();
    bool ok = cert_bytes && key_bytes && common_config(s) && common_config(c) &&
        RAND_bytes(p->auth_random, sizeof(p->auth_random)) == 1;
    for (unsigned i = 0; i < sizeof(p->auth_random); ++i) (void)snprintf(p->auth + i * 2, 3, "%02x", p->auth_random[i]);
    for (unsigned i = 0; ok && i < 2; ++i) {
        p->paths[i].client_fd = udp_socket(&p->paths[i].client_addr);
        p->paths[i].server_fd = udp_socket(&p->paths[i].server_addr);
        ok = p->paths[i].client_fd >= 0 && p->paths[i].server_fd >= 0;
    }
    if (ok) ok = mqvpn_config_set_listen(s, "127.0.0.1", ntohs(p->paths[0].server_addr.sin_port)) == MQVPN_OK &&
        mqvpn_config_set_subnet(s, "10.76.0.0/24") == MQVPN_OK &&
        mqvpn_config_set_tls_identity_pem(s, cert_bytes, cert_len, key_bytes, key_len) == MQVPN_OK &&
        mqvpn_config_set_auth_key(s, p->auth) == MQVPN_OK && mqvpn_config_set_max_clients(s, 1) == MQVPN_OK &&
        mqvpn_config_set_server(c, "127.0.0.1", ntohs(p->paths[0].server_addr.sin_port)) == MQVPN_OK &&
        mqvpn_config_set_auth_key(c, p->auth) == MQVPN_OK &&
        /* Loopback diagnostic uses the pinned-source upstream TEST certificate. */
        mqvpn_config_set_insecure(c, 1) == MQVPN_OK && mqvpn_config_set_reconnect(c, 0, 5) == MQVPN_OK;
    if (key_bytes) { memset(key_bytes, 0, key_len); free(key_bytes); }
    free(cert_bytes);
    if (ok) {
        mqvpn_server_callbacks_t scb = MQVPN_SERVER_CALLBACKS_INIT;
        scb.tun_output = unexpected_packet; scb.tunnel_config_ready = server_ready;
        scb.send_packet = server_send; scb.session_tun_output = server_packet;
        scb.on_client_connected = connected; scb.on_client_disconnected = disconnected;
        mqvpn_client_callbacks_t ccb = MQVPN_CLIENT_CALLBACKS_INIT;
        ccb.tun_output = client_packet; ccb.tunnel_config_ready = client_ready;
        p->server = mqvpn_server_new(s, &scb, p); p->client = mqvpn_client_new(c, &ccb, p);
        ok = p->server && p->client;
    }
    mqvpn_config_free(s); mqvpn_config_free(c);
    if (!ok) return false;
    for (unsigned i = 0; i < 2; ++i) {
        path_t *path = &p->paths[i]; mqvpn_path_desc_t desc = {.struct_size = sizeof(desc)};
        memcpy(desc.local_addr, &path->client_addr, sizeof(path->client_addr)); desc.local_addr_len = sizeof(path->client_addr);
        memcpy(desc.remote_addr, &path->server_addr, sizeof(path->server_addr)); desc.remote_addr_len = sizeof(path->server_addr);
        path->handle = mqvpn_client_add_path_fd(p->client, path->client_fd, &desc);
        if (path->handle < 0) return false;
    }
    if (mqvpn_server_start(p->server) != MQVPN_OK || mqvpn_client_set_server_addr(p->client,
            (const struct sockaddr *)&p->paths[0].server_addr, sizeof(p->paths[0].server_addr)) != MQVPN_OK ||
        mqvpn_client_connect(p->client) != MQVPN_OK) return false;
    uint64_t end = now_ms() + 15000U;
    while (!p->failed && !interrupted && now_ms() < end) {
        pump(p);
        if (p->ready && !p->activated) {
            if (mqvpn_client_set_tun_active(p->client, 1, -1) != MQVPN_OK) return false;
            p->activated = true;
        }
        if (p->activated && p->connections == 1 && two_active(p)) return true;
        (void)poll(NULL, 0, 1);
    }
    return false;
}

static bool send_inner(probe_t *p, bool from_client, bool ack, unsigned seq)
{
    uint8_t bytes[PACKET_BYTES]; size_t len = packet(p, bytes, from_client, ack, seq);
    return (from_client ? mqvpn_client_on_tun_packet(p->client, bytes, len)
                        : mqvpn_server_on_tun_packet(p->server, bytes, len)) == MQVPN_OK;
}

static bool transfer(probe_t *p, unsigned phase, unsigned count, bool client)
{
    p->phase = phase; p->count = count; p->sender_is_client = client;
    p->unique = 0; p->acknowledged = 0; p->application_sends = 0; p->application_retries = 0;
    memset(p->seen, 0, sizeof(p->seen)); memset(p->acknowledged_chunks, 0, sizeof(p->acknowledged_chunks));
    memset(p->pending_ack, 0, sizeof(p->pending_ack)); memset(p->last_send, 0, sizeof(p->last_send));
    uint64_t start = now_ms(), end = start + (phase == 4 ? 45000U : 25000U);
    unsigned base = 0;
    while (!p->failed && !interrupted && now_ms() < end) {
        pump(p);
        unsigned acknowledgments = 0;
        for (unsigned seq = base > WINDOW ? base - WINDOW : 0; seq < count && acknowledgments < WINDOW * 2; ++seq) {
            if (p->pending_ack[seq]) {
                if (!send_inner(p, !client, true, seq)) { p->failed = true; break; }
                p->pending_ack[seq] = false; ++acknowledgments;
            }
        }
        while (base < count && p->acknowledged_chunks[base]) ++base;
        if (base == count && p->unique == count) break;
        uint64_t now = now_ms();
        for (unsigned seq = base; seq < count && seq < base + WINDOW; ++seq) {
            if (p->acknowledged_chunks[seq] || (p->last_send[seq] && now - p->last_send[seq] < RETRY_MS)) continue;
            if (p->last_send[seq]) ++p->application_retries;
            if (!send_inner(p, client, false, seq)) { p->failed = true; break; }
            p->last_send[seq] = now; ++p->application_sends;
        }
        (void)poll(NULL, 0, 1);
    }
    bool ok = !p->failed && !interrupted && p->unique == count && p->acknowledged == count &&
        p->connections == 1 && p->disconnections == 0;
    uint8_t digest[SHA256_DIGEST_LENGTH], expected_digest[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2 + 1], expected_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256_CTX expected_hash; SHA256_Init(&expected_hash);
    for (unsigned seq = 0; seq < count; ++seq) {
        uint8_t expected[DATA_BYTES]; payload(expected, phase, seq);
        SHA256_Update(&expected_hash, expected, sizeof(expected));
    }
    SHA256_Final(expected_digest, &expected_hash);
    SHA256(p->received, (size_t)count * DATA_BYTES, digest);
    ok = ok && memcmp(digest, expected_digest, sizeof(digest)) == 0;
    for (unsigned i = 0; i < sizeof(digest); ++i) {
        (void)snprintf(hex + i * 2, 3, "%02x", digest[i]);
        (void)snprintf(expected_hex + i * 2, 3, "%02x", expected_digest[i]);
    }
    printf("{\"phase\":%u,\"success\":%s,\"unique_chunks\":%u,\"acked_chunks\":%u,"
           "\"expected_bytes\":%zu,\"received_buffer_sha256\":\"%s\",\"expected_sha256\":\"%s\",\"application_sends\":%u,"
           "\"application_retries\":%u,\"duration_ms\":%" PRIu64 "}\n",
           phase, ok ? "true" : "false", p->unique, p->acknowledged, (size_t)count * DATA_BYTES,
           hex, expected_hex, p->application_sends, p->application_retries, now_ms() - start);
    fflush(stdout);
    return ok;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) { fprintf(stderr, "usage: warm_failover_probe TEST_CERT TEST_KEY [0|1]\n"); return 2; }
    unsigned blocked = 1;
    if (argc == 4) { if (strcmp(argv[3], "0") && strcmp(argv[3], "1")) return 2; blocked = (unsigned)(argv[3][0] - '0'); }
    struct sigaction action = {.sa_handler = stop_signal};
    sigemptyset(&action.sa_mask); (void)sigaction(SIGTERM, &action, NULL); (void)sigaction(SIGINT, &action, NULL);
    probe_t *p = calloc(1, sizeof(*p)); if (!p) return 1;
    p->received = calloc(MAX_CHUNKS, DATA_BYTES); p->blocked_path = blocked; p->started_ms = now_ms();
    for (unsigned i = 0; i < 2; ++i) p->paths[i].client_fd = p->paths[i].server_fd = -1;
    p->stage = "initialize";
    bool ok = p->received && initialize(p, argv[1], argv[2]);
    uint64_t initialized_bytes[2];
    for (unsigned i = 0; i < 2; ++i)
        initialized_bytes[i] = p->paths[i].forwarded[0] + p->paths[i].forwarded[1];
    if (ok) { p->stage = "warm_request"; ok = transfer(p, 1, 4096, true); }
    if (ok) { p->stage = "warm_response"; ok = transfer(p, 2, 8192, false); }
    if (ok) {
        p->stage = "drain"; uint64_t end = now_ms() + 1000U;
        while (!p->failed && !interrupted && now_ms() < end) { pump(p); (void)poll(NULL, 0, 1); }
        ok = !p->failed && two_active(p);
        for (unsigned i = 0; i < 2; ++i)
            ok = ok && p->paths[i].forwarded[0] + p->paths[i].forwarded[1] > initialized_bytes[i] + 65536U;
    }
    if (ok) { p->stage = "second_request"; ok = transfer(p, 3, 4096, true); }
    uint64_t survivor_before[2] = {0, 0};
    if (ok) {
        p->stage = "second_response_after_blackhole"; p->blocked = true;
        memcpy(survivor_before, p->paths[1U - blocked].forwarded, sizeof(survivor_before));
        ok = transfer(p, 4, 32768, false);
        ok = ok && p->paths[1U - blocked].forwarded[1] > survivor_before[1] + 32768U * DATA_BYTES;
    }
    printf("{\"scope\":\"native_loopback_diagnostic_not_wireguard_or_http3_acceptance\","
           "\"success\":%s,\"stage\":\"%s\",\"same_session_connections\":%u,"
           "\"disconnections_before_cleanup\":%u,\"blackholed_path_index\":%u,\"elapsed_ms\":%" PRIu64 ",\"paths\":[",
           ok ? "true" : "false", p->stage, p->connections, p->disconnections, blocked, now_ms() - p->started_ms);
    for (unsigned i = 0; i < 2; ++i) {
        path_t *path = &p->paths[i];
        printf("%s{\"index\":%u,\"uplink_outer_bytes\":%" PRIu64 ",\"downlink_outer_bytes\":%" PRIu64
               ",\"blackholed_uplink_bytes\":%" PRIu64 ",\"blackholed_downlink_bytes\":%" PRIu64 "}",
               i ? "," : "", i, path->forwarded[0], path->forwarded[1], path->dropped[0], path->dropped[1]);
    }
    puts("]}");
    if (p->client) {
        mqvpn_path_info_t paths[MQVPN_MAX_PATHS]; int count = 0;
        memset(paths, 0, sizeof(paths));
        if (mqvpn_client_get_paths(p->client, paths, MQVPN_MAX_PATHS, &count) == MQVPN_OK)
            for (int i = 0; i < count; ++i)
                fprintf(stderr, "PROBE_PATH handle=%d status=%d xquic=%u tx=%" PRIu64
                        " rx=%" PRIu64 " inflight=%" PRIu64 " cwnd=%" PRIu64 "\n",
                        (int)paths[i].handle, (int)paths[i].status, (unsigned)paths[i].xquic_path_state,
                        paths[i].bytes_tx, paths[i].bytes_rx, paths[i].bytes_in_flight,
                        paths[i].congestion_window_bytes);
    }
    if (p->client) mqvpn_client_destroy(p->client);
    if (p->server) mqvpn_server_destroy(p->server);
    for (unsigned i = 0; i < 2; ++i) {
        if (p->paths[i].client_fd >= 0) close(p->paths[i].client_fd);
        if (p->paths[i].server_fd >= 0) close(p->paths[i].server_fd);
    }
    memset(p->auth_random, 0, sizeof(p->auth_random)); memset(p->auth, 0, sizeof(p->auth));
    free(p->received); free(p); return ok ? 0 : 1;
}
