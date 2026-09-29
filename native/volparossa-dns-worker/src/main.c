/* SPDX-License-Identifier: GPL-3.0-only */
/* Private, single-request libunbound ABI shim. No listener, shell, configuration
 * file, private filesystem path, hostname argv, or persistent query storage.
 * Rust owns authorization, deadlines, concurrency, child lifetime and egress
 * address policy. The sole native dependency is the distribution libunbound. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <unbound.h>

#if UNBOUND_VERSION_MAJOR < 1 || (UNBOUND_VERSION_MAJOR == 1 && \
    (UNBOUND_VERSION_MINOR < 26 || (UNBOUND_VERSION_MINOR == 26 && UNBOUND_VERSION_MICRO < 1)))
#error "Build against reviewed libunbound 1.26.1 or a newer distribution security version"
#endif

#define HEADER_BYTES 32U
#define MAX_NAME_BYTES 253U
#define MAX_ADDRESSES 16U
#define MAX_REPLY_BYTES (HEADER_BYTES + MAX_ADDRESSES * 16U)

static const uint8_t magic[8] = {'V', 'P', 'D', 'N', 'S', '0', '0', '1'};
enum result_code { RESULT_OK, RESULT_UNAVAILABLE, RESULT_NXDOMAIN,
                   RESULT_NODATA, RESULT_BOGUS };

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8U) | bytes[1]);
}

static void write_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8U);
    bytes[1] = (uint8_t)value;
}

static void write_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24U);
    bytes[1] = (uint8_t)(value >> 16U);
    bytes[2] = (uint8_t)(value >> 8U);
    bytes[3] = (uint8_t)value;
}

static int read_exact(uint8_t *bytes, size_t length)
{
    while (length != 0U) {
        ssize_t count = read(STDIN_FILENO, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        bytes += (size_t)count;
        length -= (size_t)count;
    }
    return 1;
}

static int write_exact(const uint8_t *bytes, size_t length)
{
    while (length != 0U) {
        ssize_t count = write(STDOUT_FILENO, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        bytes += (size_t)count;
        length -= (size_t)count;
    }
    return 1;
}

static int constrain_process(void)
{
    const pid_t parent = getppid();
    const struct rlimit memory = {128U * 1024U * 1024U, 128U * 1024U * 1024U};
    const struct rlimit files = {64U, 64U};
    const struct rlimit core = {0U, 0U};
    const struct rlimit cpu = {5U, 5U};
    if (parent <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent
        || prctl(PR_SET_DUMPABLE, 0) != 0
        || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        || setrlimit(RLIMIT_CORE, &core) != 0
        || setrlimit(RLIMIT_AS, &memory) != 0
        || setrlimit(RLIMIT_NOFILE, &files) != 0
        || setrlimit(RLIMIT_CPU, &cpu) != 0) return 0;
    /* Only the inherited input/output and null stderr survive. No helper,
     * identity, route or application descriptor enters libunbound. */
    return close_range(3U, ~0U, 0) == 0;
}

static int canonical_name(const uint8_t *name, size_t length)
{
    size_t label = 0U;
    if (length == 0U || length > MAX_NAME_BYTES) return 0;
    for (size_t index = 0U; index < length; ++index) {
        const uint8_t value = name[index];
        if (value == '.') {
            if (label == 0U || label > 63U || name[index - 1U] == '-') return 0;
            label = 0U;
        } else {
            if (!((value >= 'a' && value <= 'z') || (value >= '0' && value <= '9')
                  || (value == '-' && label != 0U))) return 0;
            ++label;
        }
    }
    return label != 0U && label <= 63U && name[length - 1U] != '-';
}

static struct ub_ctx *create_resolver(void)
{
    struct ub_ctx *context = ub_ctx_create();
    if (context == NULL) return NULL;
    /* These are fixed ABI initialization values, not remotely selectable
     * directives. Do not load resolv.conf, hosts, unbound.conf or auto-updates. */
    if (ub_ctx_debugout(context, NULL) != 0
        || ub_ctx_debuglevel(context, 0) != 0
        || ub_ctx_set_option(context, "module-config:", "validator iterator") != 0
        || ub_ctx_set_option(context, "use-syslog:", "no") != 0
        || ub_ctx_set_option(context, "log-queries:", "no") != 0
        || ub_ctx_set_option(context, "log-replies:", "no") != 0
        || ub_ctx_set_option(context, "val-log-level:", "0") != 0
        || ub_ctx_set_option(context, "val-permissive-mode:", "no") != 0
        || ub_ctx_set_option(context, "qname-minimisation:", "yes") != 0
        || ub_ctx_set_option(context, "cache-min-ttl:", "0") != 0
        || ub_ctx_set_option(context, "serve-expired:", "no") != 0
        || ub_ctx_set_option(context, "prefetch:", "no") != 0
        || ub_ctx_set_option(context, "root-hints:", "/usr/share/dns/root.hints") != 0
        || ub_ctx_add_ta_file(context, "/usr/share/dns/root.key") != 0) {
        ub_ctx_delete(context);
        return NULL;
    }
    return context;
}

static enum result_code encode_result(const struct ub_result *result,
                                     uint16_t rrtype, uint8_t *reply,
                                     size_t *reply_size)
{
    if (result == NULL) return RESULT_UNAVAILABLE;
    if (result->bogus != 0) return RESULT_BOGUS;
    if (result->qtype != (int)rrtype || result->qclass != 1
        || (result->secure != 0 && result->secure != 1)) return RESULT_UNAVAILABLE;
    if (result->rcode == 3 && result->nxdomain != 0 && result->havedata == 0)
        return RESULT_NXDOMAIN;
    if (result->rcode != 0 || result->nxdomain != 0) return RESULT_UNAVAILABLE;
    if (result->havedata == 0) return RESULT_NODATA;
    if (result->ttl <= 0 || result->data == NULL || result->len == NULL)
        return RESULT_UNAVAILABLE;
    const size_t address_size = rrtype == 1U ? 4U : 16U;
    size_t count = 0U;
    while (count < MAX_ADDRESSES && result->data[count] != NULL) {
        if (result->len[count] != (int)address_size) return RESULT_UNAVAILABLE;
        memcpy(reply + HEADER_BYTES + count * address_size,
               result->data[count], address_size);
        ++count;
    }
    if (count == 0U || result->data[count] != NULL) return RESULT_UNAVAILABLE;
    reply[9] = (uint8_t)result->secure;
    write_u16(reply + 10U, (uint16_t)count);
    write_u32(reply + 12U, (uint32_t)result->ttl);
    *reply_size = HEADER_BYTES + count * address_size;
    return RESULT_OK;
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1 || !constrain_process()) return 70;
    uint8_t request[HEADER_BYTES];
    uint8_t name[MAX_NAME_BYTES + 2U];
    uint8_t trailing;
    if (!read_exact(request, sizeof(request))
        || memcmp(request, magic, sizeof(magic)) != 0) return 71;
    const uint16_t rrtype = read_u16(request + 8U);
    const size_t name_length = read_u16(request + 10U);
    if ((rrtype != 1U && rrtype != 28U) || name_length == 0U
        || name_length > MAX_NAME_BYTES
        || request[12] != 0U || request[13] != 0U
        || request[14] != 0U || request[15] != 0U
        || !read_exact(name, name_length) || !canonical_name(name, name_length)
        || read(STDIN_FILENO, &trailing, 1U) != 0) return 71;
    name[name_length] = '.';
    name[name_length + 1U] = 0U;
    uint8_t reply[MAX_REPLY_BYTES] = {0};
    memcpy(reply, magic, sizeof(magic));
    memcpy(reply + 16U, request + 16U, 16U);
    size_t reply_size = HEADER_BYTES;
    enum result_code status = RESULT_UNAVAILABLE;
    struct ub_ctx *context = create_resolver();
    if (context != NULL) {
        struct ub_result *result = NULL;
        const int error = ub_resolve(context, (const char *)name, (int)rrtype, 1, &result);
        if (error == 0) status = encode_result(result, rrtype, reply, &reply_size);
        ub_resolve_free(result);
        ub_ctx_delete(context);
    }
    if (status != RESULT_OK) {
        memset(reply + 9U, 0, 7U);
        reply_size = HEADER_BYTES;
    }
    reply[8] = (uint8_t)status;
    return write_exact(reply, reply_size) ? 0 : 72;
}
