// SPDX-License-Identifier: GPL-3.0-only

#define _GNU_SOURCE

#include "daemon_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static void socket_zero(void *memory, size_t len)
{
    volatile uint8_t *bytes = memory;
    while (len > 0U) {
        *bytes++ = 0U;
        --len;
    }
}

static bool normal_absolute_path(const char *path)
{
    if (path == NULL || path[0] != '/') return false;
    const size_t len = strlen(path);
    if (len < 2U || len >= sizeof(((struct sockaddr_un *)0)->sun_path) ||
        path[len - 1U] == '/') {
        return false;
    }
    for (size_t index = 1U; index < len; ++index) {
        if (path[index] == '/' && path[index - 1U] == '/') return false;
    }
    const char *component = path + 1;
    while (*component != '\0') {
        const char *slash = strchr(component, '/');
        const size_t component_len =
            slash == NULL ? strlen(component) : (size_t)(slash - component);
        if (component_len == 0U || component_len > NAME_MAX ||
            (component_len == 1U && component[0] == '.') ||
            (component_len == 2U && component[0] == '.' &&
             component[1] == '.')) {
            return false;
        }
        if (slash == NULL) break;
        component = slash + 1;
    }
    return true;
}

static int open_parent(const char *path, char basename[108])
{
    char copy[108];
    const size_t len = strlen(path);
    memcpy(copy, path, len + 1U);
    char *last_slash = strrchr(copy, '/');
    if (last_slash == NULL || last_slash[1] == '\0') {
        errno = EINVAL;
        return -1;
    }
    const size_t basename_len = strlen(last_slash + 1);
    memcpy(basename, last_slash + 1, basename_len + 1U);
    *last_slash = '\0';

    int directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return -1;
    if (copy[0] == '\0') return directory;

    char *component = copy + 1;
    while (*component != '\0') {
        char *slash = strchr(component, '/');
        if (slash != NULL) *slash = '\0';
        const int next = openat(directory, component,
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                    O_CLOEXEC);
        if (next < 0) {
            const int saved = errno;
            close(directory);
            errno = saved;
            return -1;
        }
        close(directory);
        directory = next;
        if (slash == NULL) break;
        component = slash + 1;
    }
    return directory;
}

static bool safe_parent(int parent_fd, uid_t owner)
{
    struct stat metadata;
    return fstat(parent_fd, &metadata) == 0 && S_ISDIR(metadata.st_mode) &&
           metadata.st_uid == owner && (metadata.st_mode & 0777U) == 0700U;
}

static int enter_parent(int parent_fd, int *saved_directory)
{
    *saved_directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (*saved_directory < 0) return -1;
    if (fchdir(parent_fd) != 0) {
        const int saved = errno;
        close(*saved_directory);
        *saved_directory = -1;
        errno = saved;
        return -1;
    }
    return 0;
}

static int leave_parent(int saved_directory)
{
    const int result = fchdir(saved_directory);
    const int saved = errno;
    close(saved_directory);
    errno = saved;
    return result;
}

static bool matching_socket(const struct stat *metadata, uid_t owner)
{
    return S_ISSOCK(metadata->st_mode) && metadata->st_uid == owner &&
           (metadata->st_mode & 0777U) == 0600U && metadata->st_nlink == 1;
}

static int clear_stale_socket(int parent_fd, const char *basename, uid_t owner)
{
    struct stat before;
    if (fstatat(parent_fd, basename, &before, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!matching_socket(&before, owner)) {
        errno = EEXIST;
        return -1;
    }

    const int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (probe < 0) return -1;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    const size_t name_len = strlen(basename);
    memcpy(address.sun_path, basename, name_len + 1U);
    const socklen_t address_len =
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + name_len + 1U);
    const int connected =
        connect(probe, (const struct sockaddr *)&address, address_len);
    const int connect_error = errno;
    close(probe);
    if (connected == 0 || connect_error == EINPROGRESS ||
        connect_error == EALREADY) {
        errno = EADDRINUSE;
        return -1;
    }
    if (connect_error != ECONNREFUSED) {
        errno = connect_error;
        return -1;
    }

    struct stat after;
    if (fstatat(parent_fd, basename, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        !matching_socket(&after, owner)) {
        errno = EAGAIN;
        return -1;
    }
    return unlinkat(parent_fd, basename, 0);
}

int vmp_control_socket_open(const char *absolute_path, uid_t owner,
                            vmp_control_socket_t *out)
{
    if (out == NULL || !normal_absolute_path(absolute_path)) {
        errno = EINVAL;
        return -1;
    }
    socket_zero(out, sizeof(*out));
    out->listening_fd = -1;
    out->parent_fd = -1;
    out->owner = owner;

    const int parent_fd = open_parent(absolute_path, out->basename);
    if (parent_fd < 0 || !safe_parent(parent_fd, owner)) {
        const int saved = parent_fd < 0 ? errno : EPERM;
        if (parent_fd >= 0) close(parent_fd);
        socket_zero(out, sizeof(*out));
        out->listening_fd = -1;
        out->parent_fd = -1;
        errno = saved;
        return -1;
    }

    int saved_directory = -1;
    if (enter_parent(parent_fd, &saved_directory) != 0 ||
        clear_stale_socket(parent_fd, out->basename, owner) != 0) {
        const int saved = errno;
        if (saved_directory >= 0) (void)leave_parent(saved_directory);
        close(parent_fd);
        socket_zero(out, sizeof(*out));
        out->listening_fd = -1;
        out->parent_fd = -1;
        errno = saved;
        return -1;
    }

    const int listening =
        socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listening < 0) {
        const int saved = errno;
        (void)leave_parent(saved_directory);
        close(parent_fd);
        errno = saved;
        return -1;
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    const size_t name_len = strlen(out->basename);
    memcpy(address.sun_path, out->basename, name_len + 1U);
    const socklen_t address_len =
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + name_len + 1U);
    const mode_t previous_mask = umask(0077);
    const int bind_result =
        bind(listening, (const struct sockaddr *)&address, address_len);
    const int bind_error = errno;
    (void)umask(previous_mask);
    if (bind_result != 0 ||
        fchmodat(parent_fd, out->basename, 0600, 0) != 0 ||
        listen(listening, 16) != 0) {
        const int saved = bind_result != 0 ? bind_error : errno;
        if (bind_result == 0) (void)unlinkat(parent_fd, out->basename, 0);
        close(listening);
        (void)leave_parent(saved_directory);
        close(parent_fd);
        socket_zero(out, sizeof(*out));
        out->listening_fd = -1;
        out->parent_fd = -1;
        errno = saved;
        return -1;
    }

    struct stat metadata;
    const bool verified =
        fstatat(parent_fd, out->basename, &metadata,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        matching_socket(&metadata, owner);
    const int verify_error = verified ? 0 : EPERM;
    if (leave_parent(saved_directory) != 0 || !verified) {
        const int saved = !verified ? verify_error : errno;
        (void)unlinkat(parent_fd, out->basename, 0);
        close(listening);
        close(parent_fd);
        socket_zero(out, sizeof(*out));
        out->listening_fd = -1;
        out->parent_fd = -1;
        errno = saved;
        return -1;
    }

    out->listening_fd = listening;
    out->parent_fd = parent_fd;
    out->device = metadata.st_dev;
    out->inode = metadata.st_ino;
    out->bound = true;
    return 0;
}

void vmp_control_socket_close(vmp_control_socket_t *socket)
{
    if (socket == NULL) return;
    if (socket->listening_fd >= 0) close(socket->listening_fd);
    if (socket->bound && socket->parent_fd >= 0) {
        struct stat metadata;
        if (fstatat(socket->parent_fd, socket->basename, &metadata,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
            metadata.st_dev == socket->device &&
            metadata.st_ino == socket->inode &&
            matching_socket(&metadata, socket->owner)) {
            (void)unlinkat(socket->parent_fd, socket->basename, 0);
        }
    }
    if (socket->parent_fd >= 0) close(socket->parent_fd);
    socket_zero(socket, sizeof(*socket));
    socket->listening_fd = -1;
    socket->parent_fd = -1;
}
