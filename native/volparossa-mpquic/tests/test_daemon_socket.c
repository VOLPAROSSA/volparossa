// SPDX-License-Identifier: GPL-3.0-only

#define _GNU_SOURCE

#include "daemon_socket.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void test_secure_lifecycle(void)
{
    char directory[] = "/tmp/volparossa-mpquic-socket-XXXXXX";
    assert(mkdtemp(directory) != NULL);
    char path[108];
    const int written =
        snprintf(path, sizeof(path), "%s/control.sock", directory);
    assert(written > 0 && (size_t)written < sizeof(path));

    vmp_control_socket_t control;
    assert(vmp_control_socket_open(path, geteuid(), &control) == 0);
    struct stat metadata;
    assert(lstat(path, &metadata) == 0);
    assert(S_ISSOCK(metadata.st_mode));
    assert(metadata.st_uid == geteuid());
    assert((metadata.st_mode & 0777U) == 0600U);
    assert(metadata.st_nlink == 1);

    vmp_control_socket_t duplicate;
    errno = 0;
    assert(vmp_control_socket_open(path, geteuid(), &duplicate) != 0);
    assert(errno == EADDRINUSE);

    vmp_control_socket_close(&control);
    assert(lstat(path, &metadata) != 0 && errno == ENOENT);
    assert(rmdir(directory) == 0);
}

static void test_unsafe_parent_is_rejected(void)
{
    char directory[] = "/tmp/volparossa-mpquic-unsafe-XXXXXX";
    assert(mkdtemp(directory) != NULL);
    assert(chmod(directory, 0755) == 0);
    char path[108];
    const int written =
        snprintf(path, sizeof(path), "%s/control.sock", directory);
    assert(written > 0 && (size_t)written < sizeof(path));

    vmp_control_socket_t control;
    errno = 0;
    assert(vmp_control_socket_open(path, geteuid(), &control) != 0);
    assert(errno == EPERM);
    assert(rmdir(directory) == 0);
}

int main(void)
{
    test_secure_lifecycle();
    test_unsafe_parent_is_rejected();
    puts("daemon socket lifecycle tests passed");
    return 0;
}
