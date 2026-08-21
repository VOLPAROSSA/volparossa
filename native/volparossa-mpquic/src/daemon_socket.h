// SPDX-License-Identifier: GPL-3.0-only

#ifndef VOLPAROSSA_MPQUIC_DAEMON_SOCKET_H
#define VOLPAROSSA_MPQUIC_DAEMON_SOCKET_H

#include <stdbool.h>
#include <sys/types.h>

typedef struct vmp_control_socket {
    int listening_fd;
    int parent_fd;
    dev_t device;
    ino_t inode;
    uid_t owner;
    bool bound;
    char basename[108];
} vmp_control_socket_t;

/* Opens a regular pathname AF_UNIX SOCK_STREAM socket. Every path component
 * is traversed without symlinks; the final parent must be owned by owner with
 * mode 0700. The socket is verified as owner-owned, nlink 1, and mode 0600. */
int vmp_control_socket_open(const char *absolute_path, uid_t owner,
                            vmp_control_socket_t *out);

/* Closes and unlinks only if the path still names the exact inode created by
 * vmp_control_socket_open. */
void vmp_control_socket_close(vmp_control_socket_t *socket);

#endif
