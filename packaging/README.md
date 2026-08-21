# Debian packaging

`build-deb.sh` previews by default. Its explicit `--build` mode builds the locked release workspace,
stages only known files in a fresh temporary directory, and creates
`dist/volparossa_<version>_amd64.deb` with root-owned archive metadata. It
does not install the package, invoke systemd, or alter networking. Build mode refuses root and
refuses to overwrite an existing candidate.

```sh
./packaging/build-deb.sh --preview
SOURCE_DATE_EPOCH=1767225600 ./packaging/build-deb.sh --build
```

If `SOURCE_DATE_EPOCH` is absent, the script uses the latest Git commit timestamp and falls back to
zero in an uncommitted source tree. A release should build the same committed source twice in clean
Debian 13 environments and compare SHA-256 digests. Locked Cargo sources and the audited native
source revisions remain part of the reproducibility boundary.

The package refuses to build unless these release binaries exist after the Cargo build:

- `/usr/bin/volparossa`;
- `/usr/bin/volparossa-agent`;
- `/usr/libexec/volparossa/volparossa-helper`;
- `/usr/libexec/volparossa/volparossa-mpquic`.

The services are installed but not enabled. `volparossa` and `volparossa-users` system groups are
created. The service account is a member of both; human operators who need the agent control socket
must be added deliberately to `volparossa-users` and re-login. That group cannot access the helper
socket, which is root-owned, group `volparossa`, mode 0660.

The systemd units are deliberately strict candidates. They must pass `systemd-analyze security` and
the complete Debian 13 namespace suite before release. `ProtectKernelTunables=no` on the helper is a
documented exception needed for namespace-local MPTCP sysctls; the typed helper must prove it never
writes host sysctls. Do not weaken the other sandbox settings merely to hide an implementation bug.

Package removal stops services but preserves `/var/lib/volparossa`, including the encrypted identity.
See `docs/OPERATIONS.md` for scoped cleanup and explicit irreversible data removal.

The packaged native systemd unit is not operational yet. API v4 moves client auth and the TLS
server name into bounded, expiring route-session messages and accepts no static product secret from
the launcher. `AddPath` consumes exactly one request-bound UDP descriptor, but SCM_RIGHTS and its
request hash do not authenticate privileged-helper origin. A reviewed launcher remains blocked
until the agent orchestrates separate role-specific processes/control sockets, helper acquisition
binds trusted descriptor provenance end to end, and the exit receives its listener plus TLS
certificate/key descriptors without secret argv, environment, or files. Until then, `--build`
exits 77 before compilation, no candidate package is created, and the installed service set must
not be enabled.
