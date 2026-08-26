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

The services are installed but not enabled. `volparossa`, `volparossa-users`, and
`volparossa-worker` system groups are created. The service account is a member of the first two;
human operators who need the agent control socket must be added deliberately to
`volparossa-users` and re-login. The fully locked, no-login `volparossa-worker` account has only its
same-name primary group and is never added to the `volparossa` service group. The operator group
cannot access the helper socket, which is root-owned, group `volparossa`, mode 0660.
Because `systemd-sysusers` never rewrites a pre-existing account, helper startup also reads the
root-owned bounded passwd, group, nsswitch and shadow databases. It permits only the canonical
`files` or `files systemd` account-source order, rejects local name/numeric-ID aliases, and requires
name- and number-based NSS results plus initgroups to reproduce the local package identities
exactly. The shadow metadata must prevent worker/agent mutation or broad access, and the unique live
agent and worker entries must both have `!`-prefixed passwords; the worker additionally requires
account-expiry field `1`, exactly matching Debian 13's account-wide `u!` lock. The service identities must not belong to the resolved live
`shadow` group. Enterprise LDAP/SSS/NIS account sources are deliberately unsupported by this
pre-alpha boundary and make helper startup fail closed. `volparossa doctor` reports the binding and
lock check when run with sufficient access.

The systemd units are deliberately strict candidates. They must pass `systemd-analyze security` and
the complete Debian 13 namespace suite before release. `ProtectKernelTunables=no` on the helper is a
documented exception needed for namespace-local MPTCP sysctls; the typed helper must prove it never
writes host sysctls. Do not weaken the other sandbox settings merely to hide an implementation bug.

The repository now has a component-only live worker-identity driver. Preview is always safe and
non-writing. Build the helper as the workspace user, then run the explicit gate only as root inside
a disposable Debian 13 amd64 VM:

```sh
cargo build --locked -p volparossa-helper
./tests/helper/require-live-worker-identity-proof.sh --preview
sudo ./tests/helper/require-live-worker-identity-proof.sh --execute --yes
```

The gate requires exact systemd v257 and uses synthetic read-only account overlays, a transient
`PrivateNetwork` service and a private `/run`; it never invokes `systemd-sysusers` and does not
validate an installed package. The canonical system bus socket is bound read-only into that private
`/run`, and `DBUS_SYSTEM_BUS_ADDRESS` is pinned to that verified path. The unit retains
`NotifyAccess=main`, `FileDescriptorStoreMax=128` and
`FileDescriptorStorePreserve=yes`; success requires the two exact ordered helper records and an
external post-exit `NFileDescriptorStore=2`. The helper also requires the transient parent to expose
exactly the staged agent GID as its sole kernel supplementary group, so any additional group
inherited for host root fails closed. Retirement stops only the exact random transient unit, cleans
only its `fdstore`, binds every mutation to that run's nonzero systemd v257 `InvocationID`, accepts
only a zero count or not-found unit, and resets/collects with bounded waiting. Failed one-shots are
reset inactive before cleaning. Its one-shot, numeric-group, account-overlay,
private-network/private-`/run`, bounded-output
and no-restart deviations from the shipped helper unit are enumerated in `docs/HELPER_V3.md`. No
required disposable-VM result has been recorded yet, so this is a driver rather than package,
production-service, restart-recovery, datapath, A14 or A15 evidence.

The start request atomically carries a per-stage SHA-256 `Description` ownership marker. Bounded
unit retirement normally begins after `systemd-run` returns the exact requested name plus a nonzero
lowercase `InvocationID` and the manager reports the same marker and ID. During interruption or an
invalid reply, tentative ownership may be adopted only through bounded read-only proof of that
exact marker and a nonzero current ID. Remaining ambiguity causes no unit mutation; the proof fails
and the disposable VM must be discarded.

Package removal stops services but preserves `/var/lib/volparossa`, including the encrypted identity.
See `docs/OPERATIONS.md` for scoped cleanup and explicit irreversible data removal.

The packaged native systemd unit is not operational yet. API v6 adds role/process-instance
preflight and exact request correlation, and moves client auth, TLS names, signed reservation scope,
and the exit's bounded, unparsed in-memory PEM candidate material into expiring route-session
messages. It accepts no static product secret from the launcher. `AddPath` and
`StartExitSession` each consume exactly one
operation-bound UDP descriptor, but SCM_RIGHTS and its
request hash do not authenticate privileged-helper origin. A reviewed launcher remains blocked
until the agent orchestrates separate role-specific service identities and control sockets (the
current single same-UID unit/socket is correlation, not authentication against the agent), helper
acquisition binds trusted descriptor namespace and assigned-address provenance end to end, and a
reviewed exit backend cryptographically validates and consumes the supplied listener and in-memory
material without secret argv, environment, or files. Until then, `--build`
exits 77 before compilation, no candidate package is created, and the installed service set must
not be enabled.
