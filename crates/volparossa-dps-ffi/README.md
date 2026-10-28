# Native DPS quality ABI 1

This library calls the existing `DpsAssessRequest::assess(now)` implementation
and validates its result. It receives a **bare canonical Protobuf request**,
not a `ControlRequest` or authority to access the administrative socket. It does
not acquire clocks, sensors, radio observations, sockets or files, persist inputs,
log requests, share data or replace OS location. The C smoke test alone reads
four public synthetic fixture files.

`include/volparossa_dps.h` defines the complete C/C++ interface. One caller-owned
input produces a caller-owned 36-byte summary of nine `uint32_t` values. The
summary contains versions, status, caller-asserted frame kind, claim/pair counts
and the seven mandatory limitations. It contains no candidate coordinates,
source/observation/correlation IDs, group counts or timestamps. ECEF is an asserted
reference, not proof of a geographic anchor. Consistency is not physical truth.

Input is limited to 16,384 bytes **before** Protobuf decoding. Existing structural
validation still limits claims to 32, IDs to 16 bytes, frame shapes and enum values.
Exact re-encoding rejects unknown/duplicate fields, explicit defaults, reordered
fields and overlong varints; this bridge is intentionally stricter about encoding
than the existing socket parser. Observation list order is allowed and the shared
assessor retains its permutation-independent semantics. Invalid geometry, stale
claims and different frames remain ordinary excluded observations, not fabricated
adapter failures. The clock is supplied explicitly by the host and is unverified.

The v1 maximum canonical request calculation is 32 × (127 + 2) + 2 + 22 + 4 =
**4,156 bytes**: each observation has three 18-byte IDs, 2-byte source kind,
22-byte local frame, four 9-byte doubles, an 11-byte timestamp and 2-byte
authentication claim. Its body length is 127, needing one tag and one length byte.
The request adds version, desired local frame and maximum-age fields. A regression constructs and encodes this extremum using Prost. The bound is a
structural encoding property, not physical-positioning evidence. The larger
decode cap remains finite even for inputs rejected after decoding.

All seven limitation bits are required, exactly `0x7f`:

| Bit | Shared service limitation |
| --- | --- |
| 0 | CallerSuppliedEvidence |
| 1 | PhysicalIntegrityUnverified |
| 2 | PhysicalIndependenceUnverified |
| 3 | UncertaintyConfidenceUnknown |
| 4 | NoSensorFusion |
| 5 | NoSensorOrClockVerification |
| 6 | PairwiseConsistencyOnly |

Return zero means a validated summary, including valid **unavailable** outcomes.
Nonzero closed errors distinguish argument, input bound, message, request and
internal failures; they leave output unchanged and must never be presented as
successful positioning. No raw decoder/validation error is returned or formatted.

Null/output-alignment/output-size/range-overflow/overlap checks run before any
dereference. These checks are **not a native-pointer sandbox**. The caller must
own readable input and aligned writable output allocations, with adequate size,
valid lifetime and no conflicting concurrent accesses. Non-null dangling,
unmapped, read-only or racing pointers cannot be proved safe. A later JNI bridge
must use its own bounded copies instead of forwarding arbitrary Java addresses.

Unsafe Rust is confined to the `ffi` module. This package mirrors every workspace
Rust/Clippy lint except `unsafe_code = deny`, allowing that one documented module;
the existing workspace and local-control `forbid` remain untouched. Unwinding is
caught at the C boundary, without replacing global panic hooks. A process's
existing hook may still emit diagnostics before a caught panic. The existing
release profile uses `panic=abort`; aborting panics, allocation failures and OS
faults remain outside the recoverable-error contract.

The hosted workflow binds exact source and vectors, checks the lint exception,
executes Rust contract tests and real C11/C++17 callers linked to the static
library, with AddressSanitizer and UndefinedBehaviorSanitizer on those callers.
The stable Rust library is not sanitizer-instrumented: native coverage exercises
its real boundary, caller accesses and intercepted allocator operations, not all
internal Rust instructions. Separate ordinary C/C++ executables additionally run
under [Valgrind Memcheck](https://valgrind.org/docs/manual/mc-manual.html), which
observes accesses made by the actual Rust static library as well. That gate
requires zero reported errors, including definite/indirect/possible leaks. It uses
the official [Ubuntu Noble Valgrind package](https://packages.ubuntu.com/noble/valgrind)
`1:3.22.0-0ubuntu3` plus `libc6-dbg` at exactly the runner's already installed libc
version, on the guarded disposable hosted runner only. Authenticated apt metadata
is retained by the normal package mechanism; the workflow forbids upgrades and
fails if the matching pinned packages are unavailable. Package/tool versions enter
the artifact. It does not install tools on the development host.

Adding an ABI or passing its synthetic callers does not establish positioning.
The [current DPS/Map checkpoint](../../docs/IMPLEMENTATION_STATUS.md#decentralized-positioning-system--2026-10-21)
separates accepted quality-only ABI/debug JNI evidence from real sensors,
permission authority, navigation, fusion and physical integrity, which remain open.
