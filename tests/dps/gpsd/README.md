# Bounded public GPSD adapter proof

Run only through the explicit hosted opt-in in the existing DPS native workflow.
These scripts are not an installer or an operator GPSD launcher. The production
CLI connects only after the user explicitly selects an existing local GPSD.

The workflow first invokes system Python on `build.py --evidence-dir ABS
--source-revision SHA`. The evidence directory must already be a private,
canonical child of RUNNER_TEMP. The builder checks the exact clean source and
workflow revision. It reconstructs GPSD 3.25-5+deb13u2 from four authenticated
Debian source inputs and all eleven Debian patches, then compiles normal and
ASan/UBSan copies. It never invokes GPSD, gpspipe or upstream tests outside the
namespace. No install, systemd, udev, pip, apt or container command is used.

Three pinned Ubuntu all.deb support packages are verified before private
extraction: SCons 4.5.2+dfsg-1, setuptools and pkg-resources 68.1.2-2ubuntu1.2.
Their declared dependency closure adds only the existing system Python. They do
not replace the hosted Python, compiler or libc; actual versions are recorded.
No borrowed package manager cache, user Python site or ambient PYTHONPATH is used.
A fixed private Python carrier activates only that extracted support directory
for upstream's Python3.12 distutils probes/test helpers. It does not alter GPSD
source or the product's gpspipe executable selection. Clang is set explicitly in
the build environment because GPSD reads compiler selection from that environment.
The carrier supports upstream's exact mandatory `-tt -m py_compile tmp.py` form
without executing the file. Other module/interpreter flag forms fail closed;
no general module runner is added. The 23 Python contracts include actual hosted
carrier compilation success/syntax failure, rejected module forms and private
support resolution. This carrier correction skips or removes no upstream check
target; the complete pinned Debian series and selected build configuration remain
unchanged.

The workflow then invokes the existing wrapper's narrow interface:

```
scripts/run-isolated-test.sh --dps-gpsd-command \
  ABS_WORKSPACE/target/debug/volparossa ABS_EVIDENCE_DIR \
  ABS_EVIDENCE_DIR/build-receipt.json
```

The wrapper supplies the fixed controller plus actual parent namespace markers,
brings up only disposable loopback, and drops to the original nonzero UID with
empty supplementary groups, zero capabilities and NoNewPrivs. Separate IPC is
required because GPSD can allocate NTP shared memory even when time-service and
SHM location export options are disabled. PID teardown is the outer failure fence.
The controller separately verifies all three namespace identities and credentials.

Inside that boundary, the controller runs upstream `scons check` with a fatal
exit status, then the four real gpsfake -> PTY -> GPSD -> gpspipe -> Core cases in
`manifest.json`. The positive fixture uses PASHR,POS native ellipsoidal height,
repeated WGS84 DTM, RMC and ZDA. It contains no GGA-derived positive. All epochs
are real current UTC minus three, two and one seconds; no old record is stamped
fresh. Actual GPSD report scheduling and datum propagation must pass the runtime
trial; source inspection alone does not establish them.

Normal Python gpsfake/packet helpers drive both copies; in the sanitizer case,
GPSD_HOME selects the instrumented daemon and PATH selects instrumented gpspipe.
The Core CLI has no test-only executable override. `/proc` observations bind its
actual child executable and argv to the hashed build. Static libgps linkage avoids
LD_LIBRARY_PATH authority; sanitizer flags and both symbol families are checked.
Both C and C++ compilation receive `-fno-sanitize-recover=all`, and the proof
requires that exact flag receipt. UBSan failures therefore terminate gpspipe even
though the product deliberately clears sanitizer environment options and discards
private child stderr. Core must observe a successful child join before returning
quality. The fixture daemon additionally receives ASan leak detection and UBSan
halt-on-error options; these options do not expand the product child environment.
After collecting three epochs, Core may SIGKILL and reap gpspipe. That bounded
instrumented workload proves fatal-fault refusal and the observed kill/reap
contract; it does not prove normal-exit LeakSanitizer teardown, a leak-clean full
gpspipe program, or complete program shutdown coverage.

Original bounded logs, per-case cleanup and final JSON are retained separately.
The only raw coordinates/times saved are the explicitly public synthetic fixture.
The quality response contains no coordinates, receiver time or device path.
The radius is an operator comparison claim with unknown confidence. Navigation
authentication, datum verification, physical accuracy and independent positioning
remain unproved. A mode-3 report and three epochs from one source remain one claim.

Python contracts run with system Python on `test_proof.py` in the approved runner.
They test malformed archives, exact pins, hostile JSON, fixture/time construction,
quality-claim boundaries, isolation rejection and subprocess bounds/reaping.
No contract or native trial was executed on the development host.
