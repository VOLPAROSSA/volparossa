//! Exact command-line entry point for the disposable lifecycle supervisor.

use std::{env, ffi::OsStr, process::ExitCode};

use volparossa_netns_runner::{
    BLOCKED_EXIT_CODE, INTERNAL_CHILD_ARGUMENT, INTERNAL_ERROR_EXIT_CODE,
    INTERNAL_PID_ONE_ARGUMENT, LifecycleOutcome, run_fixed_lifecycle, run_internal_child,
    run_internal_pid_one,
};

const PREVIEW_ARGUMENT: &str = "--preview";
const RUN_ARGUMENT: &str = "--run";
const USAGE_EXIT_CODE: u8 = 64;

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let first = arguments.next();
    if arguments.next().is_some() {
        print_usage();
        return ExitCode::from(USAGE_EXIT_CODE);
    }
    match first.as_deref() {
        Some(argument) if argument == OsStr::new(INTERNAL_CHILD_ARGUMENT) => run_internal_child(),
        Some(argument) if argument == OsStr::new(INTERNAL_PID_ONE_ARGUMENT) => {
            run_internal_pid_one()
        }
        Some(argument) if argument == OsStr::new(PREVIEW_ARGUMENT) => {
            println!(
                "VOLPAROSSA fixed supervisor preview: anonymous namespace bootstrap, exact UID/GID mapping, exact self-reexec PID-1 proof, private mounts, fixed pidfd-to-signalfd supervision, an exact pristine RTNL and generation-1 nftables baseline, one pinned BOOTSTRAP_READY, one canonical GO, descriptor-relative private-run roots and slots, two run-bound nsfs endpoint pins, two atomic down-veth pairs, four fixed /30 IPv4 addresses, an all-IPv6-addrgen-NONE barrier, a canonically topology-bound atomic generation-2 parent FORWARD policy, four-end activation, two exact main-table static /32 endpoint routes, direct veth deletion B then A while that policy remains exact, pristine parent/endpoint proof under generation 2, handle-only policy deletion, semantic-empty generation 3 and final reproof before lower-owner retirement, reverse nsfs/filesystem rollback, and exact TERM/EOF/reap are implemented. The inherited canonical IPv4 ip_forward value remains byte-identical; packets, probes, dataplane or topology readiness, TOPOLOGY_READY, A14, A15, and acceptance evidence remain blocked."
            );
            ExitCode::SUCCESS
        }
        Some(argument) if argument == OsStr::new(RUN_ARGUMENT) => match run_fixed_lifecycle() {
            Ok(LifecycleOutcome::BlockedBeforeIsolation) => {
                eprintln!(
                    "BLOCKED: kernel policy did not permit the fixed anonymous namespace and ID-mapping bootstrap; no GO was emitted."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Ok(LifecycleOutcome::BlockedAfterIsolation) => {
                eprintln!(
                    "BLOCKED: anonymous namespaces were created, but kernel policy did not permit the required outer proof or exact ID mappings; no GO was emitted."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Ok(LifecycleOutcome::BlockedAtPidOneProof) => {
                eprintln!(
                    "BLOCKED: anonymous namespaces and exact ID mappings were verified, but kernel policy hid the required outer PID-1 proof; no GO was emitted."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Ok(LifecycleOutcome::BlockedAtPrivateMountSetup) => {
                eprintln!(
                    "BLOCKED: anonymous namespaces, exact ID mappings, and a self-reexecuted PID 1 were verified, but kernel policy denied the fixed private-mount setup; no BOOTSTRAP_READY or GO was emitted."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Ok(LifecycleOutcome::BlockedAfterForwardPolicyTeardown) => {
                eprintln!(
                    "BLOCKED: one pinned BOOTSTRAP_READY and canonical GO authorized the descriptor-relative private run, two live run-bound nsfs endpoint pins, two fixed veth pairs, four fixed /30 IPv4 addresses, an all-IPv6-addrgen-NONE barrier, and one canonically topology-bound parent FORWARD policy. Before link activation, PID 1 atomically installed and freshly proved one run-bound inet vpl_<run_id> table at generation 2, one priority-0 filter base chain at the forward hook with policy drop, and exactly two accept rules: the A-to-B IPv4 ICMP echo-request tuple and its exact B-to-A echo reply. It retained and re-proved that exact policy through four-end activation, the two exact static endpoint /32 routes, and direct veth deletion B then A. While generation 2 remained active, PID 1 proved the parent and both endpoints byte-exactly equal to their retained baselines while every route, address, and pair owner remained armed. It then deleted only the freshly observed table handle, proved a semantically empty generation 3, repeated the final parent/endpoint proof, and only then retired those lower owners. PID 1 unmounted nsfs B then A, restored the hidden slots, reversed every private-run creation, and emitted one rollback-complete checkpoint. The outer independently re-proved empty private mounts before fixed pidfd-to-PID1-signalfd TERM, post-GO cleanup-required EOF, and exact reap. The inherited canonical IPv4 ip_forward value remained byte-identical and was never written. This proves bounded exact policy, topology, and teardown configuration only; it makes no packet-absence, packet-capture, probe, datapath, ownership-manifest, network-topology-readiness, TOPOLOGY_READY, A14, A15, or acceptance-evidence claim."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Ok(LifecycleOutcome::BlockedByManagedSignal) => {
                eprintln!(
                    "BLOCKED: a managed outer termination signal triggered bounded fail-closed containment; no topology-completion, cleanup-evidence, or acceptance claim was made."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Err(error) => {
                eprintln!("ERROR: {error}");
                ExitCode::from(INTERNAL_ERROR_EXIT_CODE)
            }
        },
        _ => {
            print_usage();
            ExitCode::from(USAGE_EXIT_CODE)
        }
    }
}

fn print_usage() {
    eprintln!("usage: volparossa-netns-runner --preview|--run");
}
