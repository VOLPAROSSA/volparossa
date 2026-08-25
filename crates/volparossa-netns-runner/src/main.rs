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
                "VOLPAROSSA fixed supervisor preview: anonymous namespace bootstrap, exact UID/GID mapping, exact self-reexec PID-1 proof, private mounts, fixed pidfd-to-signalfd supervision, the exact new-netns RTNL baseline, a descriptor-anchored stable canonical IPv4 ip_forward value, zero nftables tables bracketed by unchanged generation 1, one pinned BOOTSTRAP_READY, one canonical GO, descriptor-relative private-run roots and slots, two distinct live network namespaces published as run-bound nsfs pins, two fixed down-veth pairs each created atomically, exact parent/A/B down-veth delta proof, four fixed /30 IPv4 addresses and exactly four kernel-owned local-table /32 routes proved while every veth end remained down, reverse address rollback endpoint B then A and parent B then A, byte-exact reproof of the retained down-veth state, reverse veth deletion B then A, pristine parent/endpoint rollback proof, ordinary reverse nsfs unmount B then A, and exact reverse filesystem rollback are implemented; link activation, explicit route requests, forwarding changes, nftables mutations, packets, probes, dataplane topology, TOPOLOGY_READY, A14, A15, and acceptance evidence remain blocked."
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
            Ok(LifecycleOutcome::BlockedAfterIpv4AddressRollback) => {
                eprintln!(
                    "BLOCKED: one pinned BOOTSTRAP_READY and canonical GO authorized descriptor-relative private-run roots, two live run-bound nsfs pins, two fixed down-veth pairs, and one scoped four-address transaction. Each pair was created atomically with its eth0 peer born directly in the exact retained endpoint namespace. PID 1 proved the exact parent and A/B down-veth deltas, installed and exactly proved 10.241.1.1/30, 10.241.1.2/30, 10.241.2.1/30, and 10.241.2.2/30 plus exactly four kernel-owned local-table /32 routes while every veth end remained down, rolled back endpoint B then A and parent B then A, re-proved the byte-exact retained down-veth state, deleted veth B then A, proved parent and both endpoints pristine again, unmounted nsfs B then A, restored the hidden slots, and reversed every private-run creation. It emitted one rollback-complete checkpoint, and the outer independently re-proved empty private mounts before fixed pidfd-to-PID1-signalfd TERM, post-GO cleanup-required EOF, and exact reap. No link was activated, no explicit route request was sent, and no connected, main-table, default, or explicit host route, forwarding change, nftables mutation, packet, probe, ownership manifest, network-topology readiness, TOPOLOGY_READY, A14, A15, or acceptance evidence was produced."
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
