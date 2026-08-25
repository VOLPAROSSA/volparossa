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
const PREVIEW_MESSAGE: &str = "VOLPAROSSA fixed supervisor preview: the fixed disposable lifecycle now implements anonymous namespace bootstrap, exact ID mappings and PID-1/private-mount proof; pinned BOOTSTRAP_READY/GO; descriptor-relative run roots; two run-bound nsfs pins; two veth pairs; four /30 addresses; IPv6 addrgen NONE; the topology-bound generation-2 parent FORWARD policy; conditional disposable-parent IPv4 forwarding; four-end activation; two static /32 routes; four affine NUD_PERMANENT neighbours; one exact run-bound 40-byte raw ICMPv4 echo request from endpoint A and one exact 60-byte reply; two identical generation-bracketed counter observations at 1/60, 1/60, 0/0; exact four-veth telemetry at one RX and TX packet and 74 RX and TX bytes per end; reverse neighbour removal preserving post-echo telemetry; counter-agnostic link/policy teardown; semantic-empty generation 3; private-run rollback; and exact TERM/EOF/reap. The outer host IPv4-forwarding record remains byte-identical. This is fixed ICMP echo plus bounded rollback evidence; packet absence, packet-capture privacy, a general VPN datapath, an ownership manifest, network-topology readiness, TOPOLOGY_READY, forced-crash cleanup, A14, A15, and acceptance evidence remain unproved.";
const FIXED_ICMP_BLOCKED_MESSAGE: &str = "BLOCKED: one pinned BOOTSTRAP_READY and canonical GO authorized the fixed descriptor-relative private run. PID 1 proved the exact disposable parent/A/B baselines, two run-bound nsfs pins, two fixed veth pairs and four /30 addresses; installed the topology-bound generation-2 parent FORWARD policy before link activation; conditionally enabled only the disposable parent ip_forward record; activated all four ends; installed the two exact static endpoint /32 routes; and installed four exact affine NUD_PERMANENT neighbours with zero probes and zero proxy neighbours. Only structurally valid volatile NDA_CACHEINFO telemetry was excluded from neighbour equality. With those neighbours armed, PID 1 consumed zero-counter policy authority, opened one nonblocking close-on-exec raw ICMPv4 socket inside endpoint A, bound it to eth0 and 10.241.1.2, connected it to 10.241.2.2, and issued exactly one sendmsg with no retry for one 40-byte echo request. The request used the first two canonical run-ID ASCII bytes as its big-endian identifier, sequence 1, and the full 32-byte canonical ASCII run ID as payload. Before the absolute deadline, endpoint A received one exact 60-byte IPv4 echo reply; source, destination, receive interface and IP_PKTINFO, IPv4 and ICMP checksums, identifier, sequence, and full payload all matched. The socket closed before two identical complete generation-bracketed observations proved the request-accept, reply-accept, and terminal-drop counters at exactly packets/bytes 1/60, 1/60, and 0/0. Fresh semantic RTNL observations proved every one of the four veth ends at exactly one RX and one TX packet and 74 RX and TX bytes, with all other parsed link statistics zero, while routes, addresses, qdiscs, four permanent neighbours, zero probes, and zero proxy-neighbour records remained exact. PID 1 removed the neighbours in reverse endpoint B/A then parent B/A order, proved the exact routed state restored without changing the post-echo link telemetry, and re-proved the exact 1/60, 1/60, 0/0 policy-counter profile. It then converted the policy to counter-agnostic cleanup authority, deleted veth B then A, restored the exact original parent ip_forward record, proved pristine parent/endpoints under generation 2, deleted only the observed table handle, proved semantic-empty generation 3, retired lower owners, reversed nsfs/filesystem state, emitted the rollback checkpoint, and completed exact TERM/EOF/reap. The outer host ip_forward record remained byte-identical. This proves one fixed run-bound ICMPv4 echo request/reply exchange, its exact two-accept/zero-drop counter profile, matching four-veth link telemetry, and bounded configuration teardown. It does not prove packet absence, packet-capture privacy, a general VPN datapath, an ownership manifest, network-topology readiness, TOPOLOGY_READY, forced-crash cleanup, A14, A15, or acceptance evidence.";

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
            println!("{PREVIEW_MESSAGE}");
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
            Ok(LifecycleOutcome::BlockedAfterFixedIcmpEchoTeardown) => {
                eprintln!("{FIXED_ICMP_BLOCKED_MESSAGE}");
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
