// SPDX-License-Identifier: GPL-3.0-only
//! Hosted-only real CLI publication, roles-off agent crash recovery and local signed preview.
//! An explicit local artifact is never a named-cache, overlay or hosting authorization.

#[path = "studio_signed_site_recovery/browser.rs"]
mod browser;
#[path = "studio_signed_site_recovery/fixture.rs"]
mod fixture;
#[path = "studio_signed_site_recovery/process.rs"]
mod process;
#[path = "studio_signed_site_recovery/scenario.rs"]
mod scenario;
#[path = "studio_signed_site_recovery/site.rs"]
mod site;
#[cfg(test)]
#[path = "studio_signed_site_recovery/tests.rs"]
mod tests;

use std::cell::Cell;

use serde::Serialize;

type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize)]
struct Counts {
    positive_cli_started: u8,
    positive_cli_joined: u8,
    daemon_started: u8,
    crash_joined: u8,
    graceful_joined: u8,
    negative_cli_started: u8,
    negative_cli_joined: u8,
    cli_rejections: u8,
    agent_rejections: u8,
    #[serde(skip)]
    failure_joined: u8,
}
impl Counts {
    fn complete(self) -> bool {
        self == Self {
            positive_cli_started: 6,
            positive_cli_joined: 6,
            daemon_started: 2,
            crash_joined: 1,
            graceful_joined: 1,
            negative_cli_started: 2,
            negative_cli_joined: 2,
            cli_rejections: 2,
            agent_rejections: 0,
            failure_joined: 0,
        }
    }
}
#[derive(Clone, Copy, Default)]
enum Cleanup {
    #[default]
    NotStarted,
    Unconfirmed,
    FailureJoined,
    CrashJoined,
    GracefulJoined,
}
struct Progress {
    counts: Cell<Counts>,
    cleanup: Cell<Cleanup>,
}
impl Progress {
    fn new() -> Self {
        Self {
            counts: Cell::new(Counts::default()),
            cleanup: Cell::new(Cleanup::NotStarted),
        }
    }
    fn count(&self, update: impl FnOnce(&mut Counts)) {
        let mut counts = self.counts.get();
        update(&mut counts);
        self.counts.set(counts);
    }
}
fn stage(value: &'static str) {
    println!(
        "\nSTUDIO_SIGNED_SITE_DIAGNOSTIC {}",
        serde_json::json!({"schema":1,"stage":value})
    );
}

#[test]
#[ignore = "requires fresh pinned Silex export and isolated disposable hosted browser fixture"]
fn studio_signed_site_recovery_native_preview_and_browser() {
    assert_eq!(
        std::env::var("VOLPAROSSA_REQUIRE_STUDIO_SIGNED_SITE_PROOF").as_deref(),
        Ok("1")
    );
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(
        std::env::var("RUNNER_ENVIRONMENT").as_deref(),
        Ok("github-hosted")
    );
    let parent = std::env::var_os("VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS")
        .expect("explicit isolated hosted wrapper");
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net")
            .expect("current namespace")
            .as_os_str(),
        parent
    );
    assert!(
        !nix::unistd::geteuid().is_root(),
        "fixture requires non-root process"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fixture runtime");
    let result = runtime.block_on(scenario::run());
    match result {
        Ok(receipt) => println!("\nSTUDIO_SIGNED_SITE_PROOF {receipt}"),
        Err(reason) => panic!("studio_signed_site_recovery_failed:{reason}"),
    }
}
