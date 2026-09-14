//! Explicit optional real-browser proof. The normal test never requires or installs a browser.
//! Run only inside its caller's verified disposable loopback namespace. The extra mount
//! sandbox must make the host read-only and expose only a fresh private fixture as writable.

use std::{fs, path::Path, process::Stdio, time::Duration};

use tokio::{process::Command, time::timeout};

pub(super) async fn render(url: &str, root: &Path, artifact: &Path) {
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        mounts.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.get(4) == Some(&"/")
                && fields
                    .get(5)
                    .is_some_and(|flags| flags.split(',').any(|flag| flag == "ro"))
        }),
        "real browser proof requires a read-only root mount sandbox"
    );
    let status = fs::read_to_string("/proc/self/status").unwrap();
    for name in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .trim();
        assert_eq!(u64::from_str_radix(value, 16).unwrap(), 0);
    }
    assert!(status.lines().any(|line| {
        line.strip_prefix("NoNewPrivs:")
            .is_some_and(|value| value.trim() == "1")
    }));
    assert!(
        !artifact.exists(),
        "browser evidence must not overwrite an existing file"
    );
    let browser = tempfile::Builder::new()
        .prefix("isolated-browser-")
        .tempdir_in(root)
        .unwrap();
    let profile = browser.path().join("profile");
    fs::create_dir(&profile).unwrap();
    let screenshot = browser.path().join("site.png");
    let error_log = browser.path().join("firefox.stderr");
    let mut command = Command::new("/usr/bin/firefox-esr");
    for variable in [
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
        "MOZ_CRASHREPORTER_DATA_DIRECTORY",
    ] {
        command.env(variable, browser.path());
    }
    command
        .env("MOZ_CRASHREPORTER_DISABLE", "1")
        .args(["--headless", "--no-remote", "--profile"])
        .arg(&profile)
        .args(["--window-size", "900,600", "--screenshot"])
        .arg(&screenshot)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(fs::File::create(&error_log).unwrap()))
        .kill_on_drop(true);
    let result = timeout(Duration::from_secs(30), command.status()).await;
    let errors = fs::read_to_string(&error_log).unwrap();
    if !matches!(result, Ok(Ok(status)) if status.success()) {
        fs::copy(&error_log, artifact.with_extension("stderr.txt")).unwrap();
    }
    let status = result
        .unwrap_or_else(|error| panic!("bounded real Firefox rendering: {error}: {errors}"))
        .expect("installed Firefox");
    assert!(status.success(), "browser did not render: {errors}",);
    let bytes = fs::read(&screenshot).expect("actual browser screenshot");
    assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n") && bytes.len() > 1000);
    fs::copy(&screenshot, artifact).unwrap();
    println!(
        "actual Firefox screenshot saved for visual verification; not a protected-network proof"
    );
    browser.close().unwrap();
}
