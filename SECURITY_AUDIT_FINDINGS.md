# Blue-team audit of orb-software: findings and proofs of concept

Date: 2026-10-08. Scope: the device-side daemons in this monorepo at commit
`1a76ec7`. Method: full source read of `update-agent`, `update-verifier`,
`update-agent-loader`, `orb-jobs-agent`, `orb-connd`, `attest`, `supervisor`,
`security-utils`, `ipcp-hpke`, `qr-link`, `efivar`, `slot-ctrl`, `agentwire`
and the smaller parsers, plus the shipped systemd units. No production code was
modified; every PoC is a test or script added next to the code it targets.

This is an internal defensive write-up. The repository's `SECURITY.md` asks
that vulnerabilities be reported to HackerOne or `security@worldcoin.org`
before publication, so treat this document as confidential until that is done.

## How to run the PoCs

All PoC tests assert the *current* (vulnerable) behaviour, so they pass today
and start failing once the issue is fixed.

```sh
# OTA update path (no hardware needed)
cargo test -p orb-update-agent-core --test poc_claim_signature
cargo test -p orb-update-agent --test poc_update_trust

# Remote job executor (needs dbus-daemon on PATH; the fixture's port picker
# requires IPv6 loopback, so on IPv4-only hosts vendor `portpicker` and run
# with --config 'patch.crates-io.portpicker.path="<dir>"' after dropping its
# IPv6 bind checks)
cargo test -p orb-jobs-agent --test poc_job_argv

# Signed WiFi/NetConfig QR replay (pure Python, mirrors the on-device check)
python3 -I security-poc/netconfig_replay.py
```

Observed on 2026-10-08: all six Rust PoC tests pass and the Python script
prints the replay and one-sided-timestamp results.

## Ranked findings

Severity is for the Orb device. "Attacker position" names the weakest position
from which the bug is reachable.

### 1. HIGH: signed manifest hash is never enforced for `application/octet-stream` components

- Where: `update-agent/src/component.rs:262-268` (`process` is a no-op for
  `OctetStream`), `update-agent/src/component.rs:740` (only the unsigned
  `sources[*].hash` is checked in `fetch`), `update-agent/src/component.rs:329`
  (`do_install` opens the raw download).
- What: the Ed25519 signature covers only the raw `manifest` JSON. The
  manifest carries each component's size and hash, but for octet-stream
  sources those values are never compared with the bytes that reach the
  partition writer, the capsule path, or `orb-mcu-util image update`. The
  manifest hash check lives only in `process_helper`, reached for XZ and
  bidiff sources.
- Attacker position: anyone who controls the claim document the agent fetches
  (compromised fleet backend, a mis-issued CA since the claim endpoint uses
  system roots with no pinning and no authentication, or a local claim file
  in recovery/`--update-location` mode). The signing key is not needed.
- Attack: take any genuine claim, keep `manifest` and `manifest-sig`, rewrite
  `sources.<name>` to `{"mime_type":"application/octet-stream","hash":sha256(evil),"size":len(evil),"url":...}`.
  The root agent installs `evil`, then sets `BootChainFwNext` to the new slot.
- Impact: arbitrary partition, QSPI, MCU firmware, or UEFI capsule content.
  Where secure boot or dm-verity covers the target this degrades to a reliable
  remote brick; non-verity partitions and MCU images are fully exposed.
- PoC: `poc_f1_octet_stream_skips_signed_manifest_hash` in
  `update-agent/tests/poc_update_trust.rs`. Same bytes are rejected on the XZ
  path and accepted on the octet-stream path.
- Fix: run `check_existing_component(on_disk, manifest.size, manifest.hash)`
  immediately before `do_install` for every mime type, or require
  `source.hash == manifest.hash && source.size == manifest.size` for
  octet-stream.

### 2. HIGH: `system_components` and `sources` are outside the signature, so a signed payload can be redirected anywhere

- Where: `update-agent/core/src/claim.rs:174-178` (signature over
  `manifest_raw` only), `update-agent/core/src/components.rs` (`Gpt`, `Raw`,
  `Can`, `Capsule` destinations), `update-agent/src/update/raw.rs:34-70`,
  `update-agent/src/update/gpt.rs:91-170`.
- What: the claim's destination map is attacker-writable. With a genuine
  signed rootfs the claim author can set the destination to QSPI offset 0,
  to the active slot's partition (`redundancy: single` adds no slot suffix),
  or to a different CAN node. `docs/src/ota/ota-structure.md` already calls
  the signature a "bonus" that does not protect the rest of the claim.
- Attacker position: same as finding 1.
- Impact: brick or overwrite of the running slot with signed-but-misplaced
  data; combined with finding 1, arbitrary content anywhere.
- PoC: `poc_f2_system_components_not_covered_by_signature` in
  `update-agent/core/tests/poc_claim_signature.rs`. One signature validates
  three different destination maps; tampering with the manifest itself is
  rejected.
- Fix: sign the whole claim (or the component-to-destination table), or keep
  a fixed on-device destination table keyed by component name and refuse
  claims that disagree with it.

### 3. MEDIUM-HIGH: path traversal and arbitrary root file write via unsigned `sources[*].name`

- Where: `update-agent/core/src/claim.rs:60` (`unique_name` = `name-hash`),
  `update-agent/src/util.rs:38` (`Path::join`), `update-agent/src/component.rs:513,566-600`
  (file opened with `create(true)` and the HTTP body written to it).
- What: both `name` and `hash` are free text from the unsigned part of the
  claim. `../../../usr/persistent/x` escapes the downloads directory and an
  absolute name discards it entirely. Contents are attacker-chosen because
  only the attacker-chosen `sources.hash` is checked.
- Attacker position: same as finding 1.
- Impact: root write to any writable path (`/usr/persistent`, scratch
  storage, the agent's own `claim.json` workspace). The rootfs is read-only
  squashfs so impact is bounded by what persists and what other services
  read from persistent storage.
- PoC: `poc_f3_source_name_path_traversal` in
  `update-agent/tests/poc_update_trust.rs`.
- Fix: derive the filename from the manifest component name plus a
  hex-validated hash, reject separators and `..`, and verify the canonical
  path stays under the downloads directory.

### 4. HIGH (by design, but worth a control): `read_file` job is an unrestricted root file read whose output is also logged

- Where: `orb-jobs-agent/src/handlers/read_file.rs:10-13`,
  `orb-jobs-agent/src/job_system/client.rs:179-184` (whole
  `JobExecutionUpdate` incl. `std_out` logged at info).
- What: no allow-list, no size cap, symlinks followed. The result is sent to
  the backend and also written to journald, which feeds Datadog.
- Attacker position: anyone who can deliver a `JobExecution` to the orb. The
  agent never checks `msg.from` (`client.rs:43-117`), so this is the relay
  server's sender policy, which is outside this repo.
- Impact: `/etc/shadow`, NetworkManager keyfiles with PSKs, tokens, any key
  on disk; `read_file /dev/zero` OOM-kills the root daemon.
- PoC: `poc_j1_read_file_has_no_allowlist` in
  `orb-jobs-agent/tests/poc_job_argv.rs`.
- Fix: allow-list directories, cap size, open with `O_NOFOLLOW`, and stop
  logging `std_out`.

### 5. MEDIUM: option and glob injection into privileged argv in `fsck`, `service` and `logs` jobs

- Where: `orb-jobs-agent/src/handlers/fsck.rs:18,26`,
  `orb-jobs-agent/src/handlers/service_control.rs:56`,
  `orb-jobs-agent/src/handlers/logs.rs:41,63`.
- What: the job token is placed where the tool parses options or patterns.
  `fsck -a` runs `umount -a` then `fsck -y -f -a`; `service stop *` runs
  `systemctl stop *`; `logs 100000000 *` buffers the whole journal in memory.
  Nothing goes through a shell, so this is semantic, not quoting.
- Attacker position: same as finding 4.
- Impact: unmount of every data partition, stopping arbitrary units including
  attest and the agent itself, memory exhaustion.
- PoC: `poc_j3_fsck_option_injection` and
  `poc_j3_service_accepts_glob_and_arbitrary_units` in
  `orb-jobs-agent/tests/poc_job_argv.rs`.
- Fix: reject tokens starting with `-`, require `/dev/` paths for `fsck`,
  allow-list unit names, bound `-n`.

### 6. MEDIUM: `ApplyMagicResetQr` on the session bus is unauthenticated and unlocks unsigned WiFi provisioning on production orbs

- Where: `orb-connd/src/service/dbus.rs:266-294` (no release, signature or
  caller check), `orb-connd/src/service/dbus.rs:104-125` (unsigned
  `ApplyWifiQr` allowed for 10 minutes after a reset, or whenever
  connectivity is not FULL).
- What: one D-Bus call deletes every WiFi profile except the built-in hotspot
  and opens a window in which an unsigned MECARD QR becomes the top-priority
  persistent profile.
- Attacker position: any process that can reach `/tmp/worldcoin_bus_socket`
  (group `worldcoin-dbus`, per the comment in the backend-status unit). The
  bus policy file is not in this repo, so whether a per-method restriction
  exists could not be verified.
- Impact: loss of operator WiFi credentials (also purged from secure storage)
  and attacker-chosen network with highest priority.
- PoC: the existing integration test
  `orb-connd/tests/qr_codes.rs::it_applies_magic_reset_qr` performs exactly
  this sequence on `OrbRelease::Prod`. It needs the Docker fixture and OP-TEE
  headers, which this container lacks.
- Fix: restrict the method by D-Bus policy to orb-core's uid, or require a
  signed payload for the reset.

### 7. MEDIUM: signed NetConfig QR is replayable fleet-wide and the freshness check is caller-controlled and one-sided

- Where: `orb-connd/src/service/netconfig.rs:84-117` (signature over the
  message, no orb id), `orb-connd/src/service/dbus.rs:172-191` (`check_ts`
  is a D-Bus argument; only `delta > 10 min` is rejected).
- What: a single fleet-wide P-256 key signs the QR. Any photographed signed
  QR works on every orb of that release class. If the caller passes
  `check_ts=false` it works forever; with `check_ts=true` a QR dated in the
  future always passes.
- Attacker position: physical presence (scan a replayed QR) plus whatever
  calls `ApplyNetconfigQr`; the in-repo callers are only tests, the real one
  is orb-core.
- PoC: `security-poc/netconfig_replay.py` verifies the shipped production
  test vector under the embedded prod key, shows it is 366 days old, and
  shows the freshness logic accepts future timestamps.
- Fix: always enforce the window, reject `|delta| > 10 min`, bind the orb id
  into the signed message.

### 8. MEDIUM: hard-coded default WiFi profile `hotspot` / `easytotypehardtoguess` auto-connects and cannot be removed

- Where: `orb-connd/src/service/mod.rs:76-77,238-275,636`,
  `orb-connd/nm_cfg/20-defaults.conf` (WiFi route metric beats cellular).
- What: public credentials, autoconnect, priority above cellular, protected
  from deletion. An evil AP with that SSID gets a network position and, by
  blackholing the connectivity check, flips the orb into the state where
  unsigned `ApplyWifiQr` is allowed (finding 6 without the bus access).
- Mitigation that holds: all backend HTTP uses pinned roots and TLS 1.3
  (`security-utils`), so this is traffic visibility and selective DoS, not
  backend MITM.
- Fix: per-device credentials or a lower priority than cellular, and do not
  treat the hotspot's lack of connectivity as permission for unsigned QR.

### 9. MEDIUM: supervisor's `ScheduleShutdown` and `RequestUpdatePermission` have no caller check; supervisor runs as root with no sandboxing

- Where: `supervisor/src/interfaces/manager.rs:146-233`,
  `supervisor/debian/orb-supervisor.worldcoin-supervisor.service`.
- What: any session-bus peer can power off or reboot the orb via logind and
  can stop `worldcoin-core` to start an update. A code-execution bug in any
  sandboxed non-root daemon on that bus becomes "reboot the orb at will".
- Fix: check the caller's uid from the message header, or a bus policy.

### 10. MEDIUM: no client-side rollback or version binding in the update agent

- Where: `ManifestComponent.version_assert` / `version_upgrade` are never
  read; `claim.version` and `magic` are never validated;
  `ORB_UPDATE_AGENT_VERSION_OVERWRITE` (`update-agent/src/main.rs:274`).
- What: every manifest ever signed with the production key remains
  installable by whoever controls the claim channel. Combine with finding 2
  to put old signed firmware anywhere.
- Fix: enforce `version_assert` per component and a monotonic signed
  version counter.

### 11. LOW-MEDIUM: verify-then-reopen-by-path in the update agent (TOCTOU)

- Where: hash checked at `component.rs:740` and `:119,:152`, file reopened
  at `:329` after a potentially long wait on
  `supervisor_proxy.request_update_permission()` (`main.rs:380`).
- What: a local principal with write access to the downloads directory can
  swap the verified file before install. Whether such a principal exists
  depends on the permissions of scratch/persistent storage, not shown in
  this repo.
- Fix: hash and install from the same open file descriptor, or re-hash
  immediately before writing.

### 12. LOW-MEDIUM: agentwire parent trusts child output in shared memory

- Where: `agentwire/src/port.rs:844-850` (`rkyv::access_unchecked` on bytes
  the child wrote, length prefix unchecked).
- What: the parent spawns sandboxed child agents (minijail optional) and then
  deserializes their output without validation. A compromised child can
  panic the parent (length larger than buffer) or feed crafted relative
  pointers for out-of-bounds reads in the parent, which defeats the sandbox
  boundary. Only a concern for consumers that run untrusted-input agents in
  the child (orb-core, outside this repo).
- Fix: use `rkyv::access` with validation and bound the length.

### 13. LOW: root `chmod -R` / `chown -R` on a user-owned directory in the attest unit

- Where: `attest/debian/orb-attest.worldcoin-attest.service` runs
  `+/bin/chmod -R +rX /usr/persistent/se` and
  `+/bin/chown -R worldcoin:worldcoin /usr/persistent/se` as root on every
  start, while the directory is owned by `worldcoin`.
- What: if the `worldcoin` user can rename `/usr/persistent/se` and replace
  it with a symlink, the next attest start chowns the target to `worldcoin`.
  Whether `/usr/persistent` is writable by that user is not visible here.
- Fix: drop the `-R` fixups, or use `chown -h` and a fixed owner at
  provisioning time.

### 14. LOW: denial-of-service edges in root daemons

- `update-agent/src/component.rs:628-632`: a source with `size: 0` and a
  server replying `Content-Length: 0` divides by zero (release: wraps then
  panics on `/ component_remote_len`).
- `update-agent/src/update/can.rs:136`: empty firmware wraps the block count
  and still sends `FwImageCheck` / `FwImageSecondaryActivate`.
- XZ extraction and `update-agent-loader` download are unbounded
  (decompression bomb, RAM exhaustion before signature check).
- `orb-jobs-agent/src/handlers/logs.rs:74-97`: `logs tail <quiet unit>`
  never times out, the `journalctl -f` child is never killed, and three such
  jobs permanently block every sequential job (`orchestrator.rs:172-180`).
- `orb-connd/src/reporters/conn_quality.rs:203-233`: backend- or
  zenoh-supplied `TestPayloadBytes` is unbounded, `vec![0u8; bytes]` aborts
  the process; `IntervalSecs: 1` plus a large payload burns metered data.
- `attest/src/remote_api.rs:510-513`: token `duration` of 0 or 1 s panics
  the main task (`Duration - Duration` underflow).
- `orb-jobs-agent/src/conn_change.rs:26-27,47`: one malformed zenoh sample
  permanently kills the connectivity watcher.

### 15. Informational

- `orb-jobs-agent` sanitises secrets only for the literal `wifi_add ` prefix
  (`sanitize.rs:16,34`); `wifi_add{...}` without a space is logged unredacted,
  including the PSK.
- Any `zenohd`-group process can declare `job/wifi_add` and receive the PSK
  the backend sends through the zoci fall-through (`ctx.rs:291-340`); the
  zenohd ACL is not in this repo.
- `attest` exposes `Token` and `ForceTokenRefresh` to every session-bus peer
  by design; the bus policy decides who that is.
- `zorb when` substitutes zenoh payloads into `bash -c` (`zorb/src/main.rs:281-299`);
  dev tool only.
- The `no-sig` build flavor (`skip-manifest-signature-verification`) is a
  real CI artifact; make sure it can never ship.
- `bidiff-squashfs` shim: allocator mismatch in `Vec::from_raw_parts` over
  g_malloc memory and no bounds check on block offsets; build-side only.

## Checked and found sound

- Manifest signature mechanics: `verify_strict`, pinned JWKs with SHA-256
  checksums, signature over the verbatim `RawValue`, `Claim` only
  constructible through `ClaimVerificationContext`.
- XZ and bidiff outputs verified against the signed manifest; bipatch output
  bounded by patch size; GPT writes bounds-checked; EFI variable writes use
  fixed, validated values; `update-agent-loader` verifies the signature over
  the sealed memfd before `fexecve`.
- All backend HTTP: pinned AWS/GTS/Starfield roots, TLS 1.3 minimum, HTTPS
  only, redirects disabled; no `danger_accept_invalid_certs` anywhere.
- QR to NetworkManager path uses typed D-Bus values; no wpa_supplicant.conf
  writing, no `nmcli`, no shell. MECARD and NetConfig parsers terminate and
  do not panic on hostile input; signature is verified before parsing.
- Every `Command::new` in the audited daemons uses argv arrays; the only
  `sh -c` in the tree is in a test and in the `zorb` dev tool.
- `ipcp-hpke`, `header-parsing`, `wld-data-id`, `orb-health`, the OP-TEE
  storage client and `qr-link` have no exploitable input handling.
- `orb-monitoring-auth` checks `SO_PEERCRED` uid before serving tokens.
- connd's secure-storage subprocess drops to a dedicated uid; connd, attest,
  update-verifier and backend-status units are hardened (non-root,
  `ProtectSystem=strict`, syscall filters). `update-agent`, `orb-jobs-agent`
  and `supervisor` run as root with no hardening.

## Items that need verification outside this repository

1. The `/tmp/worldcoin_bus_socket` busconfig: per-method `send_destination`
   restrictions for connd, supervisor and attest (findings 6, 9, 15).
2. The relay server's sender policy for the `jobs` namespace (finding 4).
3. zenohd ACLs on `/run/zenohd/zenohd.sock` (finding 15).
4. Ownership and mode of `/usr/persistent`, the update downloads directory
   and scratch storage (findings 11, 13).
5. Whether orb-core passes `check_ts=true` to `ApplyNetconfigQr` (finding 7).
6. Which partitions and MCU images are covered by secure boot or dm-verity
   authenticity checks rather than self-consistency (findings 1, 2).
