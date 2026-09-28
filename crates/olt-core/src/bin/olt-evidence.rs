//! R9.18 purely LOCAL owner-supplied C320 read-only CLI capture validator.
//! No device network calls, no SSH, no secrets, no tenant enrollment.
use olt_core::{consistent_inventory, parse_cards, parse_running_versions, CardStatus, MAX_OUTPUT};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

fn owner_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("absolute path without traversal required".into());
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "owner directory unavailable")?;
    if !meta.file_type().is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o777 != 0o700
    {
        return Err("owner 0700 directory required".into());
    }
    // Raw customer / board evidence must never be copied into ANY Git worktree.
    for ancestor in path.ancestors() {
        if ancestor.join(".git").exists() {
            return Err("raw device evidence must stay outside source repositories".into());
        }
    }
    Ok(())
}
fn read_private(path: &Path) -> Result<String, String> {
    let parent = path.parent().ok_or("missing parent")?;
    owner_directory(parent)?;
    let before = fs::symlink_metadata(path).map_err(|_| "missing private capture")?;
    if !before.file_type().is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.permissions().mode() & 0o777 != 0o600
        || before.len() == 0
        || before.len() > MAX_OUTPUT as u64
    {
        return Err("capture requires exact owner-only 0600 file <=32KiB".into());
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "refused unsafe capture file")?;
    let after = f.metadata().map_err(|_| "capture changed")?;
    if after.dev() != before.dev() || after.ino() != before.ino() {
        return Err("capture changed during read".into());
    }
    let mut data = Vec::new();
    f.take(MAX_OUTPUT as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "cannot read capture")?;
    if data.len() > MAX_OUTPUT {
        return Err("capture exceeded size".into());
    }
    String::from_utf8(data).map_err(|_| "capture must be UTF-8 text".into())
}
fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn parse(cards_raw: &str, versions_raw: Option<&str>) -> Result<Value, String> {
    let cards = parse_cards(cards_raw).map_err(|_| "exact C320 card layout not validated")?;
    let card_items:Vec<Value>=cards.iter().map(|c|json!({
        "location":c.location,
        "configured_type":c.configured_type,
        "observed_type":c.card_type,
        "state":match c.status{CardStatus::InService=>"INSERVICE",CardStatus::Standby=>"STANDBY"}
    })).collect();
    let (version_items, consistent, version_sha) = if let Some(v) = versions_raw {
        let parsed =
            parse_running_versions(v).map_err(|_| "exact C320 version layout not validated")?;
        if !consistent_inventory(&cards, &parsed) {
            return Err("board type/slot version evidence contradicts card snapshot".into());
        }
        (
            parsed
                .iter()
                .map(|x| {
                    json!({"location":x.location,"type":x.card_type,
           "kind":x.file_kind,"version":x.version})
                })
                .collect::<Vec<_>>(),
            true,
            Some(sha256_hex(v)),
        )
    } else {
        (Vec::new(), false, None)
    };
    let card_count = card_items.len();
    Ok(json!({
      "device_slot":"DEV-01",
      "evidence_class":"OWNER_SUPPLIED_OFFLINE_UNATTESTED_CAPTURE",
      "requested_action":"READ_ONLY_CARD_AND_OPTIONAL_FIRMWARE_INVENTORY",
      "cards":card_items,"running_versions":version_items,
      "cards_sha256":sha256_hex(cards_raw),
      "versions_sha256":version_sha,
      "card_count":card_count,
      "card_version_consistency_checked":consistent,
      "physical_chassis_identity_verified":false,
      "running_firmware_from_real_device_verified":false,
      "live_service_impact_measured":false,
      "independent_approver_verified":false,
      "device_adopted":false,
      "network_actions":0,"remote_commands_executed":0,"firmware_write_enabled":false,
      "operational_status":"LOCAL_CAPTURE_NEEDS_INDEPENDENT_PHYSICAL_REVIEW"
    }))
}
fn execute(args: &[String]) -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("refuse root for owner-only evidence parsing".into());
    }
    let (mut cards, mut versions, mut output) = (None, None, None);
    let mut iter = args.iter().skip(1);
    while let Some(flag) = iter.next() {
        let value = iter.next().ok_or("all flags require path values")?;
        if value.is_empty() {
            return Err("empty capture path".into());
        }
        let target = PathBuf::from(value);
        match flag.as_str() {
            "--cards" if cards.is_none() => cards = Some(target),
            "--versions" if versions.is_none() => versions = Some(target),
            "--out" if output.is_none() => output = Some(target),
            _ => return Err("unknown or duplicate capture flag".into()),
        }
    }
    let cards = cards.ok_or("--cards required")?;
    let out = output.ok_or("--out required")?;
    if out.file_name().is_none() {
        return Err("output filename required".into());
    }
    let parent = out.parent().ok_or("output owner folder required")?;
    owner_directory(parent)?;
    if out.exists() || out.is_symlink() {
        return Err("never overwrite existing output".into());
    }
    let cards_raw = read_private(&cards)?;
    let versions_raw = versions.as_ref().map(|p| read_private(p)).transpose()?;
    let observation = parse(&cards_raw, versions_raw.as_deref())?;
    let data = serde_json::to_vec_pretty(&observation).map_err(|_| "json serialization failed")?;
    // We deliberately never print/return raw device transcripts on stdout.
    // Fail closed if output cannot be written entirely and synced.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&out)
        .map_err(|_| "cannot create owner-only exclusive result")?;
    let operation = (|| {
        file.write_all(&data).map_err(|_| "writing result failed")?;
        file.write_all(b"\n").map_err(|_| "closing result failed")?;
        file.sync_all().map_err(|_| "sync result failed")?;
        Ok::<(), String>(())
    })();
    if operation.is_err() {
        drop(file);
        let _ = fs::remove_file(&out);
    }
    operation?;
    println!("C320_OFFLINE_READONLY_CAPTURE_NORMALIZED_PENDING_APPROVAL");
    Ok(())
}
fn main() {
    let args: Vec<String> = env::args().collect();
    if let Err(error) = execute(&args) {
        // Reason is bounded nonsecret static or compiler-provided metadata.
        eprintln!("C320_OFFLINE_CAPTURE_DENIED: {error}");
        std::process::exit(4);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const CARDS:&str="ZXAN#show card\nRack Shelf Slot CfgType RealType Port HardVer SoftVer Status\n-------------------------\n1 1 1 ETGO ETGOD 8 091201 V1.2.5P2 INSERVICE\n1 1 3 SMXA SMXA 0 110701 V1.2.5P2 STANDBY\n";
    const VERS:&str="ZXAN#show version-running\nPhyLoc FileType VerType VerTag BuildTime VerLength\n-------------------------\n1/1/1 ETGO MVR V1.2.5P2 2013-08-27 23:36:54 5008113\n1/1/3 SMXA MVR V1.2.5P2 2013-08-28 07:15:09 13982546\n";
    #[test]
    fn parses_strict_offline_card_plus_version_without_claiming_hardware() {
        let result = parse(CARDS, Some(VERS)).unwrap();
        assert_eq!(result["card_count"], 2);
        assert_eq!(result["cards"][0]["observed_type"], "ETGOD");
        assert_eq!(result["card_version_consistency_checked"], true);
        assert_eq!(result["physical_chassis_identity_verified"], false);
        assert_eq!(result["running_firmware_from_real_device_verified"], false);
        assert_eq!(result["firmware_write_enabled"], false);
        assert_eq!(result["device_adopted"], false);
        assert_eq!(result["network_actions"], 0);
        assert_eq!(result["remote_commands_executed"], 0);
        assert_eq!(result["cards_sha256"].as_str().unwrap().len(), 64);
    }
    #[test]
    fn first_bounded_card_capture_without_versions_still_pending() {
        let result = parse(CARDS, None).unwrap();
        assert_eq!(result["cards"][1]["state"], "STANDBY");
        assert_eq!(result["card_version_consistency_checked"], false);
        assert!(result["running_versions"].as_array().unwrap().is_empty());
        assert!(result["versions_sha256"].is_null());
        assert_eq!(result["device_adopted"], false);
    }
    #[test]
    fn rejects_injected_shell_control_duplicate_and_conflicting_version() {
        assert!(parse(&CARDS.replace("ETGOD", "ETGOD;reboot"), None).is_err());
        assert!(parse(&format!("{CARDS}\x1b[0m"), None).is_err());
        assert!(parse(
            &format!("{CARDS}1 1 1 ETGO ETGOD 8 091201 V1.2.5P2 INSERVICE\n"),
            None
        )
        .is_err());
        assert!(parse(CARDS, Some(&VERS.replace("1/1/1 ETGO", "1/1/1 OTHER"))).is_err());
        assert!(parse(
            CARDS,
            Some(&VERS.replace("1/1/3 SMXA MVR", "1/1/3 SMXA FW"))
        )
        .is_err());
    }
}
