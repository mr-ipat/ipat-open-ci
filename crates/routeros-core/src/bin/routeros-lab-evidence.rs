//! Owner-local OFFLINE and NON-PRIVILEGED only. No network or DB capability.
//! Checks redacted PRIVATE probe file shape; cannot authenticate physical I/O.
use routeros_core::evidence::normalize_staged_lab_evidence;
use routeros_core::ApprovedReadProfile;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

fn validate() -> Result<(), ()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1] != "--input" {
        return Err(());
    }
    let source = PathBuf::from(&args[2]);
    if !source.is_absolute() {
        return Err(());
    }
    // Never permit secrets or raw device payloads in repository test
    // fixtures. The only accepted artifact is a redacted owner-only file.
    let canonical = source.canonicalize().map_err(|_| ())?;
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .map_err(|_| ())?;
    let repo_root = repo.parent().and_then(|p| p.parent()).ok_or(())?;
    if canonical.starts_with(repo_root) {
        return Err(());
    }
    let stat = fs::symlink_metadata(&source).map_err(|_| ())?;
    if !stat.is_file() || stat.file_type().is_symlink() {
        return Err(());
    }
    if stat.permissions().mode() & 0o777 != 0o600 || stat.len() > 2_048 {
        return Err(());
    }
    let parent = canonical.parent().ok_or(())?;
    let pstat = fs::metadata(parent).map_err(|_| ())?;
    if !pstat.is_dir() || pstat.permissions().mode() & 0o077 != 0 {
        return Err(());
    }
    let file = File::open(&source).map_err(|_| ())?;
    let opened = file.metadata().map_err(|_| ())?;
    if opened.ino() != stat.ino() || opened.dev() != stat.dev() {
        return Err(());
    }
    let mut bytes = Vec::new();
    file.take(2_049).read_to_end(&mut bytes).map_err(|_| ())?;
    let proof = normalize_staged_lab_evidence(&bytes, ApprovedReadProfile::Dev08OwnerReportedRb951)
        .map_err(|_| ())?;
    if proof.physical_read_reviewed()
        || proof.physical_enrollment_authorized()
        || proof.tenant_binding_verified()
        || proof.configuration_writes_permitted()
    {
        return Err(());
    }
    println!(
        "R62_OFFLINE_REDACTED_SCHEMA_PASS=DEV-08; PHYSICAL_READ_AUTHENTICATED=NO; \
         TENANT_ENROLLED=NO; COMPATIBILITY=UNVERIFIED"
    );
    Ok(())
}

fn main() {
    if validate().is_err() {
        // Never interpolate a private file path, raw payload or secret.
        eprintln!("R62_OFFLINE_EVIDENCE_DENIED");
        std::process::exit(4);
    }
}
