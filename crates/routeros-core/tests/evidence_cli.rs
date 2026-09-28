//! Integration test: CLI never opens a device connection; zero credentials.
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

fn synthetic_redacted() -> Vec<u8> {
    br#"{
      "target_id":"DEV-08","model":"RB951Ui-2HnD","architecture":"mipsbe",
      "routeros":"7.23.7 (stable)",
      "test_scope":"one_authenticated_read_only_rest_get","method":"GET",
      "resource":"/rest/system/resource","read_observed":true,
      "operator_review_complete":false,"physical_device_enrolled":false,
      "tenant_binding_verified":false,"compatibility_verified":false,
      "configuration_modified":false,"hardware_revision":"NOT_OBSERVED",
      "observed_at_utc":"2026-09-26T05:52:00+00:00"
    }"#
    .to_vec()
}

fn run(path: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_routeros-lab-evidence"))
        .arg("--input")
        .arg(path)
        .output()
        .expect("run offline evidence validator")
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let folder =
            std::env::temp_dir().join(format!("ipat-routeros-r62-cli-{}", std::process::id()));
        assert!(!folder.exists(), "test folder unexpectedly exists");
        DirBuilder::new()
            .mode(0o700)
            .create(&folder)
            .expect("create isolated test dir");
        Self(folder)
    }

    fn file(&self, filename: &str, data: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join(filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .expect("create synthetic test artifact");
        file.write_all(data).expect("write redacted fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("set synthetic permissions");
        path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove synthetic evidence");
    }
}

#[test]
fn offline_cli_accepts_only_private_syntactically_valid_redacted_input() {
    let temp = TestDir::new();
    let valid = temp.file("redacted-valid.json", &synthetic_redacted(), 0o600);
    let output = run(&valid);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("R62_OFFLINE_REDACTED_SCHEMA_PASS=DEV-08"));
    assert!(stdout.contains("COMPATIBILITY=UNVERIFIED"));
    assert!(!stdout.contains("routeros") && !stdout.contains("RB951"));

    let unsafe_mode = temp.file("readable.json", &synthetic_redacted(), 0o644);
    let output = run(&unsafe_mode);
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(output.stderr, b"R62_OFFLINE_EVIDENCE_DENIED\n");

    let malformed = temp.file("unsafe.json", b"{\"password\":\"SYNTHETIC_SECRET\"}", 0o600);
    let output = run(&malformed);
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(output.stderr, b"R62_OFFLINE_EVIDENCE_DENIED\n");

    let alias = temp.0.join("symlink.json");
    std::os::unix::fs::symlink(&valid, &alias).unwrap();
    assert_eq!(run(&alias).status.code(), Some(4));
}
