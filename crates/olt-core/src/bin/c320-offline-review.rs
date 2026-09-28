//! Offline-only C320 operator evidence import from TWO fixed files.
//! NEVER network, SSH, login, firmware upload or physical verification.
use olt_core::{consistent_inventory, parse_cards, parse_running_versions, MAX_OUTPUT};
use std::{
    env,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

fn private_folder(path: &Path) -> Result<(), ()> {
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(());
    }
    let m = path.symlink_metadata().map_err(|_| ())?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o700
    {
        return Err(());
    }
    Ok(())
}
fn read_fixed(dir: &Path, name: &str) -> Result<String, ()> {
    let p = dir.join(name);
    let before = p.symlink_metadata().map_err(|_| ())?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.mode() & 0o777 != 0o600
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_OUTPUT as u64
    {
        return Err(());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)
        .map_err(|_| ())?;
    let after = file.metadata().map_err(|_| ())?;
    if !after.is_file()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.uid() != unsafe { libc::geteuid() }
        || after.mode() & 0o777 != 0o600
        || after.nlink() != 1
        || after.len() == 0
        || after.len() > MAX_OUTPUT as u64
    {
        return Err(());
    }
    let mut data = String::new();
    file.take(MAX_OUTPUT as u64 + 1)
        .read_to_string(&mut data)
        .map_err(|_| ())?;
    if data.len() > MAX_OUTPUT {
        return Err(());
    }
    Ok(data)
}
fn main() {
    let args: Vec<_> = env::args_os().collect();
    if args.len() == 2 && args[1] == "--requirements" {
        println!("R71_OFFLINE_READ_ONLY=show card,show version-running");
        println!("OWNER_PRIVATE_DIR=0700;FIXED_FILES=cards.txt,versions.txt;FILE_MODE=0600");
        println!("NO_LOGIN_NO_NETWORK_NO_FIRMWARE_NO_PHYSICAL_VERIFICATION");
        return;
    }
    if args.len() != 3
        || args[1] != "--parse"
        || env::var("IPAT_R71_OWNER_CONFIRMS_REDACTED_OFFLINE_CAPTURE").as_deref() != Ok("YES")
    {
        eprintln!("R71_DENIED: explicit offline private-capture opt-in required");
        std::process::exit(4)
    }
    let dir = PathBuf::from(&args[2]);
    let run = || -> Result<(usize, usize), ()> {
        private_folder(&dir)?;
        let cards = parse_cards(&read_fixed(&dir, "cards.txt")?).map_err(|_| ())?;
        let versions =
            parse_running_versions(&read_fixed(&dir, "versions.txt")?).map_err(|_| ())?;
        if !consistent_inventory(&cards, &versions) {
            return Err(());
        }
        Ok((cards.len(), versions.len()))
    };
    match run() {
        Ok((cards, versions)) => {
            println!(
                "R71_OFFLINE_SYNTAX_ONLY=PASS CARDS={} VERSION_ROWS={}",
                cards, versions
            );
            println!("PHYSICAL_DEVICE_IDENTITY=UNVERIFIED INTEROPERABILITY=UNTESTED");
            println!("TENANT_BINDING=FALSE FIRMWARE_EXECUTION=DISABLED");
        }
        Err(()) => {
            eprintln!(
                "R71_DENIED: untrusted directory/file, output format or card/version mismatch"
            );
            std::process::exit(4)
        }
    }
}
