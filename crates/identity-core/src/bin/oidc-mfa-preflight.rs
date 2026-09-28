//! R8.5: original identity preflight for an INDEPENDENTLY provisioned OIDC IdP.
//! This NEVER authenticates a browser, grants a role, approves a device,
//! stores a token or asserts a human was really enrolled in MFA.
use identity_core::PinnedIssuer;
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
const MAX_PUBLIC_PEM: u64 = 16 * 1024;
const MAX_BEARER: u64 = 8 * 1024;
const REQUIREMENTS: &str = "R85_REQUIRES_REAL_OPERATOR_CONTROLLED_OIDC_IDP\nMandatory: independently verified HTTPS issuer, exact audience and kid,\n0600 regular owner-only pinned public PEM inside 0700 owner-only folder,\nnonroot process and real operator-attested MFA enrollment and issuer AMR mapper.\nNo tenant or role may be inferred from JWT/Host; production browser BFF\nand safe user membership provisioning must be separately implemented.\nUsage: set IPAT_R85_REAL_IDP_PREFLIGHT=YES and four IPAT_R85_ variables;\nthen pipe an independently obtained short-lived bearer via a protected FD to --verify.\nDO NOT place real access tokens in CLI arguments, logs, repository or chat.\nResult: signed-claim gate only; no production access or physical adoption.";
fn owner_pem(path: &Path) -> Result<Vec<u8>, &'static str> {
    if !path.is_absolute()
        || path.components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("invalid key path");
    }
    let parent = path.parent().ok_or("missing private parent")?;
    let uid = unsafe { libc::geteuid() };
    for (p, mode) in [(parent, 0o700), (path, 0o600)] {
        let m = fs::symlink_metadata(p).map_err(|_| "missing private file")?;
        if m.file_type().is_symlink() || m.uid() != uid || m.permissions().mode() & 0o777 != mode {
            return Err("unsafe key owner or permissions");
        }
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "key open refused")?;
    let m = f.metadata().map_err(|_| "key metadata failed")?;
    if !m.is_file()
        || m.uid() != uid
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > MAX_PUBLIC_PEM
        || m.permissions().mode() & 0o777 != 0o600
    {
        return Err("unsafe public key file");
    }
    let mut content = Vec::new();
    File::take(f, MAX_PUBLIC_PEM + 1)
        .read_to_end(&mut content)
        .map_err(|_| "key unreadable")?;
    if content.len() as u64 > MAX_PUBLIC_PEM {
        return Err("oversized key");
    }
    Ok(content)
}
fn verified() -> Result<(), &'static str> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("root denied");
    }
    if env::var("IPAT_R85_REAL_IDP_PREFLIGHT").as_deref() != Ok("YES") {
        return Err("explicit IdP preflight opt-in required");
    }
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 0 {
        return Err("refuse echoed terminal bearer input");
    }
    let issuer = env::var("IPAT_R85_ISSUER").map_err(|_| "missing pinned issuer")?;
    let aud = env::var("IPAT_R85_AUDIENCE").map_err(|_| "missing audience")?;
    let kid = env::var("IPAT_R85_KID").map_err(|_| "missing pinned key id")?;
    let path = PathBuf::from(
        env::var("IPAT_R85_PINNED_PEM_FILE").map_err(|_| "missing private pinned key file")?,
    );
    let pem = owner_pem(&path)?;
    let verifier = PinnedIssuer::new(&issuer, &aud, &kid, &pem)
        .map_err(|_| "pinned verifier configuration invalid")?;
    let mut bearer = Vec::new();
    io::stdin()
        .take(MAX_BEARER + 2)
        .read_to_end(&mut bearer)
        .map_err(|_| "cannot read protected FD")?;
    while bearer.last().is_some_and(|c| *c == b'\n' || *c == b'\r') {
        bearer.pop();
    }
    if bearer.is_empty() || bearer.len() as u64 > MAX_BEARER {
        return Err("bearer length invalid");
    }
    let token = std::str::from_utf8(&bearer).map_err(|_| "bearer encoding invalid")?;
    let subject = verifier
        .verify_access_token(token)
        .map_err(|_| "signed issuer JWT validation failed")?;
    if !subject.signed_mfa_claim() {
        return Err("exact signed MFA method claim absent");
    }
    // Absolutely no subject, tenant, key, token or role is printed or logged.
    println!("R85_PINNED_SIGNED_MFA_CLAIM_PREFLIGHT=PASS");
    println!("ACTUAL_HUMAN_MFA_ENROLLMENT_AND_BROWSER_SESSION=NOT_VERIFIED");
    println!("PRODUCTION_DEVICE_OR_BUSINESS_ACCESS=DENIED");
    Ok(())
}
fn main() {
    if env::args().count() != 2 {
        eprintln!("R85: use --requirements or --verify");
        std::process::exit(2);
    }
    match env::args().nth(1).as_deref() {
        Some("--requirements") => println!("{REQUIREMENTS}"),
        Some("--verify") => {
            if let Err(message) = verified() {
                eprintln!("R85_DENIED: {message}");
                std::process::exit(4);
            }
        }
        _ => {
            eprintln!("R85: invalid command");
            std::process::exit(2);
        }
    }
}
