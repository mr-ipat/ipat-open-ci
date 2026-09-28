//! R9.16 DEV ONLY Site A-owned public-key presentation + disabled Site B review.
//! No live tenant identity, no actual peer activation, no push, no secrets in API.
use axum::{
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Read,
    net::Ipv4Addr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

type Answer = Result<(HeaderMap, Json<Value>), (StatusCode, HeaderMap, Json<Value>)>;
fn denied(code: StatusCode) -> (StatusCode, HeaderMap, Json<Value>) {
    (
        code,
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(
            json!({"state":"DENIED","site_a_key_available":false,"network_actions":0,
                    "router_push_enabled":false,"device_adopted":false}),
        ),
    )
}
fn private(addr: Ipv4Addr) -> bool {
    let [a, b, _, _] = addr.octets();
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
}
fn validate_pub(text: &str) -> Option<String> {
    if text.len() != 44 {
        return None;
    }
    let raw = STANDARD.decode(text).ok()?;
    if raw.len() != 32 || raw.iter().all(|x| *x == 0) || STANDARD.encode(raw) != text {
        return None;
    }
    Some(text.to_owned())
}
// Only a hardcoded *public.key* leaf is ever opened. The environment selects
// a nonroot 0700 dev-only parent and cannot provide a path to private.key.
fn dev_site_a_public_from(root: &Path) -> Option<String> {
    if !root.is_absolute() {
        return None;
    }
    let dir = root.join("site-a-dev01-lab");
    for folder in [root, &dir] {
        let m = fs::symlink_metadata(folder).ok()?;
        if !m.file_type().is_dir()
            || m.uid() != unsafe { libc::geteuid() }
            || m.permissions().mode() & 0o777 != 0o700
        {
            return None;
        }
    }
    let path = dir.join("public.key");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let m = file.metadata().ok()?;
    if !m.file_type().is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.permissions().mode() & 0o777 != 0o600
        || m.len() > 64
    {
        return None;
    }
    let mut buf = String::new();
    file.take(65).read_to_string(&mut buf).ok()?;
    if buf.len() > 64 {
        return None;
    }
    validate_pub(buf.trim())
}
fn configured_public() -> Option<String> {
    let path = env::var_os("IPAT_R916_DEV_SITE_A_KEY_FOLDER")?;
    dev_site_a_public_from(&PathBuf::from(path))
}
pub(super) async fn show_public(headers: HeaderMap) -> Answer {
    if !super::device_workbench_lab::demo_csrf_read(&headers) {
        return Err(denied(StatusCode::FORBIDDEN));
    }
    let a = configured_public().ok_or_else(|| denied(StatusCode::SERVICE_UNAVAILABLE))?;
    Ok((
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(json!({
            "mode":"DEV_ONLY_PUBLIC_SITE_A_KEY_NOT_AN_ACTIVE_TUNNEL",
            "site_a_public_key":a,"site_b_config_owner":"SITE_B_OPERATOR_LOCAL",
            "site_a_private_key_exported":false,"backup_verified":false,
            "genuine_tenant_mfa_verified":false,"tunnel_active":false,
            "router_push_enabled":false,"network_actions":0,"device_adopted":false
        })),
    ))
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManualPairingInput {
    site_slug: String,
    hub_endpoint: String,
    external_site_b: bool,
    a_tunnel_host: String,
    b_tunnel_host: String,
    olt_private_host: String,
    site_b_public_key: String,
    udp_port: u16,
}
fn canonical(ip: &str) -> Option<Ipv4Addr> {
    let parsed = ip.parse::<Ipv4Addr>().ok()?;
    (parsed.to_string() == ip).then_some(parsed)
}
fn valid_hub(a: Ipv4Addr) -> bool {
    let oct = a.octets();
    oct[0] > 0
        && oct[0] < 224
        && oct[0] != 127
        && !(oct[0] == 169 && oct[1] == 254)
        && a != Ipv4Addr::BROADCAST
}
fn prepare(input: &ManualPairingInput, a_pub: &str) -> Option<Value> {
    if input.site_slug.len() > 20
        || input.site_slug.is_empty()
        || !input.site_slug.as_bytes()[0].is_ascii_lowercase()
        || !input
            .site_slug
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || input.site_slug.ends_with('-')
        || input.site_slug.starts_with("wg-")
        || !(1024..=65535).contains(&input.udp_port)
    {
        return None;
    }
    let hub = canonical(&input.hub_endpoint)?;
    let a = canonical(&input.a_tunnel_host)?;
    let b = canonical(&input.b_tunnel_host)?;
    let olt = canonical(&input.olt_private_host)?;
    if !valid_hub(hub)
        || private(hub) == input.external_site_b
        || !private(a)
        || !private(b)
        || !private(olt)
    {
        return None;
    }
    let ax = u32::from(a);
    let bx = u32::from(b);
    let ox = u32::from(olt);
    if (ax & !3) != (bx & !3) || (ax & 3) != 1 || (bx & 3) != 2 || (ox & !3) == (ax & !3) {
        return None;
    }
    let central = validate_pub(a_pub)?;
    let spoke = validate_pub(&input.site_b_public_key)?;
    if central == spoke {
        return None;
    }
    let name = format!("wg-ipat-{}", input.site_slug);
    let commands=[
        format!("/interface/wireguard/add name={name} disabled=yes comment=IPAT-PENDING-REVIEW"),
        format!("/ip/address/add address={b}/30 interface={name} disabled=yes"),
        format!("/interface/wireguard/peers/add interface={name} public-key=\"{central}\" endpoint-address={hub} endpoint-port={} allowed-address={a}/32 persistent-keepalive=25 disabled=yes",input.udp_port)
    ];
    Some(json!({
      "mode":"DEV_ONLY_DISABLED_MANUAL_SITE_B_PAIRING",
      "site_a_role":"CENTRAL_HUB_KEY_CUSTODY_ONLY",
      "site_b_role":"OPERATOR_APPLIES_AFTER_SEPARATE_APPROVAL",
      "site_b_routeros_disabled_review_commands":commands,
      "site_a_public_key":central,
      "site_b_public_key_received":true,
      "site_a_intended_peer_allowed_ips":[format!("{b}/32"),format!("{olt}/32")],
      "site_b_intended_peer_allowed_ips":[format!("{a}/32")],
      "real_peer_activation_authorized":false,
      "independent_hub_endpoint_reachability_verified":false,
      "actual_site_subnet_overlap_checked":false,
      "last_hop_isolation_verified":false,
      "return_route_independently_verified":false,
      "site_b_console_recovery_verified":false,
      "real_tenant_mfa_verified":false,
      "backup_verified":false,
      "config_applied":false,"site_a_listener_active":false,
      "router_push_enabled":false,"network_actions":0,
      "device_adopted":false
    }))
}
pub(super) async fn manual_pairing(
    headers: HeaderMap,
    Json(input): Json<ManualPairingInput>,
) -> Answer {
    if !super::device_workbench_lab::demo_csrf(&headers) {
        return Err(denied(StatusCode::FORBIDDEN));
    }
    let central = configured_public().ok_or_else(|| denied(StatusCode::SERVICE_UNAVAILABLE))?;
    let preview = prepare(&input, &central).ok_or_else(|| denied(StatusCode::BAD_REQUEST))?;
    Ok((
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(preview),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    fn sample() -> ManualPairingInput {
        ManualPairingInput {
            site_slug: "labsite".into(),
            hub_endpoint: "198.51.100.9".into(),
            external_site_b: true,
            a_tunnel_host: "10.253.77.1".into(),
            b_tunnel_host: "10.253.77.2".into(),
            olt_private_host: "192.168.77.10".into(),
            site_b_public_key: STANDARD.encode([66u8; 32]),
            udp_port: 51820,
        }
    }
    #[test]
    fn developer_central_preview_never_activates_or_publishes_private_keys() {
        let a = STANDARD.encode([65u8; 32]);
        let value = prepare(&sample(), &a).unwrap();
        assert_eq!(value["site_a_public_key"], a);
        assert_eq!(value["mode"], "DEV_ONLY_DISABLED_MANUAL_SITE_B_PAIRING");
        for key in [
            "real_peer_activation_authorized",
            "site_a_listener_active",
            "config_applied",
            "router_push_enabled",
            "device_adopted",
            "real_tenant_mfa_verified",
            "backup_verified",
            "last_hop_isolation_verified",
        ] {
            assert_eq!(value[key], false, "{key}");
        }
        assert_eq!(value["network_actions"], 0);
        assert_eq!(
            value["site_a_intended_peer_allowed_ips"],
            json!(["10.253.77.2/32", "192.168.77.10/32"])
        );
        assert_eq!(
            value["site_b_intended_peer_allowed_ips"],
            json!(["10.253.77.1/32"])
        );
        let commands = value["site_b_routeros_disabled_review_commands"]
            .as_array()
            .unwrap();
        assert_eq!(commands.len(), 3);
        for line in commands {
            let line = line.as_str().unwrap();
            assert!(line.starts_with('/') && line.contains("disabled=yes"));
            assert!(!line.contains("private-key") && !line.contains("0.0.0.0/0"));
        }
    }
    #[test]
    fn strict_lab_input_rejects_topology_key_and_secret_injection() {
        let a = STANDARD.encode([65u8; 32]);
        let mut sample = sample();
        sample.hub_endpoint = "10.99.0.1".into();
        assert!(prepare(&sample, &a).is_none());
        sample.external_site_b = false;
        assert!(prepare(&sample, &a).is_some());
        sample.external_site_b = true;
        sample.hub_endpoint = "198.51.100.9".into();
        sample.a_tunnel_host = "10.253.77.2".into();
        assert!(prepare(&sample, &a).is_none());
        sample.a_tunnel_host = "10.253.77.1".into();
        sample.site_b_public_key = a.clone();
        assert!(prepare(&sample, &a).is_none());
        sample.site_b_public_key = "PLACEHOLDER-INVALID".into();
        assert!(prepare(&sample, &a).is_none());
        sample.site_b_public_key = STANDARD.encode([66u8; 32]);
        sample.olt_private_host = "10.253.77.3".into();
        assert!(prepare(&sample, &a).is_none());
        sample.olt_private_host = "192.168.77.10".into();
        sample.site_slug = "../escape".into();
        assert!(prepare(&sample, &a).is_none());
        let payload = serde_json::to_string(&sample).unwrap();
        let injected = payload.replacen("{", "{\"private_key\":\"FORBIDDEN\",", 1);
        assert!(serde_json::from_str::<ManualPairingInput>(&injected).is_err());
    }
    #[test]
    fn only_owner_0700_folders_and_0600_exact_public_leaf_are_read() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let site = root.path().join("site-a-dev01-lab");
        fs::create_dir(&site).unwrap();
        fs::set_permissions(&site, fs::Permissions::from_mode(0o700)).unwrap();
        let pubfile = site.join("public.key");
        let public = STANDARD.encode([77u8; 32]);
        fs::write(&pubfile, format!("{public}\n")).unwrap();
        fs::set_permissions(&pubfile, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(dev_site_a_public_from(root.path()), Some(public));
        fs::set_permissions(&pubfile, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(dev_site_a_public_from(root.path()), None);
        fs::set_permissions(&pubfile, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&pubfile, site.join("original-public.key")).unwrap();
        std::os::unix::fs::symlink(site.join("original-public.key"), &pubfile).unwrap();
        assert_eq!(dev_site_a_public_from(root.path()), None);
    }
}
