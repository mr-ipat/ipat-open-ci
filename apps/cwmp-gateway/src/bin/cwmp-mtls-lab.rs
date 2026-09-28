//! R6.7: real cryptographic client-mTLS handshake, private parser-only test.
//! NEVER an enrollment authority, persistent CWMP session or public ACS.
use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    routing::{any, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rustls::{
    pki_types::CertificateDer, server::WebPkiClientVerifier, RootCertStore, ServerConfig,
};
use std::{
    fs::{File, OpenOptions},
    io::{Cursor, Read},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::Arc,
};
const BIND: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3433));
const MAX_PEM_BYTES: usize = 32 * 1024;
const LAB_RESULT: &str = r#"{"mtls_certificate_chain_verified":true,"device_enrolled":false,"tenant_bound":false,"cwmp_response_sent":false,"production_acs":false}"#;
#[derive(Debug)]
enum SetupError {
    MissingOptIn,
    InvalidPrivateFile,
    CertificateConfiguration,
}
fn exact_opt_in() -> Result<(), SetupError> {
    if std::env::var("IPAT_RUN_PRIVATE_CWMP_MTLS_LAB").as_deref() != Ok("YES") {
        return Err(SetupError::MissingOptIn);
    }
    // Root-owned key handling is explicitly NOT an allowed lab execution path.
    if unsafe { libc::geteuid() } == 0 {
        return Err(SetupError::InvalidPrivateFile);
    }
    Ok(())
}
fn private_file(name: &str) -> Result<Vec<u8>, SetupError> {
    let value = std::env::var(name).map_err(|_| SetupError::InvalidPrivateFile)?;
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(SetupError::InvalidPrivateFile);
    }
    let parent = path.parent().ok_or(SetupError::InvalidPrivateFile)?;
    // The path owner must control the parent; do not resolve symlinks into public dirs.
    for point in [parent, path.as_path()] {
        let meta = std::fs::symlink_metadata(point).map_err(|_| SetupError::InvalidPrivateFile)?;
        if meta.file_type().is_symlink() || meta.uid() != unsafe { libc::geteuid() } {
            return Err(SetupError::InvalidPrivateFile);
        }
        let target_mode = if point == parent { 0o700 } else { 0o600 };
        if meta.mode() & 0o777 != target_mode {
            return Err(SetupError::InvalidPrivateFile);
        }
    }
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| SetupError::InvalidPrivateFile)?;
    let meta = file
        .metadata()
        .map_err(|_| SetupError::InvalidPrivateFile)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o777 != 0o600
        || meta.len() == 0
        || meta.len() > MAX_PEM_BYTES as u64
    {
        return Err(SetupError::InvalidPrivateFile);
    }
    let mut data = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_PEM_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| SetupError::InvalidPrivateFile)?;
    if data.is_empty() || data.len() > MAX_PEM_BYTES {
        return Err(SetupError::InvalidPrivateFile);
    }
    Ok(data)
}
fn exactly_one_cert(pem: Vec<u8>) -> Result<CertificateDer<'static>, SetupError> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SetupError::CertificateConfiguration)?;
    match certs.as_slice() {
        [only] => Ok(only.clone()),
        _ => Err(SetupError::CertificateConfiguration),
    }
}
fn tls_config() -> Result<ServerConfig, SetupError> {
    let ca = exactly_one_cert(private_file("IPAT_R67_TRUSTED_CLIENT_CA_PEM")?)?;
    let cert = exactly_one_cert(private_file("IPAT_R67_SERVER_CERT_PEM")?)?;
    let key_pem = private_file("IPAT_R67_SERVER_KEY_PEM")?;
    let mut reader = Cursor::new(key_pem);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|_| SetupError::CertificateConfiguration)?
        .ok_or(SetupError::CertificateConfiguration)?;
    if rustls_pemfile::private_key(&mut reader)
        .map_err(|_| SetupError::CertificateConfiguration)?
        .is_some()
    {
        return Err(SetupError::CertificateConfiguration);
    }
    let mut roots = RootCertStore::empty();
    roots
        .add(ca)
        .map_err(|_| SetupError::CertificateConfiguration)?;
    // Rustls cryptographically verifies the full presented client chain,
    // time validity, supported algorithms and clientAuth EKU. No "optional"
    // client certs; this code has no dangerous or no-client-auth branch.
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| SetupError::CertificateConfiguration)?;
    let mut tls = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .map_err(|_| SetupError::CertificateConfiguration)?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.max_early_data_size = 0;
    Ok(tls)
}
fn response_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers
}
async fn parse_lab(
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, &'static str), StatusCode> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("text/xml")
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let input = std::str::from_utf8(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    cwmp_protocol::parse_inform(input).map_err(|_| StatusCode::BAD_REQUEST)?;
    // This handler is reachable ONLY behind a mandatory cryptographic mTLS
    // acceptor. It cannot mint AuthenticatedPeer or approve tenant/device.
    Ok((response_headers(), LAB_RESULT))
}
fn app() -> Router {
    Router::new()
        .route("/lab/mtls/parse-inform", post(parse_lab))
        .route("/cwmp", any(|| async { StatusCode::SERVICE_UNAVAILABLE }))
        .fallback(|| async { StatusCode::SERVICE_UNAVAILABLE })
        .layer(DefaultBodyLimit::max(cwmp_protocol::MAX_XML_BYTES))
}
#[tokio::main]
async fn main() {
    if exact_opt_in().is_err() {
        eprintln!("R67_MTLS_LAB_DENIED: explicit opt-in/nonroot required");
        std::process::exit(4);
    }
    let config = match tls_config() {
        Ok(config) => config,
        Err(_) => {
            eprintln!("R67_MTLS_LAB_DENIED: strict private certificate prerequisites");
            std::process::exit(4);
        }
    };
    let runner = axum_server::bind_rustls(BIND, RustlsConfig::from_config(Arc::new(config)));
    if runner.serve(app().into_make_service()).await.is_err() {
        eprintln!("R67_MTLS_LAB_STOPPED: local listener failed");
        std::process::exit(4);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    #[test]
    fn exact_loopback_only_fixed_port_and_denied_by_default() {
        assert_eq!(BIND.to_string(), "127.0.0.1:3433");
        assert_eq!(
            std::env::var("IPAT_RUN_PRIVATE_CWMP_MTLS_LAB")
                .ok()
                .as_deref(),
            None
        );
    }
    #[tokio::test]
    async fn even_fake_cryptographic_headers_cannot_enable_real_cwmp() {
        let req = Request::builder()
            .method("POST")
            .uri("/cwmp")
            .header("x-client-cert-verified", "true")
            .header("x-tenant-id", "forged-tenant")
            .body(Body::from("fake-credentials"))
            .unwrap();
        assert_eq!(
            app().oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
