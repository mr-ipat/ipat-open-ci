//! R8.4 independently gated reviewer-only DB boundary.
//! Hardware admission and real-human MFA provisioning remain OFF.
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    routing::{get, post},
    Json, Router,
};
use identity_core::{PinnedIssuer, VerifiedSubject};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{path::PathBuf, str::FromStr, sync::Arc};
use tokio_postgres::{config::Host, Config, NoTls};
use uuid::Uuid;

pub(super) struct ReviewStore {
    verifier: Arc<PinnedIssuer>,
    db: Config,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueScope {
    tenant_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    tenant_id: String,
    candidate_id: String,
    request_id: String,
    decision: String,
    reason: String,
}
fn safe() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h
}
fn denied(code: StatusCode) -> (StatusCode, HeaderMap, Json<Value>) {
    (code, safe(), Json(json!({"access":false,"lab_only":true})))
}
fn signed_reviewer(verifier: &PinnedIssuer, headers: &HeaderMap) -> Option<VerifiedSubject> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return None;
    }
    let token = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    if token.contains([' ', '\t', ',']) {
        return None;
    }
    let verified = verifier.verify_access_token(token).ok()?;
    verified.signed_mfa_claim().then_some(verified)
}
fn canonical_uuid(s: &str) -> Option<Uuid> {
    let value = Uuid::parse_str(s).ok()?;
    (value.to_string() == s).then_some(value)
}
fn valid_reason(reason: &str) -> bool {
    (12..=180).contains(&reason.len())
        && reason.is_ascii()
        && reason.bytes().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    b' ' | b'_' | b'.' | b',' | b':' | b'/' | b'(' | b')' | b'-'
                )
        })
}
async fn queue(
    State(store): State<Arc<ReviewStore>>,
    headers: HeaderMap,
    Query(query): Query<QueueScope>,
) -> (StatusCode, HeaderMap, Json<Value>) {
    let Some(actor) = signed_reviewer(&store.verifier, &headers) else {
        return denied(StatusCode::UNAUTHORIZED);
    };
    let Some(tenant) = canonical_uuid(&query.tenant_id) else {
        return denied(StatusCode::BAD_REQUEST);
    };
    let Ok((db, connection)) = store.db.connect(NoTls).await else {
        return denied(StatusCode::SERVICE_UNAVAILABLE);
    };
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    // Sealed SQL independently rechecks OWN active tenant and exact
    // unrevoked security_admin membership; maker's rows are not listed.
    let rows = db
        .query(
            "WITH permit AS MATERIALIZED (
           SELECT permitted FROM ipat_platform.lookup_lab_device_reviewer($1,$2,$3::uuid)
         ) SELECT permit.permitted,d.id::text,d.pop_id,d.display_name,d.device_kind,
                  d.vendor,d.exact_model,d.requested_at::text
           FROM permit LEFT JOIN LATERAL
             ipat_platform.list_lab_device_review_queue($1,$2,$3::uuid) d
             ON true ORDER BY d.requested_at,d.id",
            &[&actor.issuer(), &actor.subject(), &tenant],
        )
        .await;
    drop(db);
    task.abort();
    let Ok(rows) = rows else {
        return denied(StatusCode::SERVICE_UNAVAILABLE);
    };
    if rows.is_empty() {
        return denied(StatusCode::FORBIDDEN);
    }
    let mut devices = Vec::new();
    for r in rows {
        let permitted: bool = r.get(0);
        if !permitted {
            return denied(StatusCode::SERVICE_UNAVAILABLE);
        }
        let Some(id): Option<String> = r.get(1) else {
            continue;
        };
        devices.push(json!({
            "id":id,"pop_id":r.get::<_,String>(2),
            "display_name":r.get::<_,String>(3),"device_kind":r.get::<_,String>(4),
            "vendor":r.get::<_,String>(5),"exact_model":r.get::<_,Option<String>>(6),
            "requested_at":r.get::<_,String>(7),"adoption_state":"pending_review",
            "connectivity":"unknown","health":"not_measured"
        }));
    }
    // The permit and queue were read in the SAME SQL statement/snapshot.
    (
        StatusCode::OK,
        safe(),
        Json(json!({
            "lab_only":true,"source":"restricted-postgresql",
            "signed_mfa_claim":true,"actual_idp_mfa_onboarded":false,
            "device_contacted":false,"count":devices.len(),"limit":100,
            "devices":devices
        })),
    )
}
async fn decide(
    State(store): State<Arc<ReviewStore>>,
    headers: HeaderMap,
    Json(input): Json<Decision>,
) -> (StatusCode, HeaderMap, Json<Value>) {
    let Some(actor) = signed_reviewer(&store.verifier, &headers) else {
        return denied(StatusCode::UNAUTHORIZED);
    };
    let (Some(tenant), Some(candidate), Some(request)) = (
        canonical_uuid(&input.tenant_id),
        canonical_uuid(&input.candidate_id),
        canonical_uuid(&input.request_id),
    ) else {
        return denied(StatusCode::BAD_REQUEST);
    };
    if !matches!(input.decision.as_str(), "approved" | "rejected") || !valid_reason(&input.reason) {
        return denied(StatusCode::BAD_REQUEST);
    }
    let Ok((db, connection)) = store.db.connect(NoTls).await else {
        return denied(StatusCode::SERVICE_UNAVAILABLE);
    };
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    // Real single PostgreSQL transaction, independently sealed writer role.
    // No physical probing, enrollment, job enqueue or firmware actuation.
    let result = db
        .query_one(
            "SELECT ipat_platform.review_lab_device_candidate(
          $1,$2,$3::uuid,$4::uuid,$5::uuid,$6,$7)",
            &[
                &actor.issuer(),
                &actor.subject(),
                &tenant,
                &candidate,
                &request,
                &input.decision,
                &input.reason,
            ],
        )
        .await;
    drop(db);
    task.abort();
    let Ok(row) = result else {
        return denied(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Some(id): Option<Uuid> = row.get(0) else {
        return denied(StatusCode::FORBIDDEN);
    };
    (
        StatusCode::OK,
        safe(),
        Json(json!({
            "lab_only":true,"metadata_review_recorded":true,
            "review_id":id.to_string(),"decision":input.decision,
            "signed_mfa_claim":true,"actual_idp_mfa_onboarded":false,
            "physical_device_adopted":false,"device_contacted":false,
            "connectivity":"unknown","health":"not_measured"
        })),
    )
}
pub(super) fn router(store: Arc<ReviewStore>) -> Router {
    Router::new()
        .route("/lab/auth/device-reviews", get(queue))
        .route("/lab/auth/device-reviews/decision", post(decide))
        .layer(DefaultBodyLimit::max(2048))
        .with_state(store)
}
fn valid_reviewer_db(c: &Config) -> bool {
    c.get_user() == Some("ipat_lab_device_reviewer")
        && c.get_dbname().is_some()
        && c.get_hosts().len() == 1
        && c.get_hostaddrs().is_empty()
        && c.get_options().is_none()
        && matches!(c.get_hosts()[0],Host::Unix(ref p) if p.is_absolute())
}
pub(super) fn from_owner_environment(
    verifier: Arc<PinnedIssuer>,
) -> Result<Arc<ReviewStore>, &'static str> {
    if unsafe { libc::geteuid() } == 0
        || std::env::var("IPAT_LAB_OIDC_VERIFY").as_deref() != Ok("YES")
        || std::env::var("IPAT_LAB_SCOPED_MEMBERSHIP").as_deref() != Ok("YES")
        || std::env::var("IPAT_R84_SIMULATED_REVIEW").as_deref() != Ok("YES")
    {
        return Err("explicit nonroot review-lab prerequisite missing");
    }
    let path = PathBuf::from(
        std::env::var("IPAT_R84_REVIEW_CONNINFO_FILE")
            .map_err(|_| "missing separate reviewer credential path")?,
    );
    let raw = super::tenant_membership_lab::read_owner_file(&path)?;
    let db = Config::from_str(raw.trim()).map_err(|_| "invalid reviewer DB config")?;
    if !valid_reviewer_db(&db) {
        return Err("requires own restricted unix-socket reviewer");
    }
    Ok(Arc::new(ReviewStore { verifier, db }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_separate_restricted_db_and_exact_safe_reason() {
        assert!(valid_reviewer_db(
            &Config::from_str(
                "host=/var/run/postgresql user=ipat_lab_device_reviewer dbname=ipat_synthetic"
            )
            .unwrap()
        ));
        for s in [
          "host=127.0.0.1 user=ipat_lab_device_reviewer dbname=ipat_synthetic",
          "host=/var/run/postgresql user=ipat_lab_identity_reader dbname=ipat_synthetic",
          "host=/var/run/postgresql user=ipat_lab_device_reviewer dbname=ipat_synthetic options='-c role=postgres'"
        ]{assert!(!valid_reviewer_db(&Config::from_str(s).unwrap()));}
        assert!(valid_reason("Approve metadata only"));
        for s in [
            "",
            "quick",
            "store password=abc; in reason",
            "unsafe\ntext",
            &"x".repeat(181),
        ] {
            assert!(!valid_reason(s));
        }
        assert!(canonical_uuid("11111111-1111-4111-8111-111111111111").is_some());
        assert!(canonical_uuid("../dev/null").is_none());
    }
}

#[cfg(test)]
mod pg_integration {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::{
        fs,
        process::{Command, Stdio},
    };
    use tower::ServiceExt;
    async fn invoke(
        app: Router,
        path: &str,
        method: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> axum::response::Response {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "other-ISP.example.invalid")
            .header("X-Tenant-Id", "FORGED")
            .header("X-Verified-Role", "platform_owner");
        if let Some(b) = bearer {
            req = req.header(header::AUTHORIZATION, b);
        }
        if body.is_some() {
            req = req.header(header::CONTENT_TYPE, "application/json");
        }
        app.oneshot(
            req.body(Body::from(body.map_or_else(String::new, |v| v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn r84_real_signed_mfa_claim_two_humans_actual_postgres_immutable_review() {
        if std::env::var("IPAT_PG_EPHEMERAL_TEST").as_deref() != Ok("1") {
            return;
        }
        assert_eq!(std::env::var("PGHOST").unwrap(), "127.0.0.1");
        assert_eq!(std::env::var("PGDATABASE").unwrap(), "ipat_synthetic");
        assert_eq!(
            std::env::var("IPAT_PG_SYNTHETIC_PASSWORD").unwrap(),
            "local_ci_synthetic_only"
        );
        let tmp = tempfile::tempdir().unwrap();
        let private = tmp.path().join("only-ephemeral-private.key");
        let public = tmp.path().join("only-ephemeral-public.pem");
        assert!(Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out"
            ])
            .arg(&private)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("openssl")
            .args(["pkey", "-pubout", "-in"])
            .arg(&private)
            .arg("-out")
            .arg(&public)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        let verifier = Arc::new(
            PinnedIssuer::new(
                "https://id.example.invalid/realms/lab",
                "ipat-control-api",
                "private-lab",
                &fs::read(public).unwrap(),
            )
            .unwrap(),
        );
        let pem = fs::read(private).unwrap();
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("private-lab".to_string());
        h.typ = Some("JWT".to_string());
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sign = |subject: &str, mfa: bool| {
            let mut claim = json!({"iss":"https://id.example.invalid/realms/lab",
             "aud":"ipat-control-api","sub":subject,"iat":ts,"nbf":ts,"exp":ts+300,
             "roles":["platform_owner"],"tenant_id":"forged-tenant"});
            if mfa {
                claim["amr"] = json!(["pwd", "mfa"]);
            }
            encode(&h, &claim, &EncodingKey::from_rsa_pem(&pem).unwrap()).unwrap()
        };
        let checker = sign("synthetic-checker", true);
        let no_mfa = sign("synthetic-checker", false);
        let self_review = sign("synthetic-operator", true);
        assert!(verifier
            .verify_access_token(&checker)
            .unwrap()
            .signed_mfa_claim());
        assert!(!verifier
            .verify_access_token(&no_mfa)
            .unwrap()
            .signed_mfa_claim());
        // HTTP expects the signed JWT in the single exact Bearer scheme.
        // Direct verifier assertions above deliberately use the raw token.
        let checker = format!("Bearer {checker}");
        let no_mfa = format!("Bearer {no_mfa}");
        let self_review = format!("Bearer {self_review}");
        let reviewer = Config::from_str(
            "host=127.0.0.1 port=5432 user=ipat_lab_device_reviewer \
            password=local_ci_synthetic_only dbname=ipat_synthetic",
        )
        .unwrap();
        let registrar = Config::from_str(
            "host=127.0.0.1 port=5432 user=ipat_lab_device_registrar \
            password=local_ci_synthetic_only dbname=ipat_synthetic",
        )
        .unwrap();
        let (reg, connection) = registrar.connect(NoTls).await.unwrap();
        let reg_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let tenant_a = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let tenant_b = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
        let make = |n: u32| Uuid::parse_str(&format!("e8400000-0000-4000-8000-{n:012}")).unwrap();
        let create =
            |tenant: &Uuid, request: Uuid, pop: &str| (tenant.to_owned(), request, pop.to_string());
        for (tenant, request, pop) in [
            create(&tenant_a, make(101), "pop-a"),
            create(&tenant_b, make(102), "pop-b"),
        ] {
            let inserted = reg
                .query_one(
                    "SELECT ipat_platform.propose_lab_device_candidate(
                  $1,$2,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10)",
                    &[
                        &"https://id.example.invalid/realms/lab",
                        &"synthetic-operator",
                        &tenant,
                        &request,
                        &pop,
                        &"LAB-R84-REVIEW",
                        &"olt",
                        &"ZTE",
                        &Some("VIRTUAL-C320"),
                        &Some("10.26.4.10"),
                    ],
                )
                .await
                .unwrap();
            assert!(inserted.get::<_, Option<Uuid>>(0).is_some());
        }
        drop(reg);
        reg_task.abort();
        let (reg, connection) = registrar.connect(NoTls).await.unwrap();
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        assert!(
            reg.query_one("SELECT id FROM ipat_ops.device_candidates LIMIT 1", &[])
                .await
                .is_err(),
            "registrar has no raw table access"
        );
        drop(reg);
        task.abort();
        let app = crate::app_with_lab(true).merge(router(Arc::new(ReviewStore {
            verifier,
            db: reviewer,
        })));
        let path_a = format!("/lab/auth/device-reviews?tenant_id={tenant_a}");
        let path_b = format!("/lab/auth/device-reviews?tenant_id={tenant_b}");
        assert_eq!(
            invoke(app.clone(), &path_a, "GET", None, None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            invoke(app.clone(), &path_a, "GET", Some(&no_mfa), None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let first = invoke(app.clone(), &path_a, "GET", Some(&checker), None).await;
        assert_eq!(first.status(), StatusCode::OK);
        let out = to_bytes(first.into_body(), 16384).await.unwrap();
        let a: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(a["signed_mfa_claim"], true);
        assert_eq!(a["actual_idp_mfa_onboarded"], false);
        let items = a["devices"].as_array().unwrap();
        assert!(items.iter().any(|v| v["display_name"] == "LAB-R84-REVIEW"));
        assert!(!String::from_utf8_lossy(&out).contains("10.26.4.10"));
        let own_a = items
            .iter()
            .find(|v| v["display_name"] == "LAB-R84-REVIEW")
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let b = invoke(app.clone(), &path_b, "GET", Some(&checker), None).await;
        assert_eq!(b.status(), StatusCode::OK);
        let bs = to_bytes(b.into_body(), 16384).await.unwrap();
        let other: Value = serde_json::from_slice(&bs).unwrap();
        assert!(!other["devices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == own_a));
        let decision_path = "/lab/auth/device-reviews/decision";
        let candidate = json!({"tenant_id":tenant_a.to_string(),
           "candidate_id":own_a,"request_id":make(103).to_string(),
           "decision":"approved","reason":"Reviewed metadata only"});
        assert_eq!(
            invoke(
                app.clone(),
                decision_path,
                "POST",
                Some(&self_review),
                Some(candidate.clone())
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            invoke(
                app.clone(),
                decision_path,
                "POST",
                Some(&no_mfa),
                Some(candidate.clone())
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let bad = json!({"tenant_id":tenant_b.to_string(),
           "candidate_id":own_a,"request_id":make(104).to_string(),
           "decision":"approved","reason":"Reviewed metadata only"});
        assert_eq!(
            invoke(
                app.clone(),
                decision_path,
                "POST",
                Some(&checker),
                Some(bad)
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let approved = invoke(
            app.clone(),
            decision_path,
            "POST",
            Some(&checker),
            Some(candidate.clone()),
        )
        .await;
        assert_eq!(approved.status(), StatusCode::OK);
        let val: Value =
            serde_json::from_slice(&to_bytes(approved.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(val["metadata_review_recorded"], true);
        assert_eq!(val["physical_device_adopted"], false);
        assert_eq!(val["connectivity"], "unknown");
        let same = invoke(
            app.clone(),
            decision_path,
            "POST",
            Some(&checker),
            Some(candidate.clone()),
        )
        .await;
        assert_eq!(same.status(), StatusCode::OK);
        let duplicate: Value =
            serde_json::from_slice(&to_bytes(same.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(duplicate["review_id"], val["review_id"]);
        let mut mutate = candidate.clone();
        mutate["decision"] = json!("rejected");
        assert_eq!(
            invoke(
                app.clone(),
                decision_path,
                "POST",
                Some(&checker),
                Some(mutate)
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            invoke(
                app.clone(),
                "/v1/tenant/devices",
                "GET",
                Some(&checker),
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            invoke(
                crate::app_with_lab(true),
                &path_a,
                "GET",
                Some(&checker),
                None
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }
}
