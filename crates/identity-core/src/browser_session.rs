//! R8.8 OFFLINE-only browser BFF session primitives. NO HTTP login or tenant
//! entitlement is granted here. The caller MUST independently prove genuine
//! real operator MFA, confidential IdP code exchange, trusted Host/origin and
//! re-query active DB tenant/role/POP membership on EVERY protected API call.
//! This in-memory store is NOT multi-pod K3s/shared durable browser storage.
use crate::oidc_id_token::VerifiedBrowserIdentity;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

const SESSION_LIMIT: usize = 64;
const SESSION_LIFETIME: u64 = 900;
const IDLE_LIFETIME: Duration = Duration::from_secs(300);
const HANDLE_BYTES: usize = 32;

/// Handle/CSRF secrets may ONLY be sent in independently verified TLS browser
/// cookie and same-origin anti-CSRF response respectively; never log either.
pub struct IssuedSession {
    cookie_secret: String,
    csrf_secret: String,
    expires_at: u64,
    cookie_max_age_secs: u64,
}
impl IssuedSession {
    pub fn cookie_secret(&self) -> &str {
        &self.cookie_secret
    }
    pub fn csrf_secret(&self) -> &str {
        &self.csrf_secret
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    /// Only mount on HTTPS after verified proxy+Host+real IdP+DB membership.
    /// On plain HTTP private lab this is just an UNEMITTED policy fixture.
    pub fn secure_cookie_header(&self) -> String {
        format!(
            "__Host-ipat_session={}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
            self.cookie_secret, self.cookie_max_age_secs
        )
    }
}
struct Entry {
    issuer: String,
    subject: String,
    expires_at: u64,
    last_used: Instant,
    csrf_hash: [u8; 32],
}
/// Identity-only. NO roles, tenant, POP, device rights, or raw JWTs present.
pub struct SessionIdentity<'a> {
    issuer: &'a str,
    subject: &'a str,
    expires_at: u64,
}
impl<'a> SessionIdentity<'a> {
    pub fn issuer(&self) -> &str {
        self.issuer
    }
    pub fn subject(&self) -> &str {
        self.subject
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
#[derive(Clone, Copy)]
pub enum RequestKind {
    Read,
    Mutation,
}

#[derive(Default)]
pub struct BrowserSessionVault {
    sessions: HashMap<[u8; 32], Entry>,
}
fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}
fn valid_secret(raw: &str) -> bool {
    raw.len() == 43
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn secret() -> Option<String> {
    let mut raw = [0_u8; HANDLE_BYTES];
    getrandom::fill(&mut raw).ok()?;
    Some(URL_SAFE_NO_PAD.encode(raw))
}
impl BrowserSessionVault {
    /// May be called ONLY after confidential real IdP+MFA verification.
    /// This function itself cannot establish that an actual human IdP exists.
    /// A separate PostgreSQL membership check remains mandatory for EVERY
    /// subsequent tenant/device API, not just session issuance.
    pub fn issue(&mut self, identity: VerifiedBrowserIdentity, now: u64) -> Option<IssuedSession> {
        self.prune(now);
        if now >= identity.expires_at() || self.sessions.len() >= SESSION_LIMIT {
            return None;
        }
        let cookie = secret()?;
        let csrf = secret()?;
        let key = digest(&cookie);
        if self.sessions.contains_key(&key) {
            return None;
        }
        let expiry = now
            .saturating_add(SESSION_LIFETIME)
            .min(identity.expires_at());
        self.sessions.insert(
            key,
            Entry {
                issuer: identity.issuer().to_owned(),
                subject: identity.subject().to_owned(),
                expires_at: expiry,
                last_used: Instant::now(),
                csrf_hash: digest(&csrf),
            },
        );
        Some(IssuedSession {
            cookie_secret: cookie,
            csrf_secret: csrf,
            expires_at: expiry,
            cookie_max_age_secs: expiry.saturating_sub(now),
        })
    }
    /// Fail closed. Caller MUST separately check trusted HTTPS Host, explicit
    /// allowed request origin (on mutations) AND fresh exact DB membership.
    /// Never authorize a mutation based on a cookie alone.
    pub fn authenticate<'a>(
        &'a mut self,
        cookie: &str,
        csrf: Option<&str>,
        kind: RequestKind,
        trusted_host_origin: bool,
        now: u64,
    ) -> Option<SessionIdentity<'a>> {
        if !trusted_host_origin || !valid_secret(cookie) {
            return None;
        }
        let key = digest(cookie);
        let expired = self.sessions.get(&key).is_some_and(|entry| {
            now >= entry.expires_at || entry.last_used.elapsed() >= IDLE_LIFETIME
        });
        if expired {
            self.sessions.remove(&key);
            return None;
        }
        let entry = self.sessions.get_mut(&key)?;
        if matches!(kind, RequestKind::Mutation) {
            let supplied = csrf.filter(|v| valid_secret(v))?;
            if !bool::from(digest(supplied).ct_eq(&entry.csrf_hash)) {
                return None;
            }
        }
        entry.last_used = Instant::now();
        Some(SessionIdentity {
            issuer: &entry.issuer,
            subject: &entry.subject,
            expires_at: entry.expires_at,
        })
    }
    /// Revoke the exact handle. Rotation must re-verify a freshly signed pair
    /// and recheck active DB membership, not extend a stale CSRF/cookie pair.
    pub fn revoke(&mut self, cookie: &str) -> bool {
        valid_secret(cookie) && self.sessions.remove(&digest(cookie)).is_some()
    }
    pub fn prune(&mut self, now: u64) {
        self.sessions
            .retain(|_, entry| now < entry.expires_at && entry.last_used.elapsed() < IDLE_LIFETIME);
    }
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }
}
