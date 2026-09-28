//! R8.7 original strictly OFFLINE OIDC token-pair verifier. No token exchange,
//! browser session, actual MFA enrollment or tenant role is ever minted here.
use super::{
    valid_identifier, IdentityError, PinnedIssuer, VerifiedSubject, MAX_ACCESS_TOKEN_LIFETIME_SECS,
    MAX_CLOCK_LEEWAY_SECS, MAX_TOKEN_BYTES,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

const MAX_AUTH_AGE: u64 = 300;
/// No Debug or Serialize: validated fields must never appear in HTTP/CLI/logs.
pub struct VerifiedBrowserIdentity {
    subject: String,
    issuer: String,
    expires_at: u64,
}
impl VerifiedBrowserIdentity {
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
#[derive(Deserialize)]
struct SignedIdClaims {
    iss: String,
    aud: String,
    sub: String,
    exp: u64,
    iat: u64,
    nbf: u64,
    auth_time: u64,
    nonce: String,
    at_hash: String,
    azp: Option<String>,
    amr: Vec<String>,
}
impl PinnedIssuer {
    /// Accept only a matching freshly authenticated synthetic signed pair:
    /// the actual IdP must be independently trusted, enrolled and tested.
    /// This function does NOT assert that a human IdP/MFA exists.
    pub fn verify_offline_browser_pair(
        &self,
        client_id: &str,
        expected_nonce: &str,
        id_token: &str,
        access_token: &str,
    ) -> Result<VerifiedBrowserIdentity, IdentityError> {
        if !valid_identifier(client_id, 80)
            || !super::browser_pkce::Challenge::valid_state(expected_nonce)
            || id_token.is_empty()
            || id_token.len() > MAX_TOKEN_BYTES
            || !id_token.is_ascii()
            || id_token.chars().any(char::is_whitespace)
        {
            return Err(IdentityError::InvalidToken);
        }
        let VerifiedSubject {
            issuer,
            subject,
            expires_at,
            signed_mfa_claim,
        } = self.verify_access_token(access_token)?;
        // An access token alone, or an unreviewed signed claim, never
        // grants a browser login. Require exact independent ID MFA signal.
        if !signed_mfa_claim {
            return Err(IdentityError::InvalidSignatureOrClaims);
        }
        let header = decode_header(id_token).map_err(|_| IdentityError::InvalidToken)?;
        if header.alg != Algorithm::RS256
            || header.kid.as_deref() != Some(self.kid.as_str())
            || header.typ.as_deref() != Some("JWT")
            || header.jku.is_some()
            || header.jwk.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
            || header.crit.is_some()
            || header.cty.is_some()
        {
            return Err(IdentityError::InvalidToken);
        }
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[client_id]);
        validation.set_required_spec_claims(&[
            "iss",
            "aud",
            "sub",
            "exp",
            "iat",
            "nbf",
            "auth_time",
            "nonce",
            "at_hash",
            "amr",
        ]);
        validation.validate_nbf = true;
        validation.leeway = MAX_CLOCK_LEEWAY_SECS;
        let id = decode::<SignedIdClaims>(id_token, &self.key, &validation)
            .map_err(|_| IdentityError::InvalidSignatureOrClaims)?
            .claims;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IdentityError::InvalidSignatureOrClaims)?
            .as_secs();
        if id.iss != issuer
            || id.aud != client_id
            || id.azp.as_deref().is_some_and(|azp| azp != client_id)
            || id.sub != subject
            || !valid_identifier(&id.sub, 128)
            || id.exp <= now
            || id.exp <= id.iat
            || id.exp.saturating_sub(id.iat) > MAX_ACCESS_TOKEN_LIFETIME_SECS
            || id.iat > now.saturating_add(MAX_CLOCK_LEEWAY_SECS)
            || id.nbf > now.saturating_add(MAX_CLOCK_LEEWAY_SECS)
            || id.nbf < id.iat.saturating_sub(MAX_CLOCK_LEEWAY_SECS)
            || id.auth_time > now.saturating_add(MAX_CLOCK_LEEWAY_SECS)
            || now.saturating_sub(id.auth_time) > MAX_AUTH_AGE
            || id.auth_time > id.iat.saturating_add(MAX_CLOCK_LEEWAY_SECS)
            || id.amr.len() > 8
            || id.amr.iter().any(|s| s.len() > 32)
            || !id.amr.iter().any(|s| s == "mfa")
            || id.nonce.len() != 43
            || !id.nonce.is_ascii()
        {
            return Err(IdentityError::InvalidSignatureOrClaims);
        }
        let hash = Sha256::digest(access_token.as_bytes());
        let expected_hash = URL_SAFE_NO_PAD.encode(&hash[..16]);
        if id.at_hash.len() != expected_hash.len()
            || !bool::from(id.at_hash.as_bytes().ct_eq(expected_hash.as_bytes()))
            || !bool::from(id.nonce.as_bytes().ct_eq(expected_nonce.as_bytes()))
        {
            return Err(IdentityError::InvalidSignatureOrClaims);
        }
        Ok(VerifiedBrowserIdentity {
            subject,
            issuer,
            expires_at: id.exp.min(expires_at),
        })
    }
}
