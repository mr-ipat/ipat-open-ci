//! R6.9: strict verification of an independently pinned OIDC JWT access token.
//! Authentication is NOT tenant/role authorization. This crate cannot mint
//! DashboardSubject or mark a membership approved.
pub mod browser_pkce;
pub mod browser_session;
pub mod oidc_id_token;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_PUBLIC_KEY_BYTES: usize = 16 * 1024;
const MAX_CLOCK_LEEWAY_SECS: u64 = 10;
const MAX_ACCESS_TOKEN_LIFETIME_SECS: u64 = 900;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    InvalidConfiguration,
    InvalidToken,
    InvalidSignatureOrClaims,
    TokenNotYetIssued,
    TokenLifetimeExceeded,
}
/// This trusted key is supplied from an independently verified issuer's JWKS,
/// provisioned outside HTTP or token input; this module NEVER fetches jku/x5u.
pub struct PinnedIssuer {
    issuer: String,
    audience: String,
    kid: String,
    key: DecodingKey,
}
/// A verified JWT subject; intentionally no tenant, roles, POP or Debug output.
pub struct VerifiedSubject {
    issuer: String,
    subject: String,
    expires_at: u64,
    signed_mfa_claim: bool,
}
impl VerifiedSubject {
    /// Authenticated by the pinned signature verifier, never an HTTP Host
    /// header, untrusted request claim, or proposed tenant-domain mapping.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    /// Only an exact, signed `amr: ["mfa"]` from the configured pinned issuer.
    /// This is NOT proof that a real human MFA/IdP was provisioned by IPAT.
    pub fn signed_mfa_claim(&self) -> bool {
        self.signed_mfa_claim
    }
}
#[derive(Deserialize)]
struct AccessClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    nbf: u64,
    #[serde(default)]
    amr: Option<Vec<String>>,
    // Additional OIDC claims such as roles, groups and tenant IDs are ignored.
    // Never treat their presence or contents as membership evidence.
}
impl PinnedIssuer {
    pub fn new(
        issuer: &str,
        audience: &str,
        kid: &str,
        rsa_public_key_pem: &[u8],
    ) -> Result<Self, IdentityError> {
        if issuer.len() > 512
            || !issuer.starts_with("https://")
            || issuer.contains(['?', '#', '@', '\\'])
            || issuer.chars().any(char::is_whitespace)
            || !valid_identifier(audience, 128)
            || !valid_identifier(kid, 128)
            || rsa_public_key_pem.is_empty()
            || rsa_public_key_pem.len() > MAX_PUBLIC_KEY_BYTES
        {
            return Err(IdentityError::InvalidConfiguration);
        }
        let key = DecodingKey::from_rsa_pem(rsa_public_key_pem)
            .map_err(|_| IdentityError::InvalidConfiguration)?;
        Ok(Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            kid: kid.to_owned(),
            key,
        })
    }

    pub fn verify_access_token(&self, token: &str) -> Result<VerifiedSubject, IdentityError> {
        if token.len() > MAX_TOKEN_BYTES
            || token.is_empty()
            || token.split('.').count() != 3
            || !token.is_ascii()
            || token.chars().any(char::is_whitespace)
        {
            return Err(IdentityError::InvalidToken);
        }
        let header = decode_header(token).map_err(|_| IdentityError::InvalidToken)?;
        if header.alg != Algorithm::RS256
            || header.kid.as_deref() != Some(self.kid.as_str())
            || !matches!(header.typ.as_deref(), Some("JWT") | Some("at+jwt"))
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
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "exp", "nbf"]);
        validation.validate_nbf = true;
        validation.leeway = MAX_CLOCK_LEEWAY_SECS;
        let claims = decode::<AccessClaims>(token, &self.key, &validation)
            .map_err(|_| IdentityError::InvalidSignatureOrClaims)?
            .claims;
        if claims.iss != self.issuer
            || claims.aud != self.audience
            || !valid_identifier(&claims.sub, 128)
        {
            return Err(IdentityError::InvalidSignatureOrClaims);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IdentityError::InvalidSignatureOrClaims)?
            .as_secs();
        if claims.iat > now.saturating_add(MAX_CLOCK_LEEWAY_SECS)
            || claims.nbf > now.saturating_add(MAX_CLOCK_LEEWAY_SECS)
        {
            return Err(IdentityError::TokenNotYetIssued);
        }
        if claims.exp <= now
            || claims.exp <= claims.iat
            || claims.exp.saturating_sub(claims.iat) > MAX_ACCESS_TOKEN_LIFETIME_SECS
            || claims.nbf < claims.iat.saturating_sub(MAX_CLOCK_LEEWAY_SECS)
        {
            return Err(IdentityError::TokenLifetimeExceeded);
        }
        Ok(VerifiedSubject {
            issuer: self.issuer.clone(),
            subject: claims.sub,
            expires_at: claims.exp,
            signed_mfa_claim: claims.amr.as_ref().is_some_and(|methods| {
                methods.len() <= 8
                    && methods.iter().all(|s| s.len() <= 32)
                    && methods.iter().any(|method| method == "mfa")
            }),
        })
    }
}
fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_' | b'.' | b':' | b'/'))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cannot_create_issuer_with_user_relative_jwks_http_or_invalid_keys() {
        for url in [
            "",
            "http://localhost/realms/test",
            "https://a/#bad",
            "https://u@a/realms/test",
            "https://a/ x",
        ] {
            assert!(matches!(
                PinnedIssuer::new(url, "ipat-control-api", "one", b"not-a-key"),
                Err(IdentityError::InvalidConfiguration)
            ));
        }
        assert!(matches!(
            PinnedIssuer::new(
                "https://id.example.invalid/realms/ipat",
                "ipat-control-api",
                "one",
                b"not-a-key"
            ),
            Err(IdentityError::InvalidConfiguration)
        ));
    }
}
