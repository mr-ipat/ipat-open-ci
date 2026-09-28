//! R8.6 exact OIDC Authorization Code PKCE S256 primitives.
//! No IdP token exchange, operator login, device privilege or session is minted.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Challenge {
    state: String,
    nonce: String,
    verifier: String,
}
impl Challenge {
    pub fn random() -> Result<Self, &'static str> {
        let mut bytes = [[0u8; 32]; 3];
        for value in &mut bytes {
            getrandom::fill(value).map_err(|_| "secure OS RNG unavailable")?;
        }
        Ok(Self {
            state: URL_SAFE_NO_PAD.encode(bytes[0]),
            nonce: URL_SAFE_NO_PAD.encode(bytes[1]),
            verifier: URL_SAFE_NO_PAD.encode(bytes[2]),
        })
    }
    pub fn state(&self) -> &str {
        &self.state
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn verifier(&self) -> &str {
        &self.verifier
    }
    pub fn s256(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.verifier.as_bytes()))
    }
    pub fn valid_state(s: &str) -> bool {
        s.len() == 43
            && s.bytes()
                .all(|v| v.is_ascii_alphanumeric() || v == b'-' || v == b'_')
    }
    /// Exact configured trusted endpoint only. Never use an endpoint
    /// supplied by a request or an untrusted OIDC token header.
    pub fn authorize_url(&self, endpoint: &str, client_id: &str, callback: &str) -> Option<String> {
        if !endpoint.starts_with("https://")
            || !endpoint.ends_with("/protocol/openid-connect/auth")
            || endpoint.contains(['?', '#', '@', '\\'])
            || !endpoint.is_ascii()
            || client_id.is_empty()
            || client_id.len() > 80
            || !client_id
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_' | b'.'))
            || callback != "http://127.0.0.1:48765/lab/auth/browser/callback"
        {
            return None;
        }
        Some(format!(
            "{endpoint}?response_type=code&client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%3A48765%2Flab%2Fauth%2Fbrowser%2Fcallback&scope=openid&code_challenge_method=S256&code_challenge={}&state={}&nonce={}",
            self.s256(), self.state, self.nonce
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    #[test]
    fn crypto_rng_generates_distinct_unpadded_256_bit_values() {
        let mut states = HashSet::new();
        for _ in 0..64 {
            let c = Challenge::random().unwrap();
            assert!(Challenge::valid_state(c.state()));
            assert!(Challenge::valid_state(c.nonce()));
            assert!(Challenge::valid_state(c.verifier()));
            assert_ne!(c.state(), c.nonce());
            assert_ne!(c.nonce(), c.verifier());
            assert!(Challenge::valid_state(&c.s256()));
            assert!(states.insert(c.state().to_string()));
        }
    }
    #[test]
    fn rfc7636_s256_reference_vector() {
        let c = Challenge {
            state: "q".repeat(43),
            nonce: "n".repeat(43),
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
        };
        assert_eq!(c.s256(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }
    #[test]
    fn no_untrusted_auth_redirect_or_callback() {
        let c = Challenge::random().unwrap();
        let url = c
            .authorize_url(
                "https://id.example.invalid/realms/lab/protocol/openid-connect/auth",
                "ipat-private-browser",
                "http://127.0.0.1:48765/lab/auth/browser/callback",
            )
            .unwrap();
        for part in [
            "response_type=code",
            "scope=openid",
            "code_challenge_method=S256",
            "state=",
            "nonce=",
        ] {
            assert!(url.contains(part));
        }
        assert!(!url.contains(c.verifier()));
        for endpoint in [
            "http://evil.invalid/protocol/openid-connect/auth",
            "https://evil.invalid/@inject/protocol/openid-connect/auth",
            "https://evil.invalid/?a=1/protocol/openid-connect/auth",
            "https://evil.invalid/#x/protocol/openid-connect/auth",
        ] {
            assert!(c
                .authorize_url(
                    endpoint,
                    "ipat",
                    "http://127.0.0.1:48765/lab/auth/browser/callback"
                )
                .is_none());
        }
        assert!(c
            .authorize_url(
                "https://id.example.invalid/protocol/openid-connect/auth",
                "ipat",
                "https://evil.invalid/callback"
            )
            .is_none());
    }
}
