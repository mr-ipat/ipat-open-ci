//! Canonical tenant identifiers; does not authenticate any network request.

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTenantId;

impl TenantId {
    /// Permit only lower-case DNS-label-like stable identifiers.
    pub fn parse(value: &str) -> Result<Self, InvalidTenantId> {
        if value.is_empty() || value.len() > 63 {
            return Err(InvalidTenantId);
        }
        let bytes = value.as_bytes();
        let is_lower_alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        if !is_lower_alnum(bytes[0]) || !is_lower_alnum(bytes[bytes.len() - 1]) {
            return Err(InvalidTenantId);
        }
        if !bytes.iter().all(|c| is_lower_alnum(*c) || *c == b'-') {
            return Err(InvalidTenantId);
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_synthetic_tenants() {
        assert_eq!(TenantId::parse("kangnet").unwrap().as_str(), "kangnet");
        assert_eq!(TenantId::parse("nengnet").unwrap().as_str(), "nengnet");
    }

    #[test]
    fn rejects_ambiguous_or_unbounded_identifiers() {
        for candidate in ["", "-bad", "bad-", "Upper", "has.dot", "two spaces"] {
            assert!(TenantId::parse(candidate).is_err(), "{candidate}");
        }
        assert!(TenantId::parse(&"x".repeat(64)).is_err());
        assert!(TenantId::parse(&"x".repeat(63)).is_ok());
    }
}
