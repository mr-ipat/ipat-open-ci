//! Unprivileged validation of *redacted, local, syntactically untrusted*
//! R6.1 Python lab probe artifacts. This is not proof of a physical read,
//! customer consent, credential identity, trusted timestamp or tenant binding.
use super::{normalize_resource, ApprovedReadProfile, ResourceError, UnreviewedInventory};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const REQUIRED_STRING_KEYS: [&str; 9] = [
    "target_id",
    "model",
    "architecture",
    "routeros",
    "test_scope",
    "method",
    "resource",
    "hardware_revision",
    "observed_at_utc",
];
const REQUIRED_BOOL_KEYS: [&str; 6] = [
    "read_observed",
    "operator_review_complete",
    "physical_device_enrolled",
    "tenant_binding_verified",
    "compatibility_verified",
    "configuration_modified",
];

struct PrivateEvidence {
    strings: BTreeMap<String, String>,
    flags: BTreeMap<String, bool>,
}

impl<'de> Deserialize<'de> for PrivateEvidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = PrivateEvidence;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("exactly the allowlisted local redacted evidence fields")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut strings = BTreeMap::new();
                let mut flags = BTreeMap::new();
                let mut seen = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if seen.len() >= REQUIRED_STRING_KEYS.len() + REQUIRED_BOOL_KEYS.len() {
                        return Err(de::Error::custom("excessive evidence fields"));
                    }
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate evidence field"));
                    }
                    if REQUIRED_STRING_KEYS.contains(&key.as_str()) {
                        let value = map.next_value::<String>()?;
                        if value.len() > 96 {
                            return Err(de::Error::custom("unsafe evidence string"));
                        }
                        strings.insert(key, value);
                    } else if REQUIRED_BOOL_KEYS.contains(&key.as_str()) {
                        flags.insert(key, map.next_value::<bool>()?);
                    } else {
                        // Unlike the untrusted device response parser, this
                        // PRIVATE artifacts schema is exact/closed.
                        return Err(de::Error::custom("unapproved evidence field"));
                    }
                }
                if REQUIRED_STRING_KEYS
                    .iter()
                    .any(|key| !strings.contains_key(*key))
                    || REQUIRED_BOOL_KEYS
                        .iter()
                        .any(|key| !flags.contains_key(*key))
                {
                    return Err(de::Error::custom("missing evidence field"));
                }
                Ok(PrivateEvidence { strings, flags })
            }
        }
        deserializer.deserialize_map(StrictVisitor)
    }
}

/// Validates a locally held *redacted* probe result without authenticating it.
/// Deliberately returns the same restrictive UnreviewedInventory type as a
/// raw synthetic read: no enrollment, tenant assignment or write authority.
pub fn normalize_staged_lab_evidence(
    redacted: &[u8],
    profile: ApprovedReadProfile,
) -> Result<UnreviewedInventory, ResourceError> {
    if redacted.is_empty() || redacted.len() > 2_048 {
        return Err(ResourceError::Oversized);
    }
    let fields: PrivateEvidence =
        serde_json::from_slice(redacted).map_err(|_| ResourceError::InvalidJson)?;
    let string = |key: &str| fields.strings.get(key).map(String::as_str).unwrap_or("");
    let flag = |key: &str| *fields.flags.get(key).unwrap_or(&false);

    // Two strictly read-only transports may produce the SAME untrusted,
    // redacted identity tuple. Never mix method, scope and resource values.
    let read_only_rest = string("test_scope") == "one_authenticated_read_only_rest_get"
        && string("method") == "GET"
        && string("resource") == "/rest/system/resource";
    let read_only_ssh = string("test_scope") == "one_authenticated_read_only_ssh_exec"
        && string("method") == "SSH_EXEC"
        && string("resource") == "/system/resource:board-name,architecture-name,version";
    if string("target_id") != "DEV-08"
        || !(read_only_rest || read_only_ssh)
        || string("hardware_revision") != "NOT_OBSERVED"
        || !flag("read_observed")
        || flag("operator_review_complete")
        || flag("physical_device_enrolled")
        || flag("tenant_binding_verified")
        || flag("compatibility_verified")
        || flag("configuration_modified")
    {
        return Err(ResourceError::InvalidJson);
    }
    // This is a syntax sanity check only, never a cryptographic proof of time.
    let time = string("observed_at_utc");
    if time.len() < 20
        || time.len() > 40
        || !time.is_ascii()
        || !time.contains('T')
        || !(time.ends_with('Z') || time.ends_with("+00:00"))
    {
        return Err(ResourceError::InvalidJson);
    }
    // serde_json encodes controlled text safely; does not serialize unknown
    // raw device fields, and reuses the exact Rust firmware/board policy.
    let minimal = serde_json::json!({
        "board-name": string("model"),
        "architecture-name": string("architecture"),
        "version": string("routeros"),
    });
    let bytes = serde_json::to_vec(&minimal).map_err(|_| ResourceError::InvalidJson)?;
    normalize_resource(&bytes, profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_evidence() -> serde_json::Value {
        // Explicitly synthetic: independent proof/consent is never inferred
        // by validating a JSON file supplied by an untrusted local user.
        serde_json::json!({
            "target_id": "DEV-08",
            "model": "RB951Ui-2HnD",
            "architecture": "mipsbe",
            "routeros": "7.23.7 (stable)",
            "test_scope": "one_authenticated_read_only_rest_get",
            "method": "GET",
            "resource": "/rest/system/resource",
            "read_observed": true,
            "operator_review_complete": false,
            "physical_device_enrolled": false,
            "tenant_binding_verified": false,
            "compatibility_verified": false,
            "configuration_modified": false,
            "hardware_revision": "NOT_OBSERVED",
            "observed_at_utc": "2026-09-26T05:52:00+00:00",
        })
    }

    fn parse(value: serde_json::Value) -> Result<UnreviewedInventory, ResourceError> {
        normalize_staged_lab_evidence(
            &serde_json::to_vec(&value).unwrap(),
            ApprovedReadProfile::Dev08OwnerReportedRb951,
        )
    }

    #[test]
    fn accepts_only_synthetic_unreviewed_redacted_first_read() {
        let result = parse(good_evidence()).unwrap();
        assert_eq!(result.target_id(), "DEV-08");
        assert_eq!(result.observed_routeros(), "7.23.7 (stable)");
        assert!(!result.physical_read_reviewed());
        assert!(!result.tenant_binding_verified());
        assert!(!result.configuration_writes_permitted());
    }

    #[test]
    fn cannot_promote_or_relabel_unreviewed_metadata() {
        for (field, value) in [
            ("operator_review_complete", true),
            ("physical_device_enrolled", true),
            ("tenant_binding_verified", true),
            ("compatibility_verified", true),
            ("configuration_modified", true),
            ("read_observed", false),
        ] {
            let mut file = good_evidence();
            file[field] = serde_json::json!(value);
            assert!(parse(file).is_err(), "{field}");
        }
    }

    #[test]
    fn accepts_synthetic_ssh_unreviewed_identity_without_forged_privileges() {
        let mut file = good_evidence();
        file["test_scope"] = serde_json::json!("one_authenticated_read_only_ssh_exec");
        file["method"] = serde_json::json!("SSH_EXEC");
        file["resource"] =
            serde_json::json!("/system/resource:board-name,architecture-name,version");
        let result = parse(file.clone()).unwrap();
        assert_eq!(result.target_id(), "DEV-08");
        assert!(!result.physical_read_reviewed());
        assert!(!result.physical_enrollment_authorized());
        assert!(!result.tenant_binding_verified());
        assert!(!result.configuration_writes_permitted());
        for (field, forged) in [
            ("method", "POST"),
            ("method", "GET"),
            ("resource", "/system/resource/set"),
            ("test_scope", "one_authenticated_read_only_rest_get"),
        ] {
            let mut altered = file.clone();
            altered[field] = serde_json::json!(forged);
            assert!(parse(altered).is_err(), "{field}");
        }
        file["tenant_binding_verified"] = serde_json::json!(true);
        assert!(parse(file).is_err());
    }

    #[test]
    fn disallows_privileged_http_method_or_unapproved_resource() {
        for (field, value) in [
            ("method", "POST"),
            ("method", "PUT"),
            ("resource", "/rest/ip/firewall/filter"),
            ("resource", "/rest/ppp/secret"),
            ("test_scope", "full_management"),
            ("target_id", "DEV-05"),
            ("hardware_revision", "ASSUMED"),
        ] {
            let mut file = good_evidence();
            file[field] = serde_json::json!(value);
            assert!(parse(file).is_err(), "{field}");
        }
    }

    #[test]
    fn rejects_injected_extra_pii_and_missing_fields() {
        let mut extra = good_evidence();
        extra["serial-number"] = serde_json::json!("FAKE_SENSITIVE_SERIAL");
        assert!(parse(extra).is_err());
        let mut incomplete = good_evidence();
        incomplete
            .as_object_mut()
            .unwrap()
            .remove("operator_review_complete");
        assert!(parse(incomplete).is_err());
    }

    #[test]
    fn rejects_duplicate_unknown_and_oversized_evidence() {
        let raw = serde_json::to_string(&good_evidence()).unwrap();
        let duplicate = raw.replacen(
            "\"target_id\":\"DEV-08\"",
            "\"target_id\":\"DEV-08\",\"target_id\":\"DEV-08\"",
            1,
        );
        assert_eq!(
            normalize_staged_lab_evidence(
                duplicate.as_bytes(),
                ApprovedReadProfile::Dev08OwnerReportedRb951
            ),
            Err(ResourceError::InvalidJson)
        );
        assert_eq!(
            normalize_staged_lab_evidence(
                &vec![b'X'; 2_049],
                ApprovedReadProfile::Dev08OwnerReportedRb951
            ),
            Err(ResourceError::Oversized)
        );
    }

    #[test]
    fn rejects_wrong_firmware_hardware_timestamp_and_unsafe_types() {
        for (field, value) in [
            ("routeros", serde_json::json!("7.23.70")),
            ("model", serde_json::json!("FakeRB")),
            ("architecture", serde_json::json!("arm")),
            ("observed_at_utc", serde_json::json!("unknown")),
            (
                "observed_at_utc",
                serde_json::json!("2026-09-26T05:52:00+01:00"),
            ),
            ("model", serde_json::json!(100)),
        ] {
            let mut file = good_evidence();
            file[field] = value;
            assert!(parse(file).is_err(), "{field}");
        }
    }
}
