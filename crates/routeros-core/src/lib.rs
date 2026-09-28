//! Offline IPAT RouterOS resource normalization. NOT an authenticated adapter,
//! device connector, physical interoperability claim, or enrollment capability.
//! No network, secrets, raw response logging, or mutation methods exist here.

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeSet;
use std::fmt;

/// Offline validation of PRIVATE redacted R6.1 probe output. Still untrusted.
pub mod evidence;

const MAX_RESOURCE_BYTES: usize = 32_768;
const MAX_FIELDS: usize = 64;
const EXPECTED_BOARD: &str = "RB951Ui-2HnD";
const EXPECTED_ARCH: &str = "mipsbe";
const EXPECTED_VERSION: &str = "7.23.7";

/// New firmware, board revisions and vendors require separate, reviewed
/// profiles and physical evidence. This enum is intentionally NOT user input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovedReadProfile {
    Dev08OwnerReportedRb951,
}

/// Never propagate raw JSON or device-provided strings through errors/logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceError {
    Oversized,
    InvalidJson,
    DuplicateField,
    ExcessiveFields,
    UnexpectedCardinality,
    MissingIdentity,
    UnsafeIdentity,
    UnapprovedHardware,
    UnapprovedFirmware,
}

#[derive(Default)]
struct ResourceRow {
    board: Option<String>,
    arch: Option<String>,
    version: Option<String>,
}

impl<'de> Deserialize<'de> for ResourceRow {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RowVisitor;
        impl<'de> Visitor<'de> for RowVisitor {
            type Value = ResourceRow;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("one bounded RouterOS system resource object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut seen = BTreeSet::new();
                let mut row = ResourceRow::default();
                while let Some(key) = map.next_key::<String>()? {
                    if seen.len() >= MAX_FIELDS {
                        return Err(de::Error::custom("excessive fields"));
                    }
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate field"));
                    }
                    match key.as_str() {
                        "board-name" => row.board = Some(map.next_value::<String>()?),
                        "architecture-name" => row.arch = Some(map.next_value::<String>()?),
                        "version" => row.version = Some(map.next_value::<String>()?),
                        // Never deserialize/export IP addresses, serials,
                        // credentials, PPPoE state or any unapproved field.
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(row)
            }
        }
        deserializer.deserialize_map(RowVisitor)
    }
}

struct ResourceReply(ResourceRow);

impl<'de> Deserialize<'de> for ResourceReply {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ReplyVisitor;
        impl<'de> Visitor<'de> for ReplyVisitor {
            type Value = ResourceReply;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("exactly one RouterOS resource record")
            }

            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                let row = ResourceRow::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(ResourceReply(row))
            }

            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                let row = seq
                    .next_element::<ResourceRow>()?
                    .ok_or_else(|| de::Error::custom("missing single resource record"))?;
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("unexpected additional resource record"));
                }
                Ok(ResourceReply(row))
            }
        }
        deserializer.deserialize_any(ReplyVisitor)
    }
}

/// Unreviewed evidence only. The constructor is private and there is no
/// conversion to VerifiedDevice, tenant membership or privileged command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnreviewedInventory {
    board: String,
    architecture: String,
    observed_routeros: String,
}

impl UnreviewedInventory {
    pub fn target_id(&self) -> &'static str {
        "DEV-08"
    }
    pub fn board(&self) -> &str {
        &self.board
    }
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
    pub fn observed_routeros(&self) -> &str {
        &self.observed_routeros
    }
    pub fn physical_enrollment_authorized(&self) -> bool {
        false
    }
    pub fn tenant_binding_verified(&self) -> bool {
        false
    }
    pub fn configuration_writes_permitted(&self) -> bool {
        false
    }
    pub fn physical_read_reviewed(&self) -> bool {
        false
    }
}

fn safe_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_' | b'(' | b')' | b' ')
        })
}

fn known_version(v: &str) -> bool {
    // The official REST schema permits a human-readable channel suffix.
    // Never accept arbitrary strings (e.g. testing/development) as proof
    // that a different image matches the owner-reported version.
    v == EXPECTED_VERSION || v == "7.23.7 (stable)" || v == "7.23.7 (long-term)"
}

/// Normalize ONLY the exact owner-reported initial lab target. Does not
/// access any equipment, assert source authenticity or grant authorization.
pub fn normalize_resource(
    input: &[u8],
    _profile: ApprovedReadProfile,
) -> Result<UnreviewedInventory, ResourceError> {
    if input.is_empty() || input.len() > MAX_RESOURCE_BYTES {
        return Err(ResourceError::Oversized);
    }
    let reply: ResourceReply = serde_json::from_slice(input).map_err(|err| {
        let msg = err.to_string();
        if msg.contains("duplicate field") {
            ResourceError::DuplicateField
        } else if msg.contains("excessive fields") {
            ResourceError::ExcessiveFields
        } else if msg.contains("resource record") {
            ResourceError::UnexpectedCardinality
        } else {
            ResourceError::InvalidJson
        }
    })?;
    let board = reply.0.board.ok_or(ResourceError::MissingIdentity)?;
    let arch = reply.0.arch.ok_or(ResourceError::MissingIdentity)?;
    let version = reply.0.version.ok_or(ResourceError::MissingIdentity)?;
    if !safe_token(&board) || !safe_token(&arch) || !safe_token(&version) {
        return Err(ResourceError::UnsafeIdentity);
    }
    if board != EXPECTED_BOARD || arch != EXPECTED_ARCH {
        return Err(ResourceError::UnapprovedHardware);
    }
    if !known_version(&version) {
        return Err(ResourceError::UnapprovedFirmware);
    }
    Ok(UnreviewedInventory {
        board,
        architecture: arch,
        observed_routeros: version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> &'static [u8] {
        br#"[{"board-name":"RB951Ui-2HnD","architecture-name":"mipsbe",
             "version":"7.23.7","serial-number":"FAKE_SERIAL_MUST_BE_DROPPED",
             "ip-address":"PRIVATE_IP_MUST_BE_DROPPED",
             "password":"FAKE_SECRET_MUST_BE_DROPPED"}]"#
    }

    #[test]
    fn normalizes_exact_owner_report_without_ever_marking_hardware_verified() {
        let inventory =
            normalize_resource(good(), ApprovedReadProfile::Dev08OwnerReportedRb951).unwrap();
        assert_eq!(inventory.board(), "RB951Ui-2HnD");
        assert_eq!(inventory.architecture(), "mipsbe");
        assert_eq!(inventory.observed_routeros(), "7.23.7");
        assert_eq!(inventory.target_id(), "DEV-08");
        assert!(!inventory.physical_enrollment_authorized());
        assert!(!inventory.tenant_binding_verified());
        assert!(!inventory.configuration_writes_permitted());
        assert!(!inventory.physical_read_reviewed());
        let output = format!("{inventory:?}");
        for forbidden in ["FAKE_SERIAL", "FAKE_SECRET", "PRIVATE_IP"] {
            assert!(!output.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn normalizes_validated_shape_variants_and_documented_channel_suffix() {
        for version in ["7.23.7", "7.23.7 (stable)", "7.23.7 (long-term)"] {
            let json = format!(
                r#"{{"architecture-name":"mipsbe","board-name":"RB951Ui-2HnD",
                "version":"{version}","cpu-count":"1"}}"#
            );
            let result = normalize_resource(
                json.as_bytes(),
                ApprovedReadProfile::Dev08OwnerReportedRb951,
            )
            .unwrap();
            assert_eq!(result.observed_routeros(), version);
        }
    }

    #[test]
    fn rejects_other_device_or_architecture() {
        for (board, arch) in [("CCR2004", "mipsbe"), ("RB951Ui-2HnD", "arm")] {
            let input = format!(
                r#"[{{"board-name":"{board}","architecture-name":"{arch}","version":"7.23.7"}}]"#
            );
            assert_eq!(
                normalize_resource(
                    input.as_bytes(),
                    ApprovedReadProfile::Dev08OwnerReportedRb951
                ),
                Err(ResourceError::UnapprovedHardware)
            );
        }
    }

    #[test]
    fn rejects_other_version_and_unapproved_channels() {
        for version in [
            "7.23.6",
            "7.23.70",
            "7.23.7 (development)",
            "7.23.7 (testing)",
        ] {
            let input = format!(
                r#"[{{"board-name":"RB951Ui-2HnD","architecture-name":"mipsbe",
                   "version":"{version}"}}]"#
            );
            assert_eq!(
                normalize_resource(
                    input.as_bytes(),
                    ApprovedReadProfile::Dev08OwnerReportedRb951
                ),
                Err(ResourceError::UnapprovedFirmware)
            );
        }
    }

    #[test]
    fn rejects_duplicate_even_unapproved_fields_before_returning_any_evidence() {
        for input in [
            br#"[{"board-name":"RB951Ui-2HnD","board-name":"RB951Ui-2HnD","architecture-name":"mipsbe","version":"7.23.7"}]"#.as_slice(),
            br#"[{"board-name":"RB951Ui-2HnD","architecture-name":"mipsbe","version":"7.23.7","secret":"a","secret":"b"}]"#.as_slice(),
        ] {
            assert_eq!(
                normalize_resource(input, ApprovedReadProfile::Dev08OwnerReportedRb951),
                Err(ResourceError::DuplicateField)
            );
        }
    }

    #[test]
    fn rejects_missing_identity_and_wrong_json_type() {
        for input in [
            br#"[]"#.as_slice(),
            br#"[{"board-name":"RB951Ui-2HnD","version":"7.23.7"}]"#.as_slice(),
            br#""FAKE""#.as_slice(),
            br#"null"#.as_slice(),
        ] {
            assert!(
                normalize_resource(input, ApprovedReadProfile::Dev08OwnerReportedRb951).is_err()
            );
        }
    }

    #[test]
    fn rejects_multiple_rows_and_unbounded_responses() {
        let multiple = format!(
            "[{},{}]",
            String::from_utf8_lossy(good())
                .trim_start_matches('[')
                .trim_end_matches(']'),
            String::from_utf8_lossy(good())
                .trim_start_matches('[')
                .trim_end_matches(']')
        );
        assert_eq!(
            normalize_resource(
                multiple.as_bytes(),
                ApprovedReadProfile::Dev08OwnerReportedRb951
            ),
            Err(ResourceError::UnexpectedCardinality)
        );
        assert_eq!(
            normalize_resource(
                &vec![b'a'; MAX_RESOURCE_BYTES + 1],
                ApprovedReadProfile::Dev08OwnerReportedRb951
            ),
            Err(ResourceError::Oversized)
        );
    }

    #[test]
    fn rejects_control_characters_in_identifying_fields() {
        let input = br#"[{"board-name":"RB951Ui-2HnD\\n","architecture-name":"mipsbe","version":"7.23.7"}]"#;
        assert!(normalize_resource(input, ApprovedReadProfile::Dev08OwnerReportedRb951).is_err());
    }

    #[test]
    fn rejects_malicious_duplicate_bomb_before_logging_any_payload() {
        let fields = (0..MAX_FIELDS + 1)
            .map(|i| format!(r#""extra{i}":"x""#))
            .collect::<Vec<_>>()
            .join(",");
        let input = format!(
            r#"[{{"board-name":"RB951Ui-2HnD","architecture-name":"mipsbe","version":"7.23.7",{fields}}}]"#
        );
        assert_eq!(
            normalize_resource(
                input.as_bytes(),
                ApprovedReadProfile::Dev08OwnerReportedRb951
            ),
            Err(ResourceError::ExcessiveFields)
        );
    }
}
