//! ZTE C320 PURE offline laboratory parser and firmware planning policy.
//! Never connects, authenticates, uploads, upgrades or returns raw transcripts.
pub const MAX_OUTPUT: usize = 32768;
pub const READ_COMMANDS: [&str; 2] = ["show card", "show version-running"];
pub const WRITE_ENABLED: bool = false;
#[derive(Debug, PartialEq, Eq)]
pub enum EvidenceError {
    Empty,
    Unsafe,
    Size,
    Layout,
    Duplicate,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Card {
    pub location: String,
    /// Vendor CfgType, not necessarily identical to the physical RealType.
    pub configured_type: String,
    pub card_type: String,
    pub status: CardStatus,
}
#[derive(Debug, PartialEq, Eq)]
pub enum CardStatus {
    InService,
    Standby,
}
#[derive(Debug, PartialEq, Eq)]
pub struct RunningVersion {
    pub location: String,
    pub card_type: String,
    pub file_kind: String,
    pub version: String,
}
fn safe(input: &str) -> Result<(), EvidenceError> {
    if input.is_empty() {
        return Err(EvidenceError::Empty);
    }
    if input.len() > MAX_OUTPUT {
        return Err(EvidenceError::Size);
    }
    if input
        .bytes()
        .any(|b| b == 0 || b == 27 || (b < 32 && b != 10 && b != 13))
    {
        return Err(EvidenceError::Unsafe);
    }
    Ok(())
}
fn ident(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 32
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
fn location(r: &str, s: &str, c: &str) -> Option<String> {
    let parts = [r, s, c];
    if parts
        .iter()
        .all(|x| x.parse::<u8>().ok().is_some_and(|n| n >= 1 && n <= 22))
    {
        Some(parts.join("/"))
    } else {
        None
    }
}
/// Synthetic CLI table format, not vendor/firmware compatibility certification.
pub fn parse_cards(input: &str) -> Result<Vec<Card>, EvidenceError> {
    safe(input)?;
    let mut out: Vec<Card> = Vec::new();
    let mut header = false;
    for line in input.lines() {
        let col: Vec<_> = line.split_whitespace().collect();
        if col.starts_with(&["Rack", "Shelf", "Slot"]) {
            header = true;
            continue;
        }
        if !header || col.is_empty() || col[0].starts_with('-') {
            continue;
        }
        if col.len() < 9 || !ident(col[3]) || !ident(col[4]) {
            return Err(EvidenceError::Layout);
        }
        let loc = location(col[0], col[1], col[2]).ok_or(EvidenceError::Layout)?;
        let status = match col[col.len() - 1] {
            "INSERVICE" => CardStatus::InService,
            "STANDBY" => CardStatus::Standby,
            _ => return Err(EvidenceError::Layout),
        };
        if out.iter().any(|item| item.location == loc) {
            return Err(EvidenceError::Duplicate);
        }
        out.push(Card {
            location: loc,
            configured_type: col[3].into(),
            card_type: col[4].into(),
            status,
        });
        if out.len() > 22 {
            return Err(EvidenceError::Size);
        }
    }
    if !header || out.is_empty() {
        return Err(EvidenceError::Layout);
    }
    Ok(out)
}
// Some ACTUAL C320 builds print one-digit hours (e.g. 0:53:14) in
// show version-running. Validate 0..23 / 00..59 / 00..59 exactly.
fn valid_vendor_clock(text: &str) -> bool {
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 3
        || !(1..=2).contains(&parts[0].len())
        || parts[1].len() != 2
        || parts[2].len() != 2
        || parts.iter().any(|s| !s.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    matches!(
        (
            parts[0].parse::<u8>(),
            parts[1].parse::<u8>(),
            parts[2].parse::<u8>()
        ),
        (Ok(0..=23), Ok(0..=59), Ok(0..=59))
    )
}

pub fn parse_running_versions(input: &str) -> Result<Vec<RunningVersion>, EvidenceError> {
    safe(input)?;
    let mut out: Vec<RunningVersion> = Vec::new();
    let mut header = false;
    for line in input.lines() {
        let c: Vec<_> = line.split_whitespace().collect();
        if c.starts_with(&["PhyLoc", "FileType", "VerType"]) {
            header = true;
            continue;
        }
        if !header || c.is_empty() || c[0].starts_with('-') {
            continue;
        }
        if c.len() != 7 {
            return Err(EvidenceError::Layout);
        }
        let p: Vec<_> = c[0].split('/').collect();
        if p.len() != 3 {
            return Err(EvidenceError::Layout);
        }
        let loc = location(p[0], p[1], p[2]).ok_or(EvidenceError::Layout)?;
        if !ident(c[1])
            || !ident(c[3])
            || !matches!(c[2], "MVR" | "FW" | "BT")
            || !c[4].bytes().all(|b| b.is_ascii_digit() || b == b'-')
            || !valid_vendor_clock(c[5])
            || c[6].parse::<u64>().ok().filter(|n| *n > 0).is_none()
        {
            return Err(EvidenceError::Layout);
        }
        if out.iter().any(|v| v.location == loc && v.file_kind == c[2]) {
            return Err(EvidenceError::Duplicate);
        }
        out.push(RunningVersion {
            location: loc,
            card_type: c[1].into(),
            file_kind: c[2].into(),
            version: c[3].into(),
        });
        if out.len() > 66 {
            return Err(EvidenceError::Size);
        }
    }
    if !header || out.is_empty() {
        return Err(EvidenceError::Layout);
    }
    Ok(out)
}
/// Cross-check MVR for every observed card. Some historical C320 text
/// describes MVR by configured card type instead of physical RealType;
/// accept only these TWO types from the same observed slot, never an
/// unrelated type or an arbitrary same-family prefix.
pub fn consistent_inventory(cards: &[Card], versions: &[RunningVersion]) -> bool {
    !cards.is_empty()
        && cards.iter().all(|c| {
            versions.iter().any(|v| {
                v.location == c.location
                    && v.file_kind == "MVR"
                    && (v.card_type == c.card_type || v.card_type == c.configured_type)
            })
        })
}

/// Partial first real capture: correlate only by exact SLOT; do NOT infer
/// that mismatching firmware FileType is a vendor-approved card alias.
#[derive(Debug, PartialEq, Eq)]
pub struct FirstReadVersionCoverage {
    pub exact_mvr_slots: Vec<String>,
    pub unresolved_mvr_filetype: Vec<String>,
    pub no_mvr_reported_slots: Vec<String>,
}

pub fn reconcile_first_read_versions(
    cards: &[Card],
    versions: &[RunningVersion],
) -> Result<FirstReadVersionCoverage, EvidenceError> {
    if cards.is_empty() || versions.is_empty() {
        return Err(EvidenceError::Empty);
    }
    // A firmware record for a nonexistent physical slot is NOT a partial read.
    for entry in versions {
        let card = cards
            .iter()
            .find(|c| c.location == entry.location)
            .ok_or(EvidenceError::Layout)?;
        if entry.file_kind != "MVR" && entry.file_kind != "FW" && entry.file_kind != "BT" {
            return Err(EvidenceError::Layout);
        }
        // Within the same slot the file type must be the same for all
        // reported firmware/boot/file records. Otherwise fail closed.
        if versions
            .iter()
            .any(|other| other.location == card.location && other.card_type != entry.card_type)
        {
            return Err(EvidenceError::Layout);
        }
    }
    let mut result = FirstReadVersionCoverage {
        exact_mvr_slots: Vec::new(),
        unresolved_mvr_filetype: Vec::new(),
        no_mvr_reported_slots: Vec::new(),
    };
    for card in cards {
        let mvr: Vec<_> = versions
            .iter()
            .filter(|v| v.location == card.location && v.file_kind == "MVR")
            .collect();
        if mvr.is_empty() {
            result.no_mvr_reported_slots.push(card.location.clone());
        } else if mvr.len() != 1 {
            return Err(EvidenceError::Duplicate);
        } else if mvr[0].card_type == card.card_type || mvr[0].card_type == card.configured_type {
            result.exact_mvr_slots.push(card.location.clone());
        } else {
            // The actual ZTE lab showed same slot but different board
            // nomenclature. Preserve the unknown, do not silently map it.
            result.unresolved_mvr_filetype.push(format!(
                "{}:{}:{}:{}",
                card.location, card.configured_type, card.card_type, mvr[0].card_type
            ));
        }
    }
    Ok(result)
}

/// Operator inputs are NOT trusted attestations; checks only make a document
/// eligible for human review, never unlock firmware execution.
#[derive(Default, Clone, Copy)]
pub struct FirmwareReview {
    pub actual_chassis_and_card_identity_verified: bool,
    pub actual_running_versions_recorded: bool,
    pub exact_vendor_firmware_and_checksum_independently_verified: bool,
    pub complete_configuration_backup_restored_and_tested: bool,
    pub alarm_free_and_service_impact_reviewed: bool,
    pub approved_maintenance_window: bool,
    pub separate_maker_checker_approved: bool,
    pub independent_onsite_recovery_console_and_rollback: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Disposition {
    Blocked(&'static str),
    HumanReviewOnly,
}
pub fn review_firmware(g: FirmwareReview) -> Disposition {
    for (ok, msg) in [
        (
            g.actual_chassis_and_card_identity_verified,
            "exact physical card/chassis unknown",
        ),
        (
            g.actual_running_versions_recorded,
            "actual firmware unknown",
        ),
        (
            g.exact_vendor_firmware_and_checksum_independently_verified,
            "vendor image not verified",
        ),
        (
            g.complete_configuration_backup_restored_and_tested,
            "recovery test missing",
        ),
        (
            g.alarm_free_and_service_impact_reviewed,
            "alarms or customer impact unreviewed",
        ),
        (
            g.approved_maintenance_window,
            "no approved maintenance window",
        ),
        (g.separate_maker_checker_approved, "no independent approval"),
        (
            g.independent_onsite_recovery_console_and_rollback,
            "no onsite rollback",
        ),
    ] {
        if !ok {
            return Disposition::Blocked(msg);
        }
    }
    Disposition::HumanReviewOnly
}
