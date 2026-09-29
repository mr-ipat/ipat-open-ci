//! Private owner's first observed lab shape, REDACTED synthetic fixtures.
//! This validates parsing only. No actual Telnet/SSH credential or source IP.
use olt_core::{
    consistent_inventory, parse_cards, parse_running_versions, reconcile_first_read_versions,
    CardStatus, EvidenceError,
};
const CARDS: &str = "ZXAN#show card\nRack Shelf Slot CfgType RealType Port HardVer SoftVer Status\n-----------\n1 1 1 GTGH GTGHK 16 V1.0.0 V2.1.0 INSERVICE\n1 1 3 PRAM PRAM 3 V1.0.0 V1.01 INSERVICE\n1 1 4 SMXA SMXA 3 V1.0.0 V2.1.0 INSERVICE\n";
const VERS: &str = "ZXAN#show version-running\nPhyLoc FileType VerType VerTag BuildTime VerLength\n--------------------\n1/1/1 GTXK MVR V2.1.0 2017-07-03 00:28:55 7789380\n1/1/1 GTXK BT V4.0.16 2018-05-09 0:53:14 524288\n1/1/4 SMXA MVR V2.1.0 2017-01-17 01:04:45 24647784\n1/1/4 SMXA BT V4.0.13 2017-04-26 9:53:13 524288\n1/1/4 SMXA FW V2.1.0 2017-06-23 03:42:13 1720296\n";

#[test]
fn first_owner_lab_real_shape_retains_partial_slot_specific_version_uncertainty() {
    let cards = parse_cards(CARDS).unwrap();
    let versions = parse_running_versions(VERS).unwrap();
    assert_eq!(cards.len(), 3);
    assert_eq!(versions.len(), 5);
    assert!(cards.iter().all(|c| c.status == CardStatus::InService));
    // Strict production full-vendor coverage still FAILS as it should.
    assert!(!consistent_inventory(&cards, &versions));
    let coverage = reconcile_first_read_versions(&cards, &versions).unwrap();
    assert_eq!(coverage.exact_mvr_slots, vec!["1/1/4"]);
    assert_eq!(
        coverage.unresolved_mvr_filetype,
        vec!["1/1/1:GTGH:GTGHK:GTXK"]
    );
    assert_eq!(coverage.no_mvr_reported_slots, vec!["1/1/3"]);
}

#[test]
fn real_shaped_partial_read_fails_closed_on_nonexistent_slot_or_conflicting_type() {
    let cards = parse_cards(CARDS).unwrap();
    let wrong_slot = VERS.replace("1/1/4 SMXA MVR", "1/1/9 SMXA MVR");
    assert_eq!(
        reconcile_first_read_versions(&cards, &parse_running_versions(&wrong_slot).unwrap()),
        Err(EvidenceError::Layout)
    );
    let conflict = VERS.replace("1/1/1 GTXK BT", "1/1/1 UNRELATED BT");
    assert_eq!(
        reconcile_first_read_versions(&cards, &parse_running_versions(&conflict).unwrap()),
        Err(EvidenceError::Layout)
    );
}

#[test]
fn actual_vendor_single_digit_hour_is_supported_but_invalid_clock_rejected() {
    assert!(parse_running_versions(VERS).is_ok());
    for bad in ["44:53:14", "0:99:14", "0:53:99", "0:5:14", "0:53:x4"] {
        let invalid = VERS.replace("0:53:14", bad);
        assert_eq!(parse_running_versions(&invalid), Err(EvidenceError::Layout));
    }
}
