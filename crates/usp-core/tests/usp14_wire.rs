//! Independently hand-encoded USP v1.4 BBF protobuf binary goldens.
use usp_core::wire14::{
    encode_offline_get, inspect_no_session_get_response, WireError, MAX_RECORD_BYTES,
};
const GET_REQUEST: &[u8] = include_bytes!("fixtures/usp14_get_request.bin");
const GET_RESPONSE: &[u8] = include_bytes!("fixtures/usp14_get_response.bin");

fn swapped(raw: &[u8], original: &[u8], changed: &[u8]) -> Vec<u8> {
    assert_eq!(original.len(), changed.len());
    let found = raw
        .windows(original.len())
        .position(|w| w == original)
        .unwrap();
    let mut copy = raw.to_vec();
    copy[found..found + original.len()].copy_from_slice(changed);
    copy
}
#[test]
fn real_prost_encoder_matches_independent_manual_bbf14_get_request() {
    let actual = encode_offline_get(
        "usp::offline-controller",
        "usp::sim-agent-a",
        "r-example-1",
        &["Device.DeviceInfo."],
    )
    .unwrap();
    assert_eq!(actual, GET_REQUEST);
    assert_eq!(
        inspect_no_session_get_response(&actual).err(),
        Some(WireError::UnsupportedMessage),
        "MUST refuse treating a read-request as an authenticated response",
    );
}
#[test]
fn real_prost_decoder_parses_independent_manual_get_response_but_not_identity() {
    let got = inspect_no_session_get_response(GET_RESPONSE).unwrap();
    assert_eq!(got.message_id, "r-example-1");
    assert_eq!(got.claimed_from, "usp::sim-agent-a");
    assert_eq!(got.claimed_to, "usp::offline-controller");
    assert_eq!(got.requested_paths, 1);
    assert_eq!(got.resolved_paths, 1);
    assert_eq!(got.parameter_values, 1);
    // This claimed sender is completely unauthenticated and MUST NOT be
    // used to mint the private VerifiedAgent type in usp-core domain.
    let spoofed = swapped(GET_RESPONSE, b"usp::sim-agent-a", b"usp::sim-agent-b");
    let attacker = inspect_no_session_get_response(&spoofed).unwrap();
    assert_eq!(attacker.claimed_from, "usp::sim-agent-b");
}
#[test]
fn rejects_duplicate_record_oneof_and_unsupported_session_record() {
    let mut duplicated = GET_RESPONSE.to_vec();
    duplicated.extend_from_slice(&[0x3a, 0]); // duplicate Record.no_session tag 7
    assert_eq!(
        inspect_no_session_get_response(&duplicated).err(),
        Some(WireError::UnknownOrDuplicateField),
    );
    let mut session = GET_RESPONSE.to_vec();
    session.extend_from_slice(&[0x42, 0]); // Record.session_context tag 8
    assert_eq!(
        inspect_no_session_get_response(&session).err(),
        Some(WireError::UnknownOrDuplicateField),
    );
}
#[test]
fn rejects_unknown_record_extension_without_silent_prost_discard() {
    let mut unknown = GET_RESPONSE.to_vec();
    unknown.extend_from_slice(&[0x72, 0]); // Record.unknown field14
    assert_eq!(
        inspect_no_session_get_response(&unknown).err(),
        Some(WireError::UnknownOrDuplicateField),
    );
}
#[test]
fn refuses_mismatched_version_unsupported_message_and_bad_endpoint() {
    let version = swapped(GET_RESPONSE, b"1.4", b"9.9");
    assert_eq!(
        inspect_no_session_get_response(&version).err(),
        Some(WireError::UnsupportedRecord)
    );
    let bad_type = swapped(GET_RESPONSE, &[0x10, 0x02], &[0x10, 0x04]);
    assert_eq!(
        inspect_no_session_get_response(&bad_type).err(),
        Some(WireError::UnsupportedMessage)
    );
    let bad_identity = swapped(GET_RESPONSE, b"usp::sim-agent-a", b"ssh::sim-agent-a");
    assert_eq!(
        inspect_no_session_get_response(&bad_identity).err(),
        Some(WireError::UnsupportedRecord)
    );
}
#[test]
fn denies_invalid_payload_size_varints_and_truncation_without_panics() {
    assert_eq!(
        inspect_no_session_get_response(&vec![0x12; MAX_RECORD_BYTES + 1]).err(),
        Some(WireError::Oversize),
    );
    for bad in [&[0xff; 11][..], &[0x3a, 0xff][..], &[0x0a][..]] {
        assert!(inspect_no_session_get_response(bad).is_err());
    }
    for suffix in 1..12 {
        assert!(inspect_no_session_get_response(&GET_RESPONSE[..suffix]).is_err());
    }
}
#[test]
fn offline_get_builder_denies_writes_unscoped_paths_and_bogus_peers() {
    for path in [
        "Device..Foo",
        "InternetGatewayDevice.Foo",
        "Device.Wifi;Delete",
        "Device.SetParameterValues()",
    ] {
        assert_eq!(
            encode_offline_get("usp::controller", "usp::agent-a", "r1", &[path]).err(),
            Some(WireError::InvalidPath),
            "{path}",
        );
    }
    assert_eq!(
        encode_offline_get("usp::controller", "usp::agent-a", "r1", &[]).err(),
        Some(WireError::InvalidPath),
    );
    assert_eq!(
        encode_offline_get(
            "usp::controller",
            "usp::controller",
            "r1",
            &["Device.DeviceInfo."]
        )
        .err(),
        Some(WireError::InvalidIdentifier),
    );
    assert_eq!(
        encode_offline_get(
            "usp::controller",
            "usp::agent-a",
            "r1;reboot",
            &["Device.DeviceInfo."]
        )
        .err(),
        Some(WireError::InvalidIdentifier),
    );
}
