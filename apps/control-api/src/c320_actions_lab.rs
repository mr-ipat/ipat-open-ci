//! R9.19 strict offline-only action catalog for unadopted C320 DEV-01.
//! A historical SSH banner is NOT trusted console identity, authenticated
//! firmware inventory or permission to dispatch commands to a live OLT.
use axum::{
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

fn blocked_action(label: &'static str, status: &'static str, next: &'static str) -> Value {
    json!({"action":label,"state":status,"enabled":false,
       "requires":next,"can_run_on_live_device":false,"writes":false})
}
fn high_impact(label: &'static str) -> Value {
    json!({"action":label,"state":"HIGH_IMPACT_LOCKED",
       "enabled":false,"requires":"SEPARATE_FIRMWARE_SPECIFIC_TEST_BACKUP_RESTORE_MFA_MAKER_CHECKER_MAINTENANCE",
       "can_run_on_live_device":false,"writes":true})
}
fn readiness() -> Value {
    let mut catalog = json!({
      "target":"DEV-01",
      "mode":"PHYSICAL_C320_PRE_ADOPTION_ACTION_CATALOG",
      "adoption_state":"AUTHENTICATED_LAB_READ_OBSERVED_ADOPTION_PENDING",
      "transport":"OWNER_APPROVED_AUTHENTICATED_LAB_SSH_AND_TELNET_FIRST_READ",
      "tested_legacy_ssh_profile":"RSA_AES128CBC_GROUP14SHA256_ONLY",
      "actual_transport_authentication_stage_reached":true,
      "observed_network_host_key_still_untrusted":true,
      "credential_free_test_no_timeout":true,
      "physical_test_actual_login_performed":true,
      "observed_test_account_ssh_auth_methods":["password"],
      "publickey_offer_observed_for_test_account":false,
      "password_sent_to_physical_olt":true,
      "credentials_sent_during_transport_test":false,
      "olt_commands_during_transport_test":0,
      "preferred_connection":"ENCRYPTED_LEGACY_SSH_OBSERVED_NETWORK_KEY_LAB_ONLY",
      "alternate_telnet323_passive_tcp_reachable":true,
      "alternate_telnet323_real_telnet_iac_observed":true,
      "alternate_telnet323_observed_inbound_bytes":15,
      "alternate_telnet323_credentials_sent":false,
      "alternate_telnet323_host_identity_unverified":true,
      "alternate_telnet323_unencrypted_not_approved_for_login":false,
      "alternate_telnet323_olt_commands_executed":0,
      "real_device_authenticated":true,
      "independent_oob_olt_host_key_verified":false,
      "dedicated_device_readonly_account_verified":false,
      "management_last_hop_isolated":false,
      "model_and_firmware_read_from_real_hardware":true,
      "live_distribution_baseline_approved":false,
      "genuine_tenant_admin_mfa_verified":false,
      "independent_reviewer_approved":false,
      "worker_enabled":false,
      "network_actions":0,
      "device_adopted":false,
      "actual_device_health":"THREE_CARDS_INSERVICE_ALARMS_NOT_MEASURED",
      "capabilities":[
        blocked_action("READ_CARD_INVENTORY","ACTUAL_MANUAL_LAB_FIRST_READ_VERIFIED_WORKER_BLOCKED",
          "INDEPENDENT_HOST_KEY_RESTRICTED_ACCOUNT_SCOPED_WORKER_BASELINE_AND_SIGNED_APPROVAL"),
        blocked_action("READ_RUNNING_FIRMWARE","ACTUAL_MANUAL_LAB_PARTIAL_FW_RECONCILIATION_OPEN",
          "FIRST_REAL_CARD_READ_VERIFIED_THEN_VENDOR_EXACT_VERSION_COMMAND"),
        blocked_action("READ_ACTIVE_ALARMS","UNTESTED_ON_EXACT_FIRMWARE",
          "VENDOR_COMMAND_AND_FIRMWARE_READONLY_INTEROP_VERIFIED"),
        blocked_action("LIST_ONTS","UNTESTED_ON_EXACT_FIRMWARE",
          "VENDOR_COMMAND_AND_FIRMWARE_READONLY_INTEROP_VERIFIED"),
        blocked_action("READ_ONT_OPTICAL_METRICS","UNTESTED_ON_EXACT_FIRMWARE",
          "PER_ONU_OPTICAL_COMMAND_RATE_LIMIT_AND_INTEROP_VERIFIED"),
        high_impact("PROVISION_ONTS"),
        high_impact("REBOOT_OLT"),
        high_impact("UPGRADE_OLT_FIRMWARE"),
      ]
    });
    let lab = json!({
      "observed_lab_telnet_password_session_authenticated":true,
      "observed_lab_ssh_password_session_authenticated":true,
      "owner_attests_no_customer_connections_in_test_lab":true,
      "actual_cards_reported":3,
      "actual_cards_reported_inservice":3,
      "actual_version_rows_reported":5,
      "actual_firmware_filetype_alias_unresolved":true,
      "actual_pram_running_mvr_not_reported":true,
      "first_live_observation_from_manually_transcribed_capture":true,
      "observed_ssh_network_rsa_key_matches_historical_mac_and_vps":true,
      "observed_ssh_network_rsa_is_not_independent_physical_attestation":true,
      "temporary_default_test_credential_needs_rotation":true,
      "lab_manual_successful_read_commands":5,
      "lab_unsupported_read_command_rejected":1,
      "production_auto_adoption_approved":false,
    });
    catalog
        .as_object_mut()
        .expect("known static catalog")
        .extend(lab.as_object().expect("known static evidence").clone());
    catalog
}
pub(super) async fn list(
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<Value>), (StatusCode, HeaderMap, Json<Value>)> {
    if !super::device_workbench_lab::demo_csrf_read(&headers) {
        return Err((
            StatusCode::FORBIDDEN,
            super::private_lab_headers("application/json; charset=utf-8"),
            Json(json!({"error":"PRIVATE_LOCAL_LAB_ONLY"})),
        ));
    }
    Ok((
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(readiness()),
    ))
}
pub(super) async fn reject_execute() -> (StatusCode, HeaderMap, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(json!({"error":"REAL_HARDWARE_ACTIONS_NOT_MOUNTED",
        "network_actions":0,"worker_enabled":false,"device_adopted":false})),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_real_hardware_proof_keeps_entire_catalog_disabled() {
        let r = readiness();
        assert_eq!(
            r["transport"],
            "OWNER_APPROVED_AUTHENTICATED_LAB_SSH_AND_TELNET_FIRST_READ"
        );
        assert_eq!(
            r["tested_legacy_ssh_profile"],
            "RSA_AES128CBC_GROUP14SHA256_ONLY"
        );
        assert_eq!(r["actual_transport_authentication_stage_reached"], true);
        assert_eq!(r["credentials_sent_during_transport_test"], false);
        assert_eq!(r["olt_commands_during_transport_test"], 0);
        assert_eq!(r["alternate_telnet323_passive_tcp_reachable"], true);
        assert_eq!(r["alternate_telnet323_real_telnet_iac_observed"], true);
        assert_eq!(r["alternate_telnet323_observed_inbound_bytes"], 15);
        assert_eq!(r["alternate_telnet323_credentials_sent"], false);
        assert_eq!(
            r["alternate_telnet323_unencrypted_not_approved_for_login"],
            false
        );
        assert_eq!(r["alternate_telnet323_olt_commands_executed"], 0);
        assert_eq!(r["physical_test_actual_login_performed"], true);
        assert_eq!(r["real_device_authenticated"], true);
        assert_eq!(r["model_and_firmware_read_from_real_hardware"], true);
        assert_eq!(r["observed_lab_ssh_password_session_authenticated"], true);
        assert_eq!(
            r["observed_lab_telnet_password_session_authenticated"],
            true
        );
        assert_eq!(r["actual_cards_reported"], 3);
        assert_eq!(r["actual_version_rows_reported"], 5);
        assert_eq!(r["actual_firmware_filetype_alias_unresolved"], true);
        assert_eq!(r["actual_pram_running_mvr_not_reported"], true);
        assert_eq!(r["device_adopted"], false);
        assert_eq!(r["independent_reviewer_approved"], false);
        assert_eq!(r["independent_oob_olt_host_key_verified"], false);
        assert_eq!(r["worker_enabled"], false);
        assert_eq!(r["network_actions"], 0);
        let array = r["capabilities"].as_array().unwrap();
        assert_eq!(array.len(), 8);
        for action in array {
            assert_eq!(action["enabled"], false);
            assert_eq!(action["can_run_on_live_device"], false);
        }
        assert_eq!(array[0]["action"], "READ_CARD_INVENTORY");
        assert_eq!(
            array[0]["state"],
            "ACTUAL_MANUAL_LAB_FIRST_READ_VERIFIED_WORKER_BLOCKED"
        );
        assert_eq!(array[7]["action"], "UPGRADE_OLT_FIRMWARE");
        assert_eq!(array[7]["state"], "HIGH_IMPACT_LOCKED");
    }
}
