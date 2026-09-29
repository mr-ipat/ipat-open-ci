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
      "lab_proof_stage":"AUTHENTICATED_HARDWARE_READ_AND_OFFVPS_ENCRYPTED_BACKUP_VERIFIED",
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
      "verified_off_vps_encrypted_running_cli_reference_backup":true,
      "verified_mac_restic_isolated_byte_identical_restore":true,
      "verified_backup_at_utc":"2026-09-29T05:49:58+00:00",
      "vendor_native_startup_config_restore_tested":false,
      "separate_geo_recovery_repository_verified":false,
      "actual_local_account_privilege15_count":2,
      "actual_local_restricted_account_proven":false,
      "vendor_readonly_role_isolation_verified":false,
      "actual_live_manual_alarm_cli_syntax_verified":true,
      "actual_live_active_alarms_semantically_validated":false,
      "passwordless_ssh_service_account_verified":false,
      "physical_source_independent_console_verified":false,
      "actual_ephemeral_scripted_owner_lab_ssh_show_card_verified":true,
      "actual_ephemeral_scripted_owner_lab_ssh_read_utc":"2026-09-29T06:10:34+00:00",
      "actual_ephemeral_scripted_rust_normalizer_exact_cards":3,
      "actual_ephemeral_scripted_device_configuration_writes":0,
      "actual_ephemeral_scripted_test_credential_persisted":false,
      "ephemeral_one_shot_adapter_is_unattended_worker":false,
      "production_auto_adoption_approved":false,
    });
    catalog
        .as_object_mut()
        .expect("known static catalog")
        .extend(lab.as_object().expect("known static evidence").clone());
    catalog
}
/// Historical, SANITIZED source-backed first physical LAB C320 inventory.
/// Static release evidence ONLY, not polling or a production device record.
fn first_real_inventory() -> Value {
    json!({
        "target":"DEV-01",
        "mode":"ACTUAL_HISTORICAL_OWNER_LAB_PHYSICAL_READ_NO_WORKER",
        "recorded_date":"2026-09-29",
        "observation_is_live":false,
        "raw_captures_private_only":true,
        "device_identity_independently_attested":false,
        "real_ssh_first_read_authenticated":true,
        "owner_declares_disconnected_no_customers_lab":true,
        "cards":[
          {"slot":"1/1/1","configured":"GTGH","physical":"GTGHK",
           "card_reported_status":"INSERVICE","reported_mvr_filetype":"GTXK",
           "reported_mvr_version":"V2.1.0","mvr_card_alias_verified":false},
          {"slot":"1/1/3","configured":"PRAM","physical":"PRAM",
           "card_reported_status":"INSERVICE","reported_mvr_filetype":null,
           "reported_mvr_version":null,"mvr_card_alias_verified":false},
          {"slot":"1/1/4","configured":"SMXA","physical":"SMXA",
           "card_reported_status":"INSERVICE","reported_mvr_filetype":"SMXA",
           "reported_mvr_version":"V2.1.0","mvr_card_alias_verified":true}
        ],
        "reported_version_rows_total":5,
        "firmware_inventory_fully_reconciled":false,
        "owner_off_vps_encrypted_configuration_reference_verified":true,
        "owner_restic_isolated_byte_identical_restore_verified":true,
        "backup_verified_at_utc":"2026-09-29T05:49:58+00:00",
        "config_reference_is_vendor_native_restore_file":false,
        "device_native_restore_rehearsed":false,
        "existing_privilege15_account_count":2,
        "dedicated_verified_limited_role_account_exists":false,
        "actual_one_shot_lab_scripted_ssh_read_verified":true,
        "actual_one_shot_scripted_read_utc":"2026-09-29T06:10:34+00:00",
        "actual_one_shot_scripted_cards_matched":3,
        "scripted_read_was_unattended_production_worker":false,
        "production_worker_enabled":false,
        "real_saas_device_adopted":false
    })
}

pub(super) async fn first_read(
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
        Json(first_real_inventory()),
    ))
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
    fn historically_observed_first_real_c320_inventory_never_claims_auto_adoption() {
        let r = first_real_inventory();
        assert_eq!(r["recorded_date"], "2026-09-29");
        assert_eq!(r["observation_is_live"], false);
        assert_eq!(
            r["owner_restic_isolated_byte_identical_restore_verified"],
            true
        );
        assert_eq!(r["device_native_restore_rehearsed"], false);
        assert_eq!(r["dedicated_verified_limited_role_account_exists"], false);
        assert_eq!(r["real_saas_device_adopted"], false);
        assert_eq!(r["reported_version_rows_total"], 5);
        let cards = r["cards"].as_array().unwrap();
        assert_eq!(cards.len(), 3);
        assert!(cards
            .iter()
            .all(|c| c["card_reported_status"] == "INSERVICE"));
        assert_eq!(cards[0]["mvr_card_alias_verified"], false);
        assert_eq!(cards[1]["reported_mvr_version"], Value::Null);
        assert_eq!(cards[2]["mvr_card_alias_verified"], true);
    }

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
        assert_eq!(
            r["verified_off_vps_encrypted_running_cli_reference_backup"],
            true
        );
        assert_eq!(
            r["verified_mac_restic_isolated_byte_identical_restore"],
            true
        );
        assert_eq!(r["vendor_native_startup_config_restore_tested"], false);
        assert_eq!(r["actual_local_account_privilege15_count"], 2);
        assert_eq!(r["actual_local_restricted_account_proven"], false);
        assert_eq!(r["actual_live_manual_alarm_cli_syntax_verified"], true);
        assert_eq!(r["actual_live_active_alarms_semantically_validated"], false);
        assert_eq!(
            r["actual_ephemeral_scripted_owner_lab_ssh_show_card_verified"],
            true
        );
        assert_eq!(
            r["actual_ephemeral_scripted_rust_normalizer_exact_cards"],
            3
        );
        assert_eq!(
            r["actual_ephemeral_scripted_device_configuration_writes"],
            0
        );
        assert_eq!(
            r["actual_ephemeral_scripted_test_credential_persisted"],
            false
        );
        assert_eq!(r["ephemeral_one_shot_adapter_is_unattended_worker"], false);
        assert_eq!(r["production_auto_adoption_approved"], false);
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
