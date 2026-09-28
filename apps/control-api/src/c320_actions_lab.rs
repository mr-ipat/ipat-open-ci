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
    json!({
      "target":"DEV-01",
      "mode":"PHYSICAL_C320_PRE_ADOPTION_ACTION_CATALOG",
      "adoption_state":"OBSERVED_NOT_ADOPTED",
      "transport":"HISTORICAL_PRIVATE_SSH_BANNER_ONLY",
      "preferred_connection":"DIRECT_PRIVATE_SSH_NO_VPN_REQUIRED",
      "real_device_authenticated":false,
      "independent_oob_olt_host_key_verified":false,
      "dedicated_device_readonly_account_verified":false,
      "management_last_hop_isolated":false,
      "model_and_firmware_read_from_real_hardware":false,
      "live_distribution_baseline_approved":false,
      "genuine_tenant_admin_mfa_verified":false,
      "independent_reviewer_approved":false,
      "worker_enabled":false,
      "network_actions":0,
      "device_adopted":false,
      "actual_device_health":"NOT_MEASURED",
      "capabilities":[
        blocked_action("READ_CARD_INVENTORY","OFFLINE_PARSER_TESTED_LIVE_READ_BLOCKED",
          "INDEPENDENT_HOST_KEY_RESTRICTED_ACCOUNT_SCOPED_WORKER_BASELINE_AND_SIGNED_APPROVAL"),
        blocked_action("READ_RUNNING_FIRMWARE","OFFLINE_PARSER_TESTED_LIVE_READ_BLOCKED",
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
    })
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
        assert_eq!(r["device_adopted"], false);
        assert_eq!(r["real_device_authenticated"], false);
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
        assert_eq!(array[0]["state"], "OFFLINE_PARSER_TESTED_LIVE_READ_BLOCKED");
        assert_eq!(array[7]["action"], "UPGRADE_OLT_FIRMWARE");
        assert_eq!(array[7]["state"], "HIGH_IMPACT_LOCKED");
    }
}
