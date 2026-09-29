"""R9.19 strict LAB action catalog: no route to real device dispatch."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[4]

class TestOfflineC320ActionCatalog(unittest.TestCase):
    def test_pure_catalog_marks_every_live_action_disabled(self):
        rust=(ROOT/'apps/control-api/src/c320_actions_lab.rs').read_text()
        for line in ('READ_CARD_INVENTORY','READ_RUNNING_FIRMWARE','READ_ACTIVE_ALARMS',
                     'LIST_ONTS','READ_ONT_OPTICAL_METRICS','PROVISION_ONTS',
                     'REBOOT_OLT','UPGRADE_OLT_FIRMWARE'):
            self.assertIn(line,rust)
        for rule in ('"enabled":false','"network_actions":0','"worker_enabled":false',
                     '"device_adopted":false','"real_device_authenticated":true',
                     '"model_and_firmware_read_from_real_hardware":true',
                     '"can_run_on_live_device":false'):
            self.assertIn(rule,rust)
        for forbidden in ('Command::new(', 'subprocess','std::net','sshpass',
                          'Secret','TCPStream','"enabled":true'):
            self.assertNotIn(forbidden,rust)

    def test_actual_rust_axum_routes_and_browser_force_no_action(self):
        api=(ROOT/'apps/control-api/src/device_workbench_lab.rs').read_text()
        html=(ROOT/'web/lab/device-workbench.html').read_text()
        js=(ROOT/'web/lab/device-workbench.js').read_text()
        self.assertIn('/lab/c320-action-readiness',api)
        self.assertIn('/lab/c320-actions/{action}',api)
        self.assertIn('reject_execute',api)
        self.assertIn('c320_live_actions_are_explicitly_off_and_post_is_unmounted',api)
        for text in ('id="c320-operations"','id="refresh-c320-actions"',
                     'id="c320-actions-status"','id="c320-actions-list"'):
            self.assertIn(text,html)
        for marker in ("fetch('/lab/c320-action-readiness'",'catalog.worker_enabled!==false',
                       'catalog.device_adopted!==false','catalog.network_actions!==0',
                       "row.append(el('span','flag unknown','TERKUNCI')"):
            self.assertIn(marker,js)
        self.assertNotIn("mutate('POST','/lab/c320-actions/",js)
        self.assertLessEqual(len(html.encode()),32768)
        self.assertLessEqual(len(js.encode()),32768)

if __name__=='__main__':unittest.main()
