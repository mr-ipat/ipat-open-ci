"""ZTE C320 synthetic read-only and prominent PRD deviation guardrails.
These tests do not contact or claim compatibility with any actual OLT.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[4]
HTML = (ROOT / 'web/lab/dashboard-preview.html').read_text()
CSS = (ROOT / 'web/lab/dashboard-preview.css').read_text()
RUST = (ROOT / 'crates/olt-core/src/lib.rs').read_text()
MANIFEST = (ROOT / 'crates/olt-core/Cargo.toml').read_text()
DEVIATIONS = (ROOT / 'docs/PRD_DEVIATIONS_R71.md').read_text()

class R71SourceSafety(unittest.TestCase):
    def test_red_large_warning_is_visible_across_all_preview_workspaces(self):
        self.assertIn('class="prd-deviation-alert" role="alert"', HTML)
        self.assertIn('PERINGATAN BESAR', HTML)
        self.assertIn('TC-OLT-01', HTML)
        self.assertIn('BELUM TERHUBUNG', HTML)
        self.assertIn('docs/PRD_DEVIATIONS_R71.md', HTML)
        self.assertIn('border:4px solid #ff3434', CSS)
        self.assertIn('font-size:clamp(19px,2.8vw,30px)', CSS)
        self.assertLess(HTML.index('prd-deviation-alert'), HTML.index('class="layout"'))

    def test_no_lurking_vendor_transport_or_write_in_domain_crate(self):
        self.assertIn('pub const WRITE_ENABLED: bool = false;', RUST)
        self.assertIn('["show card", "show version-running"]', RUST)
        for forbidden in ('TcpStream','Command::new','ssh2::', 'download img',
                          'update-boot', 'patch active', 'telnet', 'ftp://'):
            self.assertNotIn(forbidden, RUST)
        self.assertEqual(MANIFEST.split('[dependencies]',1)[1].strip(), 'libc = "=0.2.189"')

    def test_offline_parsers_bounded_and_do_not_store_raw_vendor_data(self):
        for required in ('pub const MAX_OUTPUT','EvidenceError::Unsafe',
                         'EvidenceError::Duplicate','EvidenceError::Layout',
                         'fn safe(input: &str)','pub fn parse_cards',
                         'pub fn parse_running_versions'):
            self.assertIn(required, RUST)
        self.assertNotIn('pub raw_', RUST)

    def test_firmware_never_executable_even_when_review_flags_complete(self):
        self.assertIn('pub enum Disposition {', RUST)
        self.assertIn('Blocked(&', RUST)
        self.assertIn('HumanReviewOnly', RUST)
        self.assertNotIn('ApprovedToExecute', RUST)
        for required in ('exact_vendor_firmware_and_checksum_independently_verified',
                         'complete_configuration_backup_restored_and_tested',
                         'separate_maker_checker_approved',
                         'independent_onsite_recovery_console_and_rollback'):
            self.assertIn(required,RUST)

    def test_deviation_report_distinguishes_prd_s1_simulator_vs_real_hardware(self):
        for required in ('FR-016','FR-017','TC-OLT-01',
                         'tambahan BERISIKO TINGGI', 'NO_GO',
                         'HumanReviewOnly', 'operator', 'B U K A N'):
            self.assertIn(required.casefold(), DEVIATIONS.casefold())

if __name__=='__main__':
    unittest.main()
