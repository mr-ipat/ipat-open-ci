"""Source/UI/SQL static safety checks for new visible R8.3 Device Manager.
Real signed JWT→disposable PG and real loopback API are separately executed.
"""
import json
from html.parser import HTMLParser
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[4]
RUST=(ROOT/"apps/control-api/src/device_workbench_lab.rs").read_text()
MAIN=(ROOT/"apps/control-api/src/main.rs").read_text()
AUTH=(ROOT/"apps/control-api/src/tenant_membership_lab.rs").read_text()
SQL=(ROOT/"deploy/db/migrations/0006_lab_device_candidates.sql").read_text()
HTML=(ROOT/"web/lab/device-workbench.html").read_text()
CSS=(ROOT/"web/lab/device-workbench.css").read_text()
JS=(ROOT/"web/lab/device-workbench.js").read_text()
OLD=(ROOT/"web/lab/dashboard-preview.html").read_text()
INDEX=(ROOT/"web/lab/index.html").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()

class Tags(HTMLParser):
    def __init__(self):
        super().__init__();self.attrs=[];self.tags=[]
    def handle_starttag(self,tag,attrs):
        self.tags.append(tag);self.attrs += [(tag,k,v) for k,v in attrs]

class DeviceManagerContract(unittest.TestCase):
    def test_real_interactive_ui_visible_from_both_existing_dashboards(self):
        dom=Tags();dom.feed(HTML)
        for label in ("Tambah kandidat perangkat","Daftar kandidat & kondisi",
                      "Tahapan adopsi","PERINGATAN PRD","LAB-",
                      "VIRTUAL-","PENDING","UNKNOWN"):
            self.assertIn(label,HTML)
        for field in ("name","vendor","kind","model","pop","device-form",
                      "candidate-count","rows","refresh","pop-filter","kind-filter"):
            self.assertIn(("id",field),[(k,v) for _,k,v in dom.attrs])
        self.assertIn("form",dom.tags)
        self.assertEqual(dom.tags.count("script"),1)
        self.assertIn("/lab/device-workbench",OLD)
        self.assertIn("/lab/device-workbench",INDEX)
        for phrase in ("replaceChildren","textContent","encodeURIComponent",
                       'credentials:"omit"',"PENDING_REVIEW","NOT_MEASURED",
                       "volatile-in-memory-demo","real_device_count"):
            self.assertIn(phrase,JS)
        for forbidden in ("innerHTML","localStorage","sessionStorage",
                          "document.cookie","Authorization","eval(",
                          "8.8.8.8","fetch(\"/v1/"):
            self.assertNotIn(forbidden,JS)
        self.assertIn("@media(max-width:700px)",CSS)

    def test_demo_api_cannot_accept_raw_real_host_secrets_or_online_claim(self):
        for guard in (
            "display_name.starts_with(\"LAB-\")",
            "exact_model.starts_with(\"VIRTUAL-\")",
            "MAX_DEMO_CANDIDATES: usize = 24",
            'adoption_state: "PENDING_REVIEW"',
            'connectivity: "UNKNOWN"',
            'health: "NOT_MEASURED"',
            "last_verified_at: None",
            "demo_csrf(&headers)",
            "HeaderMap", "DefaultBodyLimit::max(2048)",
            "/lab/demo/device-candidates",
            "/lab/device-workbench",
            "real_device_count","physical_connection_checked",
        ):self.assertIn(guard,RUST)
        self.assertNotIn("TcpStream",RUST)
        self.assertNotIn("std::process::Command",RUST)
        self.assertNotIn("management_ipv4:",RUST)
        self.assertIn("if lab_web_enabled {",MAIN)
        self.assertIn("merge(device_workbench_lab::router())",MAIN)
        self.assertIn('lab_requested && !k3s_lab',MAIN)
        for namespace in ('"/v1/platform/{*path}"',
                          '"/v1/tenant/{*path}"','"/v1/operations/{*path}"'):
            self.assertIn(namespace,MAIN)

    def test_disposable_pg_separate_sealed_reader_and_writer_only_pending(self):
        for guard in (
            "CREATE TABLE ipat_ops.device_candidates",
            "CREATE ROLE ipat_device_registry_owner NOLOGIN",
            "CREATE ROLE ipat_device_registry_execute NOLOGIN",
            "ALTER TABLE ipat_ops.device_candidates FORCE ROW LEVEL SECURITY",
            "FOR INSERT TO ipat_device_registry_owner WITH CHECK (true)",
            "FOR SELECT TO ipat_device_registry_owner USING (true)",
            "propose_lab_device_candidate(",
            "list_lab_device_candidates(",
            "m.role='tenant_admin'","m.revoked_at IS NULL",
            "m.expires_at > statement_timestamp()",
            "t.state='active'","p_request uuid",
            "ON CONFLICT(tenant_id,requested_issuer,requested_subject,request_id)",
            "IS NOT DISTINCT FROM","connectivity text NOT NULL DEFAULT 'unknown'",
            "health text NOT NULL DEFAULT 'not_measured'",
            "last_verified_at timestamptz",
            "GRANT EXECUTE ON FUNCTION",
            "TO ipat_device_registry_execute",
            "TO ipat_identity_query",
        ):self.assertIn(guard,SQL)
        self.assertNotIn("GRANT INSERT ON ipat_ops.device_candidates TO ipat_identity_query",SQL)
        self.assertNotIn("GRANT INSERT ON ipat_ops.device_candidates TO ipat_app_runtime",SQL)
        self.assertNotIn("UPDATE ipat_ops.device_candidates",SQL)
        self.assertNotIn("password text",SQL.lower())
        for guard in (
            '"/lab/auth/device-candidates"', '"/lab/auth/device-candidates/propose"',
            "verified_bearer(&store.verifier",
            "verified_bearer(&writer.verifier",
            "visible_for_verified_candidate",
            "IPAT_R83_REGISTRY_WRITE",
            "ipat_lab_device_registrar",
            "ipat_platform.propose_lab_device_candidate",
            "ipat_platform.list_lab_device_candidates",
            "DefaultBodyLimit::max(2048)",
        ):self.assertIn(guard,AUTH)
        self.assertIn("registration_from_owner_environment(",MAIN)
        self.assertIn("registry_requested && (!scoped_requested || identity.is_none() || k3s_lab)",MAIN)

    def test_ci_actual_http_and_disposable_db_executed(self):
        for guard in (
            "test_r83_contract.py", "workbench_http_smoke.py",
            "test_device_candidates_integration.py",
            "r83_real_signed_jwt_to_actual_postgres_two_tenant_pending_adoption",
            "IPAT_R83_DEMO_HTTP=YES",
        ):self.assertIn(guard,CI)

if __name__=="__main__":unittest.main()
