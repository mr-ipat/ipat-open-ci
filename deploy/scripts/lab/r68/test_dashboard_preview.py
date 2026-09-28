"""R6.8 static contract checks for three private synthetic dashboard previews.
Never treat presentation menu visibility as authentication or authorization.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[4]
HTML = (ROOT/"web/lab/dashboard-preview.html").read_text()
CSS = (ROOT/"web/lab/dashboard-preview.css").read_text()
JS = (ROOT/"web/lab/dashboard-preview.js").read_text()
RUST = (ROOT/"apps/control-api/src/main.rs").read_text()
AUTHZ = (ROOT/"crates/authz-core/src/dashboard.rs").read_text()
INDEX = (ROOT/"web/lab/index.html").read_text()
PHASE = (ROOT/"web/lab/rollout-phase.json").read_text()
import json

class Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags=[]
        self.attributes=[]
    def handle_starttag(self,tag,attrs):
        self.tags.append(tag)
        self.attributes += [(tag,k,v) for k,v in attrs]

class DashboardPreviewContract(unittest.TestCase):
    def test_all_three_workspaces_clear_synthetic_banner_and_no_fake_login(self):
        h=Parser()
        h.feed(HTML)
        values=dict((k,v) for tag,k,v in h.attributes if tag=="option")
        for label in ("Platform Admin", "Tenant Admin", "Operasional"):
            self.assertIn(label,HTML)
        self.assertIn("Data contoh sintetis",HTML)
        self.assertIn("Pengalih ini hanya mengganti tampilan",HTML)
        self.assertIn("PRODUKSI · NO_GO",HTML)
        self.assertNotIn("type=\"password\"",HTML)
        self.assertNotIn("type=\"text\"",HTML)
        self.assertNotIn("form",h.tags)
        self.assertEqual(h.tags.count("script"),1)
        self.assertIn('href="/lab/dashboard-preview"',INDEX)
        self.assertIn('id="metric-grid"',HTML)
        self.assertIn('id="demo-nav"',HTML)
        self.assertIn('id="prd-gap-list"',HTML)
        self.assertIn('id="rollout-status"',HTML)
        self.assertIn('ISOLASI DATA TENANT TIDAK BOLEH DITUNDA',HTML)
        self.assertTrue(json.loads(PHASE)['tenant_isolation_mandatory'])
        self.assertFalse(json.loads(PHASE)['custom_domains_enabled'])
        self.assertIn('GAP_LEDGER',JS)
        self.assertIn('FR-016 / TC-OLT-01',JS)
        self.assertIn('border:2px solid #ff3434',CSS)

    def test_preview_css_js_stay_same_origin_and_dom_safe(self):
        h=Parser()
        h.feed(HTML)
        sources=[value for tag,k,value in h.attributes if k in ("src","href")]
        self.assertTrue(all(
            (value == "/lab" or value.startswith(("/lab/","#","https://github.com/mr-ipat/ipat/")))
            for value in sources
        ),sources)
        self.assertIn("/lab/dashboard-preview.js",sources)
        self.assertIn("/lab/dashboard-preview.css",sources)
        self.assertIn("@media(max-width:750px)",CSS)
        self.assertIn("textContent",JS)
        self.assertIn("createDocumentFragment",JS)
        for bad in ("innerHTML","document.cookie","localStorage","sessionStorage",
                    "Authorization","eval(","document.write","fetch(\"/v1/"):
            self.assertNotIn(bad,JS)

    def test_fake_tenant_role_switch_only_changes_synthetic_display(self):
        self.assertIn('const DEMOS = Object.freeze',JS)
        for marker in ("platform: Object.freeze", "tenant: Object.freeze",
                       "operations: Object.freeze", "updateWorkspace", "SIMULASI"):
            self.assertIn(marker,JS)
        for endpoint in ('fetch("/healthz"','fetch("/lab/status"',
                         'fetch("/lab/device-targets"'):
            self.assertIn(endpoint,JS)
        self.assertIn('catalog.physical_devices_enrolled !== 0',JS)
        self.assertIn('fetch("/lab/rollout-phase"',JS)
        self.assertIn('phase.tenant_isolation_mandatory !== true',JS)
        self.assertIn('phase.custom_domains_enabled !== false',JS)
        self.assertIn('catalog.targets.length !== 8',JS)
        self.assertIn('status.authentication_enabled !== false',JS)
        self.assertIn('status.device_operations_enabled !== false',JS)
        self.assertNotRegex(JS,r'fetch\(["\']https?://')

    def test_backend_never_exposes_preview_on_public_k3s_or_real_tenant_data(self):
        self.assertIn('lab_requested && !k3s_lab',RUST)
        for uri in ("/lab/dashboard-preview","/lab/dashboard-preview.css",
                    "/lab/dashboard-preview.js"):
            self.assertIn(uri,RUST)
        self.assertIn('StatusCode::UNAUTHORIZED',RUST)
        for api in ('/v1/platform/{*path}','/v1/tenant/{*path}',
                    '/v1/operations/{*path}'):
            self.assertIn(api,RUST)
        self.assertIn('all_real_business_api_calls_deny_even_with_forged_tenant_role_and_host',RUST)
        self.assertIn('all_three_preview_assets_are_private_and_never_enable_real_api',RUST)
        self.assertIn('header::CACHE_CONTROL, HeaderValue::from_static("no-store")',RUST)

    def test_pure_future_policy_distinguishes_platform_and_tenant_pop(self):
        for text in ("PlatformOwner", "TenantAdmin", "NocEngineer",
                     "authorized_pops","resource_tenant", "BulkPppoeWrite",
                     "platform_owner_sees_platform_metadata_only_not_customer_secrets",
                     "tenant_admin_never_crosses_tenant_or_platform_metadata",
                     "pop_scoped_noc_cannot_read_unassigned_areas_or_manage_users"):
            self.assertIn(text,AUTHZ)
        self.assertIn('DashboardSection::BulkPppoeWrite',AUTHZ)
        self.assertIn('_ => false',AUTHZ)

    def test_real_http_smoke_is_disposable_ci_and_never_opens_public_bind(self):
        script=(ROOT/"deploy/scripts/lab/r68/private-dashboard-http-smoke.sh").read_text()
        self.assertIn('GITHUB_ACTIONS:-',script)
        self.assertIn('IPAT_R68_PRIVATE_HTTP_SMOKE:-',script)
        self.assertIn('127.0.0.1:3000',script)
        self.assertIn('"/v1/"+prefix+"/overview"',script)
        self.assertIn('assert code==401',script)
        self.assertIn('kill "$pid"',script)
        self.assertIn('trap cleanup EXIT',script)
        for bad in ('sudo ', 'nft -f', 'ufw allow', 'iptables -A', '0.0.0.0:3000'):
            self.assertNotIn(bad,script)

    def test_no_real_customer_creds_or_public_cdn(self):
        for name,txt in (("HTML",HTML),("CSS",CSS),("JS",JS)):
            self.assertNotIn("F52qGGDX",txt,name)
            self.assertNotIn("198.51.100.46",txt,name)
            self.assertNotRegex(txt,r'(?i)cdn\.|https://fonts\.')
            self.assertNotIn("type=\"password\"",txt)

if __name__=="__main__":
    unittest.main()
