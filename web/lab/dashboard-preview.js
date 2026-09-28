"use strict";
// R6.8: browser-only synthetic product sketch. NEVER authentication or RBAC.
// All three views are deliberately accessible to the same private lab tester;
// there is NO tenant information or real customer data in these fixtures.
const $ = (name) => document.getElementById(name);
const DEMOS = Object.freeze({
  platform: Object.freeze({
    crumb: "Platform Admin",
    title: "Platform Admin",
    description: "Rancangan pengelolaan layanan SaaS IPAT dan perusahaan ISP. Tenant dan seluruh data di sini hanya skenario desain.",
    overview: "Ringkasan platform",
    focus: "Pengelolaan platform",
    intro: "Komponen administratif yang harus dihubungkan ke login kuat dan database platform.",
    scope: "Hanya metadata platform; tidak otomatis melihat konfigurasi atau pelanggan suatu tenant.",
    menu: Object.freeze([
      ["◈","Ringkasan","#overview"],["▥","Tenant & domain","#focus"],
      ["⟡","Kesiapan keamanan","#readiness"],["◇","Batas kewenangan","#role-scope"]
    ]),
    metrics: Object.freeze([
      ["▥","Tenant nyata","Belum aktif","Belum ada database tenant runtime yang dihubungkan"],
      ["◇","Gerbang eksternal","7 / 7","Masih membutuhkan pembuktian independen"],
      ["⬡","Perangkat terdaftar","0","Belum ada onboarding fisik ke ACS"]
    ]),
    rows: Object.freeze([
      ["▥","Pembuatan tenant & domain","Rancang verifikasi domain, subdomain dan kuota per perusahaan.","Belum aktif"],
      ["⟡","Paket & subscription","Metadata paket tanpa mengakses data pelanggan antar-tenant.","Rancangan"],
      ["◇","Keamanan & audit global","Peninjauan izin platform dengan pemisahan wewenang.","Belum aktif"]
    ])
  }),
  tenant: Object.freeze({
    crumb: "Tenant Admin · LAB-ISP",
    title: "Tenant Admin",
    description: "Pratinjau ruang kerja satu ISP sintetis. Identitas tenant nyata, domain dan login belum diaktifkan.",
    overview: "Ringkasan ISP sintetis",
    focus: "Administrasi perusahaan",
    intro: "Menu yang dirancang hanya untuk perusahaan sendiri; tidak terdapat data tenant lain.",
    scope: "Terbatas pada perusahaan sendiri. Tidak boleh mengelola platform atau data ISP lain.",
    menu: Object.freeze([
      ["◈","Ringkasan","#overview"],["♧","Tim & akses","#focus"],
      ["▥","Kesiapan inventory","#device-readiness"],["◇","Izin & audit","#role-scope"]
    ]),
    metrics: Object.freeze([
      ["◈","Data pelanggan riil","Belum ada","Hanya informasi desain, tanpa data PII"],
      ["▥","ONT terdaftar","0","Tidak ada perangkat fisik ditetapkan ke tenant ini"],
      ["◇","Autentikasi OIDC","Belum aktif","MFA dan verified tenant membership wajib"]
    ]),
    rows: Object.freeze([
      ["♧","Tim & delegasi peran","Undangan pengguna, bantuan dan audit hanya setelah OIDC/MFA.","Belum aktif"],
      ["⬡","Branding & subdomain","Identitas masing-masing ISP, pemeriksaan kepemilikan domain wajib.","Rancangan"],
      ["▥","Inventory & subscriber","Terikat tenant + POP; tidak menampilkan data nyata sebelum izin.","Diblokir"]
    ])
  }),
  operations: Object.freeze({
    crumb: "Operasional · NOC LAB",
    title: "Operasional NOC",
    description: "Pratinjau konsol tim ISP untuk gangguan, jaringan, status perangkat dan tindakan dengan persetujuan. Semua status perangkat nyata masih belum diketahui.",
    overview: "Situasi jaringan laboratorium",
    focus: "Prioritas kerja NOC",
    intro: "Kartu operasional yang hanya dapat diaktifkan dengan data perangkat terverifikasi dan izin tenant/POP.",
    scope: "NOC terikat POP yang ditugaskan. Tidak memiliki menu billing, lintas perusahaan atau provisioning tanpa persetujuan.",
    menu: Object.freeze([
      ["◈","Ringkasan","#overview"],["⌁","Insiden & tugas","#focus"],
      ["▥","Target perangkat","#device-readiness"],["◇","Kendali perubahan","#readiness"]
    ]),
    metrics: Object.freeze([
      ["⌁","Telemetri langsung","Tidak aktif","Belum ada sumber OLT, ONT atau router aktif"],
      ["▥","Target lab global","8","Rencana pengujian, bukan perangkat yang terkoneksi"],
      ["◇","Eksekusi perubahan","Terkunci","High-risk jobs memerlukan MFA, audit dan approval"]
    ]),
    rows: Object.freeze([
      ["⌁","Korelasi gangguan","Pisahkan risiko akses pelanggan, distribusi, dan perangkat.","Rancangan"],
      ["▥","Inventaris & kesehatan","Tampilkan data hanya untuk POP yang diverifikasi.","Belum aktif"],
      ["◇","PPPoE massal & tindakan","Tindakan berisiko tetap ditolak sampai review dan dual approval.","Terkunci"]
    ])
  })
});
// Audited PRD implementation gaps, NOT calculated privileges or live readiness.
const GAP_LEDGER = Object.freeze({
  platform: Object.freeze([
    ["FR-002","OIDC/MFA dan identitas pemilik platform belum terintegrasi"],
    ["FR-004","Verifikasi subdomain/custom domain dan isolasi sesi belum diterapkan"],
    ["FR-005/008","Onboarding tenant serta paket/kuota runtime belum tersedia"]
  ]),
  tenant: Object.freeze([
    ["FR-001/003","Isolasi dua tenant dan POP belum terbukti melalui alur UI/API nyata"],
    ["FR-002","Login MFA, membership dan menu berbasis izin nyata belum tersedia"],
    ["FR-018/023","Inventaris ONT/subscriber nyata dan ikatan tenant belum tersedia"]
  ]),
  operations: Object.freeze([
    ["FR-016 / TC-OLT-01","ZTE C320 fisik belum terhubung; sintaks CLI hanya diuji offline"],
    ["FR-009/010","Sesi CWMP + parameter RPC pada ONT nyata belum lulus"],
    ["FR-020/024/029","PPPoE massal nyata, korelasi dan telemetri operasional belum aktif"]
  ])
});
function text(node, value) { node.textContent = String(value); }
function element(tag, className, content) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (content !== undefined) text(el, content);
  return el;
}
function updateWorkspace(key) {
  // This control changes only synthetic presentation, never server identity.
  const state = DEMOS[key] || DEMOS.platform;
  text($("breadcrumb"), state.crumb);
  const head = $("page-title");
  head.replaceChildren(document.createTextNode(state.title + " "));
  head.appendChild(element("em", "", "Dashboard"));
  text($("page-description"), state.description);
  text($("overview-title"), state.overview);
  text($("focus-title"), state.focus);
  text($("focus-intro"), state.intro);
  text($("scope-title"), "Batas akses " + state.crumb);
  text($("scope-menu"), state.scope);
  const nav = document.createDocumentFragment();
  for (const [symbol, label, href] of state.menu) {
    const a = element("a");
    a.setAttribute("href", href);
    a.appendChild(element("span", "nav-symbol", symbol));
    a.appendChild(element("span", "", label));
    nav.appendChild(a);
  }
  $("demo-nav").replaceChildren(nav);
  const cards = document.createDocumentFragment();
  for (const [symbol, label, value, foot] of state.metrics) {
    const card = element("article", "metric");
    const top = element("div", "metric-top");
    top.appendChild(element("span", "metric-icon", symbol));
    top.appendChild(element("span", "chip", "SIMULASI"));
    card.appendChild(top);
    card.appendChild(element("p", "metric-label", label));
    card.appendChild(element("p", "metric-value", value));
    card.appendChild(element("p", "metric-foot", foot));
    cards.appendChild(card);
  }
  $("metric-grid").replaceChildren(cards);
  const rows = document.createDocumentFragment();
  for (const [symbol, label, note, status] of state.rows) {
    const row = element("div", "focus-row");
    row.appendChild(element("span", "focus-symbol", symbol));
    const content = element("div", "focus-text");
    content.appendChild(element("strong", "", label));
    content.appendChild(element("p", "", note));
    row.appendChild(content);
    row.appendChild(element("span", "focus-status", status));
    rows.appendChild(row);
  }
  $("focus-rows").replaceChildren(rows);
  const gaps = document.createDocumentFragment();
  for (const [fr, detail] of GAP_LEDGER[key] || GAP_LEDGER.platform) {
    const li = element("li");
    li.appendChild(element("span", "", fr));
    li.appendChild(element("strong", "", detail));
    li.appendChild(element("b", "", "BELUM"));
    gaps.appendChild(li);
  }
  $("prd-gap-list").replaceChildren(gaps);
}
async function checkPrivateEnvironment() {
  const button = $("check");
  button.disabled = true;
  text($("checked"), "Memeriksa tunnel privat…");
  const abort = new AbortController();
  const timeout = window.setTimeout(() => abort.abort(), 6000);
  try {
    const [health, summary, devices, rollout] = await Promise.all([
      fetch("/healthz", {cache:"no-store",signal:abort.signal}),
      fetch("/lab/status", {cache:"no-store",signal:abort.signal}),
      fetch("/lab/device-targets", {cache:"no-store",signal:abort.signal}),
      fetch("/lab/rollout-phase", {cache:"no-store",signal:abort.signal})
    ]);
    if (!health.ok || !summary.ok || !devices.ok || !rollout.ok
        || (await health.text()).trim() !== "ok") {
      throw new Error("No private lab");
    }
    const [status, catalog, phase] = await Promise.all([
      summary.json(),devices.json(),rollout.json()
    ]);
    if (status.mode !== "ssh-loopback-only" || status.production_access !== false
        || status.authentication_enabled !== false || status.device_operations_enabled !== false
        || catalog.catalog_mode !== "planned_targets_only"
        || catalog.physical_devices_enrolled !== 0
        || catalog.physical_interoperability_verified !== 0
        || catalog.compatibility_claim !== false
        || !Array.isArray(catalog.targets) || catalog.targets.length !== 8
        || phase.schema !== 1
        || phase.phase !== "private_single_endpoint_device_lab"
        || phase.domain_verification_deferred !== true
        || phase.custom_domains_enabled !== false
        || phase.public_tenant_hostnames_enabled !== false
        || phase.private_loopback_transport_only !== true
        || phase.tenant_isolation_mandatory !== true
        || phase.tenant_isolation_end_to_end_verified !== false
        || phase.authenticated_tenant_data_apis_enabled !== false
        || phase.physical_device_connected !== false
        || phase.device_reads_approved !== false
        || phase.firmware_updates_enabled !== false) {
      throw new Error("Untrusted or unexpected laboratory state");
    }
    text($("checked"), "Control API privat terhubung · tanpa login ataupun data perangkat");
    text($("rollout-status"), "Fase backend cocok · custom domain terkunci · isolasi tenant belum tervalidasi");
    text($("device-summary"), "8 target yang direncanakan · 0 perangkat nyata terdaftar");
    text($("device-badge"), "BUKAN TELEMETRI");
  } catch {
    text($("checked"), "Status belum terverifikasi; periksa tunnel privat");
    text($("rollout-status"), "Fase backend tidak terverifikasi · jangan aktifkan akses tenant atau domain");
    text($("device-summary"), "Katalog tidak tersedia; status perangkat tidak dapat disimpulkan");
    text($("device-badge"), "TIDAK DIKETAHUI");
  } finally {
    window.clearTimeout(timeout);
    button.disabled = false;
  }
}
$("workspace").addEventListener("change", (event) => updateWorkspace(event.target.value));
$("check").addEventListener("click", () => { void checkPrivateEnvironment(); });
updateWorkspace("platform");
void checkPrivateEnvironment();
