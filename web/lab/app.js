"use strict";
// Mr. iPat / IPAT: browser-only health indicators; no auth or device calls.
const byId = (id) => document.getElementById(id);
const refresh = byId("refresh");
const status = byId("api-status");
const badge = byId("api-badge");
const checked = byId("checked-at");

async function checkPrivateLab() {
  refresh.disabled = true;
  status.textContent = "Memeriksa";
  badge.textContent = "Memeriksa";
  badge.className = "status-pill checking";
  const controller = new AbortController();
  const deadline = window.setTimeout(() => controller.abort(), 6000);
  try {
    const [health, details] = await Promise.all([
      fetch("/healthz", {cache:"no-store",signal:controller.signal}),
      fetch("/lab/status", {cache:"no-store",signal:controller.signal})
    ]);
    if (!health.ok || !details.ok || (await health.text()).trim() !== "ok") {
      throw new Error("Health not available");
    }
    const state = await details.json();
    if (state.mode !== "ssh-loopback-only" || state.production_access !== false
        || state.authentication_enabled !== false) {
      throw new Error("Unexpected lab mode");
    }
    status.textContent = "Terhubung";
    badge.textContent = "Aktif";
    badge.className = "status-pill ok";
  } catch {
    status.textContent = "Tidak terhubung";
    badge.textContent = "Periksa tunnel";
    badge.className = "status-pill error";
  } finally {
    window.clearTimeout(deadline);
    checked.textContent = "Terakhir diperiksa: "
      + new Intl.DateTimeFormat("id-ID",{hour:"2-digit",minute:"2-digit",
        timeZone:"Asia/Jakarta"}).format(new Date()) + " WIB";
    refresh.disabled = false;
  }
}
// This is an immutable product *test plan*, never hardware enrollment.
async function loadHardwareTargets() {
  const table = byId("target-rows");
  const feedback = byId("target-feedback");
  try {
    const response = await fetch("/lab/device-targets", {cache:"no-store"});
    if (!response.ok) throw new Error("catalog unavailable");
    const catalog = await response.json();
    if (catalog.schema !== 1 || catalog.catalog_mode !== "planned_targets_only"
        || catalog.physical_devices_enrolled !== 0
        || catalog.physical_interoperability_verified !== 0
        || catalog.network_discovery_enabled !== false
        || catalog.compatibility_claim !== false
        || !Array.isArray(catalog.targets)
        || catalog.targets.length !== 8
        || catalog.targets.some(t => !(
          t.status === "awaiting_metadata" ||
          (t.id === "DEV-08" && t.status === "operator_reported_pending_verification"
            && t.access_gate === "ssh_host_key_changed_unverified"
            && t.family === "RB951Ui-2HnD"
            && t.firmware.includes("7.23.7"))))) {
      throw new Error("unexpected catalog provenance");
    }
    const kind = {OLT:"OLT",ONT:"ONT",ROUTER_DISTRIBUTION:"Router distribusi",
      CUSTOMER_ROUTER:"Router pelanggan"};
    const fragment = document.createDocumentFragment();
    for (const device of catalog.targets) {
      const row = document.createElement("tr");
      const fields = [device.id,kind[device.category] || "Belum dikenal",
        device.vendor + " " + device.family,
        device.test_plan + (device.id === "DEV-08" ? " · RouterOS dilaporkan: 7.23.7" : ""),
        device.status === "operator_reported_pending_verification"
          ? "SSH diblokir: verifikasi identitas" : "Menunggu metadata"];
      for (let i=0;i<fields.length;i++) {
        const cell = document.createElement("td");
        cell.textContent = String(fields[i]);
        if (i === 4) cell.className = "pending-text";
        row.appendChild(cell);
      }
      fragment.appendChild(row);
    }
    table.replaceChildren(fragment);
    byId("candidate-count").textContent = String(catalog.targets.length);
    byId("physical-count").textContent = "0";
    feedback.textContent = "DEV-08: SSH DIBLOKIR setelah kunci host berubah. Data ini status laboratorium terakhir, bukan pemantauan langsung. Perangkat fisik terdaftar: 0.";
    byId("router-security-alert").hidden = false;
  } catch {
    table.replaceChildren();
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "Katalog tidak tersedia. Status fisik tidak dapat disimpulkan.";
    row.appendChild(cell);
    table.appendChild(row);
    byId("candidate-count").textContent = "–";
    byId("physical-count").textContent = "–";
    feedback.textContent = "Pemeriksaan katalog gagal; jangan menafsirkan tabel ini sebagai koneksi perangkat.";
    byId("router-security-alert").hidden = true;
  }
}
refresh.addEventListener("click", () => {
  void checkPrivateLab();
  void loadHardwareTargets();
});
void checkPrivateLab();
void loadHardwareTargets();
