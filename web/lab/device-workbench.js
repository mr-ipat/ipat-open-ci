"use strict";
// A real interactive LAB dashboard backed by the ACTUAL private Rust server's
// VOLATILE fake-device memory. No bearer/password, real IP, serial or network I/O.
const node = (id) => document.getElementById(id);
const source = "/lab/demo/device-candidates";
let candidates = [];
let observedPhysical = null; // historical owner report, NEVER enrolled inventory
function el(tag, cls, content) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (content !== undefined) e.textContent = String(content);
  return e;
}
function td(content) { return el("td", "", content); }
function badge(content, cls) { return el("span", "flag "+cls, content); }
function status(message, failure=false) {
  node("list-status").textContent = message;
  node("list-status").style.color = failure ? "#ffb9bf" : "#9ed5d0";
}
function draw() {
  const pop = node("pop-filter").value;
  const kind = node("kind-filter").value;
  const view = candidates.filter((d) =>
    (pop === "all" || d.pop_id === pop)
    && (kind === "all" || d.device_kind === kind));
  const fragment = document.createDocumentFragment();
  for (const d of view) {
    const row = el("tr");
    const name = el("td");
    name.append(el("strong","",d.display_name),el("small","",d.id));
    row.appendChild(name);
    const type = el("td");
    type.append(el("strong","",d.device_kind.toUpperCase()),el("small","",d.vendor+" · "+d.exact_model));
    row.appendChild(type);
    row.appendChild(td(d.pop_id.toUpperCase()));
    const adoption = el("td");
    adoption.appendChild(badge("MENUNGGU REVIEW",""));
    row.appendChild(adoption);
    const connectivity = el("td");
    connectivity.appendChild(badge("UNKNOWN","unknown"));
    row.appendChild(connectivity);
    const health = el("td");
    health.appendChild(badge("BELUM DIUKUR","unknown"));
    row.appendChild(health);
    const remove = el("td");
    const button = el("button","danger","Hapus demo");
    button.type = "button";
    button.setAttribute("aria-label","Hapus kandidat demo "+d.display_name);
    button.addEventListener("click", () => { void removeDemo(d.id); });
    remove.appendChild(button);
    row.appendChild(remove);
    fragment.appendChild(row);
  }
  // A separately labeled historical row is never part of volatile
  // registered candidates or production tenant inventory.
  const physicalVisible=observedPhysical !== null && pop === "all"
    && (kind === "all" || kind === "olt");
  if (physicalVisible) {
    const physicalRow=el("tr","physical-observed-row");
    const identity=el("td");
    identity.append(el("strong","","DEV-01 · LAPORAN PEMILIK"),
                    el("small","","SSH teramati pada "+observedPhysical.observed_on));
    physicalRow.appendChild(identity);
    const device=el("td");
    device.append(el("strong","","OLT · ZTE C320 (DILAPORKAN)"),
                  el("small","","Model dan firmware BELUM diverifikasi"));
    physicalRow.appendChild(device);
    physicalRow.appendChild(td("POP BELUM DIVERIFIKASI"));
    physicalRow.appendChild(el("td","","KANDIDAT FISIK, BELUM DIADOPSI"));
    const transport=el("td");
    transport.appendChild(badge("HISTORIS / UNKNOWN","unknown"));
    physicalRow.appendChild(transport);
    const health=el("td");
    health.appendChild(badge("BELUM DIUKUR","unknown"));
    physicalRow.appendChild(health);
    physicalRow.appendChild(td("Tidak ada operasi perangkat"));
    fragment.appendChild(physicalRow);
  }
  if (!view.length && !physicalVisible) {
    const row = el("tr");
    const cell = el("td","empty","Tidak ada kandidat untuk filter ini. Gunakan formulir untuk menambah perangkat demo.");
    cell.colSpan = 7;
    row.appendChild(cell);
    fragment.appendChild(row);
  }
  node("rows").replaceChildren(fragment);
  node("candidate-count").textContent = String(candidates.length);
}
async function refresh() {
  node("refresh").disabled = true;
  try {
    const resp = await fetch(source,{cache:"no-store",credentials:"omit"});
    if (!resp.ok) throw new Error("Tidak dapat mengambil data");
    const body = await resp.json();
    if (body.lab_only !== true || body.source !== "volatile-in-memory-demo"
        || body.real_device_count !== 0 || body.physical_connection_checked !== false
        || !Array.isArray(body.devices) || body.devices.length > 24
        || body.devices.some(d => d.lab_only !== true
          || d.adoption_state !== "PENDING_REVIEW" || d.connectivity !== "UNKNOWN"
          || d.health !== "NOT_MEASURED" || d.last_verified_at !== null)) {
      throw new Error("Status backend tidak cocok; inventaris ditolak");
    }
    candidates=body.devices;
    draw();
    status(String(candidates.length)+" kandidat virtual · 0 koneksi nyata · kondisi UNKNOWN");
  } catch {
    candidates=[];
    draw();
    status("Tidak berhasil memverifikasi backend privat. Jangan menganggap perangkat aktif.",true);
  } finally {
    node("refresh").disabled=false;
  }
}
async function mutate(method,path,body) {
  return fetch(path,{
    method,credentials:"omit",cache:"no-store",
    headers:{"X-IPAT-Demo-Only":"1","Content-Type":"application/json"},
    ...(body ? {body:JSON.stringify(body)} : {})
  });
}
async function removeDemo(id) {
  try {
    const response=await mutate("DELETE",source+"/"+encodeURIComponent(id));
    if (!response.ok) throw new Error("Penolakan backend");
    await refresh();
  } catch {
    status("Penghapusan demo ditolak oleh server.",true);
  }
}
async function submit(event) {
  event.preventDefault();
  const button=node("add");
  button.disabled=true;
  node("form-status").textContent="Memvalidasi kandidat virtual…";
  const body={
    display_name:node("name").value.trim(),
    device_kind:node("kind").value,
    vendor:node("vendor").value,
    exact_model:node("model").value.trim(),
    pop_id:node("pop").value
  };
  try {
    const response=await mutate("POST",source,body);
    if (!response.ok) {
      node("form-status").textContent=response.status===409
        ? "Nama+POP sudah terdaftar atau batas 24 kandidat tercapai."
        : "Backend menolak input. Gunakan hanya identitas LAB- dan model VIRTUAL-.";
      return;
    }
    const result=await response.json();
    if (result.lab_only !== true || result.accepted !== true
        || result.device?.adoption_state !== "PENDING_REVIEW") {
      throw new Error("Respon tidak aman");
    }
    node("form-status").textContent="Kandidat "+body.display_name+" ditambahkan sebagai PENDING_REVIEW. BUKAN perangkat online.";
    await refresh();
  } catch {
    node("form-status").textContent="Permintaan gagal. Periksa koneksi privat tanpa mengaktifkan perangkat.";
  } finally {
    button.disabled=false;
  }
}
node("device-form").addEventListener("submit",event=>{void submit(event);});
node("refresh").addEventListener("click",()=>{void refresh();});
node("pop-filter").addEventListener("change",draw);
node("kind-filter").addEventListener("change",draw);
void refresh();

// R9.5 connection selector is PRESENTATION ONLY: no persist, network or secrets.
function describeConnection() {
  const method=node("connection-method").value;
  const gateway=node("connection-gateway").value;
  const messages={
    direct_secure:"Hanya bila perangkat mendukung SSH dengan identitas terverifikasi atau SNMPv3 authPriv; wajib membatasi sumber dan izin. Telnet tidak termasuk.",
    wireguard:"WireGuard membutuhkan gateway yang mendukungnya, rute /32 yang disetujui, autentikasi peer, isolasi hop terakhir dan persetujuan terpisah.",
    ipsec:"IPsec dapat digunakan dengan gateway yang kompatibel setelah parameter kriptografi, identitas peer, rute dan pemulihan diverifikasi.",
    agent:"IPAT site gateway adalah rencana pengembangan, belum dapat diinstal atau digunakan untuk adopsi fisik.",
    public_telnet:"DITOLAK: Telnet melalui IP publik tidak aman untuk autentikasi atau perintah. Pengujian tanpa kredensial hanya mencatat bukti jaringan, bukan adopsi."
  };
  let result=messages[method];
  if(method==="wireguard" && gateway==="routeros6")
    result="TIDAK KOMPATIBEL: WireGuard bawaan tidak tersedia pada RouterOS 6. Pilih IPsec atau gateway lain yang terverifikasi.";
  if(method==="wireguard" && gateway==="none")
    result="Gateway diperlukan untuk mengamankan akses perangkat Telnet-only; tidak ada tunnel site yang dapat dideploy dari pilihan ini.";
  if(method==="direct_secure" && gateway==="routeros6")
    result+=" Versi gateway tidak membuktikan bahwa OLT mendukung protokol aman.";
  node("connection-result").textContent=result+" Ini hanya simulasi pilihan UI; tidak ada konfigurasi yang dikirim.";
  node("server-plan-result").textContent="Pilihan berubah. Jalankan kembali validasi backend lab.";
}
node("connection-method").addEventListener("change",describeConnection);
node("connection-gateway").addEventListener("change",describeConnection);
describeConnection();

// The backend lab plan is never persisted or executed. This request uses the
// same local-only origin guard as existing fake-device mutations.
async function checkConnectionPlan() {
  const button=node("check-connection");
  button.disabled=true;
  node("server-plan-result").textContent="Memvalidasi rencana sintetis…";
  try {
    const response=await mutate("POST","/lab/demo/connection-plan",{
      method:node("connection-method").value,
      gateway:node("connection-gateway").value,
      device_profile:node("connection-profile").value
    });
    if (!response.ok) throw new Error("lab backend denied request");
    const result=await response.json();
    if(result.lab_only!==true || result.plan_only!==true
       || result.tenant_verified!==false || result.device_adopted!==false
       || result.credentials_used!==false || result.network_actions!==0
       || result.worker_dispatch_enabled!==false || result.health!=="NOT_MEASURED") {
       throw new Error("unexpected backend plan response");
    }
    node("server-plan-result").textContent=(result.eligible_for_separate_review
      ? "Layak ditinjau secara terpisah" : "Ditolak atau belum tersedia")
      +" · "+result.reason+" · Tidak ada konfigurasi yang diterapkan.";
  } catch {
    node("server-plan-result").textContent="Validasi ditolak/gagal. Tidak ada konfigurasi yang diterapkan.";
  } finally {button.disabled=false;}
}
node("check-connection").addEventListener("click",()=>{void checkConnectionPlan();});
// R9.11: Historical credential-free physical evidence, NEVER live telemetry.
// Ignore malformed/overclaiming server responses rather than showing ONLINE.
async function showPhysicalEvidence() {
  const statusNode = node("physical-evidence-status");
  const gatesNode = node("physical-evidence-gates");
  const gated = Object.freeze([
    ["out_of_band_host_key_verified", "Fingerprint terverifikasi melalui konsol/inventaris tepercaya"],
    ["management_segment_isolation_verified", "Segmen manajemen lokal terisolasi"],
    ["dedicated_readonly_account_verified", "Akun khusus baca-saja tervalidasi"],
    ["firmware_exact_readonly_commands_verified", "Perintah firmware baca-saja dikonfirmasi"],
    ["owner_approved_noimpact_baseline_verified", "Baseline dan penghentian darurat disetujui"],
    ["actual_worker_private_route_verified", "Worker VPS memiliki jalur privat terverifikasi"]
  ]);
  try {
    const response = await fetch("/lab/device-physical-evidence", {
      credentials:"omit",cache:"no-store"
    });
    if (!response.ok) throw new Error("evidence endpoint unavailable");
    const evidence=await response.json();
    if(evidence.schema_version!==1
      || evidence.mode!=="historical_credential_free_transport_observation"
      || evidence.target_slot!=="DEV-01"
      || evidence.private_ssh_transport_observed!==true
      || evidence.device_adopted!==false
      || evidence.credentials_sent!==false
      || evidence.olt_commands_executed!==0
      || evidence.worker_dispatch_enabled!==false
      || evidence.firmware_upgrade_enabled!==false
      || evidence.connectivity!=="UNKNOWN"
      || evidence.health!=="NOT_MEASURED"
      || evidence.owner_reported_vendor!=="ZTE"
      || evidence.owner_reported_model!=="C320"
      || evidence.owner_reported_pop!=="UNVERIFIED"
      || evidence.candidate_inventory_state!=="OBSERVED_NOT_ADOPTED"
      || evidence.direct_private_vps_ssh_transport_observed!==true
      || evidence.direct_private_vps_ssh_observed_on!=="2026-09-28"
      || evidence.direct_private_vps_ssh_observation_source!=="ipat-vps"
      || evidence.direct_private_vps_ssh_banner!=="ZTE_SSH.1.0"
      || evidence.direct_private_vps_ssh_untrusted_fingerprint_same_as_mac!==true
      || evidence.direct_private_vps_ssh_credentials_sent!==false
      || evidence.direct_private_vps_ssh_olt_commands_executed!==0
      || evidence.direct_private_vps_ssh_host_identity_verified!==false
      || evidence.direct_private_vps_ssh_last_hop_isolation_verified!==false
      || evidence.direct_private_vps_group14_auth_stage_observed_on!=="2026-09-29"
      || evidence.direct_private_vps_group14_hostkey_algorithm!=="ssh-rsa"
      || evidence.direct_private_vps_group14_cipher!=="aes128-cbc"
      || evidence.direct_private_vps_group14_kex!=="diffie-hellman-group14-sha256"
      || evidence.direct_private_vps_group14_server_hostkey_packet_received!==true
      || evidence.direct_private_vps_group14_auth_methods_advertised!==true
      || evidence.direct_private_vps_group14_client_timeout!==false
      || evidence.direct_private_vps_group14_credentials_sent!==false
      || evidence.direct_private_vps_group14_client_private_key_sent!==false
      || evidence.direct_private_vps_group14_olt_commands_executed!==0
      || evidence.direct_private_vps_group14_hostkey_oob_verified!==false
      || evidence.direct_private_vps_group14_actual_login_verified!==false
      || evidence.direct_private_vps_group14_physical_firmware_read!==false
      || evidence.direct_private_vps_tls443_noauth_checked!==true
      || evidence.direct_private_vps_tls443_tcp_reachable!==false
      || evidence.direct_private_vps_tls443_identity_verified!==false
      || evidence.direct_private_vps_tls443_api_supported!==false
      || evidence.direct_private_vps_tls443_credentials_sent!==false
      || evidence.direct_private_vps_tls443_http_requests_sent!==0
      || evidence.worker_route_observation!=="DEFAULT_ROUTE_ONLY"
      || evidence.temporary_owner_mac_vps_ssh_relay_observed!==true
      || evidence.temporary_owner_mac_vps_ssh_relay_closed!==true
      || evidence.temporary_relay_credentials_sent!==false
      || evidence.temporary_relay_olt_commands_executed!==0
      || evidence.temporary_relay_trusted_last_hop_verified!==false
      || evidence.worker_route_check_packets_sent!==0
      || evidence.physical_read_test!=="NOT_RUN"
      || gated.some(([key])=>evidence[key]!==false)) {
      throw new Error("backend evidence overclaims physical readiness");
    }
    observedPhysical={observed_on:evidence.observed_on};
    draw();
    statusNode.textContent="DEV-01 · SSH privat pernah dijangkau tanpa autentikasi ("+
      evidence.observed_on+") · fingerprint TERAMATI, BELUM DIPERCAYA · " +
      "VPS juga menjangkau SSH OLT langsung melalui IP privat tanpa login · " +
      "29/09: RSA + aes128-CBC + group14-SHA256 BERHASIL mencapai tahap autentikasi SSH tanpa password/perintah; identitas OLT masih BELUM TERPERCAYA · " +
      "uji HTTPS 443 satu kali tidak berhasil menjangkau layanan TCP; API HTTPS TIDAK TERBUKTI · " +
      "jalur akhir dan fingerprint BELUM dipercaya · " +
      "relay sementara Mac/VPS diuji tanpa login dan sudah ditutup · " +
      "rute ke IP privat via gateway default tetap dapat mencapai SSH, namun isolasi manajemen belum terbukti · " +
      "status perangkat UNKNOWN / NOT_MEASURED.";
    const items=document.createDocumentFragment();
    for(const [,title] of gated) {
      const item=el("div","physical-gate");
      item.append(el("span","flag unknown","BELUM DIVERIFIKASI"), el("span","",title));
      items.append(item);
    }
    gatesNode.replaceChildren(items);
  } catch {
    observedPhysical=null;
    draw();
    gatesNode.replaceChildren();
    statusNode.textContent="Bukti belum dapat diverifikasi. Tetap UNKNOWN; adopsi terkunci.";
  }
}
void showPhysicalEvidence();
// R9.12 simulator is an explicitly NONATTESTING preflight display.
async function checkSyntheticWireGuardReview() {
  const button=node("check-wg-review");
  const statusNode=node("wg-review-status");
  const gatesNode=node("wg-review-gates");
  button.disabled=true;
  statusNode.textContent="Memeriksa skenario contoh melalui backend lab...";
  gatesNode.replaceChildren();
  try {
    const response=await mutate("POST","/lab/demo/tunnel-review",{
      gateway:node("wg-gateway").value,
      segmentation:node("wg-segmentation").value,
      recovery:node("wg-recovery").value,
      service_baseline:node("wg-baseline").value
    });
    if(!response.ok) throw new Error("backend rejected simulation");
    const result=await response.json();
    if(result.lab_only!==true || result.synthetic_only!==true
       || result.preflight_status!=="BLOCKED_PENDING_REAL_REVIEW"
       || result.config_generated!==false || result.secrets_accepted!==false
       || result.tunnel_created!==false || result.network_actions!==0
       || result.worker_dispatch_enabled!==false || result.device_adopted!==false
       || result.service_impact_measured!==false
       || !Array.isArray(result.missing_evidence)
       || result.missing_evidence.length<4 || result.missing_evidence.length>8
       || result.missing_evidence.some(code=>typeof code!=="string"
         || !/^[A-Z_]{8,72}$/.test(code))) {
      throw new Error("invalid safety response");
    }
    statusNode.textContent="DITAHAN: skenario belum mengizinkan pembuatan tunnel atau operasi OLT.";
    const fragment=document.createDocumentFragment();
    for(const code of result.missing_evidence)
      fragment.appendChild(el("p","form-notice",code.replaceAll("_"," ")));
    gatesNode.replaceChildren(fragment);
  } catch {
    statusNode.textContent="Validasi gagal/ditolak. Seluruh aktivasi tetap terkunci.";
  } finally {button.disabled=false;}
}
node("check-wg-review").addEventListener("click",()=>{void checkSyntheticWireGuardReview();});
// R9.15: Site A chooses topology, Site B self-configures after separate review.
async function checkSiteAPlan() {
  const button=node("check-site-a-plan");
  const output=node("site-a-plan-result");
  button.disabled=true;
  output.textContent="Memvalidasi skenario Site A secara lokal pada backend privat...";
  try {
    const response=await mutate("POST","/lab/demo/site-a-plan",{
      method:node("hub-method").value,
      hub_address_scope:node("hub-address-scope").value,
      site_b_path:node("site-b-path").value,
      site_b_gateway:node("site-b-gateway").value
    });
    if(!response.ok) throw new Error("rejected plan");
    const result=await response.json();
    if(result.lab_only!==true || result.state!=="REVIEW_ONLY_NOT_DEPLOYABLE"
      || result.site_a_role!=="IPAT_CENTRAL_CONFIGURATION_AUTHORITY"
      || result.site_b_role!=="SITE_OPERATOR_SELF_CONFIGURES_NO_PUSH"
      || result.config_generated!==false || result.secrets_accepted!==false
      || result.router_push_enabled!==false || result.network_actions!==0
      || result.site_path_independently_verified!==false
      || result.real_mfa_verified!==false || result.device_adopted!==false
      || !["DIRECT_PRIVATE_NO_TUNNEL_REQUIRED","PRIVATE_HUB_WG_SITE_B_INITIATES",
            "PUBLIC_HUB_WG_SITE_B_INITIATES","IPSEC_NOT_YET_IMPLEMENTED",
            "VERIFIED_PRIVATE_ROUTE_REQUIRED","HUB_ENDPOINT_REACHABILITY_UNVERIFIED"]
            .includes(result.topology_candidate)) throw new Error("safety mismatch");
    output.textContent="SERVER PUSAT IPAT: "+result.topology_candidate.replaceAll("_"," ")+
      ". Gateway lokasi diatur oleh operator setempat. Belum ada konfigurasi atau koneksi dibuat.";
  } catch {
    output.textContent="Perencanaan ditolak/tidak dapat diverifikasi; semua tindakan terkunci.";
  } finally {button.disabled=false;}
}
node("check-site-a-plan").addEventListener("click",()=>{void checkSiteAPlan();});
// R9.16: only PUBLIC Site A/B keys. Lab output is DISABLED RouterOS text.
// The real production tenant onboarding workflow is deliberately not mounted.
let siteADevPublicAvailable=false;
async function loadSiteADevPublicKey(){
  const keyNode=node("site-a-public-key");
  const statusNode=node("site-a-key-status");
  const button=node("manual-pairing-button");
  button.disabled=true;
  siteADevPublicAvailable=false;
  keyNode.textContent="BELUM TERSEDIA";
  try{
    const response=await fetch("/lab/dev-site-a-public-key",{credentials:"omit",cache:"no-store"});
    if(!response.ok)throw new Error("developer key endpoint denied");
    const value=await response.json();
    if(value.mode!=="DEV_ONLY_PUBLIC_SITE_A_KEY_NOT_AN_ACTIVE_TUNNEL"
      || typeof value.site_a_public_key!=="string"
      || !/^[A-Za-z0-9+/]{43}=$/.test(value.site_a_public_key)
      || value.site_a_private_key_exported!==false
      || value.backup_verified!==false || value.tunnel_active!==false
      || value.router_push_enabled!==false || value.network_actions!==0
      || value.device_adopted!==false || value.genuine_tenant_mfa_verified!==false)
      throw new Error("server key status overclaims production authority");
    keyNode.textContent=value.site_a_public_key;
    statusNode.textContent="Public key DEV server pusat dimuat. Tidak ada listener, peer atau router yang diubah.";
    siteADevPublicAvailable=true;
    button.disabled=false;
  }catch{
    statusNode.textContent="Kunci server pusat tidak tersedia/terverifikasi pada backend lab; review terkunci.";
  }
}
async function submitSiteBManualReview(event){
  event.preventDefault();
  const button=node("manual-pairing-button");
  const statusNode=node("manual-pairing-status");
  const output=node("manual-pairing-output");
  output.textContent="";
  if(!siteADevPublicAvailable){
    statusNode.textContent="Ditolak: public key server pusat belum dapat dibuktikan backend.";
    return;
  }
  button.disabled=true;
  try{
    const publicB=node("manual-site-b-key").value.trim();
    if(!/^[A-Za-z0-9+/]{43}=$/.test(publicB))
      throw new Error("format public key B tidak valid");
    const response=await mutate("POST","/lab/demo/site-a-manual-pairing",{
      site_slug:"dev01-lab", hub_endpoint:node("manual-hub-ip").value.trim(),
      external_site_b:node("manual-external").value==="yes",
      a_tunnel_host:node("manual-a-ip").value.trim(),
      b_tunnel_host:node("manual-b-ip").value.trim(),
      olt_private_host:node("manual-olt-ip").value.trim(),
      site_b_public_key:publicB,
      udp_port:Number(node("manual-udp-port").value)
    });
    if(!response.ok)throw new Error("server refused unsafe pairing");
    const result=await response.json();
    const commands=result.site_b_routeros_disabled_review_commands;
    if(result.mode!=="DEV_ONLY_DISABLED_MANUAL_SITE_B_PAIRING"
      || result.site_a_role!=="CENTRAL_HUB_KEY_CUSTODY_ONLY"
      || result.site_b_role!=="OPERATOR_APPLIES_AFTER_SEPARATE_APPROVAL"
      || result.site_a_public_key!==node("site-a-public-key").textContent
      || result.site_b_public_key_received!==true
      || result.router_push_enabled!==false || result.config_applied!==false
      || result.site_a_listener_active!==false || result.network_actions!==0
      || result.device_adopted!==false || result.real_tenant_mfa_verified!==false
      || result.backup_verified!==false || result.real_peer_activation_authorized!==false
      || result.last_hop_isolation_verified!==false
      || result.return_route_independently_verified!==false
      || result.site_b_console_recovery_verified!==false
      || !Array.isArray(commands) || commands.length!==3
      || commands.some(cmd=>typeof cmd!=="string" || cmd.length>512
         || !cmd.startsWith("/") || !cmd.includes("disabled=yes")
         || cmd.includes("private-key") || cmd.includes("0.0.0.0/0")))
      throw new Error("unsafe or inconsistent server pairing result");
    output.textContent="# LAB ONLY — JANGAN TERAPKAN KE GATEWAY PRODUKSI\n"+commands.join("\n");
    statusNode.textContent="Draf nonaktif dibuat dari public key pusat dan lokasi. Belum ada pairing, listener, atau tindakan jaringan. Perlu persetujuan dan pemeriksaan topologi sebenarnya.";
  }catch{
    output.textContent="";
    statusNode.textContent="Draf ditolak/gagal. Tidak ada konfigurasi diterapkan.";
  }finally{button.disabled=!siteADevPublicAvailable;}
}
node("manual-site-b-form").addEventListener("submit",event=>{void submitSiteBManualReview(event);});
void loadSiteADevPublicKey();
const managementProtocolCandidates={
  zte_c320:[['ssh_pinned','SSH — kunci host diverifikasi'],
            ['snmpv3_authpriv','SNMPv3 authPriv — jika benar-benar tersedia']],
  cdata_olt:[['ssh_pinned','SSH — sesuai firmware'],
             ['snmpv3_authpriv','SNMPv3 authPriv'],
             ['https_vendor_verified','HTTPS vendor — hanya setelah uji firmware']],
  mikrotik_routeros7:[['routeros_api_ssl','API-SSL / TLS dengan sertifikat valid'],
                      ['routeros_rest_https','REST melalui HTTPS'],
                      ['ssh_pinned','SSH dengan host key tepercaya'],
                      ['snmpv3_authpriv','SNMPv3 authPriv']],
  ont_tr069:[['cwmp_https','ACS CWMP / TR-069 melalui HTTPS'],
            ['usp_authenticated','USP bila agent teruji']],
  ont_usp:[['usp_authenticated','USP / TR-369 terautentikasi'],
           ['cwmp_https','CWMP jika didukung']]
};
function refreshDirectProtocolChoices(){
  const profile=node('direct-device-type').value;
  const options=managementProtocolCandidates[profile]||[];
  const selector=node('direct-protocol');
  selector.replaceChildren();
  for(const [value,label] of options){
    const option=document.createElement('option');
    option.value=value;option.textContent=label;
    selector.append(option);
  }
  node('direct-protocol-status').textContent='Metode langsung diprioritaskan. Pilihan protokol ini bukan bukti layanan perangkat sudah tersedia.';
}
async function reviewDirectProtocol(){
  const button=node('direct-protocol-review');
  const output=node('direct-protocol-status');
  button.disabled=true;
  try{
    const profile=node('direct-device-type').value;
    const protocol=node('direct-protocol').value;
    const observed=node('direct-network').value;
    const allowed=managementProtocolCandidates[profile]||[];
    if(!allowed.some(([name])=>name===protocol))throw new Error('unsupported capability');
    const response=await mutate('POST','/lab/demo/direct-protocol-review',{
      device_profile:profile,candidate_protocol:protocol,network_evidence:observed
    });
    if(!response.ok)throw new Error('server denied');
    const plan=await response.json();
    if(plan.mode!=='DIRECT_MANAGEMENT_PROTOCOL_REVIEW_ONLY'
       || plan.device_profile!==profile||plan.candidate_protocol!==protocol
       || plan.preferred_path!=='DIRECT_OVER_EXISTING_NETWORK'
       || plan.wireguard_required!==false
       || plan.authentication_attempted!==false
       || plan.actual_protocol_compatibility_verified!==false
       || plan.exact_device_identity_verified!==false
       || plan.management_segment_isolation_verified!==false
       || plan.restricted_account_verified!==false
       || plan.owner_baseline_approved!==false
       || plan.device_adopted!==false || plan.network_actions!==0
       || plan.credentials_accepted!==false || plan.real_tenant_mfa_verified!==false
       || !Array.isArray(plan.available_candidate_protocols)
       || !plan.available_candidate_protocols.includes(protocol)
       || typeof plan.next_gate!=='string')
      throw new Error('unsafe server review');
    const historical=plan.network_transport_observed_historically===true
      ?'SSH privat pernah teramati; identitas fisik dan keamanan jalur BELUM terbukti. '
      :'Konektivitas nyata metode ini BELUM diverifikasi. ';
    output.textContent='PRIORITAS: koneksi langsung ('+protocol+'). '+historical+
      'Persyaratan berikutnya: '+plan.next_gate.replaceAll('_',' ')+
      '. VPN TIDAK WAJIB. Tidak ada autentikasi atau perubahan perangkat.';
  }catch{
    output.textContent='Pemeriksaan protokol ditolak. Perangkat tetap belum diadopsi; tidak ada perintah dikirim.';
  }finally{button.disabled=false;}
}
node('direct-device-type').addEventListener('change',refreshDirectProtocolChoices);
node('direct-protocol-review').addEventListener('click',()=>{void reviewDirectProtocol();});
refreshDirectProtocolChoices();
const c320ActionLabels={
  READ_CARD_INVENTORY:'Inventaris kartu',
  READ_RUNNING_FIRMWARE:'Versi firmware berjalan',
  READ_ACTIVE_ALARMS:'Alarm OLT',
  LIST_ONTS:'Daftar ONT',
  READ_ONT_OPTICAL_METRICS:'Metrik optik ONT',
  PROVISION_ONTS:'Provisioning ONT',
  REBOOT_OLT:'Reboot perangkat',
  UPGRADE_OLT_FIRMWARE:'Pembaruan firmware'
};
async function refreshC320Actions(){
  const button=node('refresh-c320-actions');
  const status=node('c320-actions-status');
  const output=node('c320-actions-list');
  button.disabled=true;
  output.replaceChildren();
  try{
    const response=await fetch('/lab/c320-action-readiness',{
      credentials:'omit',cache:'no-store'
    });
    if(!response.ok)throw new Error('not available');
    const catalog=await response.json();
    const features=catalog.capabilities;
    if(catalog.mode!=='PHYSICAL_C320_PRE_ADOPTION_ACTION_CATALOG'
      || catalog.target!=='DEV-01'
      || catalog.adoption_state!=='OBSERVED_NOT_ADOPTED'
      || catalog.preferred_connection!=='DIRECT_PRIVATE_SSH_NO_VPN_REQUIRED'
      || catalog.transport!==
          'CREDENTIAL_FREE_PRIVATE_SSH_AUTH_STAGE_REACHED_UNTRUSTED_HOST_KEY'
      || catalog.tested_legacy_ssh_profile!=='RSA_AES128CBC_GROUP14SHA256_ONLY'
      || catalog.actual_transport_authentication_stage_reached!==true
      || catalog.observed_network_host_key_still_untrusted!==true
      || catalog.credential_free_test_no_timeout!==true
      || catalog.physical_test_actual_login_performed!==false
      || catalog.credentials_sent_during_transport_test!==false
      || catalog.olt_commands_during_transport_test!==0
      || catalog.real_device_authenticated!==false
      || catalog.independent_oob_olt_host_key_verified!==false
      || catalog.dedicated_device_readonly_account_verified!==false
      || catalog.management_last_hop_isolated!==false
      || catalog.model_and_firmware_read_from_real_hardware!==false
      || catalog.live_distribution_baseline_approved!==false
      || catalog.genuine_tenant_admin_mfa_verified!==false
      || catalog.independent_reviewer_approved!==false
      || catalog.worker_enabled!==false
      || catalog.network_actions!==0 || catalog.device_adopted!==false
      || catalog.actual_device_health!=='NOT_MEASURED'
      || !Array.isArray(features) || features.length!==8
      || new Set(features.map(item=>item.action)).size!==8
      || features.some(item=>!Object.hasOwn(c320ActionLabels,item.action)
         || item.enabled!==false || item.can_run_on_live_device!==false
         || typeof item.state!=='string' || typeof item.requires!=='string'))
      throw new Error('server claims unverified live device action');
    const list=document.createDocumentFragment();
    for(const action of features){
      const row=el('div','physical-gate');
      const label=el('span','',c320ActionLabels[action.action]);
      const reason=action.state==='OFFLINE_PARSER_TESTED_LIVE_READ_BLOCKED'
        ?'Parser offline siap; pembacaan perangkat belum dijalankan'
        :action.state==='HIGH_IMPACT_LOCKED'
          ?'Aksi berisiko tinggi: tidak tersedia'
          :'Belum diuji terhadap firmware perangkat sebenarnya';
      row.append(el('span','flag unknown','TERKUNCI'),label,el('span','',reason));
      list.append(row);
    }
    output.replaceChildren(list);
    status.textContent='Profil SSH RSA + aes128-CBC + group14-SHA256 mencapai tahap autentikasi pada VPS. Seluruh delapan fungsi tetap TERKUNCI; fingerprint konsol dan akun baca-saja belum diverifikasi.';
  }catch{
    output.replaceChildren();
    status.textContent='Katalog tidak terverifikasi. Semua aksi tetap terkunci.';
  }finally{button.disabled=false;}
}
node('refresh-c320-actions').addEventListener('click',()=>{void refreshC320Actions();});
void refreshC320Actions();
