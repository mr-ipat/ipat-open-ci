// Node-native, no external libraries. Exercise the actual browser controller
// against a synthetic DOM and fake private HTTP endpoint; no real device I/O.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const file = new URL("../../../../web/lab/dashboard-preview.js", import.meta.url);
const source = fs.readFileSync(file, "utf8");
class Node {
  constructor(tag = "div", value = "") {
    this.tag = tag;
    this.value = value;
    this.textContent = "";
    this.className = "";
    this.children = [];
    this.props = {};
    this.events = {};
    this.disabled = false;
  }
  appendChild(child) {
    this.children.push(child);
    return child;
  }
  replaceChildren(...children) {
    this.children = children.flatMap((child) =>
      child.tag === "fragment" ? child.children : [child]);
  }
  setAttribute(key, value) { this.props[key] = value; }
  addEventListener(name, callback) { this.events[name] = callback; }
  get nodes() {
    return this.children.flatMap((c) => [c, ...c.nodes]);
  }
}
const nodes = new Map();
const byId = (key) => {
  if (!nodes.has(key)) nodes.set(key, new Node("id:" + key));
  return nodes.get(key);
};
const calls = [];
const mockResponse = (data) => ({
  ok: true,
  text: async () => data,
  json: async () => structuredClone(data)
});
const responses = {
  "/healthz": mockResponse("ok"),
  "/lab/status": mockResponse({
    mode:"ssh-loopback-only",production_access:false,
    authentication_enabled:false,device_operations_enabled:false
  }),
  "/lab/rollout-phase": mockResponse({
    schema:1, phase:"private_single_endpoint_device_lab",
    domain_verification_deferred:true, custom_domains_enabled:false,
    public_tenant_hostnames_enabled:false, private_loopback_transport_only:true,
    tenant_isolation_mandatory:true, tenant_isolation_end_to_end_verified:false,
    authenticated_tenant_data_apis_enabled:false,
    physical_device_connected:false, device_reads_approved:false,
    firmware_updates_enabled:false
  }),
  "/lab/device-targets": mockResponse({
    catalog_mode:"planned_targets_only",physical_devices_enrolled:0,
    physical_interoperability_verified:0,compatibility_claim:false,
    targets:Array.from({length:8},(_,i)=>({id:"DEV-"+(i+1)}))
  })
};
const browser = {
  document: {
    getElementById: byId,
    createElement: (tag) => new Node(tag),
    createDocumentFragment: () => new Node("fragment"),
    createTextNode: (text) => {
      const n = new Node("text");
      n.textContent = text;
      return n;
    }
  },
  window: {setTimeout:()=>1,clearTimeout:()=>{}},
  AbortController,
  fetch: async (url) => {
    calls.push(url);
    assert.ok(Object.hasOwn(responses,url), "Unexpected API access: "+url);
    return responses[url];
  }
};
vm.createContext(browser);
vm.runInContext(source,browser,{filename:"dashboard-preview.js"});
// Allow the three synthetic status checks to settle.
await new Promise((resolve)=>setImmediate(resolve));
assert.equal(byId("metric-grid").children.length,3);
assert.equal(byId("focus-rows").children.length,3);
assert.equal(byId("demo-nav").children.length,4);
function gaps() {
  return byId("prd-gap-list").nodes.map(n=>n.textContent).join(" ");
}
assert.match(gaps(),/FR-002/);
assert.match(gaps(),/FR-004/);
assert.doesNotMatch(gaps(),/TC-OLT-01/);
assert.match(byId("page-title").nodes.map(x=>x.textContent).join(""),/Platform Admin/);
assert.match(byId("checked").textContent,/privat terhubung/);
assert.match(byId("device-summary").textContent,/8 target.*0 perangkat nyata/);
assert.deepEqual(calls,["/healthz","/lab/status","/lab/device-targets","/lab/rollout-phase"]);
assert.match(byId("rollout-status").textContent,/custom domain terkunci/);

function links() {
  return byId("demo-nav").nodes.filter(n=>n.tag==="a")
    .map(n=>n.nodes.map(x=>x.textContent).join(" "));
}
let menu = links();
assert.ok(menu.some(x=>x.includes("Tenant & domain")));
assert.ok(!menu.some(x=>x.includes("Insiden")));
byId("workspace").events.change({target:{value:"tenant"}});
assert.match(byId("page-title").nodes.map(x=>x.textContent).join(""),/Tenant Admin/);
menu = links();
assert.ok(menu.some(x=>x.includes("Tim & akses")));
assert.ok(!menu.some(x=>x.includes("Paket")));
assert.ok(!menu.some(x=>x.includes("Insiden")));
assert.match(byId("scope-menu").textContent,/tidak boleh mengelola platform/i);
assert.match(gaps(),/FR-001\/003/);
assert.doesNotMatch(gaps(),/FR-004/);

byId("workspace").events.change({target:{value:"operations"}});
assert.match(byId("page-title").nodes.map(x=>x.textContent).join(""),/Operasional NOC/);
menu = links();
assert.ok(menu.some(x=>x.includes("Insiden & tugas")));
assert.ok(!menu.some(x=>x.includes("Tenant & domain")));
assert.ok(!menu.some(x=>x.includes("Tim & akses")));
assert.match(byId("scope-menu").textContent,/POP/);
assert.match(gaps(),/TC-OLT-01/);
assert.match(gaps(),/FR-009\/010/);
assert.doesNotMatch(gaps(),/FR-004/);

assert.deepEqual(calls,["/healthz","/lab/status","/lab/device-targets","/lab/rollout-phase"],
  "Changing visual workspace MUST NOT contact a protected API");
// A forged success flag on a new rollout manifest MUST fail the UI preflight.
responses["/lab/rollout-phase"] = mockResponse({
  schema:1,phase:"private_single_endpoint_device_lab",
  domain_verification_deferred:true,custom_domains_enabled:true,
  public_tenant_hostnames_enabled:true,private_loopback_transport_only:true,
  tenant_isolation_mandatory:false,tenant_isolation_end_to_end_verified:false,
  authenticated_tenant_data_apis_enabled:false,physical_device_connected:false,
  device_reads_approved:false,firmware_updates_enabled:false
});
byId("check").events.click();
await new Promise((resolve)=>setImmediate(resolve));
assert.match(byId("rollout-status").textContent,/tidak terverifikasi/);
assert.match(byId("checked").textContent,/belum terverifikasi/);
console.log("R75_SYNTHETIC_DOMAIN_DEFERRED_PHASE_FAILS_CLOSED=PASS");
console.log("R68_SYNTHETIC_THREE_WORKSPACE_UI_SELECTION_AND_NO_REAL_API_CALLS=PASS");
