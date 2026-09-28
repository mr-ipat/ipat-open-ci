"""ACTUAL compiled Rust/Axum localhost browser-like demo API integration.
No real CPE, identity, subscriber DB, firmware or network discovery.
"""
import json
import urllib.error
import urllib.request

BASE="http://127.0.0.1:3000"
PATH="/lab/demo/device-candidates"
FORM={"display_name":"LAB-OLT-01","pop_id":"lab-pop-a","device_kind":"olt",
      "vendor":"ZTE","exact_model":"VIRTUAL-C320"}
def call(path,method="GET",obj=None,csrf=True,host="127.0.0.1:3000"):
    headers={"Host":host}
    if method in ("POST","DELETE"):
        headers["Content-Type"]="application/json"
        if csrf:
            headers["X-IPAT-Demo-Only"]="1"
            headers["Origin"]="http://127.0.0.1:3000"
    data=None if obj is None else json.dumps(obj).encode()
    req=urllib.request.Request(BASE+path,method=method,data=data,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=4) as r:
            return r.status,{k.lower():v for k,v in r.headers.items()},r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code,{k.lower():v for k,v in e.headers.items()},e.read(65536)

def main():
    status,headers,html=call("/lab/device-workbench")
    assert status==200,(status,html[:200])
    assert b"Tambah kandidat perangkat" in html
    assert b"Daftar kandidat" in html
    assert b"PERINGATAN PRD" in html
    assert b"type=\"password\"" not in html
    assert headers.get("cache-control")=="no-store"
    assert headers.get("x-frame-options")=="DENY"
    assert call("/lab/device-workbench.css")[0]==200
    assert call("/lab/device-workbench.js")[0]==200
    assert b"Tambah &amp; kelola perangkat" in call("/lab/dashboard-preview")[2]
    assert b"Device Manager" in call("/lab")[2]
    s,_,body=call(PATH)
    state=json.loads(body)
    assert s==200 and state["count"]==0 and state["real_device_count"]==0
    assert state["physical_connection_checked"] is False
    assert call(PATH,"POST",FORM,csrf=False)[0]==403
    assert call(PATH,"POST",FORM,host="evil.invalid")[0]==403
    s,headers,body=call(PATH,"POST",FORM)
    assert s==201,(s,body)
    assert headers["cache-control"]=="no-store"
    result=json.loads(body)
    assert result["accepted"] is True
    assert result["device"]["adoption_state"]=="PENDING_REVIEW"
    assert result["device"]["connectivity"]=="UNKNOWN"
    assert result["device"]["health"]=="NOT_MEASURED"
    assert result["device"]["last_verified_at"] is None
    assert result["device"]["lab_only"] is True
    device_id=result["device"]["id"]
    assert device_id.startswith("LAB-DEMO-")
    s,_,body=call(PATH)
    state=json.loads(body)
    assert s==200 and state["count"]==1
    assert state["devices"][0]["id"]==device_id
    assert state["devices"][0]["pop_id"]=="lab-pop-a"
    assert call(PATH,"POST",FORM)[0]==409
    bad=dict(FORM,display_name="OLT REAL DEVICE")
    assert call(PATH,"POST",bad)[0]==400
    bad=dict(FORM,exact_model="C320-ACTUAL")
    assert call(PATH,"POST",bad)[0]==400
    bad=dict(FORM,management_ipv4="10.1.1.1")
    assert call(PATH,"POST",bad)[0]==422
    bad=dict(FORM,password="NEVER-ACCEPT")
    assert call(PATH,"POST",bad)[0]==422
    path=PATH+"/"+device_id
    assert call(path,"DELETE",csrf=False)[0]==403
    assert call(path,"DELETE")[0]==200
    assert call(path,"DELETE")[0]==404
    assert json.loads(call(PATH)[2])["count"]==0
    for uri in ("/v1/platform/overview","/v1/tenant/devices",
                "/v1/operations/overview"):
        assert call(uri)[0]==401,uri
    assert call("/lab/auth/device-candidates")[0]==404
    assert call("/lab/auth/device-candidates/propose","POST",FORM)[0]==404
    rollout=json.loads(call("/lab/rollout-phase")[2])
    assert rollout["physical_device_connected"] is False
    assert rollout["firmware_updates_enabled"] is False
    assert rollout["authenticated_tenant_data_apis_enabled"] is False
    print("R83_ACTUAL_RUST_TCP_HTTP_DEVICE_UI_ADD_LIST_STATUS_DENY_REAL_API=PASS")
if __name__=="__main__":main()
