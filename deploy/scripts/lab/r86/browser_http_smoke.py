"""Actual independent urllib client against compiled Rust OIDC browser flow.
A FAKE HTTPS Keycloak URL is never visited. Successful callback MUST deny login.
"""
import re
import urllib.error
import urllib.parse
import urllib.request

BASE="http://127.0.0.1:3001"
TRUSTED="https://id.example.invalid/realms/ipat/protocol/openid-connect/auth"
class NoExternalRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
OPENER=urllib.request.build_opener(NoExternalRedirect())
def call(path,host="127.0.0.1:48765",cookie=None):
    headers={"Host":host}
    if cookie: headers["Cookie"]=cookie
    req=urllib.request.Request(BASE+path,headers=headers)
    try:
        with OPENER.open(req,timeout=4) as resp:
            return resp.status,{k.lower():v for k,v in resp.headers.items()},resp.read(4096)
    except urllib.error.HTTPError as err:
        return err.code,{k.lower():v for k,v in err.headers.items()},err.read(4096)

def main():
    assert call("/healthz")[0]==200
    assert call("/lab/auth/browser/start","evil.invalid")[0]==403
    s,h,b=call("/lab/auth/browser/start")
    assert s==303,(s,b)
    assert h["cache-control"]=="no-store"
    assert h["referrer-policy"]=="no-referrer"
    assert h["location"].startswith(TRUSTED+"?")
    fields=urllib.parse.parse_qs(urllib.parse.urlsplit(h["location"]).query)
    assert fields["response_type"]==["code"]
    assert fields["scope"]==["openid"]
    assert fields["code_challenge_method"]==["S256"]
    assert fields["client_id"]==["ipat-browser-lab"]
    assert fields["redirect_uri"]==["http://127.0.0.1:48765/lab/auth/browser/callback"]
    for key in ("state","nonce","code_challenge"):
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}",fields[key][0]),key
    assert "code_verifier" not in fields
    state=fields["state"][0]
    full=h["set-cookie"]
    assert full.startswith("ipat_lab_oidc_state="+state+";")
    assert "HttpOnly" in full and "SameSite=Lax" in full
    cookie="ipat_lab_oidc_state="+state
    url="/lab/auth/browser/callback?state="+state+"&code=FAKE-CODE-NEVER-EXCHANGE"
    assert call(url)[0]==403
    assert call(url,host="other.invalid",cookie=cookie)[0]==403
    assert call(url,cookie="ipat_lab_oidc_state="+("x"*43))[0]==403
    assert call(url+"&role=platform_owner",cookie=cookie)[0]==400
    result=call(url,cookie=cookie)
    assert result[0]==503,result
    assert b'"authenticated":false' in result[2]
    assert b"FAKE-CODE" not in result[2]
    assert result[1]["set-cookie"].endswith("Max-Age=0")
    assert call(url,cookie=cookie)[0]==403
    for path in ("/v1/platform/tenants","/v1/tenant/devices",
                 "/v1/operations/overview"):
        assert call(path)[0]==401,path
    assert call("/lab/auth/device-candidates")[0]==404
    assert call("/lab/auth/device-reviews")[0]==404
    print("R86_REAL_TCP_PKCE_START_NONCE_COOKIE_303_REPLAY_DENIAL_503=PASS")
    print("R86_REAL_CUSTOMER_AUTHORIZATION_AND_PHYSICAL_ADOPTION_STILL_DISABLED=PASS")
if __name__=="__main__":main()
