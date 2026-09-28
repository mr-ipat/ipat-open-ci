"""R8.2 actual LOCAL HTTP strict SOAP tests; synthetic fake ONT only."""
import json
import urllib.request
import urllib.error
from xml.etree import ElementTree as ET

BASE = "http://127.0.0.1:3300"
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
CWMP = "urn:dslforum-org:cwmp-1-0"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
XSD = "http://www.w3.org/2001/XMLSchema"
NAME = "Device.DeviceInfo.SoftwareVersion"
INFORM = f"""<soap:Envelope xmlns:soap="{SOAP}" xmlns:cwmp="{CWMP}">
 <soap:Header><cwmp:ID soap:mustUnderstand="1">synthetic-only</cwmp:ID></soap:Header>
 <soap:Body><cwmp:Inform><DeviceId>
 <Manufacturer>SYNTHETIC</Manufacturer><OUI>001122</OUI>
 <ProductClass>FAKE-ONT</ProductClass>
 <SerialNumber>FAKE-NOT-PHYSICAL</SerialNumber></DeviceId>
 <Event><EventStruct><EventCode>0 BOOTSTRAP</EventCode>
 <CommandKey/></EventStruct></Event><MaxEnvelopes>1</MaxEnvelopes>
 <CurrentTime>2026-09-27T00:00:00Z</CurrentTime>
 <RetryCount>0</RetryCount><ParameterList/>
 </cwmp:Inform></soap:Body></soap:Envelope>"""
REPLY = f"""<soap:Envelope xmlns:soap="{SOAP}" xmlns:cwmp="{CWMP}"
 xmlns:xsi="{XSI}" xmlns:xsd="{XSD}">
 <soap:Header><cwmp:ID soap:mustUnderstand="1">ipat-synthetic-rpc-01</cwmp:ID></soap:Header>
 <soap:Body><cwmp:GetParameterValuesResponse><ParameterList>
 <ParameterValueStruct><Name>{NAME}</Name>
 <Value xsi:type="xsd:string">FAKE-SENSITIVE-DEVICE-FIRMWARE</Value>
 </ParameterValueStruct></ParameterList>
 </cwmp:GetParameterValuesResponse></soap:Body></soap:Envelope>"""
FAULT = f"""<soap:Envelope xmlns:soap="{SOAP}" xmlns:cwmp="{CWMP}">
 <soap:Header><cwmp:ID soap:mustUnderstand="1">ipat-synthetic-rpc-01</cwmp:ID></soap:Header>
 <soap:Body><soap:Fault><faultcode>soap:Client</faultcode>
 <faultstring>DO-NOT-LEAK-FAULT</faultstring>
 <detail><cwmp:Fault><FaultCode>9005</FaultCode>
 <FaultString>PRIVATE-FAULT-TEXT</FaultString></cwmp:Fault>
 </detail></soap:Fault></soap:Body></soap:Envelope>"""

def call(path, xml=None, content_type="text/xml", headers=None):
    h = {"Host": "untrusted.external.invalid",
         "X-Tenant-Id":"faked-tenant",
         "X-Client-Cert-Verified":"true"}
    if headers: h.update(headers)
    data = None
    if xml is not None:
        data = xml.encode() if isinstance(xml,str) else xml
        h["Content-Type"] = content_type
    req = urllib.request.Request(BASE+path,data=data,headers=h)
    try:
        with urllib.request.urlopen(req,timeout=3) as res:
            return res.status,{k.lower():v for k,v in res.headers.items()},res.read(8192)
    except urllib.error.HTTPError as err:
        return err.code,{k.lower():v for k,v in err.headers.items()},err.read(8192)

def verify():
    assert call("/healthz")[0] == 200
    status,headers,body=call("/lab/virtual-ont/inform",INFORM)
    assert status==200,(status,body)
    assert headers.get("cache-control")=="no-store"
    assert headers["content-type"].startswith("text/xml")
    root=ET.fromstring(body)
    assert root.find(f".//{{{CWMP}}}InformResponse") is not None
    assert root.find(f".//{{{CWMP}}}ID").text=="synthetic-only"
    assert b"FAKE-NOT-PHYSICAL" not in body
    assert b"faked-tenant" not in body
    s,h,request=call("/lab/virtual-ont/read-request")
    assert s==200 and h["content-type"].startswith("text/xml")
    rpc=ET.fromstring(request)
    assert rpc.find(f".//{{{CWMP}}}GetParameterValues") is not None
    assert NAME.encode() in request and b"SetParameterValues" not in request
    s,headers,body=call("/lab/virtual-ont/read-reply",REPLY)
    assert s==200 and headers["cache-control"]=="no-store"
    result=json.loads(body)
    assert result["parameter_count"]==1 and not result["peer_authenticated"]
    assert not result["tenant_bound"] and not result["session_established"]
    assert b"FAKE-SENSITIVE-DEVICE-FIRMWARE" not in body
    s,_,fault_body=call("/lab/virtual-ont/read-reply",FAULT)
    assert s==200 and json.loads(fault_body)["fault"] is True
    assert b"PRIVATE-FAULT" not in fault_body and b"DO-NOT-LEAK" not in fault_body
    for bad in (INFORM.replace("FAKE-NOT-PHYSICAL","REAL-PHYSICAL-SERIAL"),
                INFORM.replace("0 BOOTSTRAP","1 BOOT")):
        assert call("/lab/virtual-ont/inform",bad)[0]==403
    for bad in (REPLY.replace("ipat-synthetic-rpc-01","forged-id"),
                REPLY.replace("GetParameterValuesResponse","SetParameterValues"),
                REPLY.replace(NAME,"Device.ManagementServer.Password"),
                "<!DOCTYPE x []>"+REPLY):
        assert call("/lab/virtual-ont/read-reply",bad)[0]==400
    assert call("/lab/virtual-ont/read-reply",REPLY,"application/xml")[0]==415
    assert call("/lab/virtual-ont/read-reply",b"x"*65537)[0]==413
    assert call("/cwmp",INFORM)[0]==503
    print("R82_REAL_HTTP_INFORM_SOAP_GPV_AND_FAULT_WITH_NO_PEER_TRUST=PASS")
if __name__=="__main__":verify()
