"""R6.1 disposable localhost TLS fixture: valid CA/DNS vs wrong-name denial.

NEVER addresses an actual MikroTik, even if operator flags are set.
The production code's private target socket is monkeypatched to 127.0.0.1
and verified before creating any TLS connection.
"""
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "deploy/scripts/lab/r61/readonly-rest-probe.py"
SPEC = importlib.util.spec_from_file_location("ipat_r61_tls", SCRIPT)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)

class OnlyOneMockedPrivateRead(BaseHTTPRequestHandler):
    request_count = 0

    def do_GET(self):
        type(self).request_count += 1
        if self.path != "/rest/system/resource":
            self.send_error(404)
            return
        body = json.dumps([{
            "board-name": "RB951Ui-2HnD",
            "architecture-name": "mipsbe",
            "version": "7.23.7",
            "serial-number": "FAKE_SECRET_SERIAL_NEVER_EXPOSE",
        }]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Never print request headers, auth tokens, addresses or fixture IDs.
        pass

class QuietTLSServer(HTTPServer):
    def handle_error(self, request, client_address):
        pass

def run_openssl(*argv):
    subprocess.run(["openssl", *argv], check=True,
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=12)

@unittest.skipUnless(shutil.which("openssl"), "synthetic TLS fixture needs OpenSSL CLI")
class SyntheticVerifiedTLSTests(unittest.TestCase):
    def test_real_tls_ca_and_hostname_then_wrong_hostname_deny(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            ca = p / "ca.crt"
            cakey = p / "ca.key"
            serverkey = p / "server.key"
            csr = p / "server.csr"
            crt = p / "server.crt"
            ext = p / "san.cnf"
            ext.write_text(
                "subjectAltName=DNS:rb951.lab.internal\n"
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n", encoding="utf-8")
            cacfg = p / "ca.cnf"
            cacfg.write_text(
                "[req]\ndistinguished_name=req_dn\n"
                "x509_extensions=v3_ca\nprompt=no\n"
                "[req_dn]\nCN=R61-Synthetic-CA\n"
                "[v3_ca]\nbasicConstraints=critical,CA:TRUE\n"
                "keyUsage=critical,keyCertSign,cRLSign\n"
                "subjectKeyIdentifier=hash\n", encoding="utf-8")
            run_openssl("req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", str(cakey), "-out", str(ca),
                        "-nodes", "-days", "1", "-config", str(cacfg))
            run_openssl("req", "-newkey", "rsa:2048",
                        "-keyout", str(serverkey), "-out", str(csr),
                        "-nodes", "-subj", "/CN=rb951.lab.internal")
            run_openssl("x509", "-req", "-in", str(csr),
                        "-CA", str(ca), "-CAkey", str(cakey), "-CAcreateserial",
                        "-days", "1", "-extfile", str(ext), "-out", str(crt))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(crt), str(serverkey))
            OnlyOneMockedPrivateRead.request_count = 0
            httpd = QuietTLSServer(("127.0.0.1", 0), OnlyOneMockedPrivateRead)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()
            original_connect = socket.create_connection
            port = httpd.server_address[1]
            redirected = []
            def isolated_socket(remote, timeout=5):
                # The production client MUST still request the ONE private
                # configured IP on fixed HTTPS 443. Only the TEST uses loopback.
                if remote != ("192.168.88.42", 443):
                    raise AssertionError("unexpected target: fail without network")
                redirected.append(remote)
                return original_connect(("127.0.0.1", port), timeout=timeout)
            try:
                cfg = {
                    "management_ipv4": "192.168.88.42",
                    "tls_name": "rb951.lab.internal",
                    "expected_model": "RB951Ui-2HnD",
                    "expected_routeros": "7.23.7",
                }
                with patch.object(PROBE.socket, "create_connection", isolated_socket):
                    result = PROBE.read_one(cfg, ca, ("FAKE_USER", "FAKE_PASSWORD"))
                    self.assertEqual(result["model"], "RB951Ui-2HnD")
                    self.assertEqual(result["routeros"], "7.23.7")
                    self.assertFalse(result["physical_device_enrolled"])
                    self.assertFalse(result["operator_review_complete"])
                    self.assertNotIn("FAKE_SECRET_SERIAL", json.dumps(result))
                    cfg["tls_name"] = "wrong.lab.internal"
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        PROBE.read_one(cfg, ca, ("FAKE_USER", "FAKE_PASSWORD"))
                self.assertEqual(redirected, [("192.168.88.42", 443)] * 2)
                self.assertEqual(OnlyOneMockedPrivateRead.request_count, 1)
            finally:
                httpd.shutdown()
                worker.join(timeout=5)
                httpd.server_close()

if __name__ == "__main__":
    unittest.main()
