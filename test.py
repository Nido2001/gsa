from datetime import datetime
import locale
import plistlib as plist
import json
import hashlib
import hmac
import requests
import srp._pysrp as srp
import pbkdf2
from http.server import BaseHTTPRequestHandler, HTTPServer


def generate_cpd() -> dict:
    cpd = {
        "bootstrap": True,
        "icscrec": True,
        "pbe": False,
        "prkgen": True,
        "svct": "iCloud",
    }

    r = requests.get("https://sign.rheaa.xyz/", verify=False, timeout=5)
    r = json.loads(r.text)
    
    cpd.update({
        "X-Apple-I-Client-Time": r["X-Apple-I-Client-Time"],
        "X-Apple-I-TimeZone": str(datetime.utcnow().astimezone().tzinfo),
        "loc": locale.getlocale()[0],
        "X-Apple-Locale": locale.getlocale()[0],
        "X-Apple-I-MD": r["X-Apple-I-MD"],
        "X-Apple-I-MD-LU": r["X-Apple-I-MD-LU"],
        "X-Apple-I-MD-M": r["X-Apple-I-MD-M"],
        "X-Apple-I-MD-RINFO": r["X-Apple-I-MD-RINFO"],
        "X-Mme-Device-Id": r["X-Mme-Device-Id"],
        "X-Apple-I-SRL-NO": r["X-Apple-I-SRL-NO"],
    })
    return cpd
    
def postXMLData1(parameters) -> dict:
    body = {
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "cpd": generate_cpd(),
        },
    }
    body["Request"].update(parameters)

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": "<MacBookPro15,1> <Mac OS X;10.15.2;19C57> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
    }

    resp = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        headers=headers,
        data=plist.dumps(body),
        verify=False,
        timeout=5,
    )
    return plist.loads(resp.content)["Response"]

def postXMLData2(parameters) -> dict:
    body = {
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "cpd": generate_cpd(),
        },
    }
    body["Request"].update(parameters)

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": "<MacBookPro15,1> <Mac OS X;10.15.2;19C57> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
    }

    resp = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        headers=headers,
        data=plist.dumps(body),
        verify=False,
        timeout=5,
    )
    return resp.content

def CalculateX(password: str, salt: bytes, iterations: int) -> bytes:
    p = hashlib.sha256(password.encode("utf-8")).digest()
    return pbkdf2.PBKDF2(p, salt, iterations, hashlib.sha256).read(32)


def GSALogin(username, password):
    srp.rfc5054_enable()
    srp.no_username_in_x()
    srpclient = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    clientEphemeralsecret, clientEphemeralpublic = srpclient.start_authentication()

    plist_response = postXMLData1(
        {
            "A2k": clientEphemeralpublic,
            "ps": ["s2k", "s2k_fo"],
            "u": username,
            "o": "init",
        },
    )

    srpclient.p = CalculateX(password, plist_response["s"], plist_response["i"])
    M1 = srpclient.process_challenge(plist_response["s"], plist_response["B"])

    plist_response = postXMLData2(
        {
            "c": plist_response["c"],
            "M1": M1,
            "u": username,
            "o": "complete",
        },
    )
    return plist_response

def main(username, password):
    return GSALogin(username, password)

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_POST(self):
        post_data = self.rfile.read(int(self.headers['Content-Length']))
        res= main(json.loads(post_data.decode('utf-8'))["user"], json.loads(post_data.decode('utf-8'))["pass"])
        self._set_response()
        self.wfile.write(res)

def run(server_class=HTTPServer, handler_class=S, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('Server Starting...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()