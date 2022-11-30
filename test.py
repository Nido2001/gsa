import plistlib as plist
import json
import hashlib
import hmac
import requests
import base64
import regex as re
import os
import srp._pysrp as srp
import pbkdf2
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

import urllib3
urllib3.disable_warnings()
    
def postXMLData(parameters, locale, timezone, proxy_protocol, proxy_address) -> dict:
    r = requests.get("https://sign.rheaa.xyz/", verify=False, timeout=5)
    r = json.loads(r.text)
    cpd = {
        "X-Apple-I-Client-Time": r["X-Apple-I-Client-Time"],
        "X-Apple-I-TimeZone": timezone,
        "loc": locale,
        "X-Apple-Locale": locale,
        "X-Apple-I-MD": r["X-Apple-I-MD"],
        "X-Apple-I-MD-LU": r["X-Apple-I-MD-LU"],
        "X-Apple-I-MD-M": r["X-Apple-I-MD-M"],
        "X-Apple-I-MD-RINFO": r["X-Apple-I-MD-RINFO"],
        "X-Mme-Device-Id": r["X-Mme-Device-Id"],
        "X-Apple-I-SRL-NO": r["X-Apple-I-SRL-NO"],
        "bootstrap": True,
        "icscrec": True,
        "pbe": False,
        "prkgen": True,
        "svct": "iCloud",
    }

    body = {
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "cpd": cpd,
        },
    }
    body["Request"].update(parameters)

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": "<MacBookPro15,1> <Mac OS X;10.15.2;19C57> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
    }
    proxy_servers = {
        proxy_protocol: proxy_address,
    }
    print(proxy_servers)
    resp = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        proxies=proxy_servers,
        headers=headers,
        data=plist.dumps(body),
        verify=False,
        timeout=5,
    )
    return plist.loads(resp.content)["Response"]

def CalculateX(password: str, salt: bytes, iterations: int) -> bytes:
    p = hashlib.sha256(password.encode("utf-8")).digest()
    return pbkdf2.PBKDF2(p, salt, iterations, hashlib.sha256).read(32)


def create_session_key(usr: srp.User, name: str) -> bytes:
    k = usr.get_session_key()
    if k is None:
        raise Exception("No session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()

def Step4(usr: srp.User, data: bytes) -> bytes:
    extra_data_key = create_session_key(usr, "extra data key:")
    extra_data_iv = create_session_key(usr, "extra data iv:")
    extra_data_iv = extra_data_iv[:16]
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    padder = padding.PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()

def GSALogin(username, password, locale, timezone, proxy_protocol, proxy_address):
    srp.rfc5054_enable()
    srp.no_username_in_x()
    srpclient = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    clientEphemeralsecret, clientEphemeralpublic = srpclient.start_authentication()

    plist_response = postXMLData(
        {
            "A2k": clientEphemeralpublic,
            "ps": ["s2k", "s2k_fo"],
            "u": username,
            "o": "init",
        },
        locale,
        timezone,
        proxy_protocol,
        proxy_address,
    )

    if plist_response["Status"]["hsc"] == 409:
        return plist_response["Status"]["em"].encode('utf-8')

    if plist_response["Status"]["em"] == "Your account information was entered incorrectly.":
        return "Your account information was entered incorrectly.".encode('utf-8')
    srpclient.p = CalculateX(password, plist_response["s"], plist_response["i"])
    M1 = srpclient.process_challenge(plist_response["s"], plist_response["B"])

    plist_response = postXMLData(
        {
            "c": plist_response["c"],
            "M1": M1,
            "u": username,
            "o": "complete",
        },
        locale,
        timezone,
        proxy_protocol,
        proxy_address,
    )
    srpclient.verify_session(plist_response["M2"])
    newdata = Step4(srpclient, plist_response["spd"]).decode("utf-8")
    new = plist.dumps(plist_response).decode("utf-8")
    x = re.sub(r"\bspd<\/key>\s+\K<data>((.|\n)*)<\/data>", newdata, new)
    return x.encode('utf-8')


class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_POST(self):
        post_data = self.rfile.read(int(self.headers['Content-Length']))
        res = GSALogin(json.loads(post_data.decode('utf-8'))["user"], json.loads(post_data.decode('utf-8'))["pass"], json.loads(post_data.decode('utf-8'))["locale"], json.loads(post_data.decode('utf-8'))["timezone"], json.loads(post_data.decode('utf-8'))["proxy_protocol"], json.loads(post_data.decode('utf-8'))["proxy_address"])
        self._set_response()
        self.wfile.write(res)

port = int(os.environ.get("PORT", 17995))
def run(server_class=HTTPServer, handler_class=S, port=port):
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