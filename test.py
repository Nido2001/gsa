import plistlib as plist
import json
import hashlib
import hmac
import requests
import regex as re
from datetime import datetime
import os
import six
import pbkdf2
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import urllib3
urllib3.disable_warnings()
    
def postXMLData(parameters, locale, timezone, proxy_protocol, proxy_address, imd, imdm) -> dict:
    body = {
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "cpd": {
                "AppleIDClientIdentifier": "6DC291E9-B3E4-47D8-ABA9-B744C50A768A",
                "X-Apple-I-Client-Time": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                "X-Apple-I-MD": imd,
                "X-Apple-I-MD-M": imdm,      
                "X-Apple-I-MD-RINFO": "17106176",        
                "X-Apple-I-SRL-NO": "C76SHD7GHG6W",        
                "X-Mme-Device-Id": "fc0ccb8795d7d04bf9f67b4d277eef96fe4653e6",        
                "bootstrap": True,        
                "capp": "itunesstored",        
                "ckgen": True,        
                "dc": "2",
                "dec": "2",        
                "loc": locale,
                "pbe": True,        
                "ptkn": "",        
                "svct": "iTunes",
            },
        },
    }
    body["Request"].update(parameters)

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/1206 Darwin/20.1.0",
        "X-MMe-Client-Info": "<iPhone9,1> <iPhone OS;14.2;18B92> <com.apple.akd/1.0 (com.apple.akd/1.0)>",
    }
    proxy_servers = {
        proxy_protocol: proxy_address,
    }
    resp = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        proxies=proxy_servers,
        headers=headers,
        data=plist.dumps(body),
        verify=False,
    )
    return plist.loads(resp.content)["Response"]


def bytes_to_long(s):
    n = 0
    for b in six.iterbytes(s):
        n = (n << 8) | b
    return n

def get_random( nbytes ):
    return bytes_to_long( os.urandom( nbytes ) )

def get_random_of_length( nbytes ):
    offset = (nbytes*8) - 1
    return get_random( nbytes ) | (1 << offset)

def long_to_bytes(n):
    l = list()
    x = 0
    off = 0
    while x != n:
        b = (n >> off) & 0xFF
        l.append( chr(b) )
        x = x | (b << off)
        off += 8
    l.reverse()
    return six.b(''.join(l))

def H( hash_class, *args, **kwargs ):
    width = kwargs.get('width', None)
    h = hash_class()
    for s in args:
        if s is not None:
            data = long_to_bytes(s) if isinstance(s, six.integer_types) else s
            if width is not None and True:
                h.update( bytes(width - len(data)))
            h.update( data )

    return int( h.hexdigest(), 16 )

def bytes_to_long(s):
    n = 0
    for b in six.iterbytes(s):
        n = (n << 8) | b
    return n

def HNxorg( hash_class, N, g ):
    bin_N = long_to_bytes(N)
    bin_g = long_to_bytes(g)
    padding = len(bin_N) - len(bin_g)
    hN = hash_class( bin_N ).digest()
    hg = hash_class( b''.join( [b'\0'*padding, bin_g] ) ).digest()
    return six.b( ''.join( chr( six.indexbytes(hN, i) ^ six.indexbytes(hg, i) ) for i in range(0,len(hN)) ) )



def GSALogin(username, password, locale, timezone, proxy_protocol, proxy_address, imd, imdm):        
    n_hex, g_hex = ('''\
AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4\
A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60\
95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF\
747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907\
8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861\
60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB\
FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73''',
"2")
    N     = int(n_hex,16)
    g     = int(g_hex,16)
    k     = H(hashlib.sha256, N, g, width=len(long_to_bytes(N)))
    a     = get_random_of_length( 32 )
    A     = pow(g, a, N)
    
    plist_response = postXMLData(
        {
            "A2k": long_to_bytes(A),
            "ps": ["s2k", "s2k_fo"],
            "u": username,
            "o": "init",
        },
        locale,
        timezone,
        proxy_protocol,
        proxy_address,
        imd,
        imdm,
    )

    if plist_response["Status"]["hsc"] == 409:
        return plist_response["Status"]["em"].encode('utf-8')

    if plist_response["Status"]["em"] == "Your account information was entered incorrectly.":
        return "Your account information was entered incorrectly.".encode('utf-8')
    
    p     = pbkdf2.PBKDF2(hashlib.sha256(password.encode("utf-8")).digest(), plist_response["s"], plist_response["i"], hashlib.sha256).read(32)
    u     = H( hashlib.sha256, A, bytes_to_long(plist_response["B"]), width=len(long_to_bytes(N)) )
    x     = H( hashlib.sha256, bytes_to_long(plist_response["s"]), H( hashlib.sha256, six.b('') + six.b(':') + p ) )
    v     = pow(g, x, N)
    S     = pow((bytes_to_long(plist_response["B"]) - k*v), (a + u*x), N)
    K     = hashlib.sha256( long_to_bytes(S) ).digest()
    
    h = hashlib.sha256()
    h.update( HNxorg( hashlib.sha256, N, g ) )
    h.update( hashlib.sha256(username.encode()).digest() )
    h.update( plist_response["s"] )
    h.update( long_to_bytes(A) )
    h.update( plist_response["B"] )
    h.update( K )
    M = h.digest()

    plist_response = postXMLData(
        {
            "c": plist_response["c"],
            "M1": M,
            "u": username,
            "o": "complete",
        },
        locale,
        timezone,
        proxy_protocol,
        proxy_address,
        imd,
        imdm,
    )
    
    if plist_response["Status"]["em"] == "Unable to sign you in to your Apple ID. Try again later.":
        return "Unable to sign you in to your Apple ID. Try again later.".encode('utf-8')

    if plist_response["Status"]["em"] == "This action could not be completed. Try again.":
        return "This action could not be completed. Try again.".encode('utf-8')
        
    key = hmac.new(K, "extra data key:".encode(), hashlib.sha256).digest()
    iv = hmac.new(K, "extra data iv:".encode(), hashlib.sha256).digest()[:16]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = decryptor.update(plist_response["spd"]) + decryptor.finalize()
    padder = padding.PKCS7(128).unpadder()
    newdata = padder.update(data) + padder.finalize()
    new = plist.dumps(plist_response).decode("utf-8")
    x = re.sub(r"\bspd<\/key>\s+\K<data>((.|\n)*)<\/data>", newdata.decode("utf-8"), new)
    return x.encode('utf-8')

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_POST(self):
        post_data = self.rfile.read(int(self.headers['Content-Length']))
        res = GSALogin(json.loads(post_data.decode('utf-8'))["user"], json.loads(post_data.decode('utf-8'))["pass"], json.loads(post_data.decode('utf-8'))["locale"], json.loads(post_data.decode('utf-8'))["timezone"], json.loads(post_data.decode('utf-8'))["proxy_protocol"], json.loads(post_data.decode('utf-8'))["proxy_address"], json.loads(post_data.decode('utf-8'))["imd"], json.loads(post_data.decode('utf-8'))["imdm"])
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