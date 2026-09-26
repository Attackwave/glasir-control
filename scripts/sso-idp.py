# A minimal OIDC provider for scripts/test-console-sso.sh. It checks PKCE
# (S256) and the redirect URI the way a real provider does and signs RS256
# tokens. A fourth argument makes it answer with a forged state.
import base64, hashlib, json, secrets, subprocess, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
KEY, PORT, SUB = sys.argv[1], int(sys.argv[2]), sys.argv[3]
BADSTATE = len(sys.argv) > 4
codes = {}
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def jwt(sub):
    h = b64(json.dumps({"alg": "RS256", "kid": "k", "typ": "JWT"}).encode())
    p = b64(json.dumps({"iss": f"http://localhost:{PORT}", "aud": "glasir-control", "sub": sub, "exp": int(time.time()) + 600}).encode())
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", KEY], input=f"{h}.{p}".encode(), capture_output=True).stdout
    return f"{h}.{p}.{b64(sig)}"
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): print(self.command, self.path.split('?')[0], *a[1:], file=sys.stderr)
    def cors(self):
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
    def do_OPTIONS(self):
        self.send_response(204); self.cors(); self.end_headers()
    def do_GET(self):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        ok = q.get("response_type") == "code" and q.get("client_id") == "console" and q.get("code_challenge_method") == "S256" and q.get("code_challenge") and q.get("state")
        if not ok:
            loc = q.get("redirect_uri", "/") + "?" + urllib.parse.urlencode({"error": "invalid_request", "state": q.get("state", "")})
        else:
            code = secrets.token_urlsafe(16)
            codes[code] = (q["code_challenge"], q["redirect_uri"])
            loc = q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": "forged" if BADSTATE else q["state"]})
        self.send_response(302); self.send_header("Location", loc); self.end_headers()
    def do_POST(self):
        f = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        challenge, redirect = codes.pop(f.get("code"), (None, None))
        good = challenge and b64(hashlib.sha256(f.get("code_verifier", "").encode()).digest()) == challenge and f.get("redirect_uri") == redirect and f.get("grant_type") == "authorization_code"
        body = json.dumps({"access_token": jwt(SUB), "token_type": "Bearer"} if good else {"error": "invalid_grant"}).encode()
        self.send_response(200 if good else 400); self.cors(); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
HTTPServer(("127.0.0.1", PORT), H).serve_forever()
