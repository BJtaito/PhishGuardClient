#!/usr/bin/env python3
import os, sys, json, time, secrets, base64, datetime, argparse
from typing import Dict, Any, Optional

import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def b64u_to_bytes(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    pad = '=' * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s + pad)

def jwk_to_pubkey(jwk: Dict[str, Any]):
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("Unsupported JWK")
    x = int.from_bytes(b64u_to_bytes(jwk["x"]), "big")
    y = int.from_bytes(b64u_to_bytes(jwk["y"]), "big")
    numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return numbers.public_key()

def iso_to_epoch_ms(ts: str) -> int:
    try:
        dt = datetime.datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception:
        dt = datetime.datetime.strptime(ts[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp() * 1000)

class PGTest:
    def __init__(self, base: str, api_key: Optional[str], time_skew_ms: int, url_under_test: str):
        self.base = base.rstrip('/')
        self.api_key = api_key
        self.time_skew_ms = time_skew_ms
        self.url_under_test = url_under_test

    def headers(self) -> Dict[str, str]:
        h = {'Content-Type':'application/json'}
        if self.api_key:
            h['X-API-Key'] = self.api_key
        return h

    def get(self, path: str, **kw):
        return requests.get(self.base + path, timeout=10, **kw)

    def post(self, path: str, **kw):
        return requests.post(self.base + path, timeout=15, **kw)

    def t_livez_readyz(self):
        print("==> /livez")
        r = self.get("/livez")
        r.raise_for_status()
        print(json.dumps(r.json(), ensure_ascii=False, indent=2))

        print("==> /readyz")
        r = self.get("/readyz")
        print(f"HTTP {r.status_code}")
        data = r.json()
        print(json.dumps(data, ensure_ascii=False, indent=2))
        if r.status_code != 200:
            raise SystemExit("Readiness failed (expected 200).")

    def t_signed_health(self):
        print("==> /health_pubkey (JWK)")
        jwk = self.get("/health_pubkey").json()
        print(json.dumps(jwk, ensure_ascii=False, indent=2))
        pub = jwk_to_pubkey(jwk)

        nonce = secrets.token_hex(16)
        print(f"==> /healthz?nonce={nonce}")
        r = self.get("/healthz", params={'nonce': nonce})
        r.raise_for_status()
        js = r.json()
        payload_str = js["payload"]
        sig_b64u = js["sig"]

        payload = json.loads(payload_str)
        if payload.get("nonce") != nonce:
            raise SystemExit("Nonce mismatch in /healthz payload.")
        skew_ms = abs(int(time.time()*1000) - iso_to_epoch_ms(payload["ts"]))
        print(f"[clock] skew={skew_ms} ms (limit={self.time_skew_ms} ms)")
        if skew_ms > self.time_skew_ms:
            print("[warn] clock skew exceeds limit")

        try:
            pub.verify(base64.urlsafe_b64decode(sig_b64u + "=="),
                       payload_str.encode("utf-8"),
                       ec.ECDSA(hashes.SHA256()))
            print("[sig] ES256 signature: VALID")
        except InvalidSignature:
            raise SystemExit("ES256 signature invalid!")

        print(json.dumps({
            "server_id": payload.get("server_id"),
            "queue_depth": payload.get("queue_depth"),
            "time": payload.get("time"),
            "janitor_alive": payload.get("janitor_alive"),
            "kid": payload.get("kid")
        }, ensure_ascii=False, indent=2))

    def t_whoami(self):
        print("==> /auth/whoami (optional)")
        r = self.get("/auth/whoami", headers=self.headers())
        if r.status_code == 401:
            print("[skip] whoami unauthorized (no API key?)")
            return
        r.raise_for_status()
        print(json.dumps(r.json(), ensure_ascii=False, indent=2))

    def t_analyze_end_to_end(self):
        print("==> /analyze (start)")
        body = {"url": self.url_under_test}
        r = self.post("/analyze", headers=self.headers(), json=body)
        if r.status_code == 401:
            raise SystemExit("Unauthorized: set API_KEY env or use Bearer token.")
        if r.status_code == 429:
            raise SystemExit("Rate-limited: raise ANALYZE_RATE_PER_MIN or wait.")
        r.raise_for_status()
        task_id = r.json()["task_id"]
        print(f"[task] id={task_id}")

        for i in range(120):
            time.sleep(0.7)
            rr = self.get(f"/tasks/{task_id}", headers=self.headers())
            if rr.status_code == 403:
                raise SystemExit("Task access forbidden for current principal.")
            rr.raise_for_status()
            js = rr.json()
            st = js["status"]
            print(f"[poll] {i} status={st}")
            if st in ("done", "error"):
                print(json.dumps(js, ensure_ascii=False, indent=2))
                if st == "error":
                    raise SystemExit("Task ended with error.")
                return
        raise SystemExit("Timeout waiting for task completion.")

def main():
    base = os.getenv("BASE", "http://127.0.0.1:8000")
    api_key = os.getenv("API_KEY")
    time_skew_ms = int(os.getenv("TIME_SKEW_MS", "10000"))
    url = os.getenv("URL_UNDER_TEST", "http://example.com/login")

    # CLI override
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=base)
    ap.add_argument("--api-key", default=api_key)
    ap.add_argument("--time-skew-ms", type=int, default=time_skew_ms)
    ap.add_argument("--url", default=url)
    ap.add_argument("--skip-analyze", action="store_true")
    args = ap.parse_args()

    print(f"[cfg] base={args.base} api_key={'set' if args.api_key else 'none'} skew={args.time_skew_ms} url={args.url}")

    t = PGTest(args.base, args.api_key, args.time_skew_ms, args.url)
    t.t_livez_readyz()
    t.t_signed_health()
    t.t_whoami()
    if not args.skip_analyze:
        t.t_analyze_end_to_end()
    print("\nOK: all selected tests passed.")

if __name__ == "__main__":
    main()
