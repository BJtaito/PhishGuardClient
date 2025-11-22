"""
간단한 Client CLI

- URL 분석: /api/analyze + /api/analyze/{job_id}
- challenge 응답: /api/challenges/{id} + /client-results

실제 제품에서는 이 자리에 "로컬 Analyzer" 호출을 붙이면 되고,
지금 샘플은 그냥 API Server의 analyze 를 다시 호출해서
Analyzer 와 거의 동일한 결과를 보내는 형태(데모용)이다.
"""

import os
import time
import argparse
from typing import Any, Dict, List

import requests


API_BASE = os.getenv("PG_API_BASE", "http://localhost:9000")
API_KEY = os.getenv("PG_API_KEY", "CLIENT_PUBLIC_KEY")  # X-API-Key


def _request(method: str, path: str, *, json: Any = None, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
    url = API_BASE.rstrip("/") + path
    headers = {"X-API-Key": API_KEY}
    resp = requests.request(method, url, headers=headers, json=json, params=params, timeout=60)
    try:
        resp.raise_for_status()
    except Exception as e:
        print("HTTP error:", e)
        print("Body:", resp.text)
        raise
    return resp.json()


def analyze_once(url: str) -> Dict[str, Any]:
    """하나의 URL을 요청하고, 완료될 때까지 폴링."""
    print(f"[+] analyze: {url}")
    data = _request("POST", "/api/analyze", json={"url": url})
    job_id = data["job_id"]
    print("  job_id:", job_id)

    while True:
        time.sleep(1.0)
        status = _request("GET", f"/api/analyze/{job_id}")
        s = status["status"]
        print("  status:", s)
        if s in ("done", "error", "failed"):
            break

    print("=== final ===")
    print("verdict:", status.get("verdict"))
    print("score  :", status.get("score"))
    print("error  :", status.get("error"))
    return status.get("result") or {}


def solve_challenge(challenge_id: str, client_id: str) -> None:
    """challenge 를 불러와서, URL 들을 analyze 후 client-results 로 업로드."""
    info = _request("GET", f"/api/challenges/{challenge_id}")
    print("[+] challenge:", info["challenge_id"])
    print("  urls:", info["urls"])
    print("  nonce:", info["nonce"])
    print("  status:", info["status"])

    results: List[Dict[str, Any]] = []
    for url in info["urls"]:
        res = analyze_once(url)
        results.append({"url": url, "raw_result": res})

    body = {"client_id": client_id, "results": results}
    _request("POST", f"/api/challenges/{challenge_id}/client-results", json=body)
    print("[+] client results submitted.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Phish-Guard Client CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="URL 하나 분석")
    p_an.add_argument("url")

    p_ch = sub.add_parser("solve-challenge", help="challenge 에 응답")
    p_ch.add_argument("challenge_id")
    p_ch.add_argument("client_id")

    args = parser.parse_args()

    if args.cmd == "analyze":
        analyze_once(args.url)
    elif args.cmd == "solve-challenge":
        solve_challenge(args.challenge_id, args.client_id)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
