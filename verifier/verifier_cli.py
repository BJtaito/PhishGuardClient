"""
상위 Server (Verifier) 용 간단 CLI

- challenge 생성: POST /api/challenges
- verdict 조회:  GET /api/challenges/{id}/verdict?client_id=...

이 스크립트는 "Server ⇄ API Server" 쪽 역할을 데모한다.
"""

import os
import argparse
from typing import Any, Dict, List

import requests


API_BASE = os.getenv("PG_API_BASE", "http://localhost:9000")
API_KEY = os.getenv("PG_API_KEY", "SERVER_KEY")  # X-API-Key (server용)


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


def create_challenge(urls: List[str], threshold: float, expires_in_sec: int = 300) -> None:
    body = {"urls": urls, "threshold": threshold, "expires_in_sec": expires_in_sec}
    resp = _request("POST", "/api/challenges", json=body)
    print("[+] challenge created")
    print("  challenge_id:", resp["challenge_id"])
    print("  nonce       :", resp["nonce"])
    print("  urls        :", resp["urls"])
    print("  threshold   :", resp["threshold"])
    print("  expires_at  :", resp["expires_at"])


def get_verdict(challenge_id: str, client_id: str) -> None:
    params = {"client_id": client_id}
    resp = _request("GET", f"/api/challenges/{challenge_id}/verdict", params=params)
    print("[+] verdict")
    print("  challenge_id:", resp["challenge_id"])
    print("  client_id   :", resp["client_id"])
    print("  passed      :", resp["passed"])
    print("  avg_sim     :", resp["average_similarity"])
    print("  threshold   :", resp["threshold"])
    print("  status      :", resp["status"])
    print("  per_url_similarity:")
    for url, sim in resp["per_url_similarity"].items():
        print(f"    {url} -> {sim:.3f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Phish-Guard Verifier CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ch = sub.add_parser("create-challenge", help="challenge 생성")
    p_ch.add_argument("urls", nargs="+", help="테스트할 URL 목록")
    p_ch.add_argument("--threshold", type=float, default=0.8)
    p_ch.add_argument("--expires", type=int, default=300, help="만료까지 초")

    p_v = sub.add_parser("verdict", help="challenge 결과 조회")
    p_v.add_argument("challenge_id")
    p_v.add_argument("client_id")

    args = parser.parse_args()

    if args.cmd == "create-challenge":
        create_challenge(args.urls, args.threshold, args.expires)
    elif args.cmd == "verdict":
        get_verdict(args.challenge_id, args.client_id)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
