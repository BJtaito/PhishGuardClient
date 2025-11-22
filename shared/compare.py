# shared/compare.py
from typing import Dict, Any, Set
from urllib.parse import urlparse

def _host(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""

def _scheme(u: str) -> str:
    try:
        return (urlparse(u).scheme or "").lower()
    except Exception:
        return ""

def _chain_hosts(ev: Dict[str, Any]) -> Set[str]:
    hs: Set[str] = set()
    for r in (ev.get("redirect_chain") or []):
        h = _host(r.get("url", ""))
        if h:
            hs.add(h)
    # 마지막 final도 포함
    fh = _host(ev.get("final_url", ""))
    if fh:
        hs.add(fh)
    return hs

def compare(client_ev: Dict[str, Any], server_ev: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare client vs server evidences and emit alignment signals.
    Adds scheme hints so the caller can decide whether TLS mismatch should apply.
    """
    out: Dict[str, Any] = {
        "final_url_match": False,
        "final_host_match": False,
        "tls_leaf_match": False,
        "redirect_hosts_match": False,
        "client_scheme": "",
        "server_scheme": "",
        "both_http_no_tls": False,   # true이면 TLS 불일치 가중치 비적용 추천
        "notes": []
    }

    cu = client_ev.get("final_url", "") or ""
    su = server_ev.get("final_url", "") or ""
    out["final_url_match"] = (cu.split("?", 1)[0] == su.split("?", 1)[0])
    out["final_host_match"] = (_host(cu) == _host(su))

    cl = (client_ev.get("tls", {}) or {}).get("leaf_fingerprint", "") or ""
    sl = (server_ev.get("tls", {}) or {}).get("leaf_fingerprint", "") or ""
    out["tls_leaf_match"] = (cl != "" and sl != "" and cl == sl)

    ch = _chain_hosts(client_ev)
    sh = _chain_hosts(server_ev)
    out["redirect_hosts_match"] = (ch == sh)

    # 스킴 힌트
    out["client_scheme"] = _scheme(cu)
    out["server_scheme"] = _scheme(su)
    out["both_http_no_tls"] = (
        out["client_scheme"] == "http"
        and out["server_scheme"] == "http"
        and cl == "" and sl == ""
    )

    # 메모/노트
    if not out["final_host_match"]:
        out["notes"].append("final host differs (possible pharm/MITM/geo split)")
    if cl and sl and cl != sl:
        out["notes"].append("TLS leaf fingerprint differs")
    if ch != sh:
        out["notes"].append("redirect host set differs")

    return out