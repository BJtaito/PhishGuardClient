# shared/score.py
from typing import Dict, Any, List
import re
from urllib.parse import urlparse

# -----------------------------
# Helpers
# -----------------------------
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""

def _is_ip_host(host: str) -> bool:
    return bool(IPV4_RE.match(host or ""))

# -----------------------------
# Scorer
# -----------------------------
def score(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Rule-based scorer for phishing suspicion.
    Input: canonicalized Evidence dict (see shared/evidence.py)
    Output: {
      "risk_score": int(0-100),
      "label": "benign|suspicious|phishing",
      "reasons": [...],
      "debug": {...}
    }
    """
    score_val = 0
    reasons: List[Dict[str, Any]] = []
    ev = evidence or {}

    final_url = (ev.get("final_url") or "").lower()
    is_https = final_url.startswith("https://")
    is_http  = final_url.startswith("http://")

    # 1) HTTPS check (final URL)
    if is_http:
        score_val += 12
        reasons.append({"feature": "http_no_tls", "score": 12})

    # (Optional) Final still over HTTP → small extra bump
    if is_http:
        score_val += 6
        reasons.append({"feature": "final_over_http", "score": 6})

    # 2) Redirect depth
    chain = ev.get("redirect_chain", []) or []
    depth = len(chain)
    if depth >= 3:
        add = min(10, 3 + (depth - 2) * 2)
        score_val += add
        reasons.append({"feature": "deep_redirect_chain", "score": add, "detail": depth})

    # 2-b) Redirect chain analysis: raw IP hops & multi-host chain
    if chain:
        hosts = [_host_of(r.get("url", "")) for r in chain]
        ip_hops = sum(1 for h in hosts if _is_ip_host(h))
        distinct_hosts = len(set([h for h in hosts if h]))

        # Raw IP present in chain → suspicious (HTTP hijack/captive portal/forged hop)
        if ip_hops >= 1:
            add = 15 if ip_hops >= 2 else 10
            score_val += add
            reasons.append({"feature": "raw_ip_in_chain", "score": add, "detail": ip_hops})

        # Multiple distinct hosts across the chain → light suspicion
        if distinct_hosts >= 3:
            score_val += 6
            reasons.append({"feature": "multi_host_chain", "score": 6, "detail": distinct_hosts})

    # 3) POST with PII indicator (from network_posts sampling)
    if any(p.get("pii_hits") for p in (ev.get("network_posts") or [])):
        score_val += 25
        reasons.append({"feature": "pii_post_detected", "score": 25})

    # 4) External form action(s)
    pf = ev.get("page_findings", {}) or {}
    if pf.get("external_form_actions", 0) > 0:
        add = 18
        score_val += add
        reasons.append({
            "feature": "form_action_external",
            "score": add,
            "detail": (pf.get("form_samples", []) or [])[:3]
        })

    # 5) Favicon mismatch
    if pf.get("favicon_mismatch"):
        score_val += 8
        reasons.append({
            "feature": "favicon_mismatch",
            "score": 8,
            "detail": pf.get("favicon_mismatch")
        })

    # 6) TLS leaf fingerprint absence → **HTTPS일 때만** 적용
    leaf_fp = ((ev.get("tls") or {}).get("leaf_fingerprint") or "").strip()
    if is_https and not leaf_fp:
        score_val += 6
        reasons.append({"feature": "no_tls_fingerprint", "score": 6})

    # 최종 라벨
    label = "benign"
    if score_val >= 75:
        label = "phishing"
    elif score_val >= 50:
        label = "suspicious"

    # 디버그 정보 (스코어 튜닝용)
    debug = {
        "final_scheme": "https" if is_https else ("http" if is_http else ""),
        "redirect_depth": depth,
        "has_tls_fp": bool(leaf_fp),
        "external_form_actions": pf.get("external_form_actions", 0),
        "network_posts": len(ev.get("network_posts", []) or []),
    }

    return {
        "risk_score": min(100, max(0, int(score_val))),
        "label": label,
        "reasons": reasons,
        "debug": debug,
    }