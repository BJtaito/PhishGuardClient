
from pydantic import BaseModel, Field
from typing import List, Dict, Any

class Evidence(BaseModel):
    start_url: str = Field(..., description="User-supplied URL")
    final_url: str
    final_ip: List[str] = []
    redirect_chain: List[Dict[str, Any]] = []
    html_sha256: str
    tls: Dict[str, Any] = {}
    network_posts: List[Dict[str, Any]] = []
    page_findings: Dict[str, Any] = {}
    timestamp: str
    analyzer_version: str = "an1"

def canonicalize(ev: "Evidence") -> Dict[str, Any]:
    """Return a dict with stable ordering & normalized types for signing."""
    obj = ev.model_dump()
    # sort keys within redirect_chain items
    norm_chain = []
    for r in obj.get("redirect_chain", []):
        norm_chain.append({
            "url": str(r.get("url","")),
            "status": int(r.get("status", 0)),
            "note": str(r.get("note","")),
        })
    obj["redirect_chain"] = norm_chain
    # network_posts trimming
    norm_posts = []
    for p in obj.get("network_posts", []):
        norm_posts.append({
            "method": str(p.get("method","")),
            "dst_domain": str(p.get("dst_domain","")),
            "path": str(p.get("path","")),
            "content_type": str(p.get("content_type","")),
            "pii_hits": bool(p.get("pii_hits", False)),
        })
    obj["network_posts"] = norm_posts
    return obj
