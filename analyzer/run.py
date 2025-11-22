# analyzer/run.py
import asyncio
import hashlib
import json
import re
import socket
import ssl
import sys
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from playwright.async_api import TimeoutError as PWTimeoutError, Error as PWError

from shared.evidence import Evidence, canonicalize
from shared.score import score as score_fn

# -----------------------------
# Config / Regex
# -----------------------------
PII_REGEX = re.compile(
    r"(?:\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\b\d{3}-\d{3,4}-\d{4}\b)",
    re.I,
)

# -----------------------------
# Helpers
# -----------------------------
def domain_from(url: str) -> str:
    try:
        u = urlparse(url)
        return (u.hostname or "").lower()
    except Exception:
        return ""


async def tls_fingerprint(host: str, port: int = 443) -> str:
    """Return SHA-256 fingerprint of the leaf cert for host, or '' on failure."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(True)
                return hashlib.sha256(der).hexdigest()
    except Exception:
        return ""


# ---- timeout/type sanitation & debug helpers --------------------------------
_FLOAT_CLEAN_RE = re.compile(r"[^0-9.\-+]")

def _as_float(val) -> Optional[float]:
    """
    Coerce any input to float or None.
    Accepts strings like '30000', '30_000', '30s', '"5000"'.
    """
    try:
        if val is None:
            return None
        if isinstance(val, (int, float)):
            return float(val)
        s = str(val).strip()
        s = _FLOAT_CLEAN_RE.sub("", s)
        return float(s) if s else None
    except Exception:
        return None

def _type_name(x) -> str:
    try:
        return type(x).__name__
    except Exception:
        return "unknown"


# -----------------------------
# Core
# -----------------------------
async def analyze(url: str, nav_timeout_ms: int = 30000) -> Dict[str, Any]:
    """
    Open URL headlessly, collect evidence (redirect chain, HTML hash, TLS, POST hints),
    compute a rule-based score, and return a JSON-like dict.
    """
    redirects: List[Dict[str, Any]] = []
    posts: List[Dict[str, Any]] = []
    page_findings: Dict[str, Any] = {"external_form_actions": 0, "form_samples": []}

    # Normalize target
    target = url if re.match(r"^https?://", url, re.I) else "http://" + url
    nav_error: Optional[str] = None

    # --- Debug bucket (returned in out["debug"]) ---
    dbg: Dict[str, Any] = {
        "timeouts": {
            "nav_timeout_ms_input": nav_timeout_ms,
            "nav_timeout_ms_input_type": _type_name(nav_timeout_ms),
        },
        "goto_calls": [],
        "wait_calls": [],
        "notes": [],
    }

    # Sanitize timeout (ms) and also compute float for Playwright
    nav_timeout_ms_clean = _as_float(nav_timeout_ms)
    dbg["timeouts"]["nav_timeout_ms_clean"] = nav_timeout_ms_clean
    dbg["timeouts"]["nav_timeout_ms_clean_type"] = _type_name(nav_timeout_ms_clean)

    # Playwright timeouts accept float milliseconds. If None/0 => treat as unlimited here.
    default_timeout = float(nav_timeout_ms_clean) if (nav_timeout_ms_clean and nav_timeout_ms_clean > 0) else 0.0

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-gpu", "--no-sandbox"],
        )
        page = await browser.new_page()

        # Set page default timeouts (0 means unlimited)
        try:
            page.set_default_navigation_timeout(default_timeout)
            page.set_default_timeout(default_timeout)
        except Exception as e:
            dbg["notes"].append(f"set_default_timeout_error:{e!s}")

        # Cancel any download immediately
        async def on_download(d):
            try:
                await d.cancel()
            except Exception:
                pass
        page.on("download", on_download)

        # Capture outbound POST-like requests (basic sampling)
        async def on_request(req):
            if req.method in ("POST", "PUT", "PATCH"):
                try:
                    post_data = req.post_data or ""
                except Exception:
                    post_data = ""
                pii_hits = bool(PII_REGEX.search(post_data or ""))
                u = urlparse(req.url)
                posts.append(
                    {
                        "method": req.method,
                        "dst_domain": (u.hostname or "")[:255],
                        "path": (u.path or "")[:128],
                        "content_type": (req.headers.get("content-type", "")[:64]),
                        "pii_hits": pii_hits,
                    }
                )
        page.on("request", on_request)

        # Build redirect chain from main-document responses
        seen_doc = set()
        async def on_response(resp):
            try:
                if resp.request.resource_type == "document":
                    key = (resp.url, resp.status)
                    if key not in seen_doc:
                        seen_doc.add(key)
                        redirects.append({"url": resp.url, "status": int(resp.status), "note": ""})
            except Exception:
                pass
        page.on("response", on_response)

        # Helper: goto with sanitized timeout in kwargs only if present
        async def _goto(wait_until: str, url_: str):
            kwargs: Dict[str, Any] = {"wait_until": wait_until}
            to_val = default_timeout if default_timeout > 0 else None
            if to_val is not None:
                kwargs["timeout"] = float(to_val)
            dbg["goto_calls"].append({
                "wait_until": wait_until,
                "timeout": kwargs.get("timeout"),
                "timeout_type": _type_name(kwargs.get("timeout")),
            })
            return await page.goto(url_, **kwargs)

        # Navigation (robust)
        try:
            await _goto("commit", target)
            # Try to wait for DOMContentLoaded, but don't fail if slow
            try:
                half = float(default_timeout / 2.0) if default_timeout > 0 else None
                if half and half > 0:
                    dbg["wait_calls"].append({
                        "state": "domcontentloaded",
                        "timeout": half,
                        "timeout_type": _type_name(half),
                    })
                    await page.wait_for_load_state("domcontentloaded", timeout=half)
                else:
                    # no timeout argument -> unlimited wait? We’ll skip long wait in unlimited mode
                    dbg["wait_calls"].append({
                        "state": "domcontentloaded",
                        "timeout": None,
                        "timeout_type": "NoneType",
                        "note": "skipped_timeout_arg",
                    })
            except PWTimeoutError:
                pass
        except (PWTimeoutError, PWError) as e:
            nav_error = f"{e!s}"

        # If navigation failed hard, still proceed with minimal evidence
        if nav_error:
            final_url = target
            html = ""
        else:
            final_url = page.url
            try:
                html = await page.content()
            except Exception:
                html = ""

        html_sha256 = hashlib.sha256((html or "").encode("utf-8", "ignore")).hexdigest()

        # Parse DOM for findings (forms, favicon)
        page_domain = domain_from(final_url)
        if html:
            soup = BeautifulSoup(html, "lxml")

            # External form actions
            for f in soup.find_all("form"):
                act = (f.get("action") or "").strip()
                if not act:
                    continue
                if re.match(r"^https?://", act, re.I):
                    adomain = domain_from(act)
                    if adomain and adomain != page_domain:
                        page_findings["external_form_actions"] += 1
                        if len(page_findings["form_samples"]) < 5:
                            page_findings["form_samples"].append({"action": act})

            # Favicon mismatch
            icon = soup.find("link", rel=re.compile("icon", re.I))
            if icon and icon.get("href"):
                href = icon["href"]
                if href.startswith("//"):
                    ihost = urlparse("http:" + href).hostname or ""
                elif href.startswith("http"):
                    ihost = urlparse(href).hostname or ""
                else:
                    ihost = page_domain
                if ihost and domain_from("https://" + ihost) != page_domain:
                    page_findings["favicon_mismatch"] = f"{ihost} vs {page_domain}"

        # Resolve final IPs
        ips: List[str] = []
        try:
            if page_domain:
                infos = socket.getaddrinfo(page_domain, None)
                for info in infos:
                    ip = info[4][0]
                    if ip not in ips:
                        ips.append(ip)
        except Exception:
            pass

        # TLS leaf fingerprint for final host (HTTPS only)
        leaf_fp = ""
        if final_url.lower().startswith("https://") and page_domain:
            leaf_fp = await tls_fingerprint(page_domain)

        evidence = Evidence(
            start_url=url,
            final_url=final_url,
            final_ip=ips[:4],
            redirect_chain=redirects[:10],
            html_sha256=html_sha256,
            tls={"leaf_fingerprint": leaf_fp},
            network_posts=posts[:50],
            page_findings=page_findings,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            analyzer_version="an1",
        )

        try:
            await browser.close()
        except Exception:
            pass

    # Canonicalize & score
    ev = Evidence.model_validate(evidence.model_dump())
    ev_can = canonicalize(ev)
    scored = score_fn(ev_can)
    out: Dict[str, Any] = {"evidence": ev_can, **scored}

    # Attach analyzer debug
    out.setdefault("debug", {})["analyzer"] = dbg

    # If we had a navigation error, record it as a soft reason (+5)
    if nav_error:
        out["reasons"].append(
            {"feature": "navigation_error", "score": 5, "detail": nav_error[:200]}
        )
        out["risk_score"] = min(100, int(out["risk_score"]) + 5)

    return out


# -----------------------------
# CLI
# -----------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--out", help="Save JSON to file")
    parser.add_argument(
        "--timeout", default="30000", help="Navigation timeout in ms (int/float/str ok)"
    )
    args = parser.parse_args()

    async def go():
        timeout_ms = _as_float(args.timeout)
        res = await analyze(args.url, nav_timeout_ms=timeout_ms if timeout_ms is not None else 30000)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(res, f, ensure_ascii=False, indent=2)

    asyncio.run(go())
