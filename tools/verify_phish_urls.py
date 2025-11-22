# tools/verify_phish_urls.py  (soft-404 / challenge / parked / suspended / denied 분류)
import os, csv, glob, io, time, argparse, urllib.request, urllib.error, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

UA = "PhishGuard/0.6 (+verify-urls)"

SOFT404_PATTERNS = [
    r"\b404\b", "page not found", "not found", "no encontrado", "non trovato",
    "페이지를 찾을 수", "찾을 수 없습니다", "不存在", "未找到", "找不到", "ページが見つかりません",
]
CHALLENGE_PATTERNS = [
    "attention required", "just a moment", "checking your browser", "ddos protection",
    "are you a robot", "captcha", "cf-challenge", "cloudflare",
]
PARKED_PATTERNS = [
    "domain parking", "parkingcrew", "sedo", "domain for sale", "buy this domain",
    "this domain may be for sale", "namebright", "godaddy domain parking",
]
SUSPENDED_PATTERNS = [
    "account suspended", "website suspended", "site suspended", "this site has been suspended",
]
DENIED_PATTERNS = [
    "access denied", "forbidden", "you don't have permission", "error 1020", "error 1015",
    "blocked by", "your ip has been blocked",
]
MAINT_PATTERNS = [
    "under maintenance", "maintenance", "we'll be back soon", "service unavailable",
]

def _contains_any(text_lower: str, patterns) -> bool:
    for p in patterns:
        if isinstance(p, str):
            if p in text_lower:
                return True
        else:  # regex
            if re.search(p, text_lower):
                return True
    return False

def classify_html(html: str, code: int, headers: dict) -> (str, str):
    """
    Returns: (kind, note)
      kind in {"normal","soft404","challenge","parked","suspended","denied","maintenance","unknown"}
    """
    if code != 200:
        return ("denied" if code in (401,403) else "unknown", f"http_{code}")

    if not html:
        return ("unknown", "empty_html")

    low = html.lower()
    # 매우 짧고 404 단어만 있는 경우
    if len(low) < 2000 and _contains_any(low, SOFT404_PATTERNS):
        return ("soft404", "200_soft404_like")
    if _contains_any(low, CHALLENGE_PATTERNS):
        return ("challenge", "challenge_page")
    if _contains_any(low, PARKED_PATTERNS):
        return ("parked", "domain_parking")
    if _contains_any(low, SUSPENDED_PATTERNS):
        return ("suspended", "site_suspended")
    if _contains_any(low, DENIED_PATTERNS):
        return ("denied", "access_denied_like")
    if _contains_any(low, MAINT_PATTERNS):
        return ("maintenance", "maintenance_page")

    # 헤더 힌트(서버/로봇)
    sv = (headers.get("server","") or "").lower()
    robots = (headers.get("x-robots-tag","") or "").lower()
    if "cloudflare" in sv and "attention required" in low:
        return ("challenge", "cloudflare_attention_required")
    if "noindex" in robots and _contains_any(low, SOFT404_PATTERNS):
        return ("soft404", "robots_noindex_soft404")

    return ("normal", "ok")

def fetch_html(u: str, timeout: int, max_bytes: int):
    try:
        p = urlparse(u)
        if p.scheme not in ("http","https"):
            return (u, 0, "bad_scheme", None, "unknown")
        req = urllib.request.Request(u, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code = getattr(r, "status", 200)
            ct = (r.headers.get("content-type") or "").lower()
            headers = {k.lower(): v for k,v in r.headers.items()}
            if code != 200:
                kind, note = classify_html("", code, headers)
                return (u, code, note, None, kind)
            if ("text/html" not in ct) and ("application/xhtml" not in ct):
                return (u, code, "non_html", None, "unknown")
            data = r.read(max_bytes)
            html = data.decode("utf-8","ignore")
            kind, note = classify_html(html, code, headers)
            return (u, code, note, html, kind)
    except urllib.error.HTTPError as e:
        return (u, e.code, f"http_{e.code}", None, "unknown")
    except Exception as e:
        return (u, 0, "error", None, "unknown")

def iter_urls(root: str):
    files = glob.glob(os.path.join(root, "**", "*.csv"), recursive=True)
    for fp in files:
        with open(fp, "r", encoding="utf-8", errors="ignore", newline="") as f:
            r = csv.DictReader(f)
            for row in r:
                u = (row.get("url") or row.get("URL") or row.get("Url") or "").strip()
                if not u and row:
                    try: u = list(row.values())[0].strip()
                    except: pass
                if u: yield u

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv-root", required=True)
    ap.add_argument("--out-dir", default=r"D:\cap\tools\out")
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--timeout", type=int, default=6)
    ap.add_argument("--max-bytes", type=int, default=120000)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    alive_fp = os.path.join(args.out_dir, "phish_alive_html.csv")
    dead_fp  = os.path.join(args.out_dir, "phish_dead.csv")

    seen, urls = set(), []
    for u in iter_urls(args.csv_root):
        if u in seen: continue
        seen.add(u); urls.append(u)
        if args.limit and len(urls) >= args.limit:
            break

    print(f"[verify] total unique={len(urls)}")
    ok = bad = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex, \
         open(alive_fp,"w",newline="",encoding="utf-8") as fa, \
         open(dead_fp,"w",newline="",encoding="utf-8") as fd:
        aw = csv.writer(fa); dw = csv.writer(fd)
        aw.writerow(["url","code","kind","note","html"])
        dw.writerow(["url","code","kind","note"])
        futs = {ex.submit(fetch_html, u, args.timeout, args.max_bytes): u for u in urls}
        for i, fut in enumerate(as_completed(futs), 1):
            u, code, note, html, kind = fut.result()
            # kind 분류가 normal일 때만 alive에 HTML 포함 저장
            if code == 200 and kind == "normal" and html:
                aw.writerow([u, code, kind, note, html])
                ok += 1
            else:
                dw.writerow([u, code, kind, note])
                bad += 1
            if i % 200 == 0:
                print(f"  .. {i}/{len(urls)} alive={ok} dead={bad}")

    print(f"[verify] done: alive={ok} dead={bad} elapsed={time.time()-t0:.1f}s")
    print(f"[verify] outputs:\n  {alive_fp}\n  {dead_fp}")

if __name__ == "__main__":
    main()
