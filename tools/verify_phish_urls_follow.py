# -*- coding: utf-8 -*-
"""
verify_phish_urls_follow.py
- CSV에서 URL을 읽어 살아있는(열리는) 페이지의 최종 URL/HTML 수집
- x.co/t.co 같은 '경고 인터스티셜'을 만나면 '계속하기' 링크를 따라가 최종 본문까지 수집
- 우선 httpx(정적)로 시도, 필요시 --use-playwright 로 헤드리스 클릭 폴백
출력: phish_alive_html_follow.csv  (url, final_url, http_status, status, note, chain, html)
"""

import os, csv, json, re, asyncio, argparse, time
from urllib.parse import urljoin, urlparse
import httpx

# ---------- 탐지 패턴 ----------
X_WARN_HOSTS = {"x.co", "t.co"}
X_WARN_SNIPPETS = [
    "경고: 이 링크는 안전하지 않을 수 있습니다",
    "potentially spammy or unsafe",
    "URL policy", "help.x.com/en/safety-and-security",
    "이 경고를 무시하고", "계속하기", "continue anyway", "ignore this warning"
]

HTML_MAX = int(os.getenv("PG_ML_HTML_MAX_BYTES", "50000"))
UA = os.getenv("PG_FETCH_UA", "PhishGuard/0.6 (+verify)")

def host_of(u: str) -> str:
    try:
        return urlparse(u).hostname or ""
    except Exception:
        return ""

def looks_like_x_interstitial(url: str, html: str) -> bool:
    h = host_of(url).lower()
    if h not in X_WARN_HOSTS:
        return False
    low = (html or "").lower()
    return any(sn.lower() in low for sn in X_WARN_SNIPPETS)

def extract_continue_url_from_html(html: str, base_url: str) -> str | None:
    """
    가장 단순한 '계속하기/continue' 앵커를 찾아 절대 URL로 반환
    """
    if not html:
        return None
    # 1) '계속하기' / 'continue' 텍스트 링크
    m = re.search(r'<a[^>]+href=[\'"]([^\'"]+)[\'"][^>]*>([^<]{0,60})</a>', html, re.I)
    if m:
        href = m.group(1)
        text = (m.group(2) or "").strip().lower()
        if any(k in text for k in ["계속", "continue", "proceed", "ignore"]):
            return urljoin(base_url, href)

    # 2) 자주 나오는 id/class 힌트로 한 번 더
    m2 = re.findall(r'<a[^>]+href=[\'"]([^\'"]+)[\'"][^>]*(id|class)=["\'][^"\']*(continue|unsafe|proceed)[^"\']*["\']', html, re.I)
    if m2:
        return urljoin(base_url, m2[0][0])

    return None

def trim_html(h: str) -> str:
    if not h:
        return ""
    if len(h) <= HTML_MAX:
        return h
    keep = HTML_MAX // 2
    return h[:keep] + "\n<!-- [verify-truncated: head+tail] -->\n" + h[-keep:]

async def fetch_httpx(client: httpx.AsyncClient, url: str, timeout: float) -> tuple[str, int, str, list]:
    chain = []
    try:
        r = await client.get(url, timeout=timeout, follow_redirects=True)
        for hist in r.history:
            try:
                chain.append({"url": str(hist.request.url), "status": hist.status_code})
            except Exception:
                pass
        return (str(r.request.url), r.status_code, r.text or "", chain)
    except Exception as e:
        return (url, 0, f"__ERR__:{e!s}", chain)

async def click_with_playwright(url: str, nav_timeout_ms: int, budget_ms: int) -> tuple[str, int, str, list, str]:
    """
    Playwright로 경고 페이지에서 '계속하기' 클릭 시도.
    반환: (final_url, http_status=0(모름), html, chain, note)
    """
    note = ""
    chain = []
    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        return (url, 0, "", chain, f"pw_import_fail:{e!s}")

    try:
        t0 = time.monotonic()
        def remain_ms():
            if budget_ms <= 0: return None
            used = int((time.monotonic() - t0) * 1000)
            left = max(0, budget_ms - used)
            return left

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            ctx = await browser.new_context(ignore_https_errors=True)
            page = await ctx.new_page()

            to = nav_timeout_ms if nav_timeout_ms>0 else None
            await page.goto(url, timeout=to)
            # '계속하기/continue' 텍스트 클릭 시도
            hit = False
            for sel in ["text=계속하기", "text=continue", "text=proceed", "text=ignore"]:
                try:
                    await page.locator(sel).first.click(timeout=1500)
                    hit = True
                    break
                except Exception:
                    pass
            if not hit:
                # 모든 a 태그 중 텍스트 포함한 것 클릭
                try:
                    anchors = page.locator("a")
                    count = await anchors.count()
                    for i in range(min(count, 40)):
                        t = (await anchors.nth(i).inner_text()).strip().lower()
                        if any(k in t for k in ["계속", "continue", "proceed", "ignore"]):
                            await anchors.nth(i).click(timeout=1500)
                            hit = True
                            break
                except Exception:
                    pass

            if hit:
                # 잠깐 대기
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=2000)
                except Exception:
                    pass
                note = "pw_clicked_continue"
            else:
                note = "pw_continue_not_found"

            final_url = page.url
            html = await page.content()
            await ctx.close()
            await browser.close()
            return (final_url, 0, html, chain, note)
    except Exception as e:
        return (url, 0, "", chain, f"pw_fail:{e!s}")

async def verify_one(url: str, client: httpx.AsyncClient, timeout: float, use_pw: bool, nav_timeout_ms: int, budget_ms: int, max_interstitial_hops: int = 2):
    """
    1) httpx로 페이지 열기
    2) x.co/t.co 경고 인터스티셜이면 '계속하기' 링크 파싱 → httpx로 한 번 더
    3) 그래도 경고면 옵션에 따라 Playwright로 클릭 시도
    """
    status = "ok"
    note = ""
    chain_all = []

    final_url, code, html, chain = await fetch_httpx(client, url, timeout)
    chain_all += chain

    if html.startswith("__ERR__:"):
        return {
            "url": url, "final_url": final_url, "http_status": 0,
            "status": "error", "note": html[8:], "chain": json.dumps(chain_all, ensure_ascii=False),
            "html": ""
        }

    # 인터스티셜 추적 (httpx로 먼저)
    hops = 0
    while hops < max_interstitial_hops and looks_like_x_interstitial(final_url, html):
        nxt = extract_continue_url_from_html(html, final_url)
        if not nxt: break
        status = "interstitial_followed"
        hops += 1
        final_url, code, html, chain = await fetch_httpx(client, nxt, timeout)
        chain_all.append({"url": nxt, "status": code, "via": "continue_link"})

    # 여전히 인터스티셜이면 Playwright 폴백
    if use_pw and looks_like_x_interstitial(final_url, html):
        pw_final, _, pw_html, pw_chain, pw_note = await click_with_playwright(final_url, nav_timeout_ms, budget_ms)
        if pw_html:
            status = "interstitial_pw_followed"
            final_url, html = pw_final, pw_html
            note = pw_note

    out_html = trim_html(html if code != 0 or html else "")
    return {
        "url": url,
        "final_url": final_url,
        "http_status": code,
        "status": status,
        "note": note,
        "chain": json.dumps(chain_all, ensure_ascii=False),
        "html": out_html
    }

async def run(inp_csv: str, out_csv: str, use_pw: bool, timeout: float, concurrency: int, nav_timeout_ms: int, budget_ms: int, limit: int):
    sem = asyncio.Semaphore(concurrency)
    tasks = []

    async with httpx.AsyncClient(headers={"User-Agent": UA}, follow_redirects=True) as client:
        def submit(u):
            async def _job():
                async with sem:
                    return await verify_one(u, client, timeout, use_pw, nav_timeout_ms, budget_ms)
            return asyncio.create_task(_job())

        # 입력 읽기 (url 컬럼 기준, 없으면 첫 컬럼 추정)
        urls = []
        with open(inp_csv, newline='', encoding='utf-8', errors='ignore') as fi:
            r = csv.DictReader(fi)
            for row in r:
                u = (row.get("url") or row.get("final_url") or "").strip()
                if not u and row:
                    try:
                        u = list(row.values())[0].strip()
                    except Exception:
                        pass
                if u:
                    urls.append(u)
                if limit and len(urls) >= limit:
                    break

        # 실행
        for u in urls:
            tasks.append(submit(u))

        # 출력 준비
        cols = ["url","final_url","http_status","status","note","chain","html"]
        with open(out_csv, "w", newline='', encoding="utf-8") as fo:
            w = csv.DictWriter(fo, fieldnames=cols)
            w.writeheader()
            n = 0
            for coro in asyncio.as_completed(tasks):
                rec = await coro
                w.writerow(rec)
                n += 1
                if n % 50 == 0:
                    print(f"[verify] {n}/{len(tasks)} done", flush=True)
        print(f"[verify] done: {len(tasks)} rows → {out_csv}", flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="outp", required=True)
    ap.add_argument("--use-playwright", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--nav-timeout-ms", type=int, default=6000)
    ap.add_argument("--budget-ms", type=int, default=15000)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    asyncio.run(run(
        a.inp, a.outp, bool(a.use_playwright), a.timeout, a.concurrency,
        a.nav_timeout_ms, a.budget_ms, a.limit
    ))

if __name__ == "__main__":
    main()
