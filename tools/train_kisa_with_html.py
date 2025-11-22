# tools/train_kisa_with_html.py
# -*- coding: utf-8 -*-
import os, csv, time, asyncio, re
import datetime as dt
from urllib.parse import urlparse
import httpx
from analyzer import ml_detector as M

# ----- 설정 -----
TIMEOUT = float(os.getenv("KISA_FETCH_TIMEOUT", "6.0"))
MAX_REDIRECTS = 6
CONCURRENCY = int(os.getenv("KISA_CONCURRENCY", "6"))
SLEEP_BETWEEN = float(os.getenv("KISA_SLEEP_BETWEEN", "0.05"))  # 과도한 속도 방지
USER_AGENT = os.getenv("KISA_UA", "PhishGuardTrainer/1.0 (+httpx)")
FOLLOW_META_REFRESH = False  # 간단화를 위해 기본 off

# 차단/인터스티셜 페이지(예시) — 이런 페이지면 HTML은 기록하되 '차단 안내'일 수 있음
INTERSTITIAL_HINTS = [
    "경고: 이 링크는 안전하지 않을 수 있습니다",  # X(Twitter) 경고
    "attention required", "checking your browser before", "ddos protection by cloudflare",
    "사이트에 연결할 수 없음", "not found", "404", "410 gone"
]

def parse_ts_ymd(s: str):
    # 'YYYY-MM-DD' or 'YYYY/MM/DD' 등 대응
    if not s: return None
    s = s.strip()
    for fmt in ("%Y-%m-%d","%Y/%m/%d","%Y.%m.%d","%Y-%m","%Y/%m","%Y","%Y.%m"):
        try:
            return dt.datetime.strptime(s, fmt).timestamp()
        except:
            pass
    try:
        return dt.datetime.fromisoformat(s.replace("Z","")).timestamp()
    except:
        return None

def ensure_scheme(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    # 스킴 없으면 http 우선
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        return "http://" + u
    return u

async def fetch_html(client: httpx.AsyncClient, url: str) -> str:
    try:
        r = await client.get(url, timeout=TIMEOUT, follow_redirects=True)
        ct = (r.headers.get("content-type") or "").lower()
        # HTML만 저장
        if ("text/html" in ct) or ("application/xhtml" in ct) or ("<html" in (r.text or "")[:1024].lower()):
            return r.text or ""
        return ""
    except Exception:
        return ""

def looks_interstitial(html: str) -> bool:
    low = (html or "").lower()
    return any(h in low for h in INTERSTITIAL_HINTS)

async def process_row(
    sem: asyncio.Semaphore,
    client: httpx.AsyncClient,
    row,
    idx: int,
    total: int,
    start_ts: float,
):
    async with sem:
        url_raw = (row.get("홈페이지주소") or row.get("URL") or row.get("url") or "").strip()
        date_raw = (row.get("날짜") or row.get("date") or row.get("DATE") or "").strip()
        if not url_raw:
            return False

        url = ensure_scheme(url_raw)
        ts = parse_ts_ymd(date_raw) or time.time()

        html = await fetch_html(client, url)

        # 학습: 피싱 라벨 = -1
        # HTML이 없어도 URL 모델은 학습됨. HTML이 있으면 HTML채널도 함께 online-fit.
        M.feedback(url, label=-1, ts=ts, html=html if html else None)

        # 진행 로그 (200개마다)
        if (idx % 200) == 0:
            elapsed = time.time() - start_ts
            speed = idx / elapsed if elapsed > 0 else 0.0  # rows/sec
            pct = (idx / total) * 100 if total > 0 else 0.0
            eta_sec = (total - idx) / speed if speed > 0 else 0.0

            print(
                f"[{idx}/{total}] {pct:5.1f}%  "
                f"elapsed={elapsed/60:5.1f}m  "
                f"speed={speed:6.2f} rows/s  "
                f"eta~{eta_sec/60:5.1f}m  "
                f"url={url} "
                f"html={'Y' if html else 'N'} "
                f"interstitial={'Y' if looks_interstitial(html) else 'N'}",
                flush=True,
            )

        await asyncio.sleep(SLEEP_BETWEEN)
        return True


async def train_from_csv(path: str):
    # CSV 읽기
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore", newline="") as f:
            r = csv.DictReader(f)
            rows = list(r)
    except Exception as e:
        print(f"[ERR] read csv fail: {path} — {e}", flush=True)
        return

    total = len(rows)
    print(f"[csv] {path} rows={total}", flush=True)

    sem = asyncio.Semaphore(CONCURRENCY)
    start_ts = time.time()  # ⬅️ 이 파일에 대한 학습 시작 시각

    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        ok = 0
        tasks = []
        for i, row in enumerate(rows, 1):
            # total, start_ts를 같이 넘겨줌
            tasks.append(asyncio.create_task(
                process_row(sem, client, row, i, total, start_ts)
            ))
        for t in asyncio.as_completed(tasks):
            try:
                if await t:
                    ok += 1
            except Exception as e:
                print(f"[ERR] worker: {e}", flush=True)

    # 주기 유지보수 학습(윈도우+에이징)
    print("[maint] beat...", flush=True)
    print(M.maint_beat(), flush=True)
    print(M.status(), flush=True)


def main(root: str):
    # 폴더 내 *.csv 재귀 처리
    targets = []
    if os.path.isdir(root):
        for dirpath, _, files in os.walk(root):
            for fn in files:
                if fn.lower().endswith(".csv"):
                    targets.append(os.path.join(dirpath, fn))
    else:
        targets = [root]

    print(f"[start] files={len(targets)}", flush=True)
    t0 = time.time()
    for i, fp in enumerate(sorted(targets), 1):
        print(f"[{i}/{len(targets)}] {fp}", flush=True)
        asyncio.run(train_from_csv(fp))
    print(f"[done] elapsed={time.time()-t0:.2f}s", flush=True)

if __name__ == "__main__":
    import sys
    root = sys.argv[1] if len(sys.argv) > 1 else r"D:\cap\feeds\kisa"
    main(root)
