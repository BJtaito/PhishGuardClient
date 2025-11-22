# tools/import_feed.py
import argparse, asyncio, csv, glob, os, re, sys, time
from urllib.parse import urlparse
import httpx

URL_COL_GUESS = ["url", "uri", "phish_url", "phish", "link", "target_url", "domain"]

def refang(s: str) -> str:
    if not s: return s
    s = s.strip()
    # defang 복원: hxxp, [.] 등
    s = re.sub(r'^\s*hxxp(s?)://', r'http\1://', s, flags=re.I)
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    s = s.replace("hxxps://", "https://").replace("hxxp://", "http://")
    s = s.replace(" ", "")
    return s

def normalize_url(u: str) -> str | None:
    if not u: return None
    u = refang(u)
    # 도메인만 있으면 스킴 부여
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', u):
        # 공백/따옴표 제거
        u = u.strip().strip('"').strip("'")
        # 도메인처럼 보이면 http:// 부여
        if re.match(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', u):
            u = "http://" + u
        else:
            # 이상한 조각은 스킵
            return None
    # 너무 긴 것 / 스킴만 있는 것 제외
    if len(u) > 2048: return None
    try:
        p = urlparse(u)
        if not p.hostname:
            return None
    except Exception:
        return None
    return u

def guess_url_col(headers: list[str]) -> str | None:
    lowered = [h.lower() for h in headers]
    for cand in URL_COL_GUESS:
        if cand in lowered:
            return headers[lowered.index(cand)]
    return None

async def post_feedback(client: httpx.AsyncClient, base_url: str, api_key: str, url: str, label: int, source: str):
    payload = {"url": url, "label": label, "meta": {"source": source}}
    headers = {"X-API-Key": api_key}
    r = await client.post(f"{base_url.rstrip('/')}/ml/feedback", json=payload, headers=headers, timeout=30.0)
    r.raise_for_status()

async def worker(name, q, base_url, api_key, label, stats):
    async with httpx.AsyncClient() as client:
        while True:
            item = await q.get()
            if item is None:
                q.task_done()
                return
            url, source = item
            try:
                await post_feedback(client, base_url, api_key, url, label, source)
                stats["ok"] += 1
            except Exception as e:
                stats["fail"] += 1
            finally:
                q.task_done()

async def run(args):
    files = []
    for pat in args.glob:
        files.extend(glob.glob(pat, recursive=True))
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        print("No files matched.", file=sys.stderr)
        return 2

    label_map = {"phish": -1, "benign": 1, "unknown": 0}
    label = label_map[args.label]

    seen = set()
    q = asyncio.Queue()
    stats = {"ok": 0, "fail": 0, "skipped": 0, "enqueued": 0}

    # 파싱
    for f in files:
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                # CSV 시도
                sniff = fh.read(4096)
                fh.seek(0)
                dialect = None
                try:
                    dialect = csv.Sniffer().sniff(sniff)
                except Exception:
                    pass
                if dialect:
                    reader = csv.DictReader(fh, dialect=dialect)
                    headers = reader.fieldnames or []
                    col = args.column or guess_url_col(headers) or headers[0]
                    for row in reader:
                        raw = str(row.get(col, "")).strip()
                        u = normalize_url(raw)
                        if not u:
                            stats["skipped"] += 1
                            continue
                        if u in seen:
                            continue
                        seen.add(u)
                        await q.put((u, os.path.basename(f)))
                        stats["enqueued"] += 1
                else:
                    # 텍스트 라인 모드
                    for line in fh:
                        u = normalize_url(line.strip())
                        if not u:
                            stats["skipped"] += 1
                            continue
                        if u in seen:
                            continue
                        seen.add(u)
                        await q.put((u, os.path.basename(f)))
                        stats["enqueued"] += 1
        except Exception:
            continue

    # 워커
    workers = []
    for i in range(args.concurrency):
        workers.append(asyncio.create_task(worker(f"W{i}", q, args.base_url, args.api_key, label, stats)))
    # 종료 신호
    for _ in workers:
        await q.put(None)

    t0 = time.time()
    await q.join()
    for w in workers:
        await w

    took = time.time() - t0
    print(f"Files: {len(files)}, unique URLs: {len(seen)}")
    print(f"Queued: {stats['enqueued']}  OK: {stats['ok']}  Fail: {stats['fail']}  Skipped: {stats['skipped']}")
    print(f"Took: {took:.1f}s")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000", help="Phish-Guard server base URL")
    ap.add_argument("--api-key", required=True, help="X-API-Key value")
    ap.add_argument("--label", choices=["phish","benign","unknown"], default="phish")
    ap.add_argument("--glob", nargs="+", required=True, help="File glob(s), e.g. D:\\feeds\\**\\*.csv")
    ap.add_argument("--column", help="Column name containing URLs (if not provided, auto-guess)")
    ap.add_argument("--concurrency", type=int, default=20)
    args = ap.parse_args()
    return asyncio.run(run(args))

if __name__ == "__main__":
    raise SystemExit(main())
