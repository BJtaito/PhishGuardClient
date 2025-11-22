# D:\cap\tools\train_with_html.py
import os, csv, glob, time, io, sys
import datetime as dt
from typing import Optional
import httpx

# 우리 프로젝트 ML 모듈
from analyzer import ml_detector as M

UA = os.getenv("PG_FETCH_UA", "PhishGuard/0.6 (+html-trainer)")
TIMEOUT = float(os.getenv("PG_FETCH_TIMEOUT", "5"))
HTML_MAX = int(os.getenv("PG_ML_HTML_MAX_BYTES", "50000"))

def parse_ts(s: Optional[str]) -> Optional[float]:
    if not s: return None
    s = s.strip()
    fmts = [
        "%Y-%m-%d","%Y/%m/%d","%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S","%Y-%m","%Y/%m","%Y"
    ]
    for f in fmts:
        try:
            return dt.datetime.strptime(s, f).timestamp()
        except: pass
    try:
        return dt.datetime.fromisoformat(s.replace("Z","")).timestamp()
    except:
        return None

def is_html_response(resp_text: str, content_type: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct or "application/xhtml" in ct:
        return True
    head = (resp_text or "")[:1024].lower()
    return "<html" in head

def trim_html(h: str) -> str:
    if not h: return ""
    if len(h) <= HTML_MAX: return h
    keep = HTML_MAX // 2
    return h[:keep] + "\n<!-- [ml-truncated: head+tail] -->\n" + h[-keep:]

def fetch_html(url: str) -> str:
    try:
        with httpx.Client(follow_redirects=True, timeout=TIMEOUT, headers={"User-Agent": UA}) as client:
            r = client.get(url)
            text = r.text or ""
            if is_html_response(text, r.headers.get("content-type","")):
                return trim_html(text)
    except Exception:
        pass
    return ""  # 실패 시 HTML 없이도 진행 가능(하지만 HTML 학습은 안 됨)

def process_url(url: str, label: int, ts: Optional[float] = None, sleep_ms: int = 120):
    html = fetch_html(url)
    M.feedback(url, label=label, ts=ts, html=html if html else None)
    # 너무 빠르게 때리지 않도록 약간 쉬기
    if sleep_ms > 0:
        time.sleep(sleep_ms/1000.0)

def train_csv_root(root: str, limit_per_file: int = 0):
    files = glob.glob(os.path.join(root, "**", "*.csv"), recursive=True)
    total = 0; bad_files = 0
    t0 = time.time()
    print(f"[train-csv] files={len(files)} root={root}", flush=True)

    for idx, fp in enumerate(files, 1):
        start = time.time()
        processed = 0
        print(f"[{idx}/{len(files)}] file: {fp}", flush=True)
        try:
            with io.open(fp, "r", encoding="utf-8", errors="ignore", newline="") as f:
                r = csv.DictReader(f)
                rows_iter = r
                for row in rows_iter:
                    url = (row.get("url") or row.get("URL") or row.get("Url") or "").strip()
                    if not url and row:
                        try:
                            url = list(row.values())[0].strip()
                        except Exception:
                            continue
                    if not url:
                        continue
                    ts = parse_ts(row.get("date") or row.get("DATE") or row.get("timestamp") or "")
                    process_url(url, label=-1, ts=ts)  # -1 = 피싱
                    processed += 1; total += 1
                    if limit_per_file and processed >= limit_per_file:
                        break
                    # 중간 속도 로그
                    if (processed % 500) == 0:
                        dt_s = time.time() - start
                        rate = processed/dt_s if dt_s>0 else 0.0
                        print(f"  ... {processed} rows ({rate:.1f} r/s) {os.path.basename(fp)}", flush=True)
        except Exception as e:
            bad_files += 1
            print(f"[train-csv] ERROR {fp}: {e}", flush=True)
        finally:
            dt_s = time.time() - start
            print(f"[train-csv] done: {processed} rows in {dt_s:.2f}s", flush=True)

        # 중간 유지보수(선택) — 너무 자주 돌리면 느려져서 주석
        # print("[maint] beat...", flush=True)
        # print(M.maint_beat(), flush=True)

    print(f"[train-csv] total_rows={total} bad_files={bad_files} elapsed={time.time()-t0:.1f}s", flush=True)

def train_benign_txt(txt_path: str):
    if not os.path.exists(txt_path):
        print(f"[benign] file not found: {txt_path}", flush=True)
        return
    print(f"[benign] start: {txt_path}", flush=True)
    cnt = 0
    with io.open(txt_path, "r", encoding="utf-8") as f:
        for line in f:
            u = line.strip()
            if not u or u.startswith("#"): continue
            process_url(u, label=1, ts=None)  # 1 = 정상
            cnt += 1
    print(f"[benign] done: {cnt} urls", flush=True)

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv-root", help="CSV 루트 폴더 (재귀 탐색)")
    ap.add_argument("--benign", help="정상 URL 목록 파일(txt; 줄바꿈 구분; # 주석)")
    ap.add_argument("--limit-per-file", type=int, default=0, help="CSV 파일당 최대 처리 수(0=무제한)")
    args = ap.parse_args()

    if args.benign:
        train_benign_txt(args.benign)

    if args.csv_root:
        train_csv_root(args.csv_root, limit_per_file=args.limit_per_file)

    print("[maint] beat...", flush=True)
    print(M.maint_beat(), flush=True)
    print(M.status(), flush=True)

if __name__ == "__main__":
    main()
