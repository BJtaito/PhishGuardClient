import os, csv, glob, time, datetime as dt
from analyzer import ml_detector as M

def parse_ts(s):
    if not s: return None
    for fmt in ("%Y-%m-%d","%Y/%m/%d","%Y-%m-%d %H:%M:%S","%Y/%m/%d %H:%M:%S","%Y-%m","%Y/%m","%Y"):
        try: return dt.datetime.strptime(s.strip(), fmt).timestamp()
        except: pass
    try: return dt.datetime.fromisoformat(s.replace("Z","")).timestamp()
    except: return None

def main(root):
    files = glob.glob(os.path.join(root, "**", "*.csv"), recursive=True)
    total = 0
    bad_files = 0
    t0 = time.time()
    print(f"[train] files={len(files)} root={root}", flush=True)

    for idx, fp in enumerate(files, 1):
        fstart = time.time()
        print(f"[train] ({idx}/{len(files)}) start: {fp}", flush=True)
        processed = 0
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore", newline="") as f:
                r = csv.DictReader(f)
                for row in r:
                    url = (row.get("url") or row.get("URL") or row.get("Url") or "").strip()
                    if not url and row:
                        try:
                            url = list(row.values())[0].strip()
                        except Exception:
                            continue
                    if not url:
                        continue
                    ts = parse_ts(row.get("date") or row.get("DATE") or row.get("timestamp") or "")
                    M.feedback(url, label=-1, ts=ts)  # -1 = 피싱
                    processed += 1
                    total += 1
                    if (processed % 1000) == 0:
                        dt_s = time.time() - fstart
                        rate = processed / dt_s if dt_s > 0 else 0.0
                        print(f"  ... {processed} rows ({rate:.1f} rows/s) file={os.path.basename(fp)}", flush=True)
        except Exception as e:
            bad_files += 1
            print(f"[train] ERROR file={fp}: {e}", flush=True)
        finally:
            dt_s = time.time() - fstart
            print(f"[train] done: file={fp} rows={processed} time={dt_s:.2f}s", flush=True)

    print(f"[train] total_rows={total} bad_files={bad_files} elapsed={time.time()-t0:.2f}s", flush=True)
    print("[maint] beat...", flush=True)
    print(M.maint_beat(), flush=True)
    print(M.status(), flush=True)

if __name__ == "__main__":
    import sys
    root = sys.argv[1] if len(sys.argv)>1 else r"D:\cap\feeds\phishurl-list"
    main(root)
