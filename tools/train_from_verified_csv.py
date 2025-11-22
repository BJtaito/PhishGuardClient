# tools/train_from_verified_csv.py (발췌)
import csv, argparse, time
from analyzer import ml_detector as M

def main(alive_csv):
    with open(alive_csv, newline='', encoding='utf-8') as f:
        r = csv.DictReader(f)
        n = 0
        t0 = time.time()
        for row in r:
            kind = (row.get("kind") or "").lower()
            url  = (row.get("final_url") or row.get("url") or "").strip()
            html = (row.get("html") or "").strip()
            # 경고/소프트404/파킹 등은 건너뛴다
            if kind != "normal": 
                continue
            if not html:
                continue
            M.feedback(url, label=-1, html=html)  # 피싱 라벨
            n += 1
            if n % 500 == 0:
                print(f"[train] {n} samples...", flush=True)
    print(f"[train] done: {n} samples in {time.time()-t0:.1f}s", flush=True)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--alive-csv", required=True)
    a = ap.parse_args()
    main(a.alive_csv)
