# tools/reclassify_alive_csv.py (추가/강화 버전)
import csv, argparse, re

SOFT404 = ["404", "page not found", "찾을 수 없습니다", "페이지를 찾을 수", "未找到", "not found"]
CHALL   = ["attention required", "just a moment", "checking your browser", "captcha", "cf-challenge", "cloudflare"]
PARKED  = ["domain parking", "parkingcrew", "sedo", "domain for sale", "buy this domain", "namebright"]
SUSP    = ["account suspended", "site suspended", "website suspended"]
DENIED  = ["access denied", "forbidden", "error 1020", "error 1015", "blocked by"]
MAINT   = ["maintenance", "we'll be back soon", "서비스 점검", "점검 중"]

# ▼ 새로 추가: X 경고 인터스티셜 시그니처
X_WARN_HOSTS = {"x.co", "t.co"}
X_WARN_SNIPPETS = [
    "경고: 이 링크는 안전하지 않을 수 있습니다",
    "potentially spammy or unsafe",
    "URL policy", "help.x.com/en/safety-and-security",
    'id="back_button"', 'class="warningmsg"', "이 경고를 무시하고", "계속하기"
]
# 필요하면 Facebook/Discord/Google 경고 페이지도 비슷하게 추가 가능

def contains_any(s, kws):
    s = (s or "").lower()
    return any(k.lower() in s for k in kws)

def is_x_interstitial(row):
    url = (row.get("final_url") or row.get("url") or "")
    html = row.get("html","")
    host = ""
    try:
        host = re.split(r"://", url, 1)[1].split("/",1)[0].lower()
    except Exception:
        pass
    if host in X_WARN_HOSTS and contains_any(html, X_WARN_SNIPPETS):
        return True
    return False

def classify_html_only(row):
    html = row.get("html","")
    if not html:
        return "unknown", "empty"
    low = html.lower()
    if len(low) < 2000 and contains_any(low, SOFT404): return "soft404", "200_soft404_like"
    if contains_any(low, CHALL):  return "challenge", "challenge_page"
    if contains_any(low, PARKED): return "parked", "domain_parking"
    if contains_any(low, SUSP):   return "suspended", "site_suspended"
    if contains_any(low, DENIED): return "denied", "access_denied_like"
    if contains_any(low, MAINT):  return "maintenance", "maintenance"
    return "normal", "ok"

def main(inp, outp):
    with open(inp, newline='', encoding='utf-8') as fi, \
         open(outp, 'w', newline='', encoding='utf-8') as fo:
        r = csv.DictReader(fi)
        cols = list(r.fieldnames or [])
        for c in ["kind","note"]:
            if c not in cols: cols.append(c)
        w = csv.DictWriter(fo, fieldnames=cols)
        w.writeheader()
        for row in r:
            if is_x_interstitial(row):
                row["kind"], row["note"] = "interstitial_warning", "x_warning_page"
            else:
                k, n = classify_html_only(row)
                row["kind"], row["note"] = k, n
            w.writerow(row)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in",  dest="inp",  required=True)
    ap.add_argument("--out", dest="outp", required=True)
    a = ap.parse_args()
    main(a.inp, a.outp)
