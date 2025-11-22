# tools/seed_benign_with_html.py
import asyncio, os
from analyzer import ml_detector as M

# ✅ 정상 사이트 목록 확장
BENIGN = [
    # 포털 / 검색
    "https://www.naver.com",
    "https://search.naver.com",
    "https://www.daum.net",
    "https://www.google.com",
    "https://www.bing.com",
    "https://www.yahoo.com",

    # 뉴스 / 콘텐츠
    "https://news.naver.com",
    "https://sports.naver.com",
    "https://entertain.naver.com",
    "https://www.chosun.com",
    "https://www.joongang.co.kr",
    "https://www.donga.com",

    # SNS / 커뮤니티
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.instagram.com",
    "https://x.com",                # 트위터(X)
    "https://discord.com",
    "https://www.reddit.com",

    # 이커머스 / 쇼핑
    "https://www.amazon.com",
    "https://www.coupang.com",
    "https://www.11st.co.kr",
    "https://www.gmarket.co.kr",
    "https://www.wemakeprice.com",
    "https://www.ssg.com",

    # IT 기업 / 개발
    "https://www.apple.com",
    "https://www.microsoft.com",
    "https://cloud.google.com",
    "https://github.com",
    "https://gitlab.com",
    "https://stackoverflow.com",

    # 결제 / 핀테크
    "https://www.paypal.com",
    "https://www.kakaopay.com",
    "https://pay.naver.com",
    "https://toss.im",

    # 국내 은행 (대표 몇 개)
    "https://obank.kbstar.com",
    "https://www.shinhan.com",
    "https://obank.kebhana.com",
    "https://banking.nonghyup.com",

    # 공공 / 관공서
    "https://www.gov.kr",
    "https://www.nts.go.kr",
    "https://www.epost.go.kr",

    # 기타 서비스
    "https://www.netflix.com",
    "https://www.wikipedia.org",
    "https://www.kakao.com",
]

# 간단 fetch (서버와 동일한 httpx 사용 권장)
try:
    import httpx
except Exception:
    httpx = None


async def fetch_html(u: str, timeout=5.0) -> str:
    if not httpx:
        return ""
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": "PhishGuard/seed"}
        ) as c:
            r = await c.get(u, follow_redirects=True)
            ct = (r.headers.get("content-type") or "").lower()
            t = r.text or ""
            if ("text/html" in ct) or ("<html" in t[:1024].lower()):
                return t
    except Exception:
        return ""
    return ""


async def main():
    ok = 0
    for u in BENIGN:
        html = await fetch_html(u)

        # ✅ URL + (가능하면) HTML까지 정상(label=1)로 학습
        # train_kisa_with_html.py 시그니처와 맞춰서 html 파라미터 사용
        M.feedback(u, label=1, ts=None, html=html if html else None)

        ok += 1
        print(f"[seed] {ok}/{len(BENIGN)} {u} html={'Y' if html else 'N'}", flush=True)

    print("seeded:", ok)
    print(M.maint_beat())   # 에이징/윈도우 재학습
    print(M.status())


if __name__ == "__main__":
    asyncio.run(main())
