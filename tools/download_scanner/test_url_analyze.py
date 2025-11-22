# test_url_analyze.py
from tools.download_scanner.download_pipeline import analyze_url_with_downloads
import json

url = "https://hrd.kcue.or.kr/board/view/notice/6316?utm_source=chatgpt.com"
  # 여기다 너가 테스트할 URL 넣기

res = analyze_url_with_downloads(url, wait_seconds=20)

print("\n=== 최종 URL 다운로드 분석 결과 ===")
print(json.dumps(res, indent=2, ensure_ascii=False))
