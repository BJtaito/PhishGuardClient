# tools/download_scanner/download_pipeline.py
from __future__ import annotations

from typing import Dict, Any, List

from tools.download_scanner.dynamic_downloader import run_dynamic_and_collect_downloads
from tools.download_scanner.vt_scanner import scan_file_with_virustotal


def _normalize_vt_summary(vt_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    vt_scanner가 반환하는 결과를 최대한 일반화해서 정리.
    - risk_score_percent: 0~100 부동소수점
    - label: malicious / suspicious / clean / unknown
    - detectors: 각 카운트
    """
    summary = vt_result.get("summary") or {}

    # 기본값 처리
    risk = float(summary.get("risk_score_percent", 0.0) or 0.0)

    label = summary.get("label")
    if not label:
        # 대충 stats 기반으로 라벨 추론 (vt_scanner가 stats를 안 주면 이 부분은 무시)
        stats = summary.get("stats") or vt_result.get("stats") or {}
        mal = int(stats.get("malicious", 0) or 0)
        susp = int(stats.get("suspicious", 0) or 0)
        if mal > 0:
            label = "malicious"
        elif susp > 0:
            label = "suspicious"
        elif risk <= 5:
            label = "clean"
        else:
            label = "unknown"

    det = summary.get("detectors") or {}
    malicious = int(det.get("malicious", 0) or summary.get("malicious", 0) or 0)
    suspicious = int(det.get("suspicious", 0) or summary.get("suspicious", 0) or 0)
    harmless = int(det.get("harmless", 0) or summary.get("harmless", 0) or 0)
    undetected = int(det.get("undetected", 0) or summary.get("undetected", 0) or 0)

    total = malicious + suspicious + harmless + undetected
    return {
        "risk_score_percent": risk,
        "label": label,
        "detectors": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
        },
    }


def analyze_url_with_downloads(url: str, wait_seconds: int = 20) -> Dict[str, Any]:
    """
    1) URL에 접속해서 실제로 다운로드 되는 파일 수집
    2) 각 파일을 VirusTotal에 제출하여 악성 여부 요약
    3) URL 전체에 대한 위험도 요약 리포트 생성
    """
    downloads: List[Dict[str, Any]] = run_dynamic_and_collect_downloads(
        url, wait_seconds=wait_seconds
    )

    if not downloads:
        return {
            "url": url,
            "download_count": 0,
            "downloads": [],
            "note": "no_downloaded_files",
            "summary_line": "[INFO] 다운로드된 파일이 없습니다.",
            "max_risk_score": 0.0,
        }

    analyzed_downloads: List[Dict[str, Any]] = []
    worst_risk = 0.0

    for item in downloads:
        fpath = item.get("saved_path")
        if not fpath:
            continue

        print(f"[VT] 파일 스캔 시작: {fpath}")
        vt_result = scan_file_with_virustotal(fpath)

        vt_summary_norm = _normalize_vt_summary(vt_result)
        risk = float(vt_summary_norm.get("risk_score_percent", 0.0) or 0.0)
        if risk > worst_risk:
            worst_risk = risk

        analyzed_downloads.append(
            {
                **item,
                "vt_summary": vt_summary_norm,   # 프론트/서버에서 쓰기 좋은 요약
                "vt_raw": vt_result,             # 필요하면 디버그용
            }
        )

    summary_line = (
        f"[INFO] {len(analyzed_downloads)}개 파일 다운로드됨 / "
        f"최고 위험도 {worst_risk:.1f}%"
    )

    return {
        "url": url,
        "download_count": len(analyzed_downloads),
        "downloads": analyzed_downloads,
        "note": "ok",
        "max_risk_score": worst_risk,
        "summary_line": summary_line,
    }
