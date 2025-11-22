from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Dict, Optional

import requests

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalError(Exception):
    pass


def _auth_headers() -> Dict[str, str]:
    if not VT_API_KEY:
        raise VirusTotalError("VT_API_KEY 환경변수가 설정되어 있지 않습니다.")
    return {
        "x-apikey": VT_API_KEY,
    }


def calc_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def vt_hash_lookup(sha256: str) -> Optional[Dict[str, Any]]:
    url = f"{VT_BASE}/files/{sha256}"
    resp = requests.get(url, headers=_auth_headers(), timeout=15)
    if resp.status_code == 404:
        return None
    if resp.status_code == 429:
        # rate limit -> 호출하는 쪽에서 재시도하도록 에러로 올림
        raise VirusTotalError("VirusTotal rate limit (hash lookup)")
    if resp.status_code >= 400:
        raise VirusTotalError(f"VirusTotal hash lookup 실패: {resp.status_code} {resp.text}")
    return resp.json()


def vt_upload_file(path: str) -> Dict[str, Any]:
    url = f"{VT_BASE}/files"
    with open(path, "rb") as f:
        files = {"file": (os.path.basename(path), f)}
        resp = requests.post(url, headers=_auth_headers(), files=files, timeout=60)
    if resp.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit (upload)")
    if resp.status_code >= 400:
        raise VirusTotalError(f"VirusTotal upload 실패: {resp.status_code} {resp.text}")
    return resp.json()


def vt_poll_analysis(analysis_id: str, max_wait: int = 120, interval: int = 4) -> Dict[str, Any]:
    """
    VT analysis id로 상태를 주기적으로 조회해서 completed 될 때까지 대기.
    """
    url = f"{VT_BASE}/analyses/{analysis_id}"
    start = time.time()
    while True:
        resp = requests.get(url, headers=_auth_headers(), timeout=15)
        if resp.status_code == 429:
            # rate limit이면 잠깐 기다렸다 다시
            time.sleep(interval)
            continue
        if resp.status_code >= 400:
            raise VirusTotalError(f"VirusTotal analysis 조회 실패: {resp.status_code} {resp.text}")
        data = resp.json()
        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return data
        if time.time() - start > max_wait:
            raise VirusTotalError("VirusTotal 분석 대기 시간 초과")
        time.sleep(interval)


def _build_summary_from_stats(stats: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    timeout = int(stats.get("timeout", 0))
    failure = int(stats.get("failure", 0))

    total_engines = malicious + suspicious + harmless + undetected + timeout + failure
    if total_engines <= 0:
        risk_score_percent = 0.0
    else:
        risk_score_percent = (malicious + suspicious) * 100.0 / total_engines

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "failure": failure,
        "total_engines": total_engines,
        "risk_score_percent": risk_score_percent,
        "file_name": meta.get("file_name"),
        "file_type": meta.get("file_type"),
        "sha256": meta.get("sha256"),
        "vt_link": meta.get("vt_link"),
    }


def scan_file_with_virustotal(path: str, use_upload: bool = True) -> Dict[str, Any]:
    """
    파일 하나를 VirusTotal로 조회/업로드해서 요약 정보까지 포함한 dict 반환.
    - 먼저 SHA256 해시로 조회
    - 결과 없으면 파일 업로드 + 분석 완료 대기
    """
    sha256 = calc_sha256(path)
    meta: Dict[str, Any] = {
        "file_name": os.path.basename(path),
        "file_type": None,
        "sha256": sha256,
        "vt_link": f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else None,
    }

    result: Dict[str, Any] = {
        "file_path": path,
        "sha256": sha256,
        "hash_lookup": None,
        "upload_scan": None,
        "analysis": None,
        "summary": None,
    }

    # 1) 해시 조회
    try:
        lookup = vt_hash_lookup(sha256)
    except VirusTotalError as e:
        # 해시 조회 실패했어도, 업로드 가능하면 다시 시도
        lookup = None
        result["hash_error"] = str(e)

    if lookup:
        result["hash_lookup"] = lookup
        attrs = lookup.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        meta["file_type"] = attrs.get("type_description")
        # summary 만들기
        result["summary"] = _build_summary_from_stats(stats, meta)
        return result

    # 2) 해시 조회에 없고 업로드 허용이면 업로드 + 분석 대기
    if not use_upload:
        return result

    try:
        upload_res = vt_upload_file(path)
        result["upload_scan"] = upload_res
        analysis_id = upload_res.get("data", {}).get("id")
        if analysis_id:
            analysis = vt_poll_analysis(analysis_id)
            result["analysis"] = analysis
            attrs = analysis.get("data", {}).get("attributes", {})
            stats = attrs.get("stats") or {}
            meta["file_type"] = attrs.get("results", {}).get("file_type") or meta["file_type"]
            result["summary"] = _build_summary_from_stats(stats, meta)
    except VirusTotalError as e:
        result["upload_error"] = str(e)

    return result
