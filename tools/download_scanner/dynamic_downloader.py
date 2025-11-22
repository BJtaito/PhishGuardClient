from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, unquote

import requests
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

BASE_DIR = os.path.dirname(__file__)
DOWNLOAD_DIR = os.path.join(BASE_DIR, "downloads")

os.makedirs(DOWNLOAD_DIR, exist_ok=True)

FILE_EXTENSIONS = [
    ".exe", ".msi", ".dll", ".scr",
    ".zip", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".hwp", ".hwpx",
    ".js", ".ps1", ".bat", ".vbs",
]


# ================================
# 중복 방지용 SHA 체크
# ================================
def file_sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def already_downloaded(path: str) -> bool:
    """이미 동일 파일명이 존재하면 중복 다운로드 방지"""
    return os.path.exists(path)


# ================================
# DownloadResult
# ================================
@dataclass
class DownloadResult:
    saved_path: str
    original_url: str
    final_url: str
    redirect_chain: List[str]
    download_method: str
    content_type: Optional[str] = None
    file_type_magic: Optional[str] = None
    file_type_note: Optional[str] = None


def sanitize_filename(name: str) -> str:
    name = name.strip().replace("\0", "")
    name = re.sub(r'[\\/:*?"<>|]', "_", name)
    return name or "download.bin"


def _parse_content_disposition(cd: str, fallback_url: str) -> str:
    if not cd:
        base = os.path.basename(urlparse(fallback_url).path) or "download.bin"
        return sanitize_filename(unquote(base))

    m = re.search(r"filename\*=UTF-8''([^;]+)", cd, re.I)
    if m:
        try:
            return sanitize_filename(unquote(m.group(1)))
        except:
            pass

    m = re.search(r'filename="?([^";]+)"?', cd, re.I)
    if m:
        return sanitize_filename(unquote(m.group(1)))

    base = os.path.basename(urlparse(fallback_url).path)
    return sanitize_filename(unquote(base or "download.bin"))


def is_direct_file_url(url: str) -> bool:
    return any(url.lower().endswith(ext) for ext in FILE_EXTENSIONS)


# ================================
# 간단한 파일 magic 체크
# ================================
def detect_file_type_magic(path: str) -> str:
    try:
        with open(path, "rb") as f:
            sig = f.read(8)
    except:
        return "unknown"

    if sig.startswith(b"MZ"):
        return "pe_executable"
    if sig.startswith(b"%PDF-"):
        return "pdf"
    if sig.startswith(b"PK\x03\x04"):
        return "zip_or_office"
    if sig.startswith(b"\xD0\xCF\x11\xE0"):
        return "ole_compound"
    if sig[:4] == b"\x7fELF":
        return "elf"
    return "unknown"


# ================================
# HTTP 다운로드 (중복 체크 포함)
# ================================
def http_download(url: str, dest_dir: str) -> Optional[DownloadResult]:
    print(f"[HTTP] 요청: {url}")

    try:
        resp = requests.get(url, stream=True, allow_redirects=True, timeout=25)
    except Exception as e:
        print(f"[HTTP ERROR] {e}")
        return None

    chain = [h.url for h in resp.history] + [resp.url]
    content_type = resp.headers.get("Content-Type", "").lower()

    filename = _parse_content_disposition(resp.headers.get("Content-Disposition"), resp.url)
    dest_path = os.path.join(dest_dir, filename)

    # 중복 방지
    if already_downloaded(dest_path):
        print(f"[SKIP] 이미 존재하는 파일 (HTTP): {dest_path}")
        return None

    try:
        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(8192):
                if chunk:
                    f.write(chunk)
    except:
        print("[HTTP SAVE ERROR]")
        return None

    magic = detect_file_type_magic(dest_path)
    note = None
    if magic == "unknown" and "text/html" in content_type:
        note = "html_response_saved_as_file"

    return DownloadResult(
        saved_path=dest_path,
        original_url=url,
        final_url=resp.url,
        redirect_chain=chain,
        download_method="http_direct",
        content_type=content_type,
        file_type_magic=magic,
        file_type_note=note,
    )


# ================================
# 페이지 내 다운로드 링크 수집
# ================================
def collect_candidate_links(page):
    anchors = page.query_selector_all("a")
    candidates = []
    for a in anchors:
        href = a.get_attribute("href") or ""
        text = (a.inner_text() or "").strip()

        score = 0
        href_l = href.lower()
        text_l = text.lower()

        if any(href_l.endswith(ext) for ext in FILE_EXTENSIONS):
            score += 3
        if any(k in text_l for k in ["다운로드", "download", "첨부", "파일"]):
            score += 2
        if any(k in href_l for k in ["download", "attach", "filedown"]):
            score += 2

        if score > 0:
            candidates.append({"href": href, "text": text, "score": score})

    candidates.sort(key=lambda x: x["score"], reverse=True)
    return candidates


# ================================
# Playwright + HTTP fallback (중복 없는 최종 버전)
# ================================
def run_dynamic_and_collect_downloads(url: str, wait_seconds: int = 20, max_links: int = 10):
    results = []

    # direct file link 처리
    if is_direct_file_url(url):
        dr = http_download(url, DOWNLOAD_DIR)
        if dr:
            results.append(dr)
        return [asdict(r) for r in results]

    # 동적 페이지 처리
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(accept_downloads=True)
        page = context.new_page()

        try:
            page.goto(url, wait_until="load", timeout=30000)
        except:
            print("[Timeout] fallback HTTP")
            browser.close()
            dr = http_download(url, DOWNLOAD_DIR)
            if dr:
                results.append(dr)
            return [asdict(r) for r in results]

        page.wait_for_timeout(wait_seconds * 1000)

        candidates = collect_candidate_links(page)
        print(f"[PLAYWRIGHT] 후보 {len(candidates)}개")

        used = 0
        for c in candidates:
            if used >= max_links:
                break

            href = c["href"]
            if not href:
                continue

            full_url = urljoin(page.url, href)

            # 브라우저 다운로드 시도
            try:
                with page.expect_download(timeout=15000) as dl_info:
                    page.click(f"a[href='{href}']")
                download = dl_info.value

                tmp_path = download.path()
                filename = sanitize_filename(download.suggested_filename)
                dest_path = os.path.join(DOWNLOAD_DIR, filename)

                # 중복 방지
                if already_downloaded(dest_path):
                    print(f"[SKIP] 이미 존재하는 파일 (browser): {dest_path}")
                    continue

                shutil.move(tmp_path, dest_path)

                dr = DownloadResult(
                    saved_path=dest_path,
                    original_url=full_url,
                    final_url=download.url,
                    redirect_chain=[full_url, download.url],
                    download_method="browser_download",
                    file_type_magic=detect_file_type_magic(dest_path),
                )

                results.append(dr)
                used += 1
                continue

            except:
                print(f"[PLAYWRIGHT] 다운로드 실패 → HTTP fallback: {full_url}")

            # fallback
            dr = http_download(full_url, DOWNLOAD_DIR)
            if dr:
                dr.download_method = "http_fallback"
                results.append(dr)
                used += 1

        browser.close()

    return [asdict(r) for r in results]
