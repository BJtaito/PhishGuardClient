from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Set

from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent
from watchdog.observers import Observer

from vt_scanner import scan_file_with_virustotal

# 감시할 다운로드 폴더 (필요하면 여기 경로를 본인 PC에 맞게 수정)
DOWNLOAD_DIR = Path(r"C:\Users\hyeongseok oh\Downloads")

WATCH_EXT: Set[str] = {
    ".exe", ".msi", ".dll", ".scr",
    ".zip", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".hwp", ".hwpx",
    ".js", ".ps1", ".bat", ".vbs",
}

TEMP_EXT: Set[str] = {".tmp", ".crdownload", ".part"}


class DownloadHandler(FileSystemEventHandler):
    """
    크롬/엣지 다운로드 패턴:
      - download.tmp / .crdownload 로 생성 후
      - 최종 파일명으로 rename (moved 이벤트)
    """

    def on_created(self, event: FileCreatedEvent):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() in TEMP_EXT:
            # 아직 다운로드 중
            return
        if path.suffix.lower() in WATCH_EXT:
            print(f"[WATCHER] 새 파일 생성 감지: {path}")
            self.handle_file(path)

    def on_moved(self, event: FileMovedEvent):
        if event.is_directory:
            return
        src = Path(event.src_path)
        dst = Path(event.dest_path)
        # 임시 확장자 -> 감시 확장자로 바뀌는 순간이 '다운로드 완료' 시점
        if src.suffix.lower() in TEMP_EXT and dst.suffix.lower() in WATCH_EXT:
            print(f"[WATCHER] 다운로드 완료 감지: {dst}")
            self.handle_file(dst)

    def handle_file(self, path: Path):
        # 파일이 완전히 써지도록 잠깐 대기
        time.sleep(1.0)
        if not path.exists():
            return

        print(f"[WATCHER] VirusTotal 스캔 시작: {path}")
        try:
            vt_res = scan_file_with_virustotal(str(path))
        except Exception as e:
            print(f"[WATCHER ERROR] VT 스캔 실패: {e}")
            return

        summary = (vt_res or {}).get("summary") or {}
        malicious = summary.get("malicious", 0)
        suspicious = summary.get("suspicious", 0)
        risk = summary.get("risk_score_percent", 0.0)

        print(f"[WATCHER VT RESULT] 파일: {path.name}")
        print(f"  - 악성 엔진 수: {malicious}")
        print(f"  - 의심 엔진 수: {suspicious}")
        print(f"  - 위험도: {risk:.1f}%")
        print(f"  - VT 링크: {summary.get('vt_link')}")

        if risk >= 50.0 or malicious >= 3:
            print("  [!!!] 고위험 파일로 판단됩니다. 실행하지 마세요.")


def main():
    if not DOWNLOAD_DIR.exists():
        print(f"DOWNLOAD_DIR 존재하지 않음: {DOWNLOAD_DIR}")
        return

    event_handler = DownloadHandler()
    observer = Observer()
    observer.schedule(event_handler, str(DOWNLOAD_DIR), recursive=False)
    observer.start()

    print(f"[WATCHER] 다운로드 폴더 감시 시작: {DOWNLOAD_DIR}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[WATCHER] 종료 신호 수신, 정리 중...")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
