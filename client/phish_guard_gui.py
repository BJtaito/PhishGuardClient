"""
Phish-Guard Client GUI (Light Theme + Docker Desktop Auto Start)

위치 예시:
    D:\cap2\docker-compose.yml
    D:\cap2\client\client_gui.py

의존 패키지:
    pip install PyQt6 requests

환경변수(옵션):
    PG_API_BASE : API Gateway 주소 (기본: http://localhost:9000)
    PG_API_KEY  : X-API-Key 값
    DOCKER_DESKTOP_EXE 또는 PG_DOCKER_DESKTOP_EXE :
        Docker Desktop 실행 파일 경로를 직접 지정하고 싶을 때 사용
        (기본 경로: C:\Program Files\Docker\Docker\Docker Desktop.exe 시도)
"""

import os
import sys
import time
import subprocess
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPalette
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QTabWidget,
    QLabel,
    QMessageBox,
    QGroupBox,
    QFrame,
    QStatusBar,
)


# ─────────────────────────────────────────────────────────────
# 공통 HTTP 헬퍼
# ─────────────────────────────────────────────────────────────

def http_request(
    api_base: str,
    api_key: str,
    method: str,
    path: str,
    *,
    json_data: Any = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """API Gateway와 통신하는 공통 함수."""
    url = api_base.rstrip("/") + path
    headers: Dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key
    resp = requests.request(method, url, headers=headers, json=json_data, params=params, timeout=60)
    resp.raise_for_status()
    return resp.json()


def analyze_once(
    api_base: str,
    api_key: str,
    url: str,
    progress_cb=None,
) -> Dict[str, Any]:
    """
    하나의 URL에 대해:
      1) POST /api/analyze
      2) /api/analyze/{job_id} 폴링
    최종 result(dict)를 반환.
    """
    def log(msg: str):
        if progress_cb is not None:
            progress_cb(msg)

    log(f"[+] analyze: {url}")
    data = http_request(api_base, api_key, "POST", "/api/analyze", json_data={"url": url})
    job_id = data["job_id"]
    log(f"  job_id: {job_id}")

    while True:
        time.sleep(1.0)
        status = http_request(api_base, api_key, "GET", f"/api/analyze/{job_id}")
        s = status["status"]
        log(f"  status: {s}")
        if s in ("done", "error", "failed"):
            break

    log("=== final ===")
    log(f"verdict: {status.get('verdict')}")
    log(f"score  : {status.get('score')}")
    if status.get("error"):
        log(f"error  : {status.get('error')}")

    return status.get("result") or {}


# ─────────────────────────────────────────────────────────────
# Worker Threads
# ─────────────────────────────────────────────────────────────

class AnalyzeWorker(QThread):
    progress = pyqtSignal(str)
    finished_ok = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, api_base: str, api_key: str, url: str):
        super().__init__()
        self.api_base = api_base
        self.api_key = api_key
        self.url = url

    def run(self):
        try:
            result = analyze_once(
                self.api_base,
                self.api_key,
                self.url,
                progress_cb=lambda m: self.progress.emit(m),
            )
            self.finished_ok.emit(result)
        except Exception as e:
            self.failed.emit(str(e))


class ChallengeSolveWorker(QThread):
    progress = pyqtSignal(str)
    finished_ok = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, api_base: str, api_key: str, challenge_id: str, client_id: str):
        super().__init__()
        self.api_base = api_base
        self.api_key = api_key
        self.challenge_id = challenge_id
        self.client_id = client_id

    def run(self):
        try:
            # 1) challenge 정보
            info = http_request(
                self.api_base,
                self.api_key,
                "GET",
                f"/api/challenges/{self.challenge_id}",
            )
            urls: List[str] = info["urls"]

            self.progress.emit(f"[+] challenge {info['challenge_id']}")
            self.progress.emit(f"  nonce: {info['nonce']}")
            self.progress.emit(f"  status: {info['status']}")
            self.progress.emit(f"  urls: {urls}")

            results: List[Dict[str, Any]] = []

            for url in urls:
                res = analyze_once(
                    self.api_base,
                    self.api_key,
                    url,
                    progress_cb=lambda m, u=url: self.progress.emit(f"[{u}] {m}"),
                )
                results.append({"url": url, "raw_result": res})

            body = {"client_id": self.client_id, "results": results}
            http_request(
                self.api_base,
                self.api_key,
                "POST",
                f"/api/challenges/{self.challenge_id}/client-results",
                json_data=body,
            )
            self.progress.emit("[+] client results submitted.")
            self.finished_ok.emit()
        except Exception as e:
            self.failed.emit(str(e))


# ─────────────────────────────────────────────────────────────
# UI 유틸
# ─────────────────────────────────────────────────────────────

def make_header_label(text: str) -> QLabel:
    lbl = QLabel(text)
    f = lbl.font()
    f.setPointSize(12)
    f.setBold(True)
    lbl.setFont(f)
    return lbl


def make_card() -> QFrame:
    """밝은 카드 스타일."""
    frame = QFrame()
    frame.setFrameShape(QFrame.Shape.StyledPanel)
    frame.setFrameShadow(QFrame.Shadow.Raised)
    frame.setStyleSheet("""
        QFrame {
            background-color: #f9fafb;
            border: 1px solid #d1d5db;
            border-radius: 8px;
        }
    """)
    return frame


def verdict_to_risk(verdict: Optional[str], score: Optional[float]) -> (str, str):
    """
    verdict / score 기반으로 리스크 레벨 텍스트 + 색상 리턴.
    """
    v = (verdict or "").lower()
    s = float(score) if score is not None else None

    if v in ("phishing", "malicious"):
        return "High Risk", "#ef4444"
    if v in ("benign", "clean"):
        return "Safe", "#16a34a"
    if s is not None:
        if s >= 80:
            return "High Risk", "#ef4444"
        if s >= 50:
            return "Suspicious", "#f97316"
        return "Safe", "#16a34a"
    return "Unknown", "#6b7280"


# ─────────────────────────────────────────────────────────────
# 탭: URL 분석
# ─────────────────────────────────────────────────────────────

class AnalyzeTab(QWidget):
    def __init__(self, api_base_input: QLineEdit, api_key_input: QLineEdit, status_bar: QStatusBar):
        super().__init__()
        self.api_base_input = api_base_input
        self.api_key_input = api_key_input
        self.status_bar = status_bar
        self.worker: Optional[AnalyzeWorker] = None

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        # 좌측 카드: 입력
        left_card = make_card()
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(16, 16, 16, 16)
        left_layout.setSpacing(12)

        left_layout.addWidget(make_header_label("URL 분석"))

        form = QFormLayout()
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com/")
        form.addRow("분석할 URL:", self.url_edit)
        left_layout.addLayout(form)

        self.btn_analyze = QPushButton("분석 실행")
        self.btn_analyze.setMinimumHeight(36)
        self.btn_analyze.clicked.connect(self.on_analyze_clicked)
        left_layout.addWidget(self.btn_analyze)

        left_layout.addStretch(1)
        root.addWidget(left_card, 1)

        # 우측 카드: 결과 + 로그
        right_card = make_card()
        right_layout = QVBoxLayout(right_card)
        right_layout.setContentsMargins(16, 16, 16, 16)
        right_layout.setSpacing(8)

        header = QHBoxLayout()
        header.addWidget(make_header_label("결과 요약"))
        header.addStretch(1)
        right_layout.addLayout(header)

        risk_row = QHBoxLayout()
        risk_row.addWidget(QLabel("Risk Level:"))
        self.lbl_risk = QLabel("N/A")
        self.lbl_risk.setStyleSheet("color: #6b7280; font-weight: bold;")
        risk_row.addWidget(self.lbl_risk)
        risk_row.addStretch(1)
        right_layout.addLayout(risk_row)

        vs_row = QHBoxLayout()
        self.lbl_verdict = QLabel("Verdict: -")
        self.lbl_score = QLabel("Score: -")
        vs_row.addWidget(self.lbl_verdict)
        vs_row.addWidget(self.lbl_score)
        vs_row.addStretch(1)
        right_layout.addLayout(vs_row)

        right_layout.addWidget(QLabel("Raw Result (JSON):"))
        self.txt_json = QTextEdit()
        self.txt_json.setReadOnly(True)
        self.txt_json.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        right_layout.addWidget(self.txt_json, 4)

        right_layout.addWidget(QLabel("로그:"))
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        right_layout.addWidget(self.txt_log, 3)

        root.addWidget(right_card, 2)

    # ── 로직 ──────────────────────────────────────────────────

    def append_log(self, msg: str):
        self.txt_log.append(msg)

    def set_result_summary(self, result: Dict[str, Any]):
        verdict = result.get("verdict")
        try:
            raw_score = result.get("score")
            score = float(raw_score) if raw_score is not None else None
        except Exception:
            score = None

        risk_txt, color = verdict_to_risk(verdict, score)
        self.lbl_risk.setText(risk_txt)
        self.lbl_risk.setStyleSheet(f"color: {color}; font-weight: bold;")

        self.lbl_verdict.setText(f"Verdict: {verdict}")
        self.lbl_score.setText(f"Score: {score if score is not None else '-'}")

        import json
        self.txt_json.setPlainText(json.dumps(result, indent=2, ensure_ascii=False))

    def on_analyze_clicked(self):
        api_base = self.api_base_input.text().strip()
        api_key = self.api_key_input.text().strip()
        url = self.url_edit.text().strip()

        if not api_base or not url:
            QMessageBox.warning(self, "입력 오류", "API 주소와 URL을 입력하세요.")
            return

        self.txt_log.clear()
        self.txt_json.clear()
        self.set_result_summary({})
        self.append_log(f"[+] API_BASE = {api_base}")
        self.append_log(f"[+] URL      = {url}")

        self.btn_analyze.setEnabled(False)
        self.status_bar.showMessage("분석 중...")

        self.worker = AnalyzeWorker(api_base, api_key, url)
        self.worker.progress.connect(self.append_log)
        self.worker.finished_ok.connect(self.on_finished_ok)
        self.worker.failed.connect(self.on_failed)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()

    def on_finished_ok(self, result: Dict[str, Any]):
        self.append_log("")
        self.append_log("[+] 분석 완료")
        self.set_result_summary(result)
        self.status_bar.showMessage("분석 완료", 5000)

    def on_failed(self, msg: str):
        self.append_log("[ERROR] " + msg)
        QMessageBox.critical(self, "에러", msg)
        self.status_bar.showMessage("에러 발생", 5000)

    def on_thread_finished(self):
        self.btn_analyze.setEnabled(True)
        self.worker = None


# ─────────────────────────────────────────────────────────────
# 탭: Challenge 인증
# ─────────────────────────────────────────────────────────────

class ChallengeTab(QWidget):
    def __init__(self, api_base_input: QLineEdit, api_key_input: QLineEdit, status_bar: QStatusBar):
        super().__init__()
        self.api_base_input = api_base_input
        self.api_key_input = api_key_input
        self.status_bar = status_bar
        self.worker: Optional[ChallengeSolveWorker] = None

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        # 좌측 카드
        left_card = make_card()
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(16, 16, 16, 16)
        left_layout.setSpacing(8)

        left_layout.addWidget(make_header_label("Challenge 인증"))

        form = QFormLayout()
        self.challenge_id_edit = QLineEdit()
        self.client_id_edit = QLineEdit()
        self.challenge_id_edit.setPlaceholderText("challenge-uuid")
        self.client_id_edit.setPlaceholderText("client-identifier")

        form.addRow("Challenge ID:", self.challenge_id_edit)
        form.addRow("Client ID:", self.client_id_edit)
        left_layout.addLayout(form)

        self.btn_fetch = QPushButton("1. Challenge 정보 조회")
        self.btn_solve = QPushButton("2. Challenge 해결 (분석 + 업로드)")
        self.btn_verdict = QPushButton("3. Verifier 결과 조회")

        self.btn_fetch.setMinimumHeight(32)
        self.btn_solve.setMinimumHeight(32)
        self.btn_verdict.setMinimumHeight(32)

        self.btn_fetch.clicked.connect(self.on_fetch_clicked)
        self.btn_solve.clicked.connect(self.on_solve_clicked)
        self.btn_verdict.clicked.connect(self.on_verdict_clicked)

        left_layout.addWidget(self.btn_fetch)
        left_layout.addWidget(self.btn_solve)
        left_layout.addWidget(self.btn_verdict)

        left_layout.addStretch(1)
        root.addWidget(left_card, 1)

        # 우측 카드
        right_card = make_card()
        right_layout = QVBoxLayout(right_card)
        right_layout.setContentsMargins(16, 16, 16, 16)
        right_layout.setSpacing(8)

        right_layout.addWidget(make_header_label("Challenge 진행 상황"))

        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        right_layout.addWidget(self.txt_log, 4)

        self.lbl_verdict_summary = QLabel("Verifier 결과: -")
        self.lbl_verdict_summary.setStyleSheet("font-weight: bold; color: #111827;")
        right_layout.addWidget(self.lbl_verdict_summary)

        root.addWidget(right_card, 2)

    def append_log(self, msg: str):
        self.txt_log.append(msg)

    # ── 버튼 핸들러 ───────────────────────────────────────────

    def on_fetch_clicked(self):
        api_base = self.api_base_input.text().strip()
        api_key = self.api_key_input.text().strip()
        ch_id = self.challenge_id_edit.text().strip()

        if not api_base or not ch_id:
            QMessageBox.warning(self, "입력 오류", "API 주소와 Challenge ID를 입력하세요.")
            return

        self.append_log("")
        self.append_log(f"[+] GET /api/challenges/{ch_id}")
        self.status_bar.showMessage("Challenge 정보 조회 중...")

        try:
            info = http_request(api_base, api_key, "GET", f"/api/challenges/{ch_id}")
            import json
            self.append_log(json.dumps(info, indent=2, ensure_ascii=False))
            self.status_bar.showMessage("Challenge 정보 조회 완료", 4000)
        except Exception as e:
            msg = str(e)
            self.append_log("[ERROR] " + msg)
            QMessageBox.critical(self, "에러", msg)
            self.status_bar.showMessage("에러 발생", 5000)

    def on_solve_clicked(self):
        api_base = self.api_base_input.text().strip()
        api_key = self.api_key_input.text().strip()
        ch_id = self.challenge_id_edit.text().strip()
        client_id = self.client_id_edit.text().strip()

        if not api_base or not ch_id or not client_id:
            QMessageBox.warning(self, "입력 오류", "API 주소, Challenge ID, Client ID를 입력하세요.")
            return

        self.txt_log.clear()
        self.append_log(f"[+] solve challenge: {ch_id}")
        self.btn_fetch.setEnabled(False)
        self.btn_solve.setEnabled(False)
        self.btn_verdict.setEnabled(False)
        self.status_bar.showMessage("Challenge 해결 중 (Analyzer 실행)...")

        self.worker = ChallengeSolveWorker(api_base, api_key, ch_id, client_id)
        self.worker.progress.connect(self.append_log)
        self.worker.finished_ok.connect(self.on_solve_finished_ok)
        self.worker.failed.connect(self.on_solve_failed)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()

    def on_solve_finished_ok(self):
        self.append_log("[+] challenge solved & results submitted.")
        QMessageBox.information(self, "완료", "Challenge 결과 업로드가 완료되었습니다.")
        self.status_bar.showMessage("Challenge 결과 업로드 완료", 5000)

    def on_solve_failed(self, msg: str):
        self.append_log("[ERROR] " + msg)
        QMessageBox.critical(self, "에러", msg)
        self.status_bar.showMessage("Challenge 처리 중 에러", 5000)

    def on_thread_finished(self):
        self.btn_fetch.setEnabled(True)
        self.btn_solve.setEnabled(True)
        self.btn_verdict.setEnabled(True)
        self.worker = None

    def on_verdict_clicked(self):
        api_base = self.api_base_input.text().strip()
        api_key = self.api_key_input.text().strip()
        ch_id = self.challenge_id_edit.text().strip()
        client_id = self.client_id_edit.text().strip()

        if not api_base or not ch_id or not client_id:
            QMessageBox.warning(self, "입력 오류", "API 주소, Challenge ID, Client ID를 입력하세요.")
            return

        self.append_log(f"[+] GET /api/challenges/{ch_id}/verdict?client_id={client_id}")
        self.status_bar.showMessage("Verifier 결과 조회 중...")

        try:
            params = {"client_id": client_id}
            info = http_request(api_base, api_key, "GET", f"/api/challenges/{ch_id}/verdict", params=params)
            import json
            self.append_log(json.dumps(info, indent=2, ensure_ascii=False))

            passed = info.get("passed")
            avg_sim = info.get("average_similarity")
            threshold = info.get("threshold")

            s = f"Verifier 결과: {'PASS' if passed else 'FAIL'} (avg_sim={avg_sim:.3f}, threshold={threshold})"
            color = "#16a34a" if passed else "#dc2626"
            self.lbl_verdict_summary.setText(s)
            self.lbl_verdict_summary.setStyleSheet(f"font-weight: bold; color: {color};")

            self.status_bar.showMessage("Verifier 결과 조회 완료", 5000)
        except Exception as e:
            msg = str(e)
            self.append_log("[ERROR] " + msg)
            QMessageBox.critical(self, "에러", msg)
            self.status_bar.showMessage("에러 발생", 5000)


# ─────────────────────────────────────────────────────────────
# Main Window + Docker 자동 기동
# ─────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phish-Guard Client")
        self.resize(1100, 720)

        # 라이트 테마 적용
        QApplication.setStyle("Fusion")
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window,        QColor("#e5e7eb"))
        palette.setColor(QPalette.ColorRole.WindowText,    QColor("#111827"))
        palette.setColor(QPalette.ColorRole.Base,          QColor("#ffffff"))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#f3f4f6"))
        palette.setColor(QPalette.ColorRole.ToolTipBase,   QColor("#ffffff"))
        palette.setColor(QPalette.ColorRole.ToolTipText,   QColor("#111827"))
        palette.setColor(QPalette.ColorRole.Text,          QColor("#111827"))
        palette.setColor(QPalette.ColorRole.Button,        QColor("#ffffff"))
        palette.setColor(QPalette.ColorRole.ButtonText,    QColor("#111827"))
        palette.setColor(QPalette.ColorRole.Highlight,     QColor("#2563eb"))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
        self.setPalette(palette)

        # 중앙 위젯
        central = QWidget()
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(12)

        # 상단: API 설정 카드
        config_card = make_card()
        cfg_layout = QFormLayout(config_card)
        cfg_layout.setContentsMargins(16, 12, 16, 12)
        cfg_layout.setVerticalSpacing(8)

        title = make_header_label("API 설정")
        cfg_layout.addRow(title)

        self.api_base_edit = QLineEdit(os.getenv("PG_API_BASE", "http://localhost:9000"))
        self.api_key_edit = QLineEdit(os.getenv("PG_API_KEY", ""))
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)

        cfg_layout.addRow("API Base URL:", self.api_base_edit)
        cfg_layout.addRow("X-API-Key:", self.api_key_edit)

        btn_row = QHBoxLayout()
        self.btn_ping = QPushButton("연결 테스트")
        self.btn_ping.clicked.connect(self.on_ping_clicked)
        btn_row.addWidget(self.btn_ping)
        btn_row.addStretch(1)
        cfg_layout.addRow(btn_row)

        main_layout.addWidget(config_card)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("준비됨")

        # 탭
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 0;
            }
            QTabBar::tab {
                background: #e5e7eb;
                color: #4b5563;
                padding: 8px 16px;
                border: 1px solid #d1d5db;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                color: #111827;
            }
        """)

        self.analyze_tab = AnalyzeTab(self.api_base_edit, self.api_key_edit, self.status_bar)
        self.challenge_tab = ChallengeTab(self.api_base_edit, self.api_key_edit, self.status_bar)

        tabs.addTab(self.analyze_tab, "URL 분석")
        tabs.addTab(self.challenge_tab, "Challenge 인증")

        main_layout.addWidget(tabs, 1)

        self.setCentralWidget(central)

        # 창 뜬 뒤 Docker 백엔드 자동 기동
        QTimer.singleShot(300, self.start_backend_if_needed)

    # ── Docker / API 보조 메서드 ────────────────────────────

    def _check_api_alive(self, api_base: str, timeout: int = 2) -> bool:
        try:
            r = requests.get(api_base.rstrip("/") + "/docs", timeout=timeout)
            return r.status_code in (200, 404)
        except Exception:
            return False

    def _run_docker_command(
        self,
        docker_path: str,
        args: str,
        cwd: Optional[Path] = None,
        timeout: int = 30,
    ):
        """
        docker.exe / docker.cmd 모두 처리 가능하게 shell=True + 문자열 커맨드 사용.
        출력은 안 읽고 returncode만 확인해서 Unicode 문제 회피.
        """
        cmd = f'"{docker_path}" {args}'
        cp = subprocess.run(
            cmd,
            shell=True,
            cwd=str(cwd) if cwd is not None else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        return cp.returncode, "", ""


    def _is_docker_daemon_running(self, docker_path: str) -> bool:
        try:
            rc, out, err = self._run_docker_command(docker_path, "info", timeout=10)
            if rc == 0:
                return True
        except Exception:
            pass
        return False

    def _start_docker_desktop(self) -> bool:
        """
        Docker Desktop 실행 시도.
        - 환경변수 DOCKER_DESKTOP_EXE / PG_DOCKER_DESKTOP_EXE 우선
        - 기본 경로 C:\Program Files\Docker\Docker\Docker Desktop.exe 시도
        """
        candidates: List[Path] = []

        custom = os.getenv("DOCKER_DESKTOP_EXE") or os.getenv("PG_DOCKER_DESKTOP_EXE")
        if custom:
            candidates.append(Path(custom))

        candidates.append(Path(r"C:\Program Files\Docker\Docker\Docker Desktop.exe"))

        for p in candidates:
            if p.is_file():
                try:
                    subprocess.Popen(
                        [str(p)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    return True
                except Exception:
                    continue
        return False

    # ── Docker 백엔드 자동 기동 ────────────────────────────

    def start_backend_if_needed(self):
        """프로그램 시작 시 Docker Desktop + docker compose up -d 자동 시도."""
        api_base = self.api_base_edit.text().strip()
        if not api_base:
            return

        compose_dir = Path(__file__).resolve().parent.parent  # D:\cap2

        # 0) 이미 API 살아있으면 바로 종료
        if self._check_api_alive(api_base, timeout=2):
            self.status_bar.showMessage("백엔드 이미 실행 중", 3000)
            return

        # 1) docker 경로 찾기
        docker_path = shutil.which("docker")
        if docker_path is None:
            QMessageBox.critical(
                self,
                "Docker 없음",
                "docker 명령어를 찾을 수 없습니다.\n"
                "Docker Desktop이 설치되어 있고 PATH에 등록되어 있는지 확인하세요.",
            )
            return

        # 2) 도커 데몬 상태 확인
        self.status_bar.showMessage("Docker 데몬 상태 확인 중...", 0)
        if not self._is_docker_daemon_running(docker_path):
            # Docker Desktop 자동 실행 시도
            started = self._start_docker_desktop()
            if not started:
                QMessageBox.critical(
                    self,
                    "Docker Desktop 실행 실패",
                    "Docker Desktop 실행 파일을 찾을 수 없습니다.\n"
                    "직접 Docker Desktop을 실행한 후 다시 시도해주세요.\n\n"
                    "필요하다면 환경변수 DOCKER_DESKTOP_EXE 에 경로를 지정할 수 있습니다.",
                )
                self.status_bar.showMessage("Docker Desktop 미실행", 5000)
                return

            self.status_bar.showMessage("Docker Desktop 기동 중 (도커 데몬 준비 대기)...", 0)

            # 최대 90초 동안 도커 데몬 준비될 때까지 대기
            for _ in range(90):
                QApplication.processEvents()
                time.sleep(1)
                if self._is_docker_daemon_running(docker_path):
                    break
            else:
                QMessageBox.critical(
                    self,
                    "Docker 데몬 기동 실패",
                    "Docker Desktop을 실행했지만 도커 데몬이 준비되지 않았습니다.\n"
                    "Docker Desktop 상태를 확인한 후 다시 시도해주세요.",
                )
                self.status_bar.showMessage("Docker 데몬 기동 실패", 5000)
                return

        # 3) docker compose up -d (백그라운드로 실행만 던져놓기)
        self.status_bar.showMessage("Docker 백엔드 컨테이너 기동 중...", 0)
        try:
            compose_cmd = f'"{docker_path}" compose up -d'
            subprocess.Popen(
                compose_cmd,
                shell=True,
                cwd=str(compose_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Docker 실행 실패",
                f"docker compose up 실행에 실패했습니다.\n\n{e}",
            )
            self.status_bar.showMessage("Docker 실행 실패", 5000)
            return


        # 4) API 살아날 때까지 대기
        for _ in range(30):
            QApplication.processEvents()
            time.sleep(1)
            if self._check_api_alive(api_base, timeout=2):
                self.status_bar.showMessage("백엔드 기동 완료", 5000)
                return

        QMessageBox.critical(
            self,
            "백엔드 기동 실패",
            "docker compose up 은 완료되었지만 API 서버(/docs)가 응답하지 않습니다.\n"
            "도커 컨테이너 로그를 확인해주세요.",
        )
        self.status_bar.showMessage("백엔드 기동 실패", 5000)

    # ── 상단 연결 테스트 ──────────────────────────────────

    def on_ping_clicked(self):
        api_base = self.api_base_edit.text().strip()
        if not api_base:
            QMessageBox.warning(self, "입력 오류", "API Base URL을 입력하세요.")
            return
        self.status_bar.showMessage("연결 테스트 중...", 0)

        try:
            resp = requests.get(api_base.rstrip("/") + "/docs", timeout=5)
            if resp.status_code in (200, 404):
                QMessageBox.information(self, "성공", "서버와 통신이 가능합니다.")
                self.status_bar.showMessage("연결 확인 완료", 5000)
            else:
                QMessageBox.warning(self, "응답 이상", f"HTTP {resp.status_code} 응답")
                self.status_bar.showMessage("서버 응답 이상", 5000)
        except Exception as e:
            QMessageBox.critical(self, "실패", f"서버에 연결할 수 없습니다.\n{e}")
            self.status_bar.showMessage("연결 실패", 5000)


# ─────────────────────────────────────────────────────────────
# 엔트리 포인트
# ─────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    font = QFont()
    font.setPointSize(10)
    app.setFont(font)

    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
