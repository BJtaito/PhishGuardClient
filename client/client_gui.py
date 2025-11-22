"""
Phish-Guard Client GUI

- 로컬 백엔드와 메인 서버에 동시에 URL 분석 요청
- /health_pubkey + /healthz 기반 링크 무결성 체크
- /api/analyze/{id} 응답의 signed_payload/sig 서명 검증
- 최초 실행 시 config.json 자동 생성 (설정/업데이트/환경 분리용)

의존 패키지:
    pip install PyQt6 requests cryptography
"""

import os
import sys
import time
import subprocess
import shutil
import socket
import platform
import json
import base64
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from PyQt6.QtCore import QThread, pyqtSignal, QTimer
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
    QFrame,
    QStatusBar,
    QProgressBar,
)

# ─────────────────────────────────────────────────────────────
# cryptography (서명 검증용)
# ─────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

# ─────────────────────────────────────────────────────────────
# 기본 설정/전역 상태 (bootstrap에서 override)
# ─────────────────────────────────────────────────────────────

APP_NAME = "PhishGuardClient"

# 로컬 백엔드: Docker 컨테이너 (HTTP)
LOCAL_API_BASE = os.getenv("PG_LOCAL_API_BASE", "http://127.0.0.1:9000")

# 메인 서버 기본값 (bootstrap에서 config/env로 덮어씀)
DEFAULT_MAIN_API_BASE = "https://127.0.0.1:14444"

# API 키 기본값 (bootstrap에서 config/env로 덮어씀)
DEFAULT_API_KEY = "dev-key-123"

# TLS 검증 (False / True / CA bundle path) - bootstrap에서 최종 결정
_TLS_VERIFY: Any = False

# config.json 로딩 결과
CONFIG: Dict[str, Any] = {}

try:
    _HOSTNAME = socket.gethostname()
except Exception:
    _HOSTNAME = "unknown-host"

CLIENT_ID = os.getenv("PG_CLIENT_ID") or f"desktop-{_HOSTNAME}"
CLIENT_VERSION = "pg-client-0.5.0"

GITHUB_REPO = "BJtaito/PhishGuardClient"  # 나중에 업데이트 체크 등에 쓸 수 있음

# health_pubkey 캐시
_PUBKEY_CACHE: Dict[str, Any] = {}

# ─────────────────────────────────────────────────────────────
# bootstrap: config.json 생성 + 환경 적용
# ─────────────────────────────────────────────────────────────

def get_app_dir() -> Path:
    """플랫폼별 기본 설정 디렉터리 결정."""
    if os.name == "nt":
        base = os.getenv("APPDATA", str(Path.home()))
        return Path(base) / APP_NAME
    else:
        base = os.getenv("XDG_CONFIG_HOME", str(Path.home() / ".config"))
        return Path(base) / APP_NAME


def ensure_config(app_dir: Path) -> Path:
    """
    APPDIR/config.json 이 없으면 기본 템플릿으로 생성.
    (민감한 값 없이 구조만 잡아둔 형태)
    """
    cfg_path = app_dir / "config.json"
    if cfg_path.exists():
        return cfg_path

    default_cfg = {
        # 메인 서버 주소 (없으면 코드 기본값 사용)
        "main_api_base": "",
        # 사용자 API 키 (없으면 GUI에서 입력)
        "api_key": "",
        # TLS 검증 설정: false / true / "path/to/ca.pem"
        "tls_verify": False,
        # Challenge 탭 노출 여부 (기본 OFF)
        "enable_challenge_tab": False,
        # 업데이트 채널 (나중에 활용 가능)
        "update_channel": "stable",
    }

    cfg_path.write_text(
        json.dumps(default_cfg, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return cfg_path


def load_config(app_dir: Path) -> Dict[str, Any]:
    cfg_path = ensure_config(app_dir)
    try:
        text = cfg_path.read_text(encoding="utf-8")
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def bootstrap():
    """
    - APPDATA/XDG_CONFIG_HOME 아래에 앱 디렉토리 및 config.json 생성
    - config/env를 읽어 DEFAULT_MAIN_API_BASE, DEFAULT_API_KEY, _TLS_VERIFY 반영
    - TLS verify가 False이면 InsecureRequestWarning 경고 비활성화
    """
    global CONFIG, DEFAULT_MAIN_API_BASE, DEFAULT_API_KEY, _TLS_VERIFY

    app_dir = get_app_dir()
    app_dir.mkdir(parents=True, exist_ok=True)

    CONFIG = load_config(app_dir)

    # ─ Main API BASE: env > config > 기본값
    env_main = os.getenv("PG_MAIN_API_BASE")
    if env_main:
        DEFAULT_MAIN_API_BASE = env_main
    else:
        cfg_main = CONFIG.get("main_api_base")
        if isinstance(cfg_main, str) and cfg_main.strip():
            DEFAULT_MAIN_API_BASE = cfg_main.strip()

    # ─ API KEY: env > config > 기본값
    env_key = os.getenv("PG_API_KEY") or os.getenv("API_KEY")
    if env_key:
        DEFAULT_API_KEY = env_key
    else:
        cfg_key = CONFIG.get("api_key")
        if isinstance(cfg_key, str) and cfg_key.strip():
            DEFAULT_API_KEY = cfg_key.strip()

    # ─ TLS VERIFY: env > config > 기본 False
    env_tls = os.getenv("PG_TLS_VERIFY")
    if env_tls is not None:
        low = env_tls.lower()
        if low in ("0", "false", "no", "off"):
            _TLS_VERIFY = False
        elif low in ("1", "true", "yes", "on"):
            _TLS_VERIFY = True
        else:
            _TLS_VERIFY = env_tls  # CA 경로
    else:
        tls_cfg = CONFIG.get("tls_verify")
        if isinstance(tls_cfg, bool):
            _TLS_VERIFY = tls_cfg
        elif isinstance(tls_cfg, str) and tls_cfg.strip():
            low = tls_cfg.lower()
            if low in ("0", "false", "no", "off"):
                _TLS_VERIFY = False
            elif low in ("1", "true", "yes", "on"):
                _TLS_VERIFY = True
            else:
                _TLS_VERIFY = tls_cfg.strip()

    # ─ TLS 검증 꺼져 있으면 urllib3 경고 숨김
    if _TLS_VERIFY is False:
        try:
            import urllib3
            from urllib3.exceptions import InsecureRequestWarning

            urllib3.disable_warnings(InsecureRequestWarning)
        except Exception:
            # 경고 끄는 데 실패해도 동작에는 영향 없음
            pass


# ─────────────────────────────────────────────────────────────
# 공통 HTTP / 서명 검증 유틸
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
    """API 서버와 통신하는 공통 함수 (TLS verify 적용)."""
    url = api_base.rstrip("/") + path
    headers: Dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key
    resp = requests.request(
        method,
        url,
        headers=headers,
        json=json_data,
        params=params,
        timeout=60,
        verify=_TLS_VERIFY,
    )
    resp.raise_for_status()
    return resp.json()


def derive_verdict_score(result: Dict[str, Any]) -> Tuple[Optional[str], Optional[float]]:
    """result(dict)에서 verdict/score를 계산해서 돌려준다."""
    verdict = result.get("verdict")
    score = result.get("score")

    rs = None
    try:
        raw_rs = result.get("risk_score")
        rs = float(raw_rs) if raw_rs is not None else None
    except Exception:
        rs = None

    if score is None and rs is not None:
        score = rs
        result["score"] = score

    if verdict is None and rs is not None:
        if rs >= 80:
            verdict = "phishing"
        elif rs >= 40:
            verdict = "suspicious"
        else:
            verdict = "benign"
        result["verdict"] = verdict

    return verdict, score


def verdict_to_risk(verdict: Optional[str], score: Optional[float]) -> Tuple[str, str]:
    """verdict/score → (리스크 텍스트, 색상코드)."""
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


def _b64u_decode(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def get_server_pubkey(api_base: str, timeout: int = 5):
    """ /health_pubkey 에서 ECDSA(P-256) 공개키(JWK)를 가져와 캐시. """
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography 미설치")

    base = api_base.rstrip("/")
    if base in _PUBKEY_CACHE:
        return _PUBKEY_CACHE[base]

    r_pub = requests.get(base + "/health_pubkey", timeout=timeout, verify=_TLS_VERIFY)
    r_pub.raise_for_status()
    jwk = r_pub.json()

    try:
        x_b = _b64u_decode(jwk["x"])
        y_b = _b64u_decode(jwk["y"])
        x_int = int.from_bytes(x_b, "big")
        y_int = int.from_bytes(y_b, "big")
        nums = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1())
        pub = nums.public_key()
    except Exception as e:
        raise RuntimeError(f"공개키 파싱 실패: {e}") from e

    _PUBKEY_CACHE[base] = pub
    return pub


def verify_healthz_signature(api_base: str, timeout: int = 5) -> Tuple[bool, str]:
    """
    /health_pubkey + /healthz?nonce=... 를 이용하여
    링크 무결성(중간자 공격 여부)을 확인한다.
    """
    if not _HAS_CRYPTO:
        return False, "cryptography 미설치"

    base = api_base.rstrip("/")
    try:
        pub = get_server_pubkey(api_base, timeout=timeout)
    except Exception as e:
        return False, f"health_pubkey 실패: {e}"

    nonce = os.urandom(12).hex()
    try:
        r_h = requests.get(
            base + "/healthz",
            params={"nonce": nonce},
            timeout=timeout,
            verify=_TLS_VERIFY,
        )
        r_h.raise_for_status()
        data = r_h.json()
    except Exception as e:
        return False, f"healthz 실패: {e}"

    payload_str = data.get("payload")
    sig_b64u = data.get("sig")
    if not isinstance(payload_str, str) or not isinstance(sig_b64u, str):
        return False, "healthz 응답 형식 오류"

    try:
        payload = json.loads(payload_str)
    except Exception as e:
        return False, f"payload JSON 파싱 실패: {e}"

    if payload.get("nonce") != nonce:
        return False, "nonce 불일치 (중간 변조 가능성)"

    try:
        sig_bytes = _b64u_decode(sig_b64u)
        pub.verify(sig_bytes, payload_str.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "서명 검증 실패 (tamper)"
    except Exception as e:
        return False, f"서명 검증 에러: {e}"

    server_id = payload.get("server_id", "unknown")
    ts = payload.get("ts", "")
    return True, f"server_id={server_id}, ts={ts}"


def verify_task_result_signature(
    api_base: str, task_resp: Dict[str, Any]
) -> Tuple[Optional[Dict[str, Any]], bool, str]:
    """
    /api/analyze/{id} 응답의 signed_payload / sig 서명을 검증한다.
    반환: (payload(dict) or None, ok, msg)
    """
    if not _HAS_CRYPTO:
        return None, False, "cryptography 미설치"

    signed_payload = task_resp.get("signed_payload")
    sig_b64u = task_resp.get("sig")

    if not isinstance(signed_payload, str) or not isinstance(sig_b64u, str):
        return None, False, "서명 필드 없음 (signed_payload/sig)"

    try:
        pub = get_server_pubkey(api_base)
    except Exception as e:
        return None, False, f"health_pubkey 조회 실패: {e}"

    try:
        sig_bytes = _b64u_decode(sig_b64u)
        pub.verify(sig_bytes, signed_payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return None, False, "서명 검증 실패"
    except Exception as e:
        return None, False, f"서명 검증 에러: {e}"

    try:
        payload = json.loads(signed_payload)
    except Exception as e:
        return None, False, f"signed_payload JSON 파싱 실패: {e}"

    return payload, True, "ok"


# ─────────────────────────────────────────────────────────────
# /api/analyze 1회 실행
# ─────────────────────────────────────────────────────────────

def analyze_once(
    api_base: str,
    api_key: str,
    url: str,
    progress_cb=None,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    def log(msg: str):
        if progress_cb is not None:
            progress_cb(msg)

    log(f"[+] analyze: {url}")

    payload: Dict[str, Any] = {"url": url}
    if meta:
        payload["meta"] = meta

    data = http_request(
        api_base,
        api_key,
        "POST",
        "/api/analyze",
        json_data=payload,
    )

    job_id = data.get("job_id") or data.get("task_id")
    if not job_id:
        log("[ERROR] invalid response from /api/analyze (no job_id/task_id)")
        log("  raw response: " + json.dumps(data, indent=2, ensure_ascii=False))
        raise RuntimeError("server response has no job_id/task_id")

    log(f"  job_id: {job_id}")

    last_status = None
    status: Dict[str, Any] = {}
    while True:
        time.sleep(1.0)
        status = http_request(api_base, api_key, "GET", f"/api/analyze/{job_id}")
        s = status.get("status")
        if s != last_status:
            log(f"  status: {s}")
            last_status = s
        if s in ("done", "error", "failed"):
            break

    # ─ 결과 서명 검증 ─
    result: Dict[str, Any] = {}
    integrity: Dict[str, Any] = {}

    if status.get("signed_payload") is not None and status.get("sig") is not None:
        payload_signed, ok, msg = verify_task_result_signature(api_base, status)
        if ok and payload_signed is not None:
            result = payload_signed.get("result") or {}
            integrity["signature_ok"] = True
        else:
            log(f"[WARN] 결과 서명 검증 실패/에러: {msg}")
            integrity["signature_ok"] = False
            integrity["signature_error"] = msg
            result = status.get("result") or {}
    else:
        result = status.get("result") or {}

    if integrity:
        result.setdefault("integrity", {}).update(integrity)

    verdict, score = derive_verdict_score(result)

    log("=== final ===")
    log(f"verdict: {verdict}")
    log(f"score  : {score}")
    if status.get("error"):
        log(f"error  : {status.get('error')}")

    if result.get("integrity", {}).get("signature_ok") is True:
        log("[+] 결과 서명 검증: OK")
    elif "signature_ok" in result.get("integrity", {}):
        log("[!] 결과 서명 검증: FAIL / 오류")

    return result


# ─────────────────────────────────────────────────────────────
# Worker Threads
# ─────────────────────────────────────────────────────────────

class AnalyzeWorker(QThread):
    """로컬 서버 분석용 워커"""
    progress = pyqtSignal(str)
    finished_ok = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(
        self,
        api_base: str,
        api_key: str,
        url: str,
        meta: Optional[Dict[str, Any]] = None,
    ):
        super().__init__()
        self.api_base = api_base
        self.api_key = api_key
        self.url = url
        self.meta = meta or {}

    def run(self):
        try:
            result = analyze_once(
                self.api_base,
                self.api_key,
                self.url,
                progress_cb=lambda m: self.progress.emit(m),
                meta=self.meta,
            )
            self.finished_ok.emit(result)
        except Exception as e:
            self.failed.emit(str(e))


class MainAnalyzeWorker(QThread):
    """메인 서버 분석용 워커"""
    progress = pyqtSignal(str)
    finished_ok = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(
        self,
        api_base: str,
        api_key: str,
        url: str,
        meta: Optional[Dict[str, Any]] = None,
    ):
        super().__init__()
        self.api_base = api_base
        self.api_key = api_key
        self.url = url
        self.meta = meta or {}

    def run(self):
        try:
            result = analyze_once(
                self.api_base,
                self.api_key,
                self.url,
                progress_cb=lambda m: self.progress.emit(m),
                meta=self.meta,
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
    frame = QFrame()
    frame.setFrameShape(QFrame.Shape.StyledPanel)
    frame.setFrameShadow(QFrame.Shadow.Raised)
    frame.setStyleSheet(
        """
        QFrame {
            background-color: #fff7fb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
        }
        """
    )
    return frame


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
        self.worker_main: Optional[MainAnalyzeWorker] = None

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

        # ─ Local 결과 ─
        header = QHBoxLayout()
        header.addWidget(make_header_label("Local 결과 요약 (127.0.0.1:9000)"))
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

        http_row = QHBoxLayout()
        http_row.addWidget(QLabel("HTTP Status:"))
        self.lbl_http_status = QLabel("-")
        self.lbl_http_status.setStyleSheet("color: #6b7280;")
        http_row.addWidget(self.lbl_http_status)
        http_row.addStretch(1)
        right_layout.addLayout(http_row)

        dl_row = QHBoxLayout()
        dl_row.addWidget(QLabel("다운로드 스캔:"))
        self.lbl_downloads = QLabel("-")
        self.lbl_downloads.setStyleSheet("color: #9ca3af;")
        dl_row.addWidget(self.lbl_downloads)
        dl_row.addStretch(1)
        right_layout.addLayout(dl_row)

        sig_row_l = QHBoxLayout()
        sig_row_l.addWidget(QLabel("Local 결과 서명:"))
        self.lbl_sig_local = QLabel("N/A")
        self.lbl_sig_local.setStyleSheet("color: #9ca3af; font-weight: bold;")
        sig_row_l.addWidget(self.lbl_sig_local)
        sig_row_l.addStretch(1)
        right_layout.addLayout(sig_row_l)

        # ─ Main 결과 ─
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        right_layout.addWidget(sep)

        right_layout.addWidget(make_header_label("Main 서버 결과 요약"))

        risk_row_m = QHBoxLayout()
        risk_row_m.addWidget(QLabel("Main Risk:"))
        self.lbl_risk_main = QLabel("N/A")
        self.lbl_risk_main.setStyleSheet("color: #6b7280; font-weight: bold;")
        risk_row_m.addWidget(self.lbl_risk_main)
        risk_row_m.addStretch(1)
        right_layout.addLayout(risk_row_m)

        vs_row_m = QHBoxLayout()
        self.lbl_verdict_main = QLabel("Main Verdict: -")
        self.lbl_score_main = QLabel("Main Score: -")
        vs_row_m.addWidget(self.lbl_verdict_main)
        vs_row_m.addWidget(self.lbl_score_main)
        vs_row_m.addStretch(1)
        right_layout.addLayout(vs_row_m)

        http_row_m = QHBoxLayout()
        http_row_m.addWidget(QLabel("Main HTTP:"))
        self.lbl_http_status_main = QLabel("-")
        self.lbl_http_status_main.setStyleSheet("color: #6b7280;")
        http_row_m.addWidget(self.lbl_http_status_main)
        http_row_m.addStretch(1)
        right_layout.addLayout(http_row_m)

        dl_row_m = QHBoxLayout()
        dl_row_m.addWidget(QLabel("Main 다운로드:"))
        self.lbl_downloads_main = QLabel("-")
        self.lbl_downloads_main.setStyleSheet("color: #9ca3af;")
        dl_row_m.addWidget(self.lbl_downloads_main)
        dl_row_m.addStretch(1)
        right_layout.addLayout(dl_row_m)

        sig_row_m = QHBoxLayout()
        sig_row_m.addWidget(QLabel("Main 결과 서명:"))
        self.lbl_sig_main = QLabel("N/A")
        self.lbl_sig_main.setStyleSheet("color: #9ca3af; font-weight: bold;")
        sig_row_m.addWidget(self.lbl_sig_main)
        sig_row_m.addStretch(1)
        right_layout.addLayout(sig_row_m)

        # 진행 상태 ProgressBar
        prog_row = QHBoxLayout()
        prog_row.addWidget(QLabel("진행 상태:"))
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(14)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        prog_row.addWidget(self.progress_bar)
        right_layout.addLayout(prog_row)

        self.progress_timer = QTimer(self)
        self.progress_timer.timeout.connect(self._on_progress_tick)

        right_layout.addWidget(QLabel("Local Raw Result (JSON):"))
        self.txt_json = QTextEdit()
        self.txt_json.setReadOnly(True)
        self.txt_json.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        right_layout.addWidget(self.txt_json, 4)

        right_layout.addWidget(QLabel("로그 (Local + Main):"))
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        right_layout.addWidget(self.txt_log, 3)

        root.addWidget(right_card, 2)

    # ── 로직 ──────────────────────────────────────────────────

    def _on_progress_tick(self):
        v = self.progress_bar.value()
        if v < 90:
            self.progress_bar.setValue(v + 3)

    def append_log(self, msg: str):
        self.txt_log.append(msg)

    def set_result_summary(self, result: Optional[Dict[str, Any]], *, kind: str = "local"):
        """
        kind = "local"  → Local 결과 라벨 + JSON 업데이트
        kind = "main"   → Main 결과 라벨만 업데이트
        """
        if not result:
            if kind == "local":
                self.lbl_risk.setText("N/A")
                self.lbl_risk.setStyleSheet("color: #6b7280; font-weight: bold;")
                self.lbl_verdict.setText("Verdict: -")
                self.lbl_score.setText("Score: -")
                self.lbl_http_status.setText("-")
                self.lbl_downloads.setText("정보 없음")
                self.lbl_downloads.setStyleSheet("color: #9ca3af;")
                self.lbl_sig_local.setText("N/A")
                self.lbl_sig_local.setStyleSheet("color: #9ca3af; font-weight: bold;")
                self.txt_json.clear()
            else:
                self.lbl_risk_main.setText("N/A")
                self.lbl_risk_main.setStyleSheet("color: #6b7280; font-weight: bold;")
                self.lbl_verdict_main.setText("Main Verdict: -")
                self.lbl_score_main.setText("Main Score: -")
                self.lbl_http_status_main.setText("-")
                self.lbl_downloads_main.setText("-")
                self.lbl_downloads_main.setStyleSheet("color: #9ca3af;")
                self.lbl_sig_main.setText("N/A")
                self.lbl_sig_main.setStyleSheet("color: #9ca3af; font-weight: bold;")
            return

        verdict, score = derive_verdict_score(result)
        risk_txt, color = verdict_to_risk(verdict, score)

        features = result.get("features") or {}
        http_status = features.get("http_status")

        dl_summary = features.get("downloads_summary") or {}
        dl_enabled = dl_summary.get("enabled", False)
        dl_ran = dl_summary.get("ran", False)
        dl_count = dl_summary.get("download_count", 0)
        max_vt_risk = dl_summary.get("max_vt_risk", None)

        if not dl_enabled:
            dl_text = "비활성화됨"
            dl_color = "#9ca3af"
        elif not dl_ran:
            dl_text = "실행 안 됨"
            dl_color = "#f97316"
        elif dl_count == 0:
            dl_text = "다운로드 없음"
            dl_color = "#6b7280"
        else:
            if max_vt_risk is None:
                verdict_dl = "검사 결과 없음"
                dl_color = "#9ca3af"
            else:
                if max_vt_risk < 20:
                    verdict_dl = "정상"
                    dl_color = "#10b981"
                elif max_vt_risk < 50:
                    verdict_dl = "주의"
                    dl_color = "#facc15"
                else:
                    verdict_dl = "위험"
                    dl_color = "#ef4444"

            if max_vt_risk is None:
                dl_text = f"{dl_count}개 ({verdict_dl})"
            else:
                dl_text = f"{dl_count}개 ({verdict_dl}, max VT risk={max_vt_risk:.1f}%)"

        integrity = result.get("integrity") or {}
        sig_ok = integrity.get("signature_ok")
        if sig_ok is True:
            sig_text = "OK"
            sig_color = "#16a34a"
        elif sig_ok is False:
            sig_text = "FAIL"
            sig_color = "#ef4444"
        else:
            sig_text = "N/A"
            sig_color = "#9ca3af"

        json_text = json.dumps(result, indent=2, ensure_ascii=False)

        if kind == "local":
            self.lbl_risk.setText(risk_txt)
            self.lbl_risk.setStyleSheet(f"color: {color}; font-weight: bold;")
            self.lbl_verdict.setText(f"Verdict: {verdict if verdict is not None else '-'}")
            self.lbl_score.setText(f"Score: {score if score is not None else '-'}")
            self.lbl_http_status.setText(str(http_status) if http_status is not None else "-")
            self.lbl_downloads.setText(dl_text)
            self.lbl_downloads.setStyleSheet(f"color: {dl_color};")
            self.lbl_sig_local.setText(sig_text)
            self.lbl_sig_local.setStyleSheet(f"color: {sig_color}; font-weight: bold;")
            self.txt_json.setPlainText(json_text)
        else:
            self.lbl_risk_main.setText(risk_txt)
            self.lbl_risk_main.setStyleSheet(f"color: {color}; font-weight: bold;")
            self.lbl_verdict_main.setText(
                f"Main Verdict: {verdict if verdict is not None else '-'}"
            )
            self.lbl_score_main.setText(
                f"Main Score: {score if score is not None else '-'}"
            )
            self.lbl_http_status_main.setText(
                str(http_status) if http_status is not None else "-"
            )
            self.lbl_downloads_main.setText(dl_text)
            self.lbl_downloads_main.setStyleSheet(f"color: {dl_color};")
            self.lbl_sig_main.setText(sig_text)
            self.lbl_sig_main.setStyleSheet(f"color: {sig_color}; font-weight: bold;")

    def on_analyze_clicked(self):
        api_key = self.api_key_input.text().strip()
        url = self.url_edit.text().strip()

        if not url:
            QMessageBox.warning(self, "입력 오류", "분석할 URL을 입력하세요.")
            return

        local_api = LOCAL_API_BASE
        main_api = self.api_base_input.text().strip() or None

        self.txt_log.clear()
        self.txt_json.clear()
        self.set_result_summary({}, kind="local")
        self.set_result_summary({}, kind="main")

        self.append_log(f"[+] Local API = {local_api}")
        if main_api:
            self.append_log(f"[+] Main  API = {main_api}")
        else:
            self.append_log("[i] 메인 서버: URL 미입력 (로컬만 사용)")
        self.append_log(f"[+] URL       = {url}")

        self.btn_analyze.setEnabled(False)
        self.status_bar.showMessage("분석 중...")

        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_timer.start(300)

        meta = {
            "client": {
                "id": CLIENT_ID,
                "version": CLIENT_VERSION,
                "platform": platform.system(),
                "hostname": _HOSTNAME,
                "ui": "desktop-gui",
            },
            "source": "client_gui",
        }

        self.worker = AnalyzeWorker(local_api, api_key, url, meta=meta)
        self.worker.progress.connect(self.append_log)
        self.worker.finished_ok.connect(self.on_finished_ok)
        self.worker.failed.connect(self.on_failed)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()

        if main_api:
            self.worker_main = MainAnalyzeWorker(main_api, api_key, url, meta=meta)
            self.worker_main.progress.connect(
                lambda m: self.append_log(f"[main] {m}")
            )
            self.worker_main.finished_ok.connect(self.on_main_finished_ok)
            self.worker_main.failed.connect(self.on_main_failed)
            self.worker_main.start()
        else:
            self.worker_main = None

    def on_finished_ok(self, result: Dict[str, Any]):
        self.append_log("")
        self.append_log("[+] 로컬 분석 완료")
        self.set_result_summary(result, kind="local")
        self.status_bar.showMessage("분석 완료", 5000)

        self.progress_timer.stop()
        self.progress_bar.setValue(100)

    def on_failed(self, msg: str):
        self.append_log("[ERROR] " + msg)
        QMessageBox.critical(self, "에러", msg)
        self.status_bar.showMessage("에러 발생", 5000)

        self.progress_timer.stop()
        self.progress_bar.setValue(0)

    def on_main_finished_ok(self, result: Dict[str, Any]):
        self.append_log("")
        self.append_log("[main] 메인 서버 분석 완료 (tasks/*.json 저장 완료 예상)")
        try:
            pretty = json.dumps(result, indent=2, ensure_ascii=False)
            self.append_log("[main] result:\n" + pretty)
        except Exception:
            self.append_log("[main] (결과 JSON 직렬화 실패)")

        self.set_result_summary(result, kind="main")

    def on_main_failed(self, msg: str):
        self.append_log(f"[main][ERROR] {msg}")
        self.lbl_risk_main.setText("ERROR")
        self.lbl_risk_main.setStyleSheet("color: #ef4444; font-weight: bold;")
        self.lbl_verdict_main.setText("Main Verdict: error")
        self.lbl_score_main.setText("Main Score: -")
        self.lbl_http_status_main.setText("N/A")
        self.lbl_downloads_main.setText("에러")
        self.lbl_downloads_main.setStyleSheet("color: #ef4444;")
        self.lbl_sig_main.setText("N/A")
        self.lbl_sig_main.setStyleSheet("color: #9ca3af; font-weight: bold;")

    def on_thread_finished(self):
        self.btn_analyze.setEnabled(True)
        self.worker = None


# ─────────────────────────────────────────────────────────────
# 탭: Challenge 인증 (옵션)
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

        for btn in (self.btn_fetch, self.btn_solve, self.btn_verdict):
            btn.setMinimumHeight(32)

        self.btn_fetch.clicked.connect(self.on_fetch_clicked)
        self.btn_solve.clicked.connect(self.on_solve_clicked)
        self.btn_verdict.clicked.connect(self.on_verdict_clicked)

        left_layout.addWidget(self.btn_fetch)
        left_layout.addWidget(self.btn_solve)
        left_layout.addWidget(self.btn_verdict)
        left_layout.addStretch(1)

        root.addWidget(left_card, 1)

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
            info = http_request(
                api_base, api_key, "GET", f"/api/challenges/{ch_id}/verdict", params=params
            )
            self.append_log(json.dumps(info, indent=2, ensure_ascii=False))

            passed = info.get("passed")
            avg_sim = info.get("average_similarity")
            threshold = info.get("threshold")

            if avg_sim is not None:
                s = (
                    f"Verifier 결과: {'PASS' if passed else 'FAIL'} "
                    f"(avg_sim={avg_sim:.3f}, threshold={threshold})"
                )
            else:
                s = f"Verifier 결과: {'PASS' if passed else 'FAIL'}"

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

        QApplication.setStyle("Fusion")
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor("#fff7fb"))
        palette.setColor(QPalette.ColorRole.WindowText, QColor("#111827"))
        palette.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#ffeef5"))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#ffffff"))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#111827"))
        palette.setColor(QPalette.ColorRole.Text, QColor("#111827"))
        palette.setColor(QPalette.ColorRole.Button, QColor("#ffffff"))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor("#111827"))
        palette.setColor(QPalette.ColorRole.Highlight, QColor("#f472b6"))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
        self.setPalette(palette)

        self.local_online = False
        self.main_online = False
        self.local_trust_ok = False
        self.main_trust_ok = False
        self._last_trust_local = 0.0
        self._last_trust_main = 0.0

        central = QWidget()
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(12)

        # 상단: 연결 설정 카드
        config_card = make_card()
        cfg_layout = QFormLayout(config_card)
        cfg_layout.setContentsMargins(16, 12, 16, 12)
        cfg_layout.setVerticalSpacing(8)

        title = make_header_label("연결 설정")
        cfg_layout.addRow(title)

        # Local 서버 상태
        self.lbl_local_status = QLabel("확인 중...")
        self.lbl_local_status.setStyleSheet("color: #6b7280;")
        cfg_layout.addRow("Local 서버 (127.0.0.1:9000):", self.lbl_local_status)

        # Local 링크 서명 상태
        self.lbl_local_trust = QLabel("미검증")
        self.lbl_local_trust.setStyleSheet("color: #6b7280;")
        cfg_layout.addRow("Local 링크 서명:", self.lbl_local_trust)

        # Main 서버 URL + 상태 (CONFIG/main_api_base → DEFAULT_MAIN_API_BASE 순)
        default_main = CONFIG.get("main_api_base") or DEFAULT_MAIN_API_BASE
        self.api_base_edit = QLineEdit(default_main)
        h_main = QHBoxLayout()
        h_main.addWidget(self.api_base_edit)
        self.lbl_main_status = QLabel("미확인")
        self.lbl_main_status.setStyleSheet("color: #6b7280;")
        h_main.addWidget(self.lbl_main_status)
        cfg_layout.addRow("Main Server URL:", h_main)

        # Main 링크 서명 상태
        self.lbl_main_trust = QLabel("미검증")
        self.lbl_main_trust.setStyleSheet("color: #6b7280;")
        cfg_layout.addRow("Main 링크 서명:", self.lbl_main_trust)

        # API Key (CONFIG/api_key → DEFAULT_API_KEY 순)
        default_key = CONFIG.get("api_key") or DEFAULT_API_KEY
        self.api_key_edit = QLineEdit(default_key)
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
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
        tabs.setStyleSheet(
            """
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
            """
        )

        self.analyze_tab = AnalyzeTab(self.api_base_edit, self.api_key_edit, self.status_bar)
        tabs.addTab(self.analyze_tab, "URL 분석")

        # Challenge 탭은 config.enable_challenge_tab 이 True일 때만 표시
        self.challenge_tab: Optional[ChallengeTab] = None
        if bool(CONFIG.get("enable_challenge_tab", False)):
            self.challenge_tab = ChallengeTab(self.api_base_edit, self.api_key_edit, self.status_bar)
            tabs.addTab(self.challenge_tab, "Challenge 인증 (테스트)")

        main_layout.addWidget(tabs, 1)
        self.setCentralWidget(central)

        # 창 뜬 뒤 Docker 백엔드 자동 기동 (로컬 서버용)
        QTimer.singleShot(300, self.start_backend_if_needed)

        # 주기적으로 로컬/메인 서버 상태 + 링크 서명 체크
        self.health_timer = QTimer(self)
        self.health_timer.timeout.connect(self.update_server_status)
        self.health_timer.start(5000)
        QTimer.singleShot(1000, self.update_server_status)

    # ─ Docker / API 보조 메서드 ─

    def _check_api_alive(self, api_base: str, timeout: int = 2) -> bool:
        try:
            r = requests.get(
                api_base.rstrip("/") + "/health",
                timeout=timeout,
                verify=_TLS_VERIFY,
            )
            return r.status_code == 200
        except Exception:
            return False

    def _run_docker_command(
        self,
        docker_path: str,
        args: str,
        cwd: Optional[Path] = None,
        timeout: int = 30,
    ):
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
            rc, _out, _err = self._run_docker_command(docker_path, "info", timeout=10)
            return rc == 0
        except Exception:
            return False

    def _start_docker_desktop(self) -> bool:
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

    # 로컬 백엔드 자동 기동

    def start_backend_if_needed(self):
        api_base = LOCAL_API_BASE
        compose_dir = Path(__file__).resolve().parent.parent

        if self._check_api_alive(api_base, timeout=2):
            self.status_bar.showMessage("로컬 백엔드 이미 실행 중", 3000)
            return

        docker_path = shutil.which("docker")
        if docker_path is None:
            QMessageBox.critical(
                self,
                "Docker 없음",
                "docker 명령어를 찾을 수 없습니다.\n"
                "Docker Desktop이 설치되어 있고 PATH에 등록되어 있는지 확인하세요.",
            )
            return

        self.status_bar.showMessage("Docker 데몬 상태 확인 중...", 0)
        if not self._is_docker_daemon_running(docker_path):
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

        for _ in range(30):
            QApplication.processEvents()
            time.sleep(1)
            if self._check_api_alive(api_base, timeout=2):
                self.status_bar.showMessage("로컬 백엔드 기동 완료", 5000)
                return

        QMessageBox.critical(
            self,
            "백엔드 기동 실패",
            "docker compose up 은 완료되었지만 로컬 API 서버(/health)가 응답하지 않습니다.\n"
            "도커 컨테이너 로그를 확인해주세요.",
        )
        self.status_bar.showMessage("백엔드 기동 실패", 5000)

    # ─ 링크 서명 상태 업데이트 ─

    def _update_trust_for(self, api_base: str, *, is_local: bool):
        ok, msg = verify_healthz_signature(api_base, timeout=5)
        if is_local:
            if ok:
                self.local_trust_ok = True
                self.lbl_local_trust.setText("서명 OK")
                self.lbl_local_trust.setStyleSheet("color: #16a34a; font-weight: bold;")
                if msg:
                    self.status_bar.showMessage(f"Local 링크 서명 OK ({msg})", 4000)
            else:
                self.local_trust_ok = False
                txt = "서명 실패" + (f" ({msg})" if msg else "")
                self.lbl_local_trust.setText(txt)
                self.lbl_local_trust.setStyleSheet("color: #ef4444; font-weight: bold;")
        else:
            if ok:
                self.main_trust_ok = True
                self.lbl_main_trust.setText("서명 OK")
                self.lbl_main_trust.setStyleSheet("color: #16a34a; font-weight: bold;")
                if msg:
                    self.status_bar.showMessage(f"Main 링크 서명 OK ({msg})", 4000)
            else:
                self.main_trust_ok = False
                txt = "서명 실패" + (f" ({msg})" if msg else "")
                self.lbl_main_trust.setText(txt)
                self.lbl_main_trust.setStyleSheet("color: #ef4444; font-weight: bold;")

    # 주기적 서버 상태 체크 + 링크 challenge

    def update_server_status(self):
        now = time.time()

        # Local
        local_ok = self._check_api_alive(LOCAL_API_BASE, timeout=2)
        if local_ok != self.local_online:
            self.local_online = local_ok
            if local_ok:
                self.lbl_local_status.setText("온라인")
                self.lbl_local_status.setStyleSheet("color: #16a34a;")
            else:
                self.lbl_local_status.setText("오프라인")
                self.lbl_local_status.setStyleSheet("color: #ef4444;")
                self.lbl_local_trust.setText("오프라인")
                self.lbl_local_trust.setStyleSheet("color: #9ca3af;")
                self.local_trust_ok = False

        if local_ok and (now - self._last_trust_local >= 60):
            self._last_trust_local = now
            self._update_trust_for(LOCAL_API_BASE, is_local=True)

        # Main
        main_base = self.api_base_edit.text().strip()
        main_ok = False
        if main_base:
            main_ok = self._check_api_alive(main_base, timeout=2)
        if main_ok != self.main_online:
            self.main_online = main_ok
            if main_ok:
                self.lbl_main_status.setText("온라인")
                self.lbl_main_status.setStyleSheet("color: #16a34a;")
            else:
                if main_base:
                    self.lbl_main_status.setText("오프라인")
                    self.lbl_main_status.setStyleSheet("color: #ef4444;")
                else:
                    self.lbl_main_status.setText("URL 미입력")
                    self.lbl_main_status.setStyleSheet("color: #9ca3af;")
                self.lbl_main_trust.setText("미검증")
                self.lbl_main_trust.setStyleSheet("color: #6b7280;")
                self.main_trust_ok = False

        if main_ok and main_base and (now - self._last_trust_main >= 60):
            self._last_trust_main = now
            self._update_trust_for(main_base, is_local=False)

    # 상단 연결 테스트

    def on_ping_clicked(self):
        main_base = self.api_base_edit.text().strip()
        msgs: List[str] = []

        # Local 테스트
        try:
            r = requests.get(
                LOCAL_API_BASE.rstrip("/") + "/health",
                timeout=3,
                verify=_TLS_VERIFY,
            )
            ok_local = r.status_code == 200
        except Exception:
            ok_local = False
        msgs.append(f"Local ({LOCAL_API_BASE}) : {'OK' if ok_local else 'FAIL'}")

        # Main 테스트
        ok_main = False
        if main_base:
            try:
                r2 = requests.get(
                    main_base.rstrip("/") + "/health",
                    timeout=3,
                    verify=_TLS_VERIFY,
                )
                ok_main = r2.status_code == 200
            except Exception:
                ok_main = False
            msgs.append(f"Main  ({main_base}) : {'OK' if ok_main else 'FAIL'}")
        else:
            msgs.append("Main  : URL 미입력")

        # healthz 서명
        if ok_local:
            ok, msg = verify_healthz_signature(LOCAL_API_BASE, timeout=5)
            msgs.append(f"Local healthz 서명: {'OK' if ok else 'FAIL'} ({msg})")
        if ok_main and main_base:
            ok2, msg2 = verify_healthz_signature(main_base, timeout=5)
            msgs.append(f"Main  healthz 서명: {'OK' if ok2 else 'FAIL'} ({msg2})")

        QMessageBox.information(self, "연결 테스트 결과", "\n".join(msgs))
        self.status_bar.showMessage("연결 테스트 완료", 5000)
        self.update_server_status()


# ─────────────────────────────────────────────────────────────
# 엔트리 포인트
# ─────────────────────────────────────────────────────────────

def main():
    # ⬇️ 최초 실행 시 config.json 생성 + 설정 적용
    bootstrap()

    app = QApplication(sys.argv)
    font = QFont()
    font.setPointSize(10)
    app.setFont(font)

    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
