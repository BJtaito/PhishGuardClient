# server/app.py
import os
import sys
import re
import json
import time
import uuid
import base64
import math
import socket
import asyncio
import inspect
import pathlib
import secrets
import subprocess
import unicodedata
import contextlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from urllib.parse import urlparse, urljoin, parse_qs

# ─────────────────────────────────────────────────────────────────────────────
# 외부/로컬 분석기(선택)
# ─────────────────────────────────────────────────────────────────────────────
try:
    # analyzer/run.py의 analyze() 사용 여부 (있으면 로컬 엔진 병행)
    from analyzer.run import analyze as local_analyze
except Exception:
    local_analyze = None

try:
    # 우리 프로젝트용 온라인학습/에이징 ML 백엔드
    from analyzer.ml_detector import predict as analyzer_ml_predict
    from analyzer.ml_detector import feedback as analyzer_ml_feedback
    from analyzer.ml_detector import maint_beat as analyzer_ml_maint
    from analyzer.ml_detector import status as analyzer_ml_status
except Exception:
    analyzer_ml_predict = None
    analyzer_ml_feedback = None
    analyzer_ml_maint = None
    analyzer_ml_status = None

# 친구가 만든 다운로드 추적 + 스캐너
try:
    from tools.download_scanner.download_pipeline import (
        analyze_url_with_downloads as _analyze_url_with_downloads,
    )
    print("[download] 모듈 로드 OK:", _analyze_url_with_downloads)
except Exception as e:
    print("[download] 모듈 로드 실패:", repr(e))
    _analyze_url_with_downloads = None

# ─────────────────────────────────────────────────────────────────────────────
# .env 로드 (가장 먼저)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv, find_dotenv

    ENV_PATH = find_dotenv(filename=".env", usecwd=True) or str(
        pathlib.Path(__file__).resolve().parent.parent / ".env"
    )
    load_dotenv(ENV_PATH, override=True)
except Exception:
    ENV_PATH = ""

# ─────────────────────────────────────────────────────────────────────────────
# Windows asyncio subprocess (Playwright 호환)
# ─────────────────────────────────────────────────────────────────────────────
if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# FastAPI
# ─────────────────────────────────────────────────────────────────────────────
from fastapi import FastAPI, HTTPException, Header, Depends, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse, FileResponse, PlainTextResponse

# optional deps
try:
    import httpx as _httpx
except Exception:
    _httpx = None

try:
    import tldextract
except Exception:
    tldextract = None

# Playwright 에러 타입 (버전별 호환)
try:
    from playwright._impl._errors import TargetClosedError
except Exception:
    try:
        from playwright.async_api import Error as TargetClosedError
    except Exception:

        class TargetClosedError(Exception):
            pass


# ─────────────────────────────────────────────────────────────────────────────
# 경로 / 디렉토리
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR = pathlib.Path(os.getenv("BASE_DIR", ".")).resolve()
TASK_DIR = pathlib.Path(os.getenv("TASK_DIR", "server/tasks"))
TASK_DIR.mkdir(parents=True, exist_ok=True)

STATIC_DIR = BASE_DIR / "server" / "static"
UI_DIR = STATIC_DIR / "ui"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
UI_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# env helpers
# ─────────────────────────────────────────────────────────────────────────────
def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        try:
            return int(float(os.getenv(name, str(default))))
        except Exception:
            return default


def _env_float(name, default):
    s = os.getenv(name, str(default))
    try:
        return float(s)
    except Exception:
        m = re.sub(r"[^0-9.]", "", s or "")
        return float(m) if m else float(default)


_FLOAT_CLEAN_RE = re.compile(r"[^0-9.\-+]")


def _as_float(val):
    try:
        if val is None:
            return None
        if isinstance(val, (int, float)):
            return float(val)
        s = str(val).strip()
        s = _FLOAT_CLEAN_RE.sub("", s)
        return float(s) if s else None
    except Exception:
        return None


def _normalize_text_for_rules(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize("NFKD", str(text))
    chars = []
    for ch in text:
        if unicodedata.category(ch).startswith("M"):
            continue
        chars.append(ch)
    text = "".join(chars)
    text = text.replace("\u00a0", " ")
    text = re.sub(r"\s+", " ", text)
    return text.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 환경설정
# ─────────────────────────────────────────────────────────────────────────────
ADMIN_KEY = os.getenv("ADMIN_KEY", "dev-admin-key")
SESSION_TTL_MIN = _env_int("SESSION_TTL_MIN", 30)
NONCE_TTL_SEC = _env_int("NONCE_TTL_SEC", 120)
TASK_TTL_MIN = _env_int("TASK_TTL_MIN", 180)

# 헬스/시간 동기화
TIME_SKEW_LIMIT_MS = _env_int("TIME_SKEW_LIMIT_MS", 10000)
TIME_PROBE_INTERVAL_SEC = _env_int("TIME_PROBE_INTERVAL_SEC", 30)
READY_REQUIRE_TIME_SYNC = os.getenv("READY_REQUIRE_TIME_SYNC", "0") == "1"

# 분석/레이트리밋
ANALYZE_RATE_PER_MIN = _env_int("ANALYZE_RATE_PER_MIN", 30)

# HTML Fetch
FETCH_HTML = os.getenv("PG_FETCH_HTML", "1") == "1"
MAX_HTML_BYTES = _env_int("PG_MAX_HTML_BYTES", 300000)
FETCH_TIMEOUT = _env_float("PG_FETCH_TIMEOUT", 5.0)
FETCH_UA = os.getenv("PG_FETCH_UA", "PhishGuard/0.6 (+html-fetch)")
FOLLOW_META_REFRESH = os.getenv("PG_FOLLOW_META_REFRESH", "1") == "1"

# 점수 스케일/가중치
SCORE_MAX = _env_int("PG_SCORE_MAX", 100)
W = {
    "HTTP": _env_int("PG_W_HTTP", 12),
    "KEYWORD_ONE": _env_int("PG_W_KEYWORD_ONE", 4),
    "KEYWORD_MULTI": _env_int("PG_W_KEYWORD_MULTI", 8),
    "AT_SIGN": _env_int("PG_W_AT_SIGN", 4),
    "PUNYCODE": _env_int("PG_W_PUNYCODE", 8),
    "IP_LIT": _env_int("PG_W_IP_LIT", 8),
    "LOGIN_FORM": _env_int("PG_W_LOGIN_FORM", 25),
    "FORM": _env_int("PG_W_FORM", 6),
    "EVAL": _env_int("PG_W_EVAL", 7),
    "ATOB": _env_int("PG_W_ATOB", 6),
    "IFRAME": _env_int("PG_W_IFRAME", 5),
    "FETCH_EXT": _env_int("PG_W_FETCH_EXT", 8),
    "HTML_VERY_LARGE": _env_int("PG_W_HTML_VERY_LARGE", 2),
    "PREFIX_SUFFIX": _env_int("PG_W_PREFIX_SUFFIX", 5),
    "DOUBLE_SLASH": _env_int("PG_W_DOUBLE_SLASH", 4),
    "NONSTD_PORT": _env_int("PG_W_NONSTD_PORT", 6),
    "ANCHOR_EXT_RATIO": _env_int("PG_W_ANCHOR_EXT_RATIO", 10),
    "RES_EXT_RATIO": _env_int("PG_W_RES_EXT_RATIO", 8),
    "FORM_ACTION_EXT": _env_int("PG_W_FORM_ACTION_EXT", 10),
    "FORM_ACTION_EMPTY": _env_int("PG_W_FORM_ACTION_EMPTY", 6),
    "FORM_MAILTO": _env_int("PG_W_FORM_MAILTO", 8),
    "ONMOUSEOVER": _env_int("PG_W_ONMOUSEOVER", 4),
    "RIGHTCLICK": _env_int("PG_W_RIGHTCLICK", 4),
    "POPUP_WIN": _env_int("PG_W_POPUP_WIN", 4),
    "NAV_ERROR": _env_int("PG_W_NAV_ERROR", 0),  # 기본 0 (사유만 노출)
    "DYN_LOGIN_EXT": _env_int("PG_W_DYN_LOGIN_EXT", 12),
    "DYN_LOGIN_NOPROGRESS": _env_int("PG_W_DYN_LOGIN_NOPROGRESS", 6),
    # 지갑/시드 문구
    "WALLET_SEED": _env_int("PG_W_WALLET_SEED", 25),
    # 다운로드 + VT
    "DOWNLOAD_ANY": _env_int("PG_W_DOWNLOAD_ANY", 5),
    "DOWNLOAD_VT_SUSP": _env_int("PG_W_DOWNLOAD_VT_SUSP", 18),
    "DOWNLOAD_VT_MAL": _env_int("PG_W_DOWNLOAD_VT_MAL", 32),
    "VT_URL_HIT_UNIT": _env_int("PG_W_VT_URL_HIT_UNIT", 8),
    "VT_URL_HIT_MAX": _env_int("PG_W_VT_URL_HIT_MAX", 40),
}
PG_HIDE_NAV_ERROR = os.getenv("PG_HIDE_NAV_ERROR", "0") == "1"

# 동적 분석(Playwright)
PG_DYN_PLAYWRIGHT = os.getenv("PG_DYN_PLAYWRIGHT", "0") == "1"
PG_DYN_NAV_TIMEOUT_SEC = _env_float("PG_DYN_NAV_TIMEOUT_SEC", 12.0)
PG_DYN_TOTAL_BUDGET_SEC = _env_float("PG_DYN_TOTAL_BUDGET_SEC", 25.0)
PG_DYN_TASK_TIMEOUT_SEC = _env_float("PG_DYN_TASK_TIMEOUT_SEC", 30.0)
PG_DYN_BLOCK_SCRIPTS = os.getenv("PG_DYN_BLOCK_SCRIPTS", "0") == "1"

# ───────── VirusTotal 평판 ─────────
VT_API_KEY = (os.getenv("VT_API_KEY", "") or "").strip()
VT_ENABLE = bool(VT_API_KEY) and (os.getenv("PG_VT_ENABLE", "0") == "1")
VT_TIMEOUT = _env_float("PG_VT_TIMEOUT", 4.0)
VT_WEIGHT = max(0.0, min(1.0, _env_float("PG_VT_WEIGHT", 0.8)))

PG_DYN_MAX_CONCURRENCY = _env_int("PG_DYN_MAX_CONCURRENCY", 4)
_DYN_SEM = asyncio.Semaphore(PG_DYN_MAX_CONCURRENCY)

# 다운로드 추적 + VirusTotal 스캔
PG_DOWNLOAD_SCAN = os.getenv("PG_DOWNLOAD_SCAN", "0") == "1"
PG_DOWNLOAD_SCAN_WAIT = _env_int("PG_DOWNLOAD_SCAN_WAIT", 15)
PG_DOWNLOAD_SCAN_MIN_SCORE = _env_int("PG_DOWNLOAD_SCAN_MIN_SCORE", 40)

# ML(옵션)
PG_ENABLE_ML = os.getenv("PG_ENABLE_ML", "0") == "1"
PG_ML_BACKEND = os.getenv("PG_ML_BACKEND", "builtin")  # builtin | analyzer
PG_ML_MODEL_PATH = os.getenv("PG_ML_MODEL_PATH", "server/ml/model.pkl")
PG_ML_RULES_WEIGHT = float(os.getenv("PG_ML_RULES_WEIGHT", "0.5"))
PG_ML_DOWNLOAD_PATH = os.getenv("PG_ML_DOWNLOAD_PATH", "")  # 예: "ml/model.pkl" → /static/ml/model.pkl

# Trace
PG_TRACE_TASK = os.getenv("PG_TRACE_TASK", "0") == "1"


def _type_name(x):
    try:
        return type(x).__name__
    except Exception:
        return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# 인메모리 저장 (PoC)
# ─────────────────────────────────────────────────────────────────────────────
DEVICES: Dict[str, Dict[str, Any]] = {}
NONCES: Dict[str, Dict[str, Any]] = {}
SESSIONS: Dict[str, Dict[str, Any]] = {}
TASKS: Dict[str, Dict[str, Any]] = {}

TIME = {
    "offset_ms": None,
    "source": "unknown",
    "in_sync": None,
    "checked_at": None,
    "error": None,
}
LAST_JANITOR_BEAT: Optional[datetime] = None


def _trace(task_id: str, stage: str, **data):
    if not PG_TRACE_TASK:
        return
    try:
        rec = {"ts": now_utc().isoformat(), "stage": stage, **data}
        rec_safe = json.loads(json.dumps(rec, default=str))
        TASKS.setdefault(task_id, {}).setdefault("_trace", []).append(rec_safe)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# 모델
# ─────────────────────────────────────────────────────────────────────────────
class DeviceRegisterReq(BaseModel):
    device_id: str = Field(..., min_length=3, max_length=128)
    display_name: str = Field(..., min_length=1, max_length=128)
    public_key_pem: str = Field(..., description="ECDSA P-256 공개키 (PEM)")


class NonceReq(BaseModel):
    device_id: str


class VerifyReq(BaseModel):
    device_id: str
    nonce: str
    signature_b64: str = Field(
        ..., description="nonce 바이트에 대한 ECDSA 서명(ASN.1/DER) Base64"
    )


class AnalyzeReq(BaseModel):
    url: Optional[str] = None
    html: Optional[str] = None
    referer: Optional[str] = None
    meta: Optional[dict] = None


class StartAnalyzeResp(BaseModel):
    task_id: str


class TaskResp(BaseModel):
    task_id: str
    status: str
    result: Optional[dict] = None
    error: Optional[str] = None
    created_at: str

    # ⬇ 서버 결과 서명용 필드 추가
    signed_payload: Optional[str] = None  # canonical JSON 문자열
    sig: Optional[str] = None             # ECDSA 서명(Base64 URL-safe)
    kid: Optional[str] = None             # 키 ID (지금은 "health-v1")

class FeedbackReq(BaseModel):
    url: Optional[str] = None
    task_id: Optional[str] = None
    # -1 피싱 / 1 정상 / 0 모름(무시)
    label: int


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI 인스턴스
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Phish-Guard Server", version="0.9.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# /static 경로로 정적 파일 서빙 (server/static/**)
app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR), html=False),
    name="static",
)


# 루트에서 UI index.html 반환
@app.get("/", include_in_schema=False)
async def ui_root():
    index_path = UI_DIR / "index.html"
    if not index_path.exists():
        return JSONResponse(
            status_code=404,
            content={"detail": "UI not found. Create server/static/ui/index.html"},
        )
    return FileResponse(str(index_path))


# ─────────────────────────────────────────────────────────────────────────────
# 유틸
# ─────────────────────────────────────────────────────────────────────────────
def now_utc():
    return datetime.now(timezone.utc)


def prune_expired():
    now = now_utc()
    for k in list(NONCES.keys()):
        if NONCES[k]["expires_at"] <= now:
            NONCES.pop(k, None)
    for k in list(SESSIONS.keys()):
        if SESSIONS[k]["expires_at"] <= now:
            SESSIONS.pop(k, None)
    for k, v in list(TASKS.items()):
        created = v.get("created_at", now)
        if created + timedelta(minutes=TASK_TTL_MIN) <= now:
            TASKS.pop(k, None)


# ─────────────────────────────────────────────────────────────────────────────
# Result normalize / reasons 표준화
# ─────────────────────────────────────────────────────────────────────────────
def _normalize_result(res: dict) -> dict:
    res = dict(res or {})
    s_raw = res.get("risk_score", 0)

    try:
        s = float(s_raw)
    except Exception:
        s = 0.0

    scale = res.get("score_scale")
    try:
        scale = float(scale) if scale is not None else None
    except Exception:
        scale = None

    if not scale or scale <= 0:
        scale = float(SCORE_MAX)

    if scale > 0:
        norm = max(0.0, min(1.0, s / scale))
    else:
        norm = 0.0

    res["risk_score_norm"] = round(norm, 3)
    res["risk_score_10"] = int(round(norm * 10))
    res["risk_score_100"] = int(round(norm * 100))
    res["score_scale"] = float(scale)
    res.setdefault("engine", "quick-rules")
    return res


def _canon_reasons(reasons):
    out = []
    if reasons is None:
        return out
    if isinstance(reasons, dict):
        f = reasons.get("feature") or "note"
        d = reasons.get("detail") or ""
        s = reasons.get("score")
        try:
            s = float(s) if s is not None else None
        except Exception:
            s = None
        o = {"feature": f, "detail": str(d)}
        if s is not None:
            o["score"] = s
        out.append(o)
        return out

    if not isinstance(reasons, list):
        return [{"feature": "note", "detail": str(reasons)}]

    i = 0
    while i < len(reasons):
        item = reasons[i]
        if isinstance(item, dict) and ("feature" in item or "detail" in item):
            o = {
                "feature": item.get("feature") or "note",
                "detail": str(item.get("detail") or ""),
            }
            if "score" in item:
                try:
                    o["score"] = float(item["score"])
                except Exception:
                    pass
            out.append(o)
            i += 1
            continue

        b = reasons[i + 1] if i + 1 < len(reasons) else None
        c = reasons[i + 2] if i + 2 < len(reasons) else None
        if (
            isinstance(item, str)
            and (
                isinstance(b, (int, float))
                or (isinstance(b, str) and b.replace(".", "", 1).isdigit())
            )
            and isinstance(c, str)
        ):
            out.append({"feature": item, "score": float(b), "detail": c})
            i += 3
            continue

        out.append({"feature": "note", "detail": str(item)})
        i += 1
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 대형 서비스 화이트리스트 후처리
# ─────────────────────────────────────────────────────────────────────────────
TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "naver.com",
    "daum.net",
    "kakao.com",
    "github.com",
    "microsoft.com",
    "apple.com",
}
extra_trusted = os.getenv("PG_TRUSTED_DOMAINS", "")
if extra_trusted:
    for d in extra_trusted.split(","):
        d = d.strip().lower()
        if d:
            TRUSTED_DOMAINS.add(d)


def _registrable(host: str) -> str:
    if not host:
        return ""
    if tldextract:
        e = tldextract.extract(host)
        return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else host
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _post_adjust_trusted(result: dict, url: str) -> dict:
    try:
        host = urlparse(url or "").hostname or ""
    except Exception:
        host = ""
    reg = _registrable(host)

    if not reg or reg not in TRUSTED_DOMAINS:
        return result

    score_100 = float(result.get("risk_score_100", result.get("risk_score", 0)) or 0)
    reasons = result.get("reasons") or []
    feats = {(r.get("feature") or "").lower() for r in reasons}

    hard_flags = {
        "dyn_login_post_external",
        "dyn_login_no_progress",
        "download_vt_malicious",
        "ip_literal",
        "punycode",
    }

    if feats & hard_flags:
        return result

    new_score = min(score_100, 25.0)
    if new_score >= score_100:
        return result

    norm = max(0.0, min(1.0, new_score / 100.0))
    result["risk_score"] = new_score
    result["risk_score_100"] = new_score
    result["risk_score_10"] = int(round(norm * 10))
    result["risk_score_norm"] = round(norm, 3)
    result["score_scale"] = 100.0
    result.setdefault("reasons", []).append(
        {
            "feature": "trusted_domain_adjust",
            "detail": f"Score clamped for trusted domain {reg}",
        }
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 관리자 인증
# ─────────────────────────────────────────────────────────────────────────────
def require_admin(x_admin_key: str = Header(default="")):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="admin key invalid")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# API 키: 실시간 파싱(getter)
# ─────────────────────────────────────────────────────────────────────────────
def get_api_keys() -> dict:
    m = {}
    api_keys_env = os.getenv("API_KEYS", "") or ""
    api_key_single = os.getenv("API_KEY")
    if api_keys_env:
        for pair in api_keys_env.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if ":" in pair:
                name, key = pair.split(":", 1)
                m[name.strip()] = key.strip()
            else:
                m[f"k{len(m)+1}"] = pair.strip()
    if api_key_single:
        m.setdefault("default", api_key_single.strip())
    return m


# ─────────────────────────────────────────────────────────────────────────────
# 세션/서명
# ─────────────────────────────────────────────────────────────────────────────
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


def verify_signature(public_key_pem: str, message: bytes, signature_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        sig = base64.b64decode(signature_b64)
        pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def require_session(authorization: str = Header(default="")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    sess = SESSIONS.get(token)
    if not sess:
        raise HTTPException(status_code=401, detail="invalid or expired session")
    if sess["expires_at"] <= now_utc():
        SESSIONS.pop(token, None)
        raise HTTPException(status_code=401, detail="session expired")
    sess["expires_at"] = now_utc() + timedelta(minutes=SESSION_TTL_MIN)
    return sess["device_id"]


def resolve_principal(
    authorization: str = Header(default=""), x_api_key: str = Header(default="")
) -> str:
    api_keys = get_api_keys()
    if x_api_key:
        if not api_keys:
            raise HTTPException(
                status_code=401,
                detail="api key auth disabled (server missing API_KEYS)",
            )
        for name, key in api_keys.items():
            if x_api_key == key:
                return f"apikey:{name}"
        raise HTTPException(status_code=401, detail="invalid api key")
    if authorization.startswith("Bearer "):
        did = require_session(authorization)
        return f"device:{did}"
    raise HTTPException(status_code=401, detail="missing auth (Bearer or X-API-Key)")


# ─────────────────────────────────────────────────────────────────────────────
# 헬스(서명)
# ─────────────────────────────────────────────────────────────────────────────
KEY_DIR = pathlib.Path(os.getenv("HEALTH_KEY_DIR", "server/keys"))
KEY_DIR.mkdir(parents=True, exist_ok=True)
PRIV_PATH = KEY_DIR / "health_priv.pem"
PUB_PATH = KEY_DIR / "health_pub.pem"
KID = os.getenv("HEALTH_KID", "health-v1")


def _ensure_health_keys():
    if not PRIV_PATH.exists():
        priv = ec.generate_private_key(ec.SECP256R1())
        PRIV_PATH.write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        PUB_PATH.write_bytes(
            priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def _b64u(b: bytes):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _pubkey_jwk():
    pub = serialization.load_pem_public_key(PUB_PATH.read_bytes())
    n = pub.public_numbers()
    x = n.x.to_bytes(32, "big")
    y = n.y.to_bytes(32, "big")
    return {"kty": "EC", "crv": "P-256", "x": _b64u(x), "y": _b64u(y), "kid": KID}


def _canon_json(obj: dict) -> str:
    return json.dumps(
        obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    )


def _sign_payload(payload_str: str) -> str:
    priv = serialization.load_pem_private_key(PRIV_PATH.read_bytes(), password=None)
    der = priv.sign(payload_str.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return _b64u(der)


def _probe_time_sync():
    global TIME
    try:
        if sys.platform.startswith("win"):
            out = subprocess.run(
                ["w32tm", "/query", "/status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            txt = out.stdout
            m = re.search(r"Offset:\s*([+-]?\d+(?:\.\d+)?)\s*s", txt)
            unit = "s"
            if not m:
                m = re.search(r"Offset:\s*([+-]?\d+(?:\.\d+)?)\s*ms", txt)
                unit = "ms"
            if not m:
                raise RuntimeError("w32tm output parse failed")
            val = float(m.group(1))
            offset_ms = val * 1000.0 if unit == "s" else val
            TIME.update(
                offset_ms=offset_ms,
                source="w32tm",
                in_sync=abs(offset_ms) <= TIME_SKEW_LIMIT_MS,
                checked_at=now_utc().isoformat(),
                error=None,
            )
        else:
            out = subprocess.run(
                ["chronyc", "tracking"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            txt = out.stdout
            m = re.search(
                r"(?:System time|Last offset)\s*:\s*([+-]?\d+(?:\.\d+)?)\s*seconds",
                txt,
                re.I,
            )
            if not m:
                raise RuntimeError("chronyc output parse failed")
            val = float(m.group(1))
            offset_ms = val * 1000.0
            TIME.update(
                offset_ms=offset_ms,
                source="chronyc",
                in_sync=abs(offset_ms) <= TIME_SKEW_LIMIT_MS,
                checked_at=now_utc().isoformat(),
                error=None,
            )
    except Exception as e:
        TIME.update(
            offset_ms=None,
            source="unknown",
            in_sync=None,
            checked_at=now_utc().isoformat(),
            error=str(e),
        )


async def janitor():
    global LAST_JANITOR_BEAT
    _ensure_health_keys()
    tick = 0
    while True:
        try:
            LAST_JANITOR_BEAT = now_utc()
            prune_expired()
            if tick % max(1, TIME_PROBE_INTERVAL_SEC // 10) == 0:
                _probe_time_sync()
            if analyzer_ml_maint and (tick % 6 == 0):
                analyzer_ml_maint()
            tick += 1
        except Exception:
            pass
        await asyncio.sleep(10)


@app.on_event("startup")
async def on_startup():
    asyncio.create_task(janitor())


# ─────────────────────────────────────────────────────────────────────────────
# 헬스 엔드포인트
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"ok": True, "ts": now_utc().isoformat()}


@app.get("/livez")
async def livez():
    return {"ok": True, "ts": now_utc().isoformat()}


@app.get("/readyz")
async def readyz():
    ok = True
    reasons = []
    alive = LAST_JANITOR_BEAT and (
        now_utc() - LAST_JANITOR_BEAT
    ).total_seconds() < 30
    if not alive:
        ok = False
        reasons.append("janitor_stale")
    time_state = dict(TIME)
    if READY_REQUIRE_TIME_SYNC:
        if time_state.get("in_sync") is not True:
            ok = False
            reasons.append("time_unsynced")
    else:
        if time_state.get("in_sync") is not True:
            reasons.append("time_unsynced (not required)")
    status = 200 if ok else 503
    return JSONResponse(
        status_code=status,
        content={
            "ok": ok,
            "reasons": reasons,
            "queue_depth": len(TASKS),
            "time": time_state,
            "janitor_alive": bool(alive),
            "ts": now_utc().isoformat(),
        },
    )


@app.get("/health_pubkey")
async def health_pubkey():
    _ensure_health_keys()
    return _pubkey_jwk()


@app.get("/healthz")
async def healthz(nonce: str = Query(..., min_length=8, max_length=128)):
    _ensure_health_keys()
    payload = {
        "server_id": os.getenv("SERVER_ID", "cap-server"),
        "ts": now_utc().isoformat(),
        "queue_depth": len(TASKS),
        "time": TIME,
        "janitor_alive": bool(
            LAST_JANITOR_BEAT
            and (now_utc() - LAST_JANITOR_BEAT).total_seconds() < 30
        ),
        "nonce": nonce,
        "kid": "health-v1",
        "alg": "ES256",
        "version": "v1",
    }
    s = _canon_json(payload)
    sig = _sign_payload(s)
    return {"payload": s, "sig": sig}


# ─────────────────────────────────────────────────────────────────────────────
# 관리자/장치 + TASK EXPORT
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/admin/devices", dependencies=[Depends(require_admin)])
async def register_device(req: DeviceRegisterReq):
    if req.device_id in DEVICES:
        raise HTTPException(status_code=409, detail="device already exists")
    DEVICES[req.device_id] = {
        "display_name": req.display_name,
        "pubkey_pem": req.public_key_pem,
        "enrolled_at": now_utc(),
    }
    return {"ok": True, "device_id": req.device_id}


@app.post("/auth/nonce")
async def issue_nonce(req: NonceReq):
    if req.device_id not in DEVICES:
        raise HTTPException(status_code=404, detail="device not registered")
    nonce = secrets.token_urlsafe(32)
    NONCES[nonce] = {
        "device_id": req.device_id,
        "expires_at": now_utc() + timedelta(seconds=NONCE_TTL_SEC),
    }
    return {"nonce": nonce, "expires_in": NONCE_TTL_SEC}


@app.post("/auth/verify")
async def verify(req: VerifyReq):
    n = NONCES.get(req.nonce)
    if not n or n["device_id"] != req.device_id:
        raise HTTPException(status_code=400, detail="invalid nonce or device mismatch")
    if n["expires_at"] <= now_utc():
        NONCES.pop(req.nonce, None)
        raise HTTPException(status_code=400, detail="nonce expired")
    dev = DEVICES.get(req.device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="device not found")
    ok = verify_signature(
        dev["pubkey_pem"], req.nonce.encode("utf-8"), req.signature_b64
    )
    NONCES.pop(req.nonce, None)
    if not ok:
        raise HTTPException(status_code=401, detail="signature verification failed")
    token = secrets.token_urlsafe(40)
    SESSIONS[token] = {
        "device_id": req.device_id,
        "expires_at": now_utc() + timedelta(minutes=SESSION_TTL_MIN),
    }
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": SESSION_TTL_MIN * 60,
    }


@app.get("/auth/whoami")
async def whoami(principal: str = Depends(resolve_principal)):
    return {"principal": principal, "ts": now_utc().isoformat()}


@app.get("/admin/tasks/export", dependencies=[Depends(require_admin)])
async def admin_export_tasks(
    fmt: str = Query("json", description="json | ndjson"),
    limit: int = Query(1000, ge=1, le=100000),
):
    """
    ML 학습용으로 서버에 쌓인 TASK_DIR/*.json 을 한 번에 덤프하는 엔드포인트.
    - fmt=json  → [ {...}, {...}, ... ]
    - fmt=ndjson → 한 줄에 한 json (training friendly)
    """
    fmt = fmt.lower()
    if fmt not in ("json", "ndjson"):
        raise HTTPException(status_code=400, detail="fmt must be json or ndjson")

    files = sorted(TASK_DIR.glob("*.json"))
    if limit:
        files = files[-limit:]

    records = []
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            records.append(data)
        except Exception:
            continue

    if fmt == "json":
        return JSONResponse(records)
    else:
        lines = "\n".join(json.dumps(r, ensure_ascii=False) for r in records)
        return PlainTextResponse(
            (lines + "\n") if lines else "",
            media_type="application/x-ndjson",
        )


# ─────────────────────────────────────────────────────────────────────────────
# HTML feature extraction
# ─────────────────────────────────────────────────────────────────────────────
_ANCHOR_HREF = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\']', re.I)
_TAG_SRC = re.compile(r'<(?:img|script)\s+[^>]*src=["\']([^"\']+)["\']', re.I)
_CSS_HREF = re.compile(r'<link\s+[^>]*href=["\']([^"\']+)["\']', re.I)
_FORM = re.compile(r"<form\s+[^>]*>", re.I)
_FORM_ACTION = re.compile(r'<form[^>]*\saction=["\']([^"\']*)["\']', re.I)
_ONMOUSEOVER = re.compile(r"onmouseover\s*=", re.I)
_RIGHTCLICK = re.compile(r'oncontextmenu\s*=\s*["\']return\s+false', re.I)
_POPUP = re.compile(r"\bwindow\.open\s*\(", re.I)


def extract_html_features(html: str, base_url: str = "") -> dict:
    feats = {
        "len_html": len(html or ""),
        "has_form": False,
        "has_pw_input": False,
        "has_eval": False,
        "has_atob": False,
        "has_iframe": False,
        "anchor_external_ratio": 0.0,
        "resource_external_ratio": 0.0,
        "form_action_external_ratio": 0.0,
        "form_action_empty": False,
        "form_action_mailto": False,
        "has_onmouseover": False,
        "has_rightclick_disable": False,
        "has_popup_window": False,
    }
    if not html:
        return feats

    low = html.lower()
    feats["has_form"] = bool(_FORM.search(low))
    feats["has_pw_input"] = ("type=\"password\"" in low) or ("type='password'" in low)
    feats["has_eval"] = "eval(" in low
    feats["has_atob"] = "atob(" in low
    feats["has_iframe"] = "<iframe" in low
    feats["has_onmouseover"] = bool(_ONMOUSEOVER.search(low))
    feats["has_rightclick_disable"] = bool(_RIGHTCLICK.search(low))
    feats["has_popup_window"] = bool(_POPUP.search(low))

    try:
        base_host = urlparse(base_url).hostname or ""
        base_reg = _registrable(base_host)

        def _is_external(u):
            try:
                if not u:
                    return False
                if u.startswith("#"):
                    return False
                if u.startswith(("mailto:", "javascript:")):
                    return False
                absu = urljoin(base_url, u)
                h = urlparse(absu).hostname or ""
                if not h:
                    return False
                return _registrable(h) != base_reg
            except Exception:
                return False

        anchors = _ANCHOR_HREF.findall(html)
        if anchors:
            ext = sum(1 for a in anchors if _is_external(a))
            feats["anchor_external_ratio"] = round(ext / max(1, len(anchors)), 3)

        res1 = _TAG_SRC.findall(html)
        res2 = _CSS_HREF.findall(html)
        res = res1 + res2
        if res:
            ext = sum(1 for r in res if _is_external(r))
            feats["resource_external_ratio"] = round(ext / max(1, len(res)), 3)

        actions = _FORM_ACTION.findall(html)
        if actions:
            ext = 0
            for a in actions:
                s = (a or "").strip().lower()
                if s == "" or s in ("#", "about:blank"):
                    feats["form_action_empty"] = True
                if s.startswith("mailto:"):
                    feats["form_action_mailto"] = True
                if _is_external(a):
                    ext += 1
            feats["form_action_external_ratio"] = round(ext / max(1, len(actions)), 3)
    except Exception:
        pass
    return feats


# ─────────────────────────────────────────────────────────────────────────────
# URL lexical features (ML용)
# ─────────────────────────────────────────────────────────────────────────────
_SUSP_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "ru",
    "cn",
    "top",
    "work",
    "zip",
    "country",
    "kim",
    "men",
    "loan",
    "click",
    "party",
    "review",
    "cab",
    "stream",
}
_SHORTENERS = {
    "bit.ly",
    "goo.gl",
    "t.co",
    "ow.ly",
    "tinyurl.com",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorte.st",
    "adf.ly",
    "rebrand.ly",
    "lnkd.in",
}
_SUSP_WORDS = {
    "login",
    "signin",
    "verify",
    "update",
    "secure",
    "confirm",
    "account",
    "wallet",
    "bank",
    "password",
    "credential",
    "invoice",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _is_ipv4_literal(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""))


def _host_parts(u: str):
    try:
        p = urlparse(u)
        host = p.hostname or ""
        return p, host
    except Exception:
        return urlparse(""), ""


def extract_url_features_for_ml(u: str) -> dict:
    p, host = _host_parts(u)

    subdomain_count = 0
    tld = ""
    if tldextract:
        ext = tldextract.extract(host)
        subdomain_count = (
            len([x for x in ext.subdomain.split(".") if x]) if ext.subdomain else 0
        )
        tld = ext.suffix or ""
    else:
        parts = host.split(".")
        tld = parts[-1] if len(parts) >= 2 else ""

    digit_ratio_host = sum(ch.isdigit() for ch in host) / max(1, len(host))
    params = parse_qs(p.query or "")

    feats = {
        "url_len": len(u),
        "host_len": len(host),
        "path_len": len(p.path or ""),
        "query_len": len(p.query or ""),
        "num_dots_host": host.count("."),
        "num_hyphen_host": host.count("-"),
        "num_slash_path": (p.path or "").count("/"),
        "has_at": int("@" in u),
        "has_ip_host": int(_is_ipv4_literal(host)),
        "subdomain_count": subdomain_count,
        "digit_ratio_host": round(digit_ratio_host, 4),
        "entropy_host": round(_shannon_entropy(host), 4),
        "num_params": len(params),
        "has_https_token_in_host": int("https" in host and p.scheme != "https"),
        "shortener_host": int(any(host.endswith(s) for s in _SHORTENERS)),
        "susp_tld": int((tld or "").lower() in _SUSP_TLDS),
        "susp_words_in_url": sum(1 for w in _SUSP_WORDS if w in u.lower()),
        "scheme_http": int(p.scheme == "http"),
        "has_port": int(p.port is not None),
        "tld_len": len(tld or ""),
    }
    return feats


ML_FEATURE_ORDER = [
    "url_len",
    "host_len",
    "path_len",
    "query_len",
    "num_dots_host",
    "num_hyphen_host",
    "num_slash_path",
    "has_at",
    "has_ip_host",
    "subdomain_count",
    "digit_ratio_host",
    "entropy_host",
    "num_params",
    "has_https_token_in_host",
    "shortener_host",
    "susp_tld",
    "susp_words_in_url",
    "scheme_http",
    "has_port",
    "tld_len",
]

_ML = {"clf": None, "loaded": False, "err": None}


def _try_load_ml():
    if _ML["loaded"] or not PG_ENABLE_ML:
        return
    try:
        import joblib
        import pickle as _pickle
        import os as _os

        model_path = _os.path.normpath(PG_ML_MODEL_PATH)
        try:
            _ML["clf"] = joblib.load(model_path)
        except Exception:
            with open(model_path, "rb") as f:
                _ML["clf"] = _pickle.load(f)
        _ML["loaded"] = True
    except Exception as e:
        _ML["err"] = str(e)
        _ML["loaded"] = True


def _ml_predict(u: str, html: str = "", dyn: Optional[dict] = None) -> Optional[Dict[str, Any]]:
    if not PG_ENABLE_ML:
        return None

    backend = (PG_ML_BACKEND or "builtin").lower()

    # analyzer 백엔드
    if backend == "analyzer" and analyzer_ml_predict:
        try:
            try:
                out = analyzer_ml_predict(u, html, dyn)
            except TypeError:
                out = analyzer_ml_predict(u, html)
        except Exception:
            out = None

        if out is None:
            return None

        info: Dict[str, Any] = {"backend": "analyzer"}

        if isinstance(out, dict):
            prob = out.get("prob")
            if prob is None and "label" in out:
                try:
                    lbl = int(out["label"])
                except Exception:
                    lbl = 0
                prob_map = {-1: 0.95, 0: 0.50, 1: 0.05}
                prob = prob_map.get(lbl, 0.50)
            if prob is None:
                return None

            prob = max(0.0, min(1.0, float(prob)))
            info["prob"] = prob
            if "label" in out:
                info["label"] = out["label"]
            if "risk" in out:
                info["risk"] = out["risk"]
            if "prob_parts" in out:
                info["prob_parts"] = out["prob_parts"]
            return info

        try:
            lbl = int(out)
        except Exception:
            return None
        if lbl in (-1, 0, 1):
            prob_map = {-1: 0.95, 0: 0.50, 1: 0.05}
            return {"backend": "analyzer", "prob": prob_map[lbl], "label": lbl}
        return None

    # builtin 경로
    _try_load_ml()
    clf = _ML["clf"]
    if not clf:
        return None

    X = [[extract_url_features_for_ml(u)[k] for k in ML_FEATURE_ORDER]]
    try:
        if hasattr(clf, "predict_proba"):
            prob = float(clf.predict_proba(X)[0][1])
        elif hasattr(clf, "decision_function"):
            s = float(clf.decision_function(X)[0])
            prob = 1.0 / (1.0 + math.exp(-s))
        else:
            return None
        prob = max(0.0, min(1.0, prob))
        return {"backend": "builtin", "prob": prob}
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Fetch with redirects + meta-refresh
# ─────────────────────────────────────────────────────────────────────────────
_META_REFRESH_RE = re.compile(
    r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\']\s*\d+\s*;\s*url=([^"\']+)["\']',
    re.I,
)


async def _fetch_page(url: str) -> dict:
    out = {
        "html": "",
        "start_url": url,
        "final_url": url,
        "redirect_chain": [],
        "final_ip": [],
        "meta_refresh_to": None,
        "status_code": None,
        "http_status": None,
        "error": None,
    }
    if not (_httpx and FETCH_HTML):
        return out
    u = (url or "").strip()
    if not u.lower().startswith(("http://", "https://")):
        return out
    try:
        timeout = None
        if FETCH_TIMEOUT > 0:
            timeout = FETCH_TIMEOUT
        async with _httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": FETCH_UA},
        ) as client:
            r = await client.get(u)
            out["status_code"] = int(r.status_code)
            out["http_status"] = out["status_code"]

            for h in r.history:
                try:
                    out["redirect_chain"].append(
                        {"url": str(h.request.url), "status": h.status_code}
                    )
                except Exception:
                    pass

            out["final_url"] = str(r.request.url)
            text = r.text or ""
            ct = (r.headers.get("content-type") or "").lower()
            is_html = ("text/html" in ct) or (
                "application/xhtml" in ct
            ) or ("<html" in text[:1024].lower())
            if is_html:
                if len(text) <= MAX_HTML_BYTES:
                    html = text
                else:
                    keep = MAX_HTML_BYTES // 2
                    html = (
                        text[:keep]
                        + "\n<!-- [pg-truncated: head+tail] -->\n"
                        + text[-keep:]
                    )
                out["html"] = html

                if FOLLOW_META_REFRESH:
                    m = _META_REFRESH_RE.search(html)
                    if m:
                        target = m.group(1).strip()
                        target_abs = urljoin(out["final_url"], target)
                        out["meta_refresh_to"] = target_abs
                        try:
                            r2 = await client.get(target_abs)
                            out["redirect_chain"].append(
                                {
                                    "url": str(r2.request.url),
                                    "status": r2.status_code,
                                    "via": "meta-refresh",
                                }
                            )
                            out["final_url"] = str(r2.request.url)
                            out["status_code"] = int(r2.status_code)
                            out["http_status"] = out["status_code"]
                            t2 = r2.text or ""
                            ct2 = (r2.headers.get("content-type") or "").lower()
                            if "text/html" in ct2 or "<html" in t2[:1024].lower():
                                if len(t2) <= MAX_HTML_BYTES:
                                    out["html"] = t2
                                else:
                                    keep = MAX_HTML_BYTES // 2
                                    out["html"] = (
                                        t2[:keep]
                                        + "\n<!-- [pg-truncated: head+tail] -->\n"
                                        + t2[-keep:]
                                    )
                        except Exception:
                            pass

            try:
                host = (out["final_url"].split("://", 1)[1]).split("/", 1)[0]
                out["final_ip"] = sorted(
                    {ai[4][0] for ai in socket.getaddrinfo(host, None)}
                )
            except Exception:
                out["final_ip"] = []
    except Exception as e:
        out["error"] = str(e)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# VirusTotal URL 평판 조회
# ─────────────────────────────────────────────────────────────────────────────
async def _vt_reputation(url: str) -> Optional[dict]:
    if not VT_ENABLE:
        return None
    if not (_httpx and VT_API_KEY):
        return None

    u = (url or "").strip()
    if not u:
        return None
    if not u.lower().startswith(("http://", "https://")):
        u = "http://" + u

    try:
        url_id = base64.urlsafe_b64encode(u.encode("utf-8")).decode("ascii").rstrip("=")
    except Exception:
        return None

    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        async with _httpx.AsyncClient(timeout=VT_TIMEOUT) as client:
            r = await client.get(
                vt_url,
                headers={"x-apikey": VT_API_KEY},
            )
        if r.status_code == 404:
            return {
                "source": "virustotal",
                "found": False,
                "http_status": r.status_code,
                "malicious": 0,
                "total_engines": 0,
                "ratio": 0.0,
                "stats": {},
            }
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {
            "source": "virustotal",
            "error": str(e),
        }

    attr = (data.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    timeout = int(stats.get("timeout", 0))

    total_engines = max(1, malicious + suspicious + harmless + undetected + timeout)
    mal_hits = malicious + suspicious
    ratio = mal_hits / float(total_engines)

    return {
        "source": "virustotal",
        "found": True,
        "malicious": mal_hits,
        "total_engines": total_engines,
        "ratio": round(ratio, 4),
        "stats": stats,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Quick rules
# ─────────────────────────────────────────────────────────────────────────────
def _quick_rule_score(
    url: str,
    html: str = "",
    html_feats: Optional[Dict[str, Any]] = None,
    evidence: Optional[dict] = None,
) -> dict:
    raw_url = url or ""
    u = _normalize_text_for_rules(raw_url)
    score = 0
    reasons = []
    features = {"html": html_feats or {}}

    if evidence:
        features["redirects"] = {
            "start_url": evidence.get("start_url"),
            "final_url": evidence.get("final_url"),
            "redirect_chain": evidence.get("redirect_chain") or [],
            "meta_refresh_to": evidence.get("meta_refresh_to"),
            "final_ip": evidence.get("final_ip") or [],
            "status_code": evidence.get("status_code"),
        }
        if "dynamic" in evidence:
            features["dynamic"] = evidence.get("dynamic")

    p = urlparse(u)
    host = p.hostname or ""
    port = p.port
    path = p.path or ""

    if u.startswith("http://"):
        score += W["HTTP"]
        reasons.append(
            {"feature": "scheme", "score": W["HTTP"], "detail": "Plain HTTP"}
        )

    sus = [
        "login",
        "signin",
        "verify",
        "update",
        "password",
        "credential",
        "account",
        "secure",
        "wallet",
        "bank",
        "phishing",
        "malware",
    ]
    kw = sum(1 for k in sus if k in u)
    if kw >= 2:
        score += W["KEYWORD_MULTI"]
        reasons.append(
            {
                "feature": "keywords",
                "score": W["KEYWORD_MULTI"],
                "detail": f"{kw} suspicious terms",
            }
        )
    elif kw == 1:
        score += W["KEYWORD_ONE"]
        reasons.append(
            {
                "feature": "keywords",
                "score": W["KEYWORD_ONE"],
                "detail": "1 suspicious term",
            }
        )

    wallet_words = [
        "seed phrase",
        "secret recovery phrase",
        "recovery phrase",
        "mnemonic",
        "private key",
        "passphrase",
        "walletconnect",
        "connect wallet",
    ]
    wallet_hits_url = sum(1 for k in wallet_words if k in u)
    if wallet_hits_url:
        w_wallet = W.get("WALLET_SEED", 0)
        if w_wallet:
            score += w_wallet
            reasons.append(
                {
                    "feature": "wallet_seed_url",
                    "score": w_wallet,
                    "detail": f"{wallet_hits_url} wallet/seed terms in URL",
                }
            )

    if "@" in u:
        score += W["AT_SIGN"]
        reasons.append(
            {"feature": "url_at_sign", "score": W["AT_SIGN"], "detail": "@ in URL"}
        )
    if "xn--" in u:
        score += W["PUNYCODE"]
        reasons.append(
            {
                "feature": "punycode",
                "score": W["PUNYCODE"],
                "detail": "Punycode hostname",
            }
        )
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        score += W["IP_LIT"]
        reasons.append(
            {
                "feature": "ip_literal",
                "score": W["IP_LIT"],
                "detail": "IPv4 literal host",
            }
        )

    if "-" in host.split(":")[0].split(".")[0]:
        score += W["PREFIX_SUFFIX"]
        reasons.append(
            {
                "feature": "prefix_suffix",
                "score": W["PREFIX_SUFFIX"],
                "detail": "Hyphen in domain",
            }
        )
    if port and port not in (80, 443):
        score += W["NONSTD_PORT"]
        reasons.append(
            {
                "feature": "nonstd_port",
                "score": W["NONSTD_PORT"],
                "detail": f"Port {port}",
            }
        )
    if "//" in path:
        score += W["DOUBLE_SLASH"]
        reasons.append(
            {
                "feature": "double_slash",
                "score": W["DOUBLE_SLASH"],
                "detail": "// in path",
            }
        )

    hf = html_feats or {}

    def bump(k, feat, detail):
        w = W.get(k, 0)
        if w:
            nonlocal score, reasons
            score += w
            reasons.append({"feature": feat, "score": w, "detail": detail})

    if html:
        norm_html = _normalize_text_for_rules(html)
        wallet_hits_html = sum(1 for k in wallet_words if k in norm_html)
        if wallet_hits_html:
            w_wallet = W.get("WALLET_SEED", 0)
            if w_wallet:
                score += w_wallet
                reasons.append(
                    {
                        "feature": "wallet_seed_html",
                        "score": w_wallet,
                        "detail": f"{wallet_hits_html} wallet/seed phrases in page",
                    }
                )

    if hf.get("has_form") and hf.get("has_pw_input"):
        score += W["LOGIN_FORM"]
        reasons.append(
            {
                "feature": "login_form",
                "score": W["LOGIN_FORM"],
                "detail": "Password form present",
            }
        )
    elif hf.get("has_form"):
        score += W["FORM"]
        reasons.append(
            {
                "feature": "form",
                "score": W["FORM"],
                "detail": "Form present",
            }
        )
    if hf.get("has_eval"):
        bump("EVAL", "eval", "Uses eval()")
    if hf.get("has_atob"):
        bump("ATOB", "atob", "Uses atob()")
    if hf.get("has_iframe"):
        bump("IFRAME", "iframe", "Has <iframe>")
    ar = hf.get("anchor_external_ratio", 0.0)
    rr = hf.get("resource_external_ratio", 0.0)
    if ar > 0:
        bump("ANCHOR_EXT_RATIO", "anchor_ext_ratio", f"{ar:.2f}")
    if rr > 0:
        bump("RES_EXT_RATIO", "res_ext_ratio", f"{rr:.2f}")
    fa = hf.get("form_action_external_ratio", 0.0)
    if fa > 0:
        bump("FORM_ACTION_EXT", "form_action_ext", f"{fa:.2f}")
    if hf.get("form_action_empty"):
        bump("FORM_ACTION_EMPTY", "form_action_empty", "Empty/blank form action")
    if hf.get("form_action_mailto"):
        bump("FORM_MAILTO", "form_mailto", "mailto: form action")
    if hf.get("has_onmouseover"):
        bump("ONMOUSEOVER", "onmouseover", "JS hover manipulation")
    if hf.get("has_rightclick_disable"):
        bump("RIGHTCLICK", "rightclick_disable", "Contextmenu blocked")
    if hf.get("has_popup_window"):
        bump("POPUP_WIN", "popup_window", "window.open() usage")

    if hf.get("len_html", 0) > 250_000:
        score += W["HTML_VERY_LARGE"]
        reasons.append(
            {
                "feature": "html_size",
                "score": W["HTML_VERY_LARGE"],
                "detail": "Very large page",
            }
        )

    # 동적 분석 기반
    dyn = (evidence or {}).get("dynamic") or {}
    post_hosts = dyn.get("post_hosts") or []
    base_host = urlparse(raw_url).hostname or ""
    base_reg = _registrable(base_host)

    if hf.get("has_pw_input") and post_hosts:
        ext_posts = [h for h in post_hosts if h and h != base_reg]
        if ext_posts:
            w_dyn = W.get("DYN_LOGIN_EXT", 0)
            if w_dyn:
                score += w_dyn
                reasons.append(
                    {
                        "feature": "dyn_login_post_external",
                        "score": w_dyn,
                        "detail": f"POST to external host(s): {', '.join(ext_posts)}",
                    }
                )

    if hf.get("has_pw_input") and dyn.get("network_posts", 0) > 0:
        start_url = (evidence or {}).get("start_url") or raw_url

        def _canon(u2: str) -> str:
            return (u2 or "").split("#", 1)[0].rstrip("/")

        final_url_dyn = (dyn.get("final_url") or "").strip()
        if final_url_dyn and _canon(final_url_dyn) == _canon(start_url):
            w_stuck = W.get("DYN_LOGIN_NOPROGRESS", 0)
            if w_stuck:
                score += w_stuck
                reasons.append(
                    {
                        "feature": "dyn_login_no_progress",
                        "score": w_stuck,
                        "detail": "Login POST observed but final URL stayed the same",
                    }
                )

    # 다운로드 + VT 기반 룰
    dl_info = (evidence or {}).get("downloads") or {}
    if isinstance(dl_info, dict):
        downloads_list = dl_info.get("downloads") or dl_info.get("files") or []
        if isinstance(downloads_list, list) and downloads_list:
            bump(
                "DOWNLOAD_ANY",
                "download_any",
                f"{len(downloads_list)} file(s) downloaded",
            )

        max_vt_score = None

        if isinstance(downloads_list, list):
            for item in downloads_list:
                vt = None
                if isinstance(item, dict):
                    vt = item.get("vt") or item.get("virustotal")
                if isinstance(vt, dict):
                    vs = (
                        vt.get("score")
                        or vt.get("vt_score")
                        or vt.get("score_100")
                        or vt.get("vt_score_100")
                    )
                    try:
                        val = float(vs)
                    except Exception:
                        val = None
                    if val is not None:
                        max_vt_score = val if max_vt_score is None else max(
                            max_vt_score, val
                        )

        top_vs = (
            dl_info.get("max_vt_score")
            or dl_info.get("vt_score")
            or dl_info.get("vt_score_100")
        )
        try:
            top_vs_f = float(top_vs)
            if max_vt_score is None or top_vs_f > max_vt_score:
                max_vt_score = top_vs_f
        except Exception:
            pass

        if max_vt_score is not None:
            if max_vt_score >= 70:
                bump(
                    "DOWNLOAD_VT_MAL",
                    "download_vt_malicious",
                    f"max VT file score {max_vt_score:.0f}",
                )
            elif max_vt_score >= 30:
                bump(
                    "DOWNLOAD_VT_SUSP",
                    "download_vt_suspicious",
                    f"max VT file score {max_vt_score:.0f}",
                )

    score = max(0, min(SCORE_MAX, score))
    return {
        "risk_score": score,
        "engine": "quick-rules",
        "reasons": reasons,
        "features": features,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic analyze (Playwright)
# ─────────────────────────────────────────────────────────────────────────────
async def _dynamic_analyze(url: str) -> Optional[dict]:
    if not PG_DYN_PLAYWRIGHT:
        return None
    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        return {
            "engine": "dyn",
            "errors": [f"import_playwright:{e!s}"],
            "network_posts": 0,
            "page_findings": {},
        }

    nav_timeout_sec = _as_float(PG_DYN_NAV_TIMEOUT_SEC) or 0.0
    budget_sec = _as_float(PG_DYN_TOTAL_BUDGET_SEC) or 0.0

    timeout_ms = int(nav_timeout_sec * 1000) if nav_timeout_sec > 0 else None
    budget_ms = int(budget_sec * 1000) if budget_sec > 0 else None

    res = {
        "engine": "dyn",
        "errors": [],
        "network_posts": 0,
        "page_findings": {},
        "debug": {
            "goto_calls": [],
            "wait_calls": [],
            "timing": {},
        },
    }

    t0 = time.monotonic()

    def remain_ms():
        if budget_ms is None:
            return None
        used = int((time.monotonic() - t0) * 1000)
        left = max(0, budget_ms - used)
        res["debug"]["timing"]["used_ms"] = used
        res["debug"]["timing"]["remain_ms"] = left
        return left

    async with _DYN_SEM:
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                ctx = await browser.new_context(ignore_https_errors=True)

                block_scripts = os.getenv("PG_DYN_BLOCK_SCRIPTS", "0") == "1"

                async def _route_handler(route, request):
                    try:
                        rt = request.resource_type
                        if rt in ("image", "media", "font", "stylesheet") or (
                            block_scripts and rt == "script"
                        ):
                            await route.abort()
                        else:
                            await route.continue_()
                    except Exception:
                        with contextlib.suppress(Exception):
                            await route.abort()

                with contextlib.suppress(Exception):
                    await ctx.route("**/*", _route_handler)

                page = await ctx.new_page()

                if timeout_ms is not None:
                    page.set_default_navigation_timeout(float(timeout_ms))
                    page.set_default_timeout(float(timeout_ms))
                else:
                    page.set_default_navigation_timeout(0)
                    page.set_default_timeout(0)

                post_hosts = set()
                has_pw_input_flag = False

                def on_request(req):
                    try:
                        if req.method == "POST":
                            res["network_posts"] += 1
                            url_req = req.url
                            host_req = urlparse(url_req).hostname or ""
                            reg = _registrable(host_req)
                            if reg:
                                post_hosts.add(reg)
                    except Exception:
                        pass

                page.on("request", on_request)

                async def _goto(state: str):
                    kwargs = {"wait_until": state}
                    r = remain_ms()

                    to_val = None
                    if timeout_ms is not None and r is not None:
                        to_val = min(timeout_ms, r)
                        if to_val <= 0:
                            raise asyncio.TimeoutError("budget_exhausted")
                    elif timeout_ms is not None:
                        to_val = timeout_ms
                    elif r is not None:
                        to_val = r
                        if to_val <= 0:
                            raise asyncio.TimeoutError("budget_exhausted")

                    res["debug"]["goto_calls"].append(
                        {
                            "state": state,
                            "timeout_ms_cfg": timeout_ms,
                            "remain_ms": r,
                            "kwargs_timeout": to_val,
                            "kwargs_timeout_type": _type_name(to_val),
                        }
                    )

                    task = asyncio.create_task(page.goto(url, **kwargs))
                    try:
                        return await task
                    except asyncio.CancelledError:
                        with contextlib.suppress(asyncio.CancelledError, Exception):
                            await task
                        raise
                    except Exception as e:
                        raise e
                    finally:
                        if not task.done():
                            task.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await task

                nav_ok = False
                try:
                    await _goto("domcontentloaded")
                    nav_ok = True
                except Exception as e:
                    res["errors"].append(f"dcl:{e!s}")

                if not nav_ok:
                    try:
                        await _goto("commit")
                        r = remain_ms()
                        wait_more = 0
                        if timeout_ms is not None and r is not None:
                            wait_more = min(timeout_ms // 2, r // 2)
                        elif timeout_ms is not None:
                            wait_more = timeout_ms // 2
                        elif r is not None:
                            wait_more = r // 2

                        if wait_more and wait_more > 0:
                            tmo = _as_float(wait_more)
                            if tmo and tmo > 0:
                                res["debug"]["wait_calls"].append(
                                    {
                                        "state": "domcontentloaded",
                                        "timeout": tmo,
                                        "timeout_type": _type_name(tmo),
                                    }
                                )
                                with contextlib.suppress(Exception):
                                    await page.wait_for_load_state(
                                        "domcontentloaded", timeout=tmo
                                    )
                        nav_ok = True
                    except Exception as e:
                        res["errors"].append(f"commit:{e!s}")

                if not nav_ok:
                    try:
                        await _goto("load")
                        nav_ok = True
                    except Exception as e:
                        res["errors"].append(f"load:{e!s}")

                if nav_ok:
                    try:
                        r = remain_ms()
                        if r is None or r > 0:
                            pw_input = await page.query_selector("input[type='password']")
                            if pw_input:
                                has_pw_input_flag = True

                                try:
                                    form = await pw_input.evaluate_handle(
                                        "el => el.closest('form')"
                                    )
                                except Exception:
                                    form = None

                                if form:
                                    with contextlib.suppress(Exception):
                                        user_input = await form.query_selector(
                                            "input[type='email'],"
                                            "input[name*='user' i],"
                                            "input[name*='login' i],"
                                            "input[type='text']"
                                        )
                                        if user_input:
                                            await user_input.fill("test@example.com")

                                    with contextlib.suppress(Exception):
                                        await pw_input.fill("P@ssw0rd!")

                                    submit = None
                                    with contextlib.suppress(Exception):
                                        submit = await form.query_selector(
                                            "button[type='submit'],"
                                            "input[type='submit'],"
                                            "button"
                                        )

                                    if submit:
                                        tmo = None
                                        r2 = remain_ms()
                                        if timeout_ms is not None and r2 is not None:
                                            tmo = min(timeout_ms, r2)
                                        elif timeout_ms is not None:
                                            tmo = timeout_ms
                                        elif r2 is not None:
                                            tmo = r2

                                        try:
                                            await submit.click()
                                            if tmo and tmo > 0:
                                                res["debug"]["wait_calls"].append(
                                                    {
                                                        "state": "login_click",
                                                        "timeout": float(tmo),
                                                        "timeout_type": _type_name(
                                                            tmo
                                                        ),
                                                    }
                                                )
                                                with contextlib.suppress(Exception):
                                                    await page.wait_for_load_state(
                                                        "networkidle",
                                                        timeout=float(tmo),
                                                    )
                                        except Exception as e:
                                            res["errors"].append(
                                                f"login_click:{e!s}"
                                            )
                    except Exception as e:
                        res["errors"].append(f"login_click_outer:{e!s}")

                form_actions = []
                with contextlib.suppress(Exception):
                    form_actions = await page.eval_on_selector_all(
                        "form",
                        "(els) => els.map(e => e.getAttribute('action'))",
                    ) or []

                res["page_findings"]["external_form_actions"] = sum(
                    1 for a in form_actions if a and a.lower().startswith("http")
                )
                res["page_findings"]["form_samples"] = form_actions[:3]

                html_snapshot = ""
                with contextlib.suppress(Exception):
                    html_snapshot = await page.content()

                if html_snapshot:
                    if len(html_snapshot) > MAX_HTML_BYTES:
                        keep = MAX_HTML_BYTES // 2
                        html_snapshot = (
                            html_snapshot[:keep]
                            + "\n<!-- [dyn-truncated: head+tail] -->\n"
                            + html_snapshot[-keep:]
                        )
                    res["html_snapshot"] = html_snapshot

                with contextlib.suppress(Exception):
                    final_url = page.url
                    res["final_url"] = final_url
                    host = final_url.split("://", 1)[1].split("/", 1)[0]
                    res["final_ip"] = sorted(
                        {ai[4][0] for ai in socket.getaddrinfo(host, None)}
                    )

                res["login_form_present"] = bool(has_pw_input_flag)

                with contextlib.suppress(Exception, TargetClosedError):
                    await page.close()
                with contextlib.suppress(Exception, TargetClosedError):
                    await ctx.close()
                with contextlib.suppress(Exception, TargetClosedError):
                    await browser.close()

                if post_hosts:
                    res["post_hosts"] = sorted(post_hosts)

        except asyncio.TimeoutError:
            res["errors"].append("dyn_fail:timeout")
        except asyncio.CancelledError:
            res["errors"].append("dyn_cancelled")
        except TargetClosedError as e:
            res["errors"].append(f"dyn_fail:target_closed:{e!s}")
        except Exception as e:
            res["errors"].append(f"dyn_fail:{e!s}")

    return res


# ─────────────────────────────────────────────────────────────────────────────
# Download + VirusTotal 스캔
# ─────────────────────────────────────────────────────────────────────────────
async def _scan_downloads(url: str) -> Optional[dict]:
    if not (PG_DOWNLOAD_SCAN and _analyze_url_with_downloads):
        return None
    loop = asyncio.get_running_loop()

    def _call():
        try:
            try:
                return _analyze_url_with_downloads(
                    url, wait_seconds=PG_DOWNLOAD_SCAN_WAIT
                )
            except TypeError:
                return _analyze_url_with_downloads(url)
        except Exception as e:
            return {"error": str(e)}

    return await loop.run_in_executor(None, _call)


# ─────────────────────────────────────────────────────────────────────────────
# Analyze flow
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/analyze", response_model=StartAnalyzeResp)
async def start_analyze(req: AnalyzeReq, principal: str = Depends(resolve_principal)):
    if not req.url and not req.html:
        raise HTTPException(status_code=400, detail="url or html required")

    # 레이트리밋
    key = f"analyze:{principal}"
    if not getattr(start_analyze, "_rate", None):
        start_analyze._rate = {}
    bucket = start_analyze._rate
    now_min = int(time.time() // 60)
    b = bucket.get(key)
    if not b or b["t"] != now_min:
        b = {"t": now_min, "n": 0}
    b["n"] += 1
    bucket[key] = b
    if b["n"] > ANALYZE_RATE_PER_MIN:
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    task_id = str(uuid.uuid4())
    TASKS[task_id] = {
        "status": "queued",
        "created_at": now_utc(),
        "by": principal,
        "payload": {
            "url": req.url,
            "html": req.html,
            "referer": req.referer,
            "meta": req.meta or {},
        },
    }
    asyncio.create_task(_run_analysis(task_id))
    return StartAnalyzeResp(task_id=task_id)


@app.post("/api/analyze", response_model=StartAnalyzeResp)
async def api_start_analyze(
    req: AnalyzeReq,
    principal: str = Depends(resolve_principal),
):
    return await start_analyze(req, principal)


@app.get("/api/analyze/{task_id}", response_model=TaskResp)
async def api_get_analyze(
    task_id: str,
    principal: str = Depends(resolve_principal),
    verbose: bool = Query(False),
):
    return await get_task(task_id, principal, verbose)


async def _run_analysis(task_id: str):
    TASKS[task_id]["status"] = "running"
    payload = TASKS[task_id]["payload"]
    url = (payload.get("url") or "").strip()
    html = payload.get("html") or ""
    _trace(task_id, "start", url=url, have_html=bool(html))

    # 1) 정적 페치
    evidence = None
    if url.startswith(("http://", "https://")):
        try:
            fetched = await _fetch_page(url)
            evidence = fetched
            if fetched.get("html"):
                html = fetched["html"]
        except Exception as e:
            TASKS[task_id]["fetch_error"] = str(e)
    _trace(task_id, "fetch_done", evidence=evidence)

    # 2) 동적 분석(옵션)
    dyn_res = {
        "engine": "dyn",
        "errors": ["dyn_not_run"],
        "network_posts": 0,
        "page_findings": {},
    }
    _trace(
        task_id,
        "dyn_before",
        dyn_enabled=PG_DYN_PLAYWRIGHT,
        nav_timeout=PG_DYN_NAV_TIMEOUT_SEC,
        budget=PG_DYN_TOTAL_BUDGET_SEC,
        task_timeout=PG_DYN_TASK_TIMEOUT_SEC,
    )
    try:
        if PG_DYN_PLAYWRIGHT and url.startswith(("http://", "https://")):
            coro = _dynamic_analyze(url)
            if PG_DYN_TASK_TIMEOUT_SEC and _as_float(PG_DYN_TASK_TIMEOUT_SEC):
                tmp = await asyncio.wait_for(
                    coro, timeout=_as_float(PG_DYN_TASK_TIMEOUT_SEC)
                )
            else:
                tmp = await coro
            dyn_res = (
                tmp
                if isinstance(tmp, dict)
                else {
                    "engine": "dyn",
                    "errors": ["dyn_returned_none"],
                    "network_posts": 0,
                    "page_findings": {},
                }
            )
        else:
            dyn_res = {
                "engine": "dyn",
                "errors": [
                    "dyn_disabled" if not PG_DYN_PLAYWRIGHT else "scheme_not_http"
                ],
                "network_posts": 0,
                "page_findings": {},
            }
    except asyncio.TimeoutError:
        dyn_res = {
            "engine": "dyn",
            "errors": ["dyn_task_timeout"],
            "network_posts": 0,
            "page_findings": {},
        }
    except Exception as e:
        dyn_res = {
            "engine": "dyn",
            "errors": [f"dyn_fail:{e!s}"],
            "network_posts": 0,
            "page_findings": {},
        }
    finally:
        _trace(task_id, "dyn_after", dyn_res=dyn_res)

    # 2.5) evidence에 dynamic 병합 + 동적 HTML 스냅샷 사용
    if dyn_res:
        evidence = evidence or {}
        evidence.setdefault("dynamic", {}).update(dyn_res)
        dyn_html = dyn_res.get("html_snapshot")
        if dyn_html:
            html = dyn_html

    # 2.6) 다운로드 분석 (옵션)
    downloads_info = None
    try:
        if url.startswith(("http://", "https://")):
            downloads_info = await _scan_downloads(url)
    except Exception as e:
        downloads_info = {"error": str(e)}
    _trace(task_id, "downloads_after", downloads=downloads_info)

    if downloads_info is not None:
        evidence = evidence or {}
        evidence["downloads"] = downloads_info

    # 3) HTML 특징 추출
    base_for_html = (
        (evidence.get("dynamic", {}) if evidence else {}).get("final_url")
        or (evidence.get("final_url") if (evidence and evidence.get("final_url")) else url)
    )
    html_feats = extract_html_features(html, base_url=base_for_html) if html else {}

    # 4) 외부 분석기(local_analyze) 시도
    def _wrap_result(x):
        if isinstance(x, dict) and "risk_score" in x:
            return x
        if isinstance(x, tuple) and len(x) in (2, 3):
            score = float(x[0])
            reasons = x[1] if isinstance(x[1], list) else []
            features = x[2] if len(x) > 2 and isinstance(x[2], dict) else {}
            return {
                "risk_score": score,
                "engine": "adapter",
                "reasons": reasons,
                "features": features,
            }
        if isinstance(x, (int, float)):
            return {"risk_score": float(x), "engine": "adapter"}
        return None

    result = None
    _trace(task_id, "local_analyze_before", has_local=bool(local_analyze))
    try:
        if local_analyze is not None:
            try:
                maybe = local_analyze(
                    url=url, html=html, meta=payload.get("meta") or {}
                )
            except TypeError:
                try:
                    maybe = local_analyze(url, html)
                except TypeError:
                    maybe = local_analyze(
                        {"url": url, "html": html, "meta": payload.get("meta") or {}}
                    )
            result0 = await maybe if inspect.isawaitable(maybe) else maybe
            result = _wrap_result(result0)
        _trace(task_id, "local_analyze_after", result=result)
    except Exception as e:
        TASKS[task_id]["error_raw"] = f"local_analyze failed: {e}"
        _trace(task_id, "local_analyze_error", error=str(e))

    # 5) 룰 폴백
    if result is None:
        result = _quick_rule_score(url, html, html_feats, evidence=evidence)

    # 5.1) 동적 에러는 사유만
    for msg in TASKS[task_id].get("dyn_errors", []):
        result.setdefault("reasons", []).append(
            {
                "feature": "navigation_error",
                "score": W.get("NAV_ERROR", 0),
                "detail": str(msg),
            }
        )

    feats = result.setdefault("features", {})

    http_status = None
    if evidence:
        http_status = evidence.get("http_status") or evidence.get("status_code")
    feats["http_status"] = http_status

    # 다운로드 summary
    if downloads_info is not None:
        feats["downloads"] = downloads_info
        dl_list = []
        if isinstance(downloads_info, dict):
            dl_list = (
                downloads_info.get("downloads")
                or downloads_info.get("files")
                or []
            )

        max_vt_risk = None

        for item in dl_list:
            if not isinstance(item, dict):
                continue
            summary = item.get("vt_summary") or {}
            try:
                r = float(summary.get("risk_score_percent", 0.0) or 0.0)
            except Exception:
                r = None
            if r is not None:
                max_vt_risk = r if max_vt_risk is None else max(max_vt_risk, r)

        if max_vt_risk is None:
            try:
                max_vt_risk = float(
                    downloads_info.get("max_risk_score")
                    or downloads_info.get("max_vt_score")
                    or 0.0
                )
            except Exception:
                max_vt_risk = 0.0

        dl_summary = {
            "enabled": PG_DOWNLOAD_SCAN,
            "ran": bool(downloads_info) and not downloads_info.get("error"),
            "download_count": len(dl_list),
            "max_vt_risk": max_vt_risk,
        }
        feats["downloads_summary"] = dl_summary

        # 1) 다운로드 존재 자체
        if dl_summary["download_count"] > 0:
            d_any = W.get("DOWNLOAD_ANY", 0)
            if d_any:
                base_score = float(result.get("risk_score", 0.0) or 0.0)
                new_score = min(SCORE_MAX, base_score + d_any)
                result["risk_score"] = new_score
                result.setdefault("reasons", []).append(
                    {
                        "feature": "download_any",
                        "score": d_any,
                        "detail": f"{dl_summary['download_count']} file(s) downloaded",
                    }
                )

        # 2) VT 위험도에 따른 추가 가중치
        if max_vt_risk is not None:
            feat_name = None
            delta = 0

            if max_vt_risk >= 70.0:
                feat_name = "download_vt_malicious"
                delta = W.get("DOWNLOAD_VT_MAL", 0)
            elif max_vt_risk >= 30.0:
                feat_name = "download_vt_suspicious"
                delta = W.get("DOWNLOAD_VT_SUSP", 0)

            if feat_name and delta > 0:
                base_score = float(result.get("risk_score", 0.0) or 0.0)
                new_score = min(SCORE_MAX, base_score + delta)
                result["risk_score"] = new_score
                result.setdefault("reasons", []).append(
                    {
                        "feature": feat_name,
                        "score": delta,
                        "detail": (
                            f"Max downloaded file VT risk ≈ {max_vt_risk:.1f}%"
                        ),
                    }
                )

    # 5.3) VirusTotal URL 평판
    vt_info = None
    base_for_vt = None
    if evidence:
        base_for_vt = evidence.get("final_url") or evidence.get("start_url")
    if not base_for_vt:
        base_for_vt = url

    if VT_ENABLE and base_for_vt:
        try:
            vt_info = await _vt_reputation(base_for_vt)
        except Exception as e:
            vt_info = {"source": "virustotal", "error": str(e)}

    _trace(task_id, "vt_after", vt_info=vt_info)

    if vt_info is not None:
        feats["virustotal"] = vt_info

        if vt_info.get("found") and not vt_info.get("error"):
            mal = int(vt_info.get("malicious", 0) or 0)
            ratio = float(vt_info.get("ratio", 0.0) or 0.0)
            engines = int(vt_info.get("total_engines", 0) or 0)

            if mal > 0:
                if mal >= 3:
                    vt_norm = 0.95
                elif mal == 2:
                    vt_norm = 0.90
                else:
                    vt_norm = 0.80

                vt_norm = max(vt_norm, min(0.99, ratio * 1.2))

                vt_contrib = vt_norm * SCORE_MAX
                cur = float(result.get("risk_score", 0.0) or 0.0)

                new_score = max(cur, vt_contrib)
                result["risk_score"] = new_score

                result.setdefault("reasons", []).append(
                    {
                        "feature": "vt_url_malicious",
                        "score": round(vt_contrib, 1),
                        "detail": (
                            f"VirusTotal: {mal}/{engines} engines flagged "
                            f"(ratio={ratio:.3f})"
                        ),
                    }
                )
            else:
                result.setdefault("reasons", []).append(
                    {
                        "feature": "vt_url_info",
                        "detail": (
                            f"VirusTotal: {mal}/{engines} malicious engines "
                            f"(ratio={ratio:.3f})"
                        ),
                    }
                )

    # 5.5) ML 앙상블
    ml_info = _ml_predict(url, html)
    _trace(task_id, "ml_fuse", ml_info=ml_info, rules_weight=PG_ML_RULES_WEIGHT)

    if ml_info is not None:
        if isinstance(ml_info, dict):
            ml_p = float(ml_info.get("prob", 0.5))
        else:
            ml_p = float(ml_info)

        base_score = float(result.get("risk_score", 0.0))

        try:
            scale = float(SCORE_MAX) if SCORE_MAX > 0 else 100.0
            rules_norm = max(0.0, min(1.0, base_score / scale))
        except Exception:
            rules_norm = 0.0

        w_cfg = max(0.0, min(1.0, PG_ML_RULES_WEIGHT))

        if rules_norm >= 0.8:
            w = 1.0
        else:
            w = w_cfg

        if w >= 1.0:
            fused_norm = rules_norm
        else:
            fused_norm = w * rules_norm + (1.0 - w) * ml_p

        fused_norm = max(0.0, min(1.0, fused_norm))
        fused_100 = int(round(100 * fused_norm))

        result.setdefault("reasons").append(
            {
                "feature": "ml_prob",
                "score": round(ml_p, 3),
                "detail": f"ML phishing probability (w_rules={w})",
            }
        )

        ml_feat = feats.setdefault("ml", {})
        if isinstance(ml_info, dict):
            for k, v in ml_info.items():
                if k != "prob":
                    ml_feat[k] = v
        ml_feat.update(
            {
                "prob": round(ml_p, 4),
                "rules_norm": round(rules_norm, 4),
                "weight_rules": w,
            }
        )

        result["risk_score"] = fused_100

    # 6) 결과 표준화
    result = _normalize_result(result)
    if "reasons" in result:
        result["reasons"] = _canon_reasons(result["reasons"])
        if PG_HIDE_NAV_ERROR:
            result["reasons"] = [
                r
                for r in result["reasons"]
                if (r.get("feature") or "").lower() != "navigation_error"
            ]
        else:
            for r in result["reasons"]:
                if (r.get("feature") or "").lower() == "navigation_error":
                    r.pop("score", None)
    if not result.get("reasons"):
        result["risk_score"] = 0
        result = _normalize_result(result)

    # 🔹 신뢰 도메인 점수 보정 먼저
    result = _post_adjust_trusted(result, url)

    # 🔹 최종 점수는 반드시 0~100 스케일의 risk_score로 통일
    result["risk_score"] = result.get("risk_score_100", 0)
    result["score_scale"] = 100
    result["score"] = result["risk_score"]


    # 7) 저장
    TASKS[task_id]["status"] = "done"
    TASKS[task_id]["result"] = result
    record = {
        "task_id": task_id,
        "created_at": TASKS[task_id]["created_at"].isoformat(),
        "by": TASKS[task_id]["by"],
        "payload": TASKS[task_id]["payload"],
        "result": result,
    }
    _trace(task_id, "done", final_score=result.get("risk_score"))
    try:
        (TASK_DIR / f"{task_id}.json").write_text(
            json.dumps(record, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception as _e:
        TASKS[task_id]["persist_error"] = str(_e)


@app.get("/tasks/{task_id}", response_model=TaskResp)
async def get_task(
    task_id: str,
    principal: str = Depends(resolve_principal),
    verbose: bool = Query(False),
):
    t = TASKS.get(task_id)
    if not t:
        raise HTTPException(status_code=404, detail="task not found")
    if t.get("by") != principal:
        raise HTTPException(status_code=403, detail="forbidden")

    # 1) 서명 대상이 되는 payload 구성 (trace 같은 디버그 정보는 제외)
    base_payload = {
        "task_id": task_id,
        "status": t["status"],
        "result": t.get("result"),
        "error": t.get("error"),
        "created_at": t["created_at"].isoformat(),
    }

    # 2) canonical JSON → 서명 문자열
    payload_str = _canon_json(base_payload)
    sig = _sign_payload(payload_str)

    # 3) 클라이언트에 내려줄 result (verbose일 때만 trace를 추가)
    result_for_client = t.get("result")
    if verbose and t.get("_trace"):
        if result_for_client is None:
            result_for_client = {}
        # shallow copy 해서 trace 추가
        if not isinstance(result_for_client, dict):
            result_for_client = dict(result_for_client)
        result_for_client.setdefault("debug", {})["trace"] = t["_trace"]

    # 4) 응답 생성
    resp = TaskResp(
        task_id=task_id,
        status=t["status"],
        result=result_for_client,
        error=t.get("error"),
        created_at=base_payload["created_at"],
        signed_payload=payload_str,
        sig=sig,
        kid=KID,
    )
    return resp



# ─────────────────────────────────────────────────────────────────────────────
# ML 피드백/상태 엔드포인트
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/ml/feedback")
async def ml_feedback(
    req: FeedbackReq, principal: str = Depends(resolve_principal)
):
    if not analyzer_ml_feedback:
        raise HTTPException(status_code=503, detail="ml feedback not available")
    url = (req.url or "").strip()
    if not url and req.task_id:
        t = TASKS.get(req.task_id)
        if not t or t.get("by") != principal:
            raise HTTPException(
                status_code=404, detail="task not found or forbidden"
            )
        url = (t.get("payload") or {}).get("url") or ""
    if not url:
        raise HTTPException(status_code=400, detail="url required")
    if req.label not in (-1, 0, 1):
        raise HTTPException(
            status_code=400, detail="label must be one of -1/0/1"
        )
    return analyzer_ml_feedback(url, req.label)


@app.get("/ml/status")
async def ml_status():
    """
    클라이언트용 ML 모델 상태:
    - enabled / backend / model_path
    - version: 모델 파일 mtime 기반 (정수 문자열)
    - download_url: /static/... 경로 (PG_ML_DOWNLOAD_PATH 기준)
    - backend_status: analyzer 백엔드가 있으면 추가 정보
    """
    info: Dict[str, Any] = {
        "enabled": PG_ENABLE_ML,
        "backend": PG_ML_BACKEND,
        "model_path": PG_ML_MODEL_PATH,
        "version": None,
        "download_url": None,
    }

    # 모델 파일 mtime → version
    try:
        p = pathlib.Path(PG_ML_MODEL_PATH)
        if p.is_file():
            st = p.stat()
            info["version"] = str(int(st.st_mtime))
    except Exception as e:
        info["model_error"] = str(e)

    # analyzer 백엔드 상태 (있다면)
    if analyzer_ml_status:
        try:
            info["backend_status"] = analyzer_ml_status()
        except Exception as e:
            info["backend_status_error"] = str(e)

    # 클라에서 다운로드할 URL
    if PG_ML_DOWNLOAD_PATH:
        info["download_url"] = f"/static/{PG_ML_DOWNLOAD_PATH.lstrip('/')}"
    else:
        info["download_url"] = None

    return info


# ─────────────────────────────────────────────────────────────────────────────
# 디버그 엔드포인트
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/_debug/config")
async def _debug_config():
    return {
        "dotenv_path": ENV_PATH,
        "cwd": os.getcwd(),
        "api_keys_loaded": list(get_api_keys().keys()),
    }


@app.get("/_debug/flags")
async def _debug_flags():
    return {
        "dyn_enabled": PG_DYN_PLAYWRIGHT,
        "dyn_nav_timeout_sec": PG_DYN_NAV_TIMEOUT_SEC,
        "dyn_total_budget_sec": PG_DYN_TOTAL_BUDGET_SEC,
        "dyn_task_timeout_sec": PG_DYN_TASK_TIMEOUT_SEC,
        "dyn_block_scripts": PG_DYN_BLOCK_SCRIPTS,
        "nav_error_weight": W.get("NAV_ERROR", 0),
        "hide_nav_error": PG_HIDE_NAV_ERROR,
        "fetch_html": FETCH_HTML,
        "follow_meta_refresh": FOLLOW_META_REFRESH,
        "fetch_timeout": FETCH_TIMEOUT,
        "score_max": SCORE_MAX,
        "ml_enabled": PG_ENABLE_ML,
        "ml_backend": PG_ML_BACKEND,
        "ml_model_path": PG_ML_MODEL_PATH,
        "ml_rules_weight": PG_ML_RULES_WEIGHT,
        "trace_task": PG_TRACE_TASK,
        "download_scan": PG_DOWNLOAD_SCAN,
        "download_scan_wait": PG_DOWNLOAD_SCAN_WAIT,
        "download_scan_min_score": PG_DOWNLOAD_SCAN_MIN_SCORE,
        "vt_enable": VT_ENABLE,
        "vt_weight": VT_WEIGHT,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 전역 에러 처리
# ─────────────────────────────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def unhandled_exc(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "internal error", "error": str(exc)},
    )
