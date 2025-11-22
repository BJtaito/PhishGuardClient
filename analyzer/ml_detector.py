# -*- coding: utf-8 -*-
"""
우리 프로젝트용 ML 모듈 (온라인 학습 + 에이징 + HTML 채널 + Dyn 힌트)

채널
- URL_HASH:  URL 문자 n-gram 해싱 + SGDClassifier(partial_fit)
- URL_LEX:   URL 19개 수치 피처 + SGDClassifier(partial_fit)
- HTML_HASH: HTML 문자 n-gram 해싱 + SGDClassifier(partial_fit)
- HTML_NUM:  HTML 16개 정적 피처 + SGDClassifier(partial_fit)
- DYN_HINT:  동적 분석 결과(dyn)를 점수화한 힌트 채널 (휴리스틱)

특징
- 온라인 학습 feedback(), 주기 재학습 maint_beat() (에이징 가중치)
- 상태/데이터 저장: analyzer/ml_state/
- HTML은 .env 설정에 따라 data.jsonl에 **절삭 저장**(선택)
"""

from __future__ import annotations
import os, re, json, time, math, threading, io, datetime as _dt
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
from collections import Counter
import unicodedata

# ---------- 런타임 의존성 ----------
try:
    import numpy as np
    from sklearn.feature_extraction.text import HashingVectorizer
    from sklearn.linear_model import SGDClassifier
    from sklearn.utils.validation import check_is_fitted
    import joblib
except Exception as e:
    np = None
    _IMPORT_ERR = f"sklearn_import_fail:{e!s}"
else:
    _IMPORT_ERR = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None  # 없어도 동작(단순 정규식 파서로 대체)

# ---------- 경로/환경 ----------
BASE_DIR   = os.path.dirname(__file__)
STATE_DIR  = os.path.join(BASE_DIR, "ml_state")
os.makedirs(STATE_DIR, exist_ok=True)

DATA_PATH        = os.path.join(STATE_DIR, "data.jsonl")  # 학습 샘플 저장
MODEL_HASH_URL   = os.path.join(STATE_DIR, "url_hash_sgd.joblib")
MODEL_LEX_URL    = os.path.join(STATE_DIR, "url_lex_sgd.joblib")
MODEL_HASH_HTML  = os.path.join(STATE_DIR, "html_hash_sgd.joblib")
MODEL_NUM_HTML   = os.path.join(STATE_DIR, "html_num_sgd.joblib")
META_PATH        = os.path.join(STATE_DIR, "meta.json")

# .env 제어
PG_ML_ONLINE         = os.getenv("PG_ML_ONLINE", "1") == "1"
PG_ML_AUTOTRAIN      = os.getenv("PG_ML_AUTOTRAIN", "1") == "1"
PG_ML_DECAY_LAMBDA   = float(os.getenv("PG_ML_DECAY_LAMBDA", "0.08"))
PG_ML_WINDOW_DAYS    = int(os.getenv("PG_ML_WINDOW_DAYS", "60"))
PG_ML_MINIBATCH      = int(os.getenv("PG_ML_MINIBATCH", "256"))
PG_ML_RETRAIN_EVERY  = int(os.getenv("PG_ML_RETRAIN_EVERY", "3600"))

PG_ML_HTML_ENABLE    = os.getenv("PG_ML_HTML_ENABLE", "1") == "1"  # HTML 채널 사용
PG_ML_STORE_HTML     = os.getenv("PG_ML_STORE_HTML", "1") == "1"   # data.jsonl에 HTML 저장
PG_ML_HTML_MAX_BYTES = int(os.getenv("PG_ML_HTML_MAX_BYTES", "50000"))

# 앙상블 가중치
PG_ML_ENS_URL_HASH_W  = float(os.getenv("PG_ML_ENS_URL_HASH_W", "0.6"))
PG_ML_ENS_URL_LEX_W   = float(os.getenv("PG_ML_ENS_URL_LEX_W",  "0.4"))
PG_ML_ENS_HTML_HASH_W = float(os.getenv("PG_ML_ENS_HTML_HASH_W","0.3"))
PG_ML_ENS_HTML_NUM_W  = float(os.getenv("PG_ML_ENS_HTML_NUM_W", "0.2"))
# 🔥 NEW: 동적 채널 가중치
PG_ML_ENS_DYN_W       = float(os.getenv("PG_ML_ENS_DYN_W", "0.8"))

# 🔽 최종 verdict 기준값 (피싱/정상 threshold)
# prob >= TH_PHISH     → label = -1 (피싱)
# prob <= TH_BENIGN    → label = 1  (정상)
# 그 사이               → label = 0  (애매/수상)
PG_ML_TH_PHISH   = float(os.getenv("PG_ML_TH_PHISH", "0.60"))
PG_ML_TH_BENIGN  = float(os.getenv("PG_ML_TH_BENIGN", "0.20"))

# 내부 라벨: y=1(피싱), y=0(정상)
_LABEL_MAP = { -1: 1, 1: 0, 0: 0 }

_LOCK = threading.Lock()
_STATE: Dict[str, Any] = {
    # URL
    "url_hash_vec": None,
    "url_hash_sgd": None,
    "url_lex_sgd":  None,
    # HTML
    "html_hash_vec": None,
    "html_hash_sgd": None,
    "html_num_sgd":  None,
    # 공통
    "classes": np.array([0,1]) if np is not None else None,
    "last_train_ts": 0.0,
    "initialized": False,
    "load_err": _IMPORT_ERR,
}

# ---------- 유틸: 시간/로그 ----------
def _now_ts() -> float:
    return time.time()

def _utc_iso(ts: float | None = None) -> str:
    if ts is None:
        ts = _now_ts()
    return _dt.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")

def _log(msg: str):
    # print(f"[ml] {msg}")
    pass

# ---------- URL 19개 수치 피처 ----------
_SUSP_TLDS = {
    "tk","ml","ga","cf","gq","ru","cn","top","work","zip","country",
    "kim","men","loan","click","party","review","cab","stream"
}
_SHORTENERS = {
    "bit.ly","goo.gl","t.co","ow.ly","tinyurl.com","is.gd","buff.ly","cutt.ly",
    "shorte.st","adf.ly","rebrand.ly","lnkd.in"
}
_SUSP_WORDS = {"login","signin","verify","update","secure","confirm",
               "account","wallet","bank","password","credential","invoice"}

def _is_ipv4_literal(h: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h or ""))

def _entropy(s: str) -> float:
    if not s: return 0.0
    c = Counter(s); n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

ML_FEATURE_ORDER = [
    "url_len","host_len","path_len","query_len","num_dots_host","num_hyphen_host",
    "num_slash_path","has_at","has_ip_host","subdomain_count","digit_ratio_host",
    "entropy_host","num_params","has_https_token_in_host","shortener_host","susp_tld",
    "susp_words_in_url","scheme_http","has_port","tld_len"
]

def _extract_lex19(url: str) -> List[float]:
    p = urlparse(url)
    host = (p.hostname or "")
    path = (p.path or "")
    query = (p.query or "")
    subdomain_count = host.count(".") - 1 if host.count(".")>=2 else 0
    tld = host.split(".")[-1] if "." in host else ""
    digit_ratio = (sum(ch.isdigit() for ch in host) / max(1,len(host)))
    feats = {
        "url_len": len(url),
        "host_len": len(host),
        "path_len": len(path),
        "query_len": len(query),
        "num_dots_host": host.count("."),
        "num_hyphen_host": host.count("-"),
        "num_slash_path": path.count("/"),
        "has_at": int("@" in url),
        "has_ip_host": int(_is_ipv4_literal(host)),
        "subdomain_count": subdomain_count,
        "digit_ratio_host": round(digit_ratio, 4),
        "entropy_host": round(_entropy(host), 4),
        "num_params": (query.count("&") + (1 if query else 0)),
        "has_https_token_in_host": int("https" in host and p.scheme != "https"),
        "shortener_host": int(any(host.endswith(s) for s in _SHORTENERS)),
        "susp_tld": int((tld or "").lower() in _SUSP_TLDS),
        "susp_words_in_url": sum(1 for w in _SUSP_WORDS if w in url.lower()),
        "scheme_http": int(p.scheme == "http"),
        "has_port": int(p.port is not None),
        "tld_len": len(tld or ""),
    }
    return [feats[k] for k in ML_FEATURE_ORDER]

# ---------- HTML 16개 정적 피처 ----------
_HTML_SUSP_WORDS = {"login","signin","verify","update","secure","confirm",
                    "account","wallet","bank","password","credential","invoice","otp","pin"}

def _normalize_for_kw(s: str) -> str:
    """
    HTML 텍스트에서 피싱 키워드를 찾을 때:
    - 대소문자 무시
    - 악센트 제거 (Påssword -> Password)
    - 일부 leet 문자 보정 (0->o, @->a, $->s 등)
    """
    if not s:
        return ""
    # 악센트/호환 문자 분해 후 결합문자 제거
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.lower()
    table = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    })
    return s.translate(table)

def _extract_html_num(html: str) -> List[float]:
    # 길이 제한(모델 안정)
    h = (html or "")
    L = len(h)
    Lc = min(L, 300000)

    # 기본 카운트(정규식)
    low_raw = h.lower()
    low_norm = _normalize_for_kw(h)  # 악센트/leet 제거된 버전

    has_form  = 1 if "<form" in low_raw else 0
    has_pw    = 1 if ("type=\"password\"" in low_raw or "type='password'" in low_raw) else 0
    iframes   = low_raw.count("<iframe")
    scripts   = low_raw.count("<script")
    inputs    = low_raw.count("<input")
    evals     = low_raw.count("eval(")
    atobs     = low_raw.count("atob(")
    onmouseover = 1 if "onmouseover=" in low_raw else 0
    rightclick = 1 if "oncontextmenu=\"return false" in low_raw or "oncontextmenu='return false" in low_raw else 0
    window_open = low_raw.count("window.open(")

    # 외부 링크/메일to 대충 카운트
    http_links = len(re.findall(r'href=["\']https?://', low_raw))
    mailtos    = low_raw.count("href=\"mailto:") + low_raw.count("href='mailto:")

    # 🔥 keyword 탐지는 normalize된 문자열 기준
    susp_kw = sum(1 for w in _HTML_SUSP_WORDS if w in low_norm)

    return [
        float(Lc),
        float(has_form),
        float(has_pw),
        float(iframes),
        float(scripts),
        float(inputs),
        float(evals),
        float(atobs),
        float(onmouseover),
        float(rightclick),
        float(window_open),
        float(http_links),
        float(mailtos),
        float(susp_kw),
        # 간단 비율: 스크립트/길이, 링크/길이(스케일 안정 위해 1e5로 나눔)
        float(scripts)/max(1.0, Lc/1e5),
        float(http_links)/max(1.0, Lc/1e5),
    ]

# ---------- Dyn(동적 분석) 힌트 피처 ----------
def _registrable_host(host: str) -> str:
    """간단한 registrable host 추출 (마지막 2개 label 기준)."""
    h = host or ""
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h

def _dyn_features(url: str, html: str, dyn: Optional[dict]) -> Dict[str, Any]:
    """
    dyn 구조 (server._dynamic_analyze에서 넘어오는 것 기준):

    {
      "engine": "dyn",
      "errors": [...],
      "network_posts": int,
      "post_hosts": ["example.com", ...],   # registrable host 목록
      "final_url": "https://....",
      "page_findings": {...},
      ...
    }
    """
    base_host = urlparse(url or "").hostname or ""
    base_reg = _registrable_host(base_host)

    has_dyn = 1 if dyn else 0
    n_posts = 0
    n_post_external = 0
    has_errors = 0
    login_no_progress = 0
    has_login_kw = 0

    if dyn:
        try:
            n_posts = int(dyn.get("network_posts") or 0)
        except Exception:
            n_posts = 0

        post_hosts = dyn.get("post_hosts") or []
        for h in post_hosts:
            if h and _registrable_host(h) != base_reg:
                n_post_external += 1

        if dyn.get("errors"):
            has_errors = 1

        # "로그인 후에도 URL이 그대로" 패턴
        if n_posts > 0:
            final_url = dyn.get("final_url") or ""
            if final_url:
                def _canon(u: str) -> str:
                    return (u or "").split("#", 1)[0].rstrip("/")
                try:
                    if _canon(final_url) == _canon(url):
                        login_no_progress = 1
                except Exception:
                    login_no_progress = 0

    # HTML 기반 login 키워드 (Påssword 등까지 normalize)
    if html:
        norm = _normalize_for_kw(html)
        for w in ("password", "login", "sign in", "로그인", "비밀번호"):
            if w in norm:
                has_login_kw = 1
                break

    return {
        "has_dyn": has_dyn,
        "n_posts": n_posts,
        "n_post_external": n_post_external,
        "has_errors": has_errors,
        "login_no_progress": login_no_progress,
        "has_login_kw": has_login_kw,
    }

def _score_dyn(f: Dict[str, Any]) -> float:
    """
    동적 피처 스코어링:
      - has_login_kw: HTML에 로그인/비번 계열 텍스트 존재
      - n_posts: POST 발생
      - n_post_external: 다른 등록가능 도메인으로 POST
      - login_no_progress: POST 후에도 URL이 그대로
    """
    if not f.get("has_dyn"):
        return 0.0

    s = 0.0
    if f.get("has_login_kw"):
        s += 1.2
    if f.get("n_posts", 0) > 0:
        s += 1.0
    if f.get("n_post_external", 0) > 0:
        s += 1.8
    if f.get("n_posts", 0) > 3:
        s += 0.5
    if f.get("login_no_progress"):
        # "로그인 버튼 눌렀는데 여전히 같은 페이지" → 강한 시그널
        s += 2.0
    if f.get("has_errors"):
        # 에러가 있다고 무조건 피싱은 아니지만, 살짝 가중
        s += 0.3

    return s

# ---------- 시그모이드 ----------
def _sigmoid(x: float) -> float:
    try:
        return 1.0/(1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0

# ---------- 모델 로드/초기화/저장 ----------
def _init_models_locked():
    if _STATE.get("initialized"):
        return
    if np is None:
        _STATE["initialized"] = True
        return

    # URL/HTML 해싱 벡터라이저
    url_hv  = HashingVectorizer(encoding="utf-8", decode_error="ignore",
                                analyzer="char_wb", ngram_range=(3,5),
                                n_features=2**18, alternate_sign=False, norm="l2",
                                lowercase=True)
    html_hv = HashingVectorizer(encoding="utf-8", decode_error="ignore",
                                analyzer="char_wb", ngram_range=(3,5),
                                n_features=2**19, alternate_sign=False, norm="l2",
                                lowercase=True)

    # 분류기
    url_hash = SGDClassifier(loss="log_loss", alpha=1e-5, random_state=42)
    url_lex  = SGDClassifier(loss="log_loss", alpha=1e-5, random_state=42)
    html_hash= SGDClassifier(loss="log_loss", alpha=1e-5, random_state=42)
    html_num = SGDClassifier(loss="log_loss", alpha=1e-5, random_state=42)

    # 로드 시도
    try:
        if os.path.exists(MODEL_HASH_URL):
            url_hash = joblib.load(MODEL_HASH_URL)
    except Exception as e:
        _log(f"load_url_hash_fail:{e!s}")
    try:
        if os.path.exists(MODEL_LEX_URL):
            url_lex = joblib.load(MODEL_LEX_URL)
    except Exception as e:
        _log(f"load_url_lex_fail:{e!s}")
    try:
        if os.path.exists(MODEL_HASH_HTML):
            html_hash = joblib.load(MODEL_HASH_HTML)
    except Exception as e:
        _log(f"load_html_hash_fail:{e!s}")
    try:
        if os.path.exists(MODEL_NUM_HTML):
            html_num = joblib.load(MODEL_NUM_HTML)
    except Exception as e:
        _log(f"load_html_num_fail:{e!s}")

    _STATE.update({
        "url_hash_vec":  url_hv,
        "url_hash_sgd":  url_hash,
        "url_lex_sgd":   url_lex,
        "html_hash_vec": html_hv,
        "html_hash_sgd": html_hash,
        "html_num_sgd":  html_num,
        "initialized": True
    })

def _save_models_locked():
    if np is None:
        return
    try: joblib.dump(_STATE["url_hash_sgd"],  MODEL_HASH_URL)
    except Exception as e: _log(f"save_url_hash_fail:{e!s}")
    try: joblib.dump(_STATE["url_lex_sgd"],   MODEL_LEX_URL)
    except Exception as e: _log(f"save_url_lex_fail:{e!s}")
    try: joblib.dump(_STATE["html_hash_sgd"], MODEL_HASH_HTML)
    except Exception as e: _log(f"save_html_hash_fail:{e!s}")
    try: joblib.dump(_STATE["html_num_sgd"],  MODEL_NUM_HTML)
    except Exception as e: _log(f"save_html_num_fail:{e!s}")

    meta = {"last_train_ts": _STATE.get("last_train_ts", 0.0), "updated_at": _utc_iso()}
    try:
        with open(META_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

# ---------- 퍼시스턴스: 데이터 저장/로드 ----------
def _trim_html_for_store(html: str) -> str:
    if not html: return ""
    h = html
    if len(h) > PG_ML_HTML_MAX_BYTES:
        keep = PG_ML_HTML_MAX_BYTES // 2
        h = h[:keep] + "\n<!-- [ml-truncated: head+tail] -->\n" + h[-keep:]
    return h

def _append_data_line(url: str, y: int, ts: Optional[float] = None, html: Optional[str] = None):
    ts = ts or _now_ts()
    rec = {"ts": ts, "url": url, "y": int(y)}
    if PG_ML_HTML_ENABLE and PG_ML_STORE_HTML and html:
        rec["html"] = _trim_html_for_store(html)
    try:
        with io.open(DATA_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        _log(f"append_data_fail:{e!s}")

def _load_window_data(days: int) -> List[Dict[str, Any]]:
    cutoff = _now_ts() - days * 86400
    out: List[Dict[str, Any]] = []
    if not os.path.exists(DATA_PATH):
        return out
    try:
        with io.open(DATA_PATH, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                    if r.get("ts", 0) >= cutoff:
                        out.append(r)
                except Exception:
                    continue
    except Exception:
        pass
    return out

# ---------- 예측 ----------
def predict(url: str, html: str = "", dyn: Optional[dict] = None) -> Dict[str, Any]:
    """
    Returns:
      {
        "prob": float,          # 피싱(내부 y=1) 확률
        "label": -1|0|1,        # -1(피싱), 0(애매), 1(정상)
        "prob_parts": {         # (디버깅/튜닝용) 각 채널별 확률
            "url_hash": float,
            "url_lex": float,
            "html_hash": float | None,
            "html_num": float | None,
            "dyn": float | None,
        },
        "risk": "phish" | "suspicious" | "benign"
      }

    dyn: server.app._dynamic_analyze()에서 온 evidence["dynamic"] 딕셔너리
    """
    if _IMPORT_ERR:
        return {"label": 0}

    with _LOCK:
        _init_models_locked()
        uv    = _STATE["url_hash_vec"]
        uhl   = _STATE["url_hash_sgd"]
        ulx   = _STATE["url_lex_sgd"]
        hv    = _STATE["html_hash_vec"]
        hhl   = _STATE["html_hash_sgd"]
        hnl   = _STATE["html_num_sgd"]

        # URL_HASH
        try:
            X_uh = uv.transform([url])
            try:
                check_is_fitted(uhl)
                p_uh = float(uhl.predict_proba(X_uh)[0][1]) if hasattr(uhl, "predict_proba") \
                       else _sigmoid(float(uhl.decision_function(X_uh)[0]))
            except Exception:
                p_uh = 0.5
        except Exception:
            p_uh = 0.5

        # URL_LEX
        try:
            X_ul = np.asarray([_extract_lex19(url)], dtype=float)
            try:
                check_is_fitted(ulx)
                p_ul = float(ulx.predict_proba(X_ul)[0][1]) if hasattr(ulx, "predict_proba") \
                       else _sigmoid(float(ulx.decision_function(X_ul)[0]))
            except Exception:
                p_ul = 0.5
        except Exception:
            p_ul = 0.5

        # HTML 채널
        p_hh = None
        p_hn = None
        if PG_ML_HTML_ENABLE and html:
            # HTML_HASH
            try:
                X_hh = hv.transform([html])
                try:
                    check_is_fitted(hhl)
                    p_hh = float(hhl.predict_proba(X_hh)[0][1]) if hasattr(hhl, "predict_proba") \
                           else _sigmoid(float(hhl.decision_function(X_hh)[0]))
                except Exception:
                    p_hh = 0.5
            except Exception:
                p_hh = 0.5
            # HTML_NUM
            try:
                X_hn = np.asarray([_extract_html_num(html)], dtype=float)
                try:
                    check_is_fitted(hnl)
                    p_hn = float(hnl.predict_proba(X_hn)[0][1]) if hasattr(hnl, "predict_proba") \
                           else _sigmoid(float(hnl.decision_function(X_hn)[0]))
                except Exception:
                    p_hn = 0.5
            except Exception:
                p_hn = 0.5

        # DYN 힌트 채널 (학습 모델은 아니고 휴리스틱 스코어)
        p_dyn = None
        try:
            f_dyn = _dyn_features(url, html, dyn)
            if f_dyn.get("has_dyn"):
                s_dyn = _score_dyn(f_dyn)
                p_dyn = _sigmoid(s_dyn)
        except Exception:
            p_dyn = None

        # 앙상블
        parts = []
        if p_uh is not None:
            parts.append((PG_ML_ENS_URL_HASH_W,  p_uh))
        if p_ul is not None:
            parts.append((PG_ML_ENS_URL_LEX_W,   p_ul))
        if PG_ML_HTML_ENABLE and p_hh is not None:
            parts.append((PG_ML_ENS_HTML_HASH_W, p_hh))
        if PG_ML_HTML_ENABLE and p_hn is not None:
            parts.append((PG_ML_ENS_HTML_NUM_W,  p_hn))
        if p_dyn is not None:
            parts.append((PG_ML_ENS_DYN_W,       p_dyn))

        if not parts:  # 비정상일 일은 거의 없음
            prob = 0.5
        else:
            wsum = sum(max(0.0, min(1.0, w)) for w,_ in parts)
            if wsum <= 0:
                wsum = float(len(parts))
            prob = sum(max(0.0,min(1.0,w))*p for w,p in parts) / wsum

        # threshold 적용
        th_phish  = PG_ML_TH_PHISH
        th_benign = PG_ML_TH_BENIGN
        # 안전장치 (이상한 값 들어올 경우)
        if th_phish <= th_benign:
            th_phish  = 0.60
            th_benign = 0.20

        if prob >= th_phish:
            label = -1        # 피싱
            risk  = "phish"
        elif prob <= th_benign:
            label = 1         # 정상
            risk  = "benign"
        else:
            label = 0         # 중간/수상
            risk  = "suspicious"

        prob_parts = {
            "url_hash": p_uh,
            "url_lex":  p_ul,
            "html_hash": p_hh,
            "html_num":  p_hn,
            "dyn":       p_dyn,
        }

        return {
            "prob": float(prob),
            "label": int(label),
            "prob_parts": prob_parts,
            "risk": risk,
        }

# ---------- 피드백(온라인 학습) ----------
def feedback(url: str, label: int, ts: Optional[float] = None, html: Optional[str] = None) -> Dict[str, Any]:
    """
    label: -1(피싱), 1(정상), 0(무시)
    html: 가능하면 함께 주면 HTML 채널도 온라인 학습
    """
    if _IMPORT_ERR:
        return {"ok": False, "error": _IMPORT_ERR}
    if label not in (-1, 0, 1):
        return {"ok": False, "error": "invalid_label"}
    if label == 0:
        return {"ok": True, "note": "ignored"}

    y = _LABEL_MAP[label]
    ts = ts or _now_ts()

    with _LOCK:
        _init_models_locked()
        # 저장
        _append_data_line(url, y, ts, html=html if (PG_ML_HTML_ENABLE and PG_ML_STORE_HTML) else None)

        if PG_ML_ONLINE:
            try:
                clz = _STATE["classes"]
                # URL_HASH
                uv  = _STATE["url_hash_vec"]
                uhl = _STATE["url_hash_sgd"]
                X_uh = uv.transform([url])
                try:
                    check_is_fitted(uhl)
                    uhl.partial_fit(X_uh, np.array([y]))
                except Exception:
                    uhl.partial_fit(X_uh, np.array([y]), classes=clz)

                # URL_LEX
                ulx = _STATE["url_lex_sgd"]
                X_ul = np.asarray([_extract_lex19(url)], dtype=float)
                try:
                    check_is_fitted(ulx)
                    ulx.partial_fit(X_ul, np.array([y]))
                except Exception:
                    ulx.partial_fit(X_ul, np.array([y]), classes=clz)

                if PG_ML_HTML_ENABLE and html:
                    # HTML_HASH
                    hv  = _STATE["html_hash_vec"]
                    hhl = _STATE["html_hash_sgd"]
                    X_hh = hv.transform([html])
                    try:
                        check_is_fitted(hhl)
                        hhl.partial_fit(X_hh, np.array([y]))
                    except Exception:
                        hhl.partial_fit(X_hh, np.array([y]), classes=clz)

                    # HTML_NUM
                    hnl = _STATE["html_num_sgd"]
                    X_hn = np.asarray([_extract_html_num(html)], dtype=float)
                    try:
                        check_is_fitted(hnl)
                        hnl.partial_fit(X_hn, np.array([y]))
                    except Exception:
                        hnl.partial_fit(X_hn, np.array([y]), classes=clz)

                _STATE["last_train_ts"] = _now_ts()
                _save_models_locked()
            except Exception as e:
                return {"ok": False, "error": f"online_fit_fail:{e!s}"}

    return {"ok": True}

# ---------- 유지보수 재학습(윈도우 + 에이징) ----------
def maint_beat() -> Dict[str, Any]:
    if _IMPORT_ERR:
        return {"ok": False, "error": _IMPORT_ERR}

    now = _now_ts()
    with _LOCK:
        _init_models_locked()
        if not PG_ML_AUTOTRAIN:
            return {"ok": True, "skipped": "autotrain_disabled"}

        last = _STATE.get("last_train_ts", 0.0)
        if (now - last) < PG_ML_RETRAIN_EVERY:
            return {"ok": True, "skipped": "too_soon", "secs_left": PG_ML_RETRAIN_EVERY - (now - last)}

        rows = _load_window_data(PG_ML_WINDOW_DAYS)
        if not rows:
            _STATE["last_train_ts"] = now
            _save_models_locked()
            return {"ok": True, "info": "no_data"}

        clz = _STATE["classes"]
        uv, uhl = _STATE["url_hash_vec"], _STATE["url_hash_sgd"]
        ulx      = _STATE["url_lex_sgd"]
        hv, hhl  = _STATE["html_hash_vec"], _STATE["html_hash_sgd"]
        hnl      = _STATE["html_num_sgd"]

        urls = [r["url"] for r in rows]
        ys   = np.asarray([int(r["y"]) for r in rows], dtype=int)
        ages = np.asarray([max(0.0, (now - float(r.get("ts", now))) / 86400.0) for r in rows], dtype=float)
        sw   = np.exp(-PG_ML_DECAY_LAMBDA * ages).astype(float)

        # URL_HASH
        X_uh = uv.transform(urls)
        try:
            check_is_fitted(uhl)
            pass
        except Exception:
            uhl.partial_fit(X_uh, ys, classes=clz, sample_weight=sw)
        else:
            n = len(urls); bs = max(1, min(PG_ML_MINIBATCH, n))
            for i in range(0, n, bs):
                sl = slice(i, min(i+bs, n))
                uhl.partial_fit(X_uh[sl], ys[sl], sample_weight=sw[sl])

        # URL_LEX
        X_ul = np.asarray([_extract_lex19(u) for u in urls], dtype=float)
        try:
            check_is_fitted(ulx)
            pass
        except Exception:
            ulx.partial_fit(X_ul, ys, classes=clz, sample_weight=sw)
        else:
            n = len(urls); bs = max(1, min(PG_ML_MINIBATCH, n))
            for i in range(0, n, bs):
                sl = slice(i, min(i+bs, n))
                ulx.partial_fit(X_ul[sl], ys[sl], sample_weight=sw[sl])

        # HTML 채널(저장된 html이 있을 때만)
        if PG_ML_HTML_ENABLE:
            htmls = [r.get("html") for r in rows]
            has_html_idx = [i for i,h in enumerate(htmls) if h]
            if has_html_idx:
                hh_list = [htmls[i] for i in has_html_idx]
                ys_h    = ys[has_html_idx]
                sw_h    = sw[has_html_idx]

                # HTML_HASH
                X_hh = hv.transform(hh_list)
                try:
                    check_is_fitted(hhl)
                    pass
                except Exception:
                    hhl.partial_fit(X_hh, ys_h, classes=clz, sample_weight=sw_h)
                else:
                    n = len(hh_list); bs = max(1, min(PG_ML_MINIBATCH, n))
                    for i in range(0, n, bs):
                        sl = slice(i, min(i+bs, n))
                        hhl.partial_fit(X_hh[sl], ys_h[sl], sample_weight=sw_h[sl])

                # HTML_NUM
                X_hn = np.asarray([_extract_html_num(h) for h in hh_list], dtype=float)
                try:
                    check_is_fitted(hnl)
                    pass
                except Exception:
                    hnl.partial_fit(X_hn, ys_h, classes=clz, sample_weight=sw_h)
                else:
                    n = len(hh_list); bs = max(1, min(PG_ML_MINIBATCH, n))
                    for i in range(0, n, bs):
                        sl = slice(i, min(i+bs, n))
                        hnl.partial_fit(X_hn[sl], ys_h[sl], sample_weight=sw_h[sl])

        _STATE["last_train_ts"] = now
        _save_models_locked()
        return {"ok": True, "trained": len(urls)}

# ---------- 상태 ----------
def status() -> Dict[str, Any]:
    with _LOCK:
        _init_models_locked()
        try:
            with open(META_PATH, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {"updated_at": None, "last_train_ts": _STATE.get("last_train_ts", 0.0)}

        info = {
            "sklearn_ok": (_IMPORT_ERR is None),
            "initialized": _STATE.get("initialized", False),
            "last_train_ts": _STATE.get("last_train_ts", 0.0),
            "last_train_iso": _utc_iso(_STATE.get("last_train_ts", 0.0)),
            "meta": meta,
            "models": {
                "url_hash_loaded":  os.path.exists(MODEL_HASH_URL),
                "url_lex_loaded":   os.path.exists(MODEL_LEX_URL),
                "html_hash_loaded": os.path.exists(MODEL_HASH_HTML),
                "html_num_loaded":  os.path.exists(MODEL_NUM_HTML),
            },
            "data_exists": os.path.exists(DATA_PATH),
            "paths": {
                "state_dir": STATE_DIR,
                "data": DATA_PATH,
                "model_url_hash": MODEL_HASH_URL,
                "model_url_lex":  MODEL_LEX_URL,
                "model_html_hash":MODEL_HASH_HTML,
                "model_html_num": MODEL_NUM_HTML,
                "meta": META_PATH
            }
        }
        return info
