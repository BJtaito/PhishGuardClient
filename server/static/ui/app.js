(function () {
  const apiKeyInput = document.getElementById("apiKeyInput");
  const urlInput = document.getElementById("urlInput");
  const htmlInput = document.getElementById("htmlInput");
  const form = document.getElementById("analyzeForm");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const fillExampleBtn = document.getElementById("fillExampleBtn");

  const statusDot = document.getElementById("statusDot");
  const statusText = document.getElementById("statusText");

  const resultHeaderSmall = document.getElementById("resultHeaderSmall");
  const emptyState = document.getElementById("emptyState");
  const resultPanel = document.getElementById("resultPanel");
  const riskTag = document.getElementById("riskTag");
  const riskTagLabel = document.getElementById("riskTagLabel");
  const scoreValue = document.getElementById("scoreValue");
  const scoreBar = document.getElementById("scoreBar");
  const pillRow = document.getElementById("pillRow");
  const reasonList = document.getElementById("reasonList");
  const infoLine = document.getElementById("infoLine");
  const jsonToggle = document.getElementById("jsonToggle");
  const jsonView = document.getElementById("jsonView");

  // API Key 로컬 저장
  (function initApiKey() {
    const saved = window.localStorage.getItem("pg_api_key") || "";
    if (saved) {
      apiKeyInput.value = saved;
    } else {
      apiKeyInput.value = "dev-key-123";
    }
    apiKeyInput.addEventListener("input", () => {
      window.localStorage.setItem("pg_api_key", apiKeyInput.value.trim());
    });
  })();

  fillExampleBtn.addEventListener("click", () => {
    if (!urlInput.value.trim()) {
      urlInput.value = "http://yufsv3.zoeu.uno";
    } else {
      urlInput.value = "https://www.naver.com/";
    }
  });

  function setStatus(mode, text) {
    statusDot.classList.remove("busy", "error");
    if (mode === "busy") {
      statusDot.classList.add("busy");
    } else if (mode === "error") {
      statusDot.classList.add("error");
    }
    statusText.textContent = text;
  }

  function setLoading(loading) {
    analyzeBtn.disabled = loading;
    if (loading) {
      analyzeBtn.innerHTML =
        '<span class="icon">⏱</span><span>분석 중...</span>';
      setStatus(
        "busy",
        "서버에 분석을 요청했습니다. 잠시만 기다려 주세요."
      );
    } else {
      analyzeBtn.innerHTML =
        '<span class="icon">▶</span><span>분석 요청</span>';
    }
  }

  function resetResult() {
    emptyState.style.display = "block";
    resultPanel.style.display = "none";
    resultHeaderSmall.textContent = "아직 분석 결과가 없습니다.";
    reasonList.innerHTML = "";
    pillRow.innerHTML = "";
    infoLine.textContent = "";
    jsonView.textContent = "";
    jsonView.classList.remove("show");
    jsonToggle.classList.remove("open");
    scoreValue.textContent = "0";
    scoreBar.style.transform = "scaleX(0)";
    riskTag.className = "tag-risk tag-risk-safe";
    riskTagLabel.textContent = "정상 (Low)";
  }

  function classifyRisk(norm) {
    if (norm == null || isNaN(norm)) norm = 0;
    if (norm < 0.2) return { tag: "정상 (Low)", cls: "tag-risk tag-risk-safe" };
    if (norm < 0.5)
      return { tag: "주의 (Medium)", cls: "tag-risk tag-risk-warn" };
    return { tag: "위험 (High)", cls: "tag-risk tag-risk-danger" };
  }

  function renderResult(result, meta) {
    emptyState.style.display = "none";
    resultPanel.style.display = "block";

    const score100 =
      typeof result.risk_score_100 === "number"
        ? result.risk_score_100
        : typeof result.risk_score === "number"
        ? result.risk_score
        : 0;

    const norm =
      typeof result.risk_score_norm === "number"
        ? result.risk_score_norm
        : score100 / 100;

    const cls = classifyRisk(norm);
    riskTag.className = cls.cls;
    riskTagLabel.textContent = cls.tag;
    scoreValue.textContent = score100.toString();
    scoreBar.style.transform =
      "scaleX(" + Math.max(0, Math.min(1, norm)) + ")";

    const url = meta?.url || meta?.payload?.url || "N/A";
    resultHeaderSmall.textContent = url ? "URL: " + url : "직접 HTML 분석";

    pillRow.innerHTML = "";

    // Score scale
    const scale = result.score_scale || 100;
    const pill1 = document.createElement("div");
    pill1.className = "pill";
    pill1.innerHTML = '<span class="key">Scale</span>' + scale;
    pillRow.appendChild(pill1);

    // ML 정보
    if (result.features && result.features.ml) {
      const { prob, rules_norm, weight_rules } = result.features.ml;
      const pillMl = document.createElement("div");
      pillMl.className = "pill pill-pill-bad";
      pillMl.innerHTML =
        '<span class="key">ML</span>' +
        "p=" +
        (prob != null ? prob.toFixed(3) : "?") +
        " · rules=" +
        (rules_norm != null ? rules_norm.toFixed(3) : "?") +
        " · w=" +
        (weight_rules != null ? weight_rules.toFixed(2) : "?");
      pillRow.appendChild(pillMl);
    }

    // Redirects 정보
    if (result.features && result.features.redirects) {
      const rd = result.features.redirects;
      const pillRd = document.createElement("div");
      pillRd.className = "pill";
      const start = rd.start_url || "";
      const fin = rd.final_url || "";
      pillRd.innerHTML =
        '<span class="key">Redirect</span>' +
        (start ? "⇢ " + start + " → " + fin : "없음");
      pillRow.appendChild(pillRd);

      if (rd.final_ip && rd.final_ip.length) {
        const pillIp = document.createElement("div");
        pillIp.className = "pill";
        pillIp.innerHTML =
          '<span class="key">IP</span>' +
          rd.final_ip.slice(0, 2).join(", ") +
          (rd.final_ip.length > 2 ? " …" : "");
        pillRow.appendChild(pillIp);
      }
    }

    // Dynamic 분석 요약
    if (result.features && result.features.dynamic) {
      const dyn = result.features.dynamic;
      const pillDyn = document.createElement("div");
      pillDyn.className = "pill";
      const posts = dyn.network_posts ?? 0;
      const errs = dyn.errors && dyn.errors.length ? dyn.errors.length : 0;
      pillDyn.innerHTML =
        '<span class="key">Dyn</span>' +
        `POST=${posts}` +
        (errs ? ` · errors=${errs}` : "");
      pillRow.appendChild(pillDyn);
    }

    // reasons 리스트
    reasonList.innerHTML = "";
    if (Array.isArray(result.reasons) && result.reasons.length > 0) {
      for (const r of result.reasons) {
        const li = document.createElement("li");
        const feat = r.feature || "note";
        const detail = r.detail || "";
        const score =
          typeof r.score === "number" ? r.score : null;
        li.innerHTML =
          '<span class="reason-feature">[' +
          feat +
          "]</span>" +
          (score !== null
            ? '<span class="reason-score">+' + score + "</span>"
            : "") +
          (detail
            ? ' <span class="reason-detail">' + detail + "</span>"
            : "");
        reasonList.appendChild(li);
      }
    } else {
      const li = document.createElement("li");
      li.textContent = "룰 기반 근거가 없습니다. (score=0)";
      reasonList.appendChild(li);
    }

    // info 라인
    const engine = result.engine || "quick-rules";
    const mlInfo =
      result.features && result.features.ml
        ? " · ML prob=" + result.features.ml.prob
        : "";
    infoLine.textContent =
      "engine=" + engine + " · norm=" + norm.toFixed(3) + mlInfo;

    // Raw JSON
    const raw = { meta, result };
    jsonView.textContent = JSON.stringify(raw, null, 2);

    // 🔹 다운로드 분석 영역 렌더링
    if (result.features) {
      renderDownloadsSection(result.features);
    }
  }

  jsonToggle.addEventListener("click", () => {
    const isOpen = jsonView.classList.toggle("show");
    jsonToggle.classList.toggle("open", isOpen);
  });

  async function pollTask(taskId, apiKey, url) {
    const started = Date.now();
    const timeoutMs = 20000;
    while (true) {
      const elapsed = Date.now() - started;
      if (elapsed > timeoutMs) {
        throw new Error("타임아웃: 20초 이내에 결과를 받지 못했습니다.");
      }
      const res = await fetch(
        `/api/analyze/${encodeURIComponent(taskId)}?verbose=1`,
        {
          headers: {
            "X-API-Key": apiKey,
          },
        }
      );
      if (!res.ok) {
        const text = await res.text();
        throw new Error("GET /api/analyze 오류: " + res.status + " " + text);
      }
      const data = await res.json();
      if (data.status === "done") {
        return data;
      }
      if (data.status === "error") {
        throw new Error("작업 오류: " + (data.error || "unknown"));
      }
      await new Promise((r) => setTimeout(r, 700));
    }
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    resetResult();

    const apiKey = apiKeyInput.value.trim();
    const url = urlInput.value.trim();
    const html = htmlInput.value.trim();

    if (!url && !html) {
      setStatus("error", "URL이나 HTML 중 하나는 반드시 입력해 주세요.");
      return;
    }

    setLoading(true);

    try {
      const payload = {
        url: url || null,
        html: html || null,
        meta: {},
      };

      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey || "",
        },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error("POST /api/analyze 실패: " + res.status + " " + text);
      }

      const data = await res.json();
      const taskId = data.task_id;
      setStatus("busy", "작업 ID " + taskId + " 대기 중...");

      const taskData = await pollTask(taskId, apiKey || "", url);
      renderResult(taskData.result, {
        task_id: taskData.task_id,
        created_at: taskData.created_at,
        url,
        payload: { url, html },
      });
      setStatus("idle", "완료: score=" + taskData.result.risk_score_100);
    } catch (err) {
      console.error(err);
      setStatus("error", "에러: " + (err.message || err.toString()));
    } finally {
      setLoading(false);
    }
  });

  // 초기 상태
  resetResult();
  setStatus("idle", "대기 중");
})();

// 다운로드 분석 영역 렌더링
function renderDownloadsSection(features) {
  const container = document.getElementById("downloads-section");
  if (!container) return;

  container.innerHTML = ""; // 초기화

  const title = document.createElement("h3");
  title.textContent = "다운로드 분석";
  container.appendChild(title);

  const summary = (features && features.downloads_summary) || {};
  const downloadsInfo = (features && features.downloads) || null;

  const statusP = document.createElement("p");
  statusP.className = "downloads-status";

  if (!summary.enabled) {
    statusP.textContent = "비활성화됨 (.env에서 PG_DOWNLOAD_SCAN=1 설정 필요)";
    container.appendChild(statusP);
    return;
  }

  if (!summary.ran) {
    statusP.textContent = "분석 실패 또는 실행되지 않음";
    container.appendChild(statusP);

    if (downloadsInfo && downloadsInfo.error) {
      const err = document.createElement("code");
      err.textContent = downloadsInfo.error;
      err.style.display = "block";
      err.style.marginTop = "4px";
      container.appendChild(err);
    }
    return;
  }

  if (summary.download_count === 0) {
    statusP.textContent = "다운로드된 파일 없음";
    container.appendChild(statusP);
    return;
  }

  if (downloadsInfo && downloadsInfo.summary_line) {
    statusP.textContent = downloadsInfo.summary_line;
  } else {
    statusP.textContent = `${summary.download_count}개 파일 다운로드됨`;
  }
  container.appendChild(statusP);

  const listWrap = document.createElement("div");
  listWrap.className = "downloads-list";

  const items =
    (downloadsInfo && (downloadsInfo.downloads || downloadsInfo.files)) || [];

  items.forEach((item, idx) => {
    const card = document.createElement("div");
    card.className = "download-card";

    const name = document.createElement("div");
    name.className = "download-name";
    name.textContent = `${idx + 1}. ${
      item.filename || item.saved_path || "파일"
    }`;
    card.appendChild(name);

    const vt =
      (item.vt_summary ||
        (item.vt_full && item.vt_full.summary) ||
        item.vt ||
        {}) || {};

    const riskRaw =
      vt.risk_score_percent ??
      vt.risk ??
      vt.risk_score ??
      vt.score ??
      null;

    const engines =
      vt.engines_total ??
      vt.total_engines ??
      vt.num_engines ??
      vt.total ??
      null;

    const mal =
      vt.malicious ??
      vt.mal_hits ??
      vt.num_malicious ??
      vt.detected ??
      null;

    const meta = document.createElement("div");
    meta.className = "download-meta";

    const parts = [];

    if (riskRaw != null && !isNaN(riskRaw)) {
      parts.push(`위험도: ${Number(riskRaw).toFixed(1)}%`);
    }

    if (mal != null && engines != null) {
      parts.push(`VirusTotal: ${mal}/${engines} 엔진 탐지`);
    }

    if (!parts.length) {
      parts.push("VirusTotal 결과 없음");
    }

    meta.textContent = parts.join(" · ");
    card.appendChild(meta);

    listWrap.appendChild(card);
  });

  container.appendChild(listWrap);
}
