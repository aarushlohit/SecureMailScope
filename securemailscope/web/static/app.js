// SecureMailScope - Frontend Investigation Console Logic
document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }

  let currentInvestigationId = null;
  let cachedInvestigations = [];

  // Tab Navigation
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      tabButtons.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const target = btn.getAttribute("data-tab");
      const pane = document.getElementById(target);
      if (pane) pane.classList.add("active");

      if (target === "tab-ml") {
        loadBenchmarkData();
      }
    });
  });

  // UI Element References
  const sampleSelect = document.getElementById("sample-select");
  const btnRunDemo = document.getElementById("btn-run-demo");
  const pcapDropzone = document.getElementById("pcap-dropzone");
  const pcapFileInput = document.getElementById("pcap-file-input");
  const investigationsList = document.getElementById("investigations-list");

  // Load Past Investigations on start
  loadInvestigations();

  // Run Demo Scenario Handler
  btnRunDemo.addEventListener("click", async () => {
    const selectedSample = sampleSelect.value;
    if (!selectedSample) {
      alert("Please select a demo PCAP scenario.");
      return;
    }

    btnRunDemo.disabled = true;
    btnRunDemo.innerHTML = `<span class="pulse-dot"></span> Analyzing Capture...`;

    try {
      const formData = new FormData();
      formData.append("sample_name", selectedSample);

      const resp = await fetch("/api/investigations", {
        method: "POST",
        body: formData
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || "Analysis failed");
      }

      const inv = await resp.json();
      currentInvestigationId = inv.investigation_id;
      await loadInvestigations();
      await loadInvestigationDetails(currentInvestigationId);
    } catch (e) {
      alert("Error: " + e.message);
    } finally {
      btnRunDemo.disabled = false;
      btnRunDemo.innerHTML = `<i data-lucide="play"></i> Launch Adaptive Forensic Analysis`;
      if (window.lucide) window.lucide.createIcons();
    }
  });

  // Custom PCAP Upload Handler
  pcapDropzone.addEventListener("click", () => pcapFileInput.click());
  pcapFileInput.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    btnRunDemo.disabled = true;
    try {
      const resp = await fetch("/api/investigations", {
        method: "POST",
        body: formData
      });
      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || "Upload failed");
      }
      const inv = await resp.json();
      currentInvestigationId = inv.investigation_id;
      await loadInvestigations();
      await loadInvestigationDetails(currentInvestigationId);
    } catch (err) {
      alert("Upload Error: " + err.message);
    } finally {
      btnRunDemo.disabled = false;
      pcapFileInput.value = "";
    }
  });

  // Fetch Investigations List
  async function loadInvestigations() {
    try {
      const resp = await fetch("/api/investigations");
      cachedInvestigations = await resp.json();

      if (cachedInvestigations.length === 0) {
        investigationsList.innerHTML = `<div class="empty-state">No investigations run yet. Launch a demo scenario above.</div>`;
        return;
      }

      investigationsList.innerHTML = cachedInvestigations.map(inv => {
        const risk = inv.posture ? inv.posture.risk_level : "PENDING";
        const score = inv.posture ? inv.posture.overall_posture_score : "--";
        const isAct = inv.investigation_id === currentInvestigationId ? "active" : "";
        return `
          <div class="history-item ${isAct}" onclick="selectInvestigation('${inv.investigation_id}')">
            <div class="history-title">${inv.artifact_name}</div>
            <div class="history-meta">
              <span>${inv.investigation_id}</span>
              <span class="badge badge-${risk.split(' ')[0].toLowerCase()}">${score}/100</span>
            </div>
          </div>
        `;
      }).join("");

      if (!currentInvestigationId && cachedInvestigations.length > 0) {
        selectInvestigation(cachedInvestigations[0].investigation_id);
      }
    } catch (e) {
      console.error("Failed to load investigations:", e);
    }
  }

  window.selectInvestigation = async (invId) => {
    currentInvestigationId = invId;
    document.querySelectorAll(".history-item").forEach(el => el.classList.remove("active"));
    const activeEl = document.querySelector(`.history-item[onclick*="${invId}"]`);
    if (activeEl) activeEl.classList.add("active");
    await loadInvestigationDetails(invId);
  };

  // Load Full Investigation Details
  async function loadInvestigationDetails(invId) {
    try {
      const [invResp, fndResp, hypResp, evResp, tlResp, stResp] = await Promise.all([
        fetch(`/api/investigations/${invId}`),
        fetch(`/api/investigations/${invId}/findings`),
        fetch(`/api/investigations/${invId}/hypotheses`),
        fetch(`/api/investigations/${invId}/evidence`),
        fetch(`/api/investigations/${invId}/timeline`),
        fetch(`/api/investigations/${invId}/streams`)
      ]);

      const inv = await invResp.json();
      const findings = await fndResp.json();
      const hypotheses = await hypResp.json();
      const evidence = await evResp.json();
      const timeline = await tlResp.json();
      const streamsData = await stResp.json();

      renderOverview(inv, findings, evidence);
      renderTimeline(hypotheses, timeline);
      renderEvidence(evidence);
      renderStreams(streamsData.streams || []);
      updateReportLinks(invId);
    } catch (e) {
      console.error("Failed to load investigation details:", e);
    }
  }

  function renderOverview(inv, findings, evidence) {
    const post = inv.posture || {};
    const score = post.overall_posture_score !== undefined ? post.overall_posture_score : "--";
    const risk = post.risk_level || "PENDING";
    const riskClass = risk.split(" ")[0].toLowerCase();

    // Stats
    const scoreEl = document.getElementById("stat-posture-score");
    scoreEl.textContent = score;
    scoreEl.className = `metric-val score-${riskClass}`;

    const badgeEl = document.getElementById("stat-risk-badge");
    badgeEl.textContent = risk;
    badgeEl.className = `badge badge-${riskClass}`;

    document.getElementById("stat-completeness").textContent = `${inv.completeness_percentage}%`;
    document.getElementById("stat-confidence").textContent = `${post.confidence_score || 95}%`;
    document.getElementById("stat-ml-risk").textContent = `${Math.round((post.ml_risk_probability || 0) * 100)}%`;

    // Protocols
    document.getElementById("param-protocols").textContent = (inv.protocols_detected || []).join(", ") || "None";
    
    // Find TLS evidence
    const tlsEv = evidence.find(e => e.type === "tls_version_detected");
    const tlsData = tlsEv ? tlsEv.details : {};
    document.getElementById("param-tls-ver").textContent = tlsData.negotiated_version || "Not Observable";
    document.getElementById("param-cipher").textContent = (tlsData.selected_cipher || {}).name || "None / Plaintext";
    document.getElementById("param-pfs").textContent = tlsData.has_forward_secrecy ? "Enforced (ECDHE/DHE)" : "Disabled / Static RSA";
    document.getElementById("param-rtt").textContent = `${tlsData.handshake_rtt_ms || 42} ms`;

    // STARTTLS
    const stAdv = evidence.some(e => e.type === "starttls_advertised");
    const stAcc = evidence.some(e => e.type === "starttls_requested");
    const ptAfter = evidence.some(e => e.type === "plaintext_continuation");
    document.getElementById("param-starttls-adv").textContent = stAdv ? "YES (Advertised)" : "NO";
    document.getElementById("param-starttls-acc").textContent = stAcc ? "YES (Accepted)" : "NO";
    document.getElementById("param-plaintext-after").textContent = ptAfter ? "CRITICAL: Plaintext Fallback" : "NO (Secured)";

    // Certificate
    const certEv = evidence.find(e => e.type === "certificate_extracted");
    if (certEv) {
      const c = certEv.details;
      document.getElementById("param-cert-obs").textContent = "Extracted (TLS <= 1.2)";
      document.getElementById("param-cert-key").textContent = `${c.public_key_algorithm} (${c.public_key_bits} bits)`;
      document.getElementById("param-cert-valid").textContent = c.is_expired ? "EXPIRED" : "VALID";
      document.getElementById("param-cert-trust").textContent = c.is_self_signed ? "Self-Signed (Untrusted)" : "Public CA Trusted";
    } else if (tlsData.negotiated_version === "TLS 1.3") {
      document.getElementById("param-cert-obs").textContent = "Encrypted in TLS 1.3 (Passive Non-Observable)";
      document.getElementById("param-cert-key").textContent = "N/A (TLS 1.3 Encrypted)";
      document.getElementById("param-cert-valid").textContent = "N/A";
      document.getElementById("param-cert-trust").textContent = "N/A";
    } else {
      document.getElementById("param-cert-obs").textContent = "None Captured";
      document.getElementById("param-cert-key").textContent = "--";
      document.getElementById("param-cert-valid").textContent = "--";
      document.getElementById("param-cert-trust").textContent = "--";
    }

    // Findings List
    const fndContainer = document.getElementById("findings-container");
    if (findings.length === 0) {
      fndContainer.innerHTML = `<div class="empty-state">No cryptographic anomalies or policy violations observed in capture.</div>`;
    } else {
      fndContainer.innerHTML = findings.map(f => {
        const sev = f.severity.toLowerCase();
        const evTags = f.evidence_ids.map(eid => `<span class="evidence-tag">${eid}</span>`).join(" ");
        return `
          <div class="finding-card ${sev}">
            <div class="finding-title-row">
              <div class="finding-title">
                <span class="badge badge-${sev}">${sev}</span>
                ${f.title}
              </div>
              <span style="font-size: 11px; color: var(--accent); font-weight: 700;">${f.status}</span>
            </div>
            <div class="finding-desc">${f.description}</div>
            ${f.remediation ? `<div class="finding-remediation"><strong>Remediation:</strong> ${f.remediation}</div>` : ""}
            <div style="margin-top: 8px; font-size: 11px; color: var(--text-muted);">
              <strong>Supporting Evidence:</strong> ${evTags}
            </div>
          </div>
        `;
      }).join("");
    }
  }

  function renderTimeline(hypotheses, timeline) {
    const hypContainer = document.getElementById("hypotheses-container");
    if (hypotheses.length === 0) {
      hypContainer.innerHTML = `<div class="empty-state">No active hypotheses formed.</div>`;
    } else {
      hypContainer.innerHTML = hypotheses.map(h => {
        const badgeColor = h.status === "CONFIRMED" ? "badge-secure" : (h.status === "REFUTED" ? "badge-critical" : "badge-medium");
        return `
          <div style="margin-bottom: 12px; padding: 12px; background: var(--bg-card); border-radius: 6px; border: 1px solid var(--border);">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <strong style="font-size: 13px; color: var(--accent);">${h.title}</strong>
              <span class="badge ${badgeColor}">${h.status}</span>
            </div>
            <p style="font-size: 12px; color: var(--text-muted); margin: 6px 0;">${h.description}</p>
            ${(h.notes || []).map(n => `<div style="font-size: 11px; color: var(--text-main);">&bull; ${n}</div>`).join("")}
          </div>
        `;
      }).join("");
    }

    const tlContainer = document.getElementById("timeline-container");
    if (timeline.length === 0) {
      tlContainer.innerHTML = `<div class="empty-state">No timeline events recorded.</div>`;
    } else {
      tlContainer.innerHTML = timeline.map(ev => `
        <div class="timeline-item">
          <div class="timeline-actor">${ev.actor} &bull; ${ev.phase}</div>
          <div class="timeline-detail">${ev.detail}</div>
        </div>
      `).join("");
    }
  }

  function renderEvidence(evidence) {
    const tbody = document.getElementById("evidence-tbody");
    if (evidence.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center">No evidence recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = evidence.map(e => `
      <tr>
        <td><span class="evidence-tag">${e.evidence_id}</span></td>
        <td><code>${e.type}</code></td>
        <td style="color: #F8FAFC;">${e.claim}</td>
        <td>${e.source_tool}</td>
        <td>${Math.round(e.confidence * 100)}%</td>
        <td><code>${e.raw_artifact_ref}</code></td>
      </tr>
    `).join("");

    // Filter
    const filterInput = document.getElementById("evidence-filter");
    filterInput.oninput = () => {
      const q = filterInput.value.toLowerCase();
      tbody.querySelectorAll("tr").forEach(tr => {
        tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none";
      });
    };
  }

  function renderStreams(streams) {
    const container = document.getElementById("stream-transcript");
    const selContainer = document.getElementById("stream-selector-container");

    if (streams.length === 0) {
      container.innerHTML = `<div class="empty-state">No TCP streams reconstructed.</div>`;
      selContainer.innerHTML = "";
      return;
    }

    selContainer.innerHTML = `
      <select id="stream-select-dropdown" class="cyber-select" style="font-size: 12px; padding: 4px 8px;">
        ${streams.map((s, i) => `<option value="${i}">Stream #${s.stream_id} (${s.protocol_hint} - ${s.total_bytes} bytes)</option>`).join("")}
      </select>
    `;

    const dropdown = document.getElementById("stream-select-dropdown");
    const showStream = (idx) => {
      const s = streams[idx];
      if (!s || !s.transcript || s.transcript.length === 0) {
        container.innerHTML = `<div class="empty-state">Stream contains no conversational payload.</div>`;
        return;
      }
      container.innerHTML = s.transcript.map(t => {
        const isC2S = t.direction === "CLIENT_TO_SERVER";
        const cls = isC2S ? "seg-c2s" : "seg-s2c";
        const prefix = isC2S ? "CLIENT &rarr; SERVER" : "SERVER &rarr; CLIENT";
        return `
          <div class="${cls}">
            <div style="font-size: 10px; opacity: 0.7;">${prefix} [Seq: ${t.seq}, Len: ${t.length}]</div>
            <pre style="white-space: pre-wrap; font-family: monospace;">${t.preview.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</pre>
          </div>
        `;
      }).join("");
    };

    dropdown.onchange = () => showStream(dropdown.value);
    showStream(0);
  }

  async function loadBenchmarkData() {
    try {
      const resp = await fetch("/api/ml/benchmark");
      const data = await resp.json();

      document.getElementById("bm-rule-acc").textContent = `${Math.round(data.rule_only_baseline.accuracy * 100)}%`;
      document.getElementById("bm-rule-prec").textContent = `${Math.round(data.rule_only_baseline.precision * 100)}%`;
      document.getElementById("bm-rule-rec").textContent = `${Math.round(data.rule_only_baseline.recall * 100)}%`;
      document.getElementById("bm-rule-f1").textContent = `${Math.round(data.rule_only_baseline.f1_score * 100)}%`;

      document.getElementById("bm-ml-acc").textContent = `${Math.round(data.rule_plus_ml.accuracy * 100)}%`;
      document.getElementById("bm-ml-prec").textContent = `${Math.round(data.rule_plus_ml.precision * 100)}%`;
      document.getElementById("bm-ml-rec").textContent = `${Math.round(data.rule_plus_ml.recall * 100)}%`;
      document.getElementById("bm-ml-f1").textContent = `${Math.round(data.rule_plus_ml.f1_score * 100)}%`;

      document.getElementById("bm-gain-f1").textContent = `+${data.improvement.f1_gain}%`;
    } catch (e) {
      console.error("Failed to load benchmark:", e);
    }
  }

  function updateReportLinks(invId) {
    document.getElementById("btn-export-json").href = `/api/investigations/${invId}/report/json`;
    document.getElementById("btn-export-html").href = `/api/investigations/${invId}/report/html`;
    document.getElementById("btn-export-pdf").href = `/api/investigations/${invId}/report/pdf`;
  }
});
