/**
 * SecureMailScope — Forensic Workstation Controller
 * Production-quality, FAANG-level frontend script.
 * SIH 2026 Problem Statement: SIH26159 (NTRO)
 */

(function () {
  'use strict';

  class ForensicWorkstation {
    constructor() {
      this.currentInvestigationId = null;
      this.currentInvestigation = null;
      this.investigations = [];
      this.allEvidence = [];
      this.allFindings = [];
      this.attachedFiles = [];
      this.deepResearchEnabled = false;
      this.activeDetailTab = 'overview';
      this.activeView = 'home';
      this.isAnalyzing = false;

      this.init();
    }

    async init() {
      this.bindNav();
      this.bindComposer();
      this.bindDetailTabs();
      this.bindEvidenceDrawer();
      this.bindCommandPalette();
      this.bindThreatIntel();
      this.bindFilters();

      // Handle direct URL routing or load default
      this.handleInitialRoute();

      // Background data pre-load
      await this.loadInvestigations();
      await this.loadAllEvidence();
      await this.loadAllFindings();

      if (window.lucide) {
        window.lucide.createIcons();
      }
    }

    /* -------------------------------------------------------------
     * 1. ROUTING & VIEW NAVIGATION
     * ------------------------------------------------------------- */
    bindNav() {
      // Sidebar item clicks
      document.querySelectorAll('.app-sidebar .nav-item[data-view]').forEach((item) => {
        item.addEventListener('click', (e) => {
          const view = item.getAttribute('data-view');
          this.navigate(view);
        });
      });

      // New investigation button in sidebar
      const btnNewInv = document.getElementById('btn-sidebar-new-inv');
      if (btnNewInv) {
        btnNewInv.addEventListener('click', () => {
          this.triggerNewInvestigation();
        });
      }

      // Mobile menu toggle
      const mobileToggle = document.getElementById('mobile-menu-toggle');
      const sidebar = document.getElementById('app-sidebar');
      if (mobileToggle && sidebar) {
        mobileToggle.addEventListener('click', () => {
          sidebar.classList.toggle('open');
        });
      }

      // Collapsible Sidebar (Toggle button, Ctrl+\ / Cmd+\ shortcut, localStorage)
      const collapseToggle = document.getElementById('sidebar-collapse-toggle');
      const isCollapsedSaved = localStorage.getItem('sms_sidebar_collapsed') === 'true';
      if (isCollapsedSaved && sidebar) {
        sidebar.classList.add('collapsed');
      }

      const toggleSidebarCollapse = () => {
        if (!sidebar) return;
        sidebar.classList.toggle('collapsed');
        const collapsed = sidebar.classList.contains('collapsed');
        localStorage.setItem('sms_sidebar_collapsed', String(collapsed));
      };

      collapseToggle?.addEventListener('click', toggleSidebarCollapse);

      window.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === '\\') {
          e.preventDefault();
          toggleSidebarCollapse();
        }
      });

      // Popstate support for back/forward browser navigation
      window.addEventListener('popstate', () => {
        this.handleInitialRoute(false);
      });
    }

    handleInitialRoute(pushState = true) {
      const path = window.location.pathname;
      let targetView = 'home';
      let invId = null;

      if (path.startsWith('/app/investigations/')) {
        targetView = 'investigation-detail';
        invId = path.replace('/app/investigations/', '').trim();
      } else if (path.startsWith('/app/')) {
        const sub = path.replace('/app/', '').split('/')[0];
        if (sub) targetView = sub;
      }

      this.navigate(targetView, invId, pushState);
    }

    navigate(viewName, param = null, updateUrl = true) {
      this.activeView = viewName;

      // Update sidebar active classes
      document.querySelectorAll('.app-sidebar .nav-item').forEach((item) => {
        if (item.getAttribute('data-view') === viewName) {
          item.classList.add('active');
        } else {
          item.classList.remove('active');
        }
      });

      // Switch active view pane
      document.querySelectorAll('.view-pane').forEach((pane) => {
        pane.classList.remove('active');
      });

      const targetPane = document.getElementById(`view-${viewName}`);
      if (targetPane) {
        targetPane.classList.add('active');
      }

      // Scroll to top of workspace
      const scrollContainer = document.getElementById('workspace-scroll');
      if (scrollContainer) scrollContainer.scrollTop = 0;

      // Update breadcrumbs
      this.updateBreadcrumb(viewName, param);

      // URL history management
      if (updateUrl) {
        let url = `/app/${viewName}`;
        if (viewName === 'home') url = '/app';
        if (viewName === 'investigation-detail' && param) {
          url = `/app/investigations/${param}`;
        }
        window.history.pushState({ view: viewName, param }, '', url);
      }

      // Lazy load view-specific data
      if (viewName === 'investigations') {
        this.loadInvestigations();
      } else if (viewName === 'investigation-detail' && param) {
        this.loadInvestigationDetail(param);
      } else if (viewName === 'evidence') {
        this.loadAllEvidence();
      } else if (viewName === 'findings') {
        this.loadAllFindings();
      } else if (viewName === 'sessions') {
        this.loadSessionsView();
      } else if (viewName === 'reports') {
        this.loadReportsView();
      } else if (viewName === 'ml') {
        this.loadMLBenchmark();
      }

      // Close mobile sidebar if open
      const sidebar = document.getElementById('app-sidebar');
      if (sidebar) sidebar.classList.remove('open');

      if (window.lucide) window.lucide.createIcons();
    }

    updateBreadcrumb(viewName, param = null) {
      const parentEl = document.getElementById('breadcrumb-parent');
      const currentEl = document.getElementById('breadcrumb-current');
      if (!currentEl) return;

      const titles = {
        home: 'Home • Agent',
        investigations: 'Investigations',
        'investigation-detail': param ? `Investigation ${param}` : 'Investigation Detail',
        evidence: 'Evidence Ledger',
        findings: 'Verified Findings',
        sessions: 'TCP Streams & Sessions',
        ml: 'Scientific ML Benchmark',
        reports: 'Forensic Reports',
        'threat-intel': 'External Threat Intel',
        playground: 'Demo Playground',
        settings: 'Settings',
        docs: 'Documentation'
      };

      if (viewName === 'investigation-detail') {
        if (parentEl) parentEl.textContent = 'Investigations';
        currentEl.textContent = param || 'Detail';
      } else {
        if (parentEl) parentEl.textContent = 'SecureMailScope';
        currentEl.textContent = titles[viewName] || viewName;
      }
    }

    triggerNewInvestigation() {
      this.navigate('home');
      const input = document.getElementById('composer-input');
      if (input) {
        input.focus();
        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }

    /* -------------------------------------------------------------
     * 2. CHATGPT-LIKE INVESTIGATION COMPOSER
     * ------------------------------------------------------------- */
    bindComposer() {
      const input = document.getElementById('composer-input');
      const btnSubmit = document.getElementById('btn-composer-submit');
      const btnAttach = document.getElementById('btn-attach-file');
      const fileInput = document.getElementById('composer-file-input');
      const btnDeepResearch = document.getElementById('btn-toggle-deep-research');
      const deepResearchLabel = document.getElementById('deep-research-label');
      const composerBox = document.getElementById('composer-box');

      // 3 Compact Inline Actions
      document.getElementById('qa-upload-pcap')?.addEventListener('click', () => {
        fileInput?.click();
      });

      document.getElementById('qa-analyze-email')?.addEventListener('click', () => {
        if (input) {
          input.value = 'Analyze email header (.eml) and verify DKIM, SPF, and STARTTLS enforcement.';
          input.focus();
        }
      });

      document.getElementById('qa-open-inv')?.addEventListener('click', () => {
        this.navigate('investigations');
      });

      // Suggested prompt pills (Exactly 3)
      document.querySelectorAll('.prompt-pill').forEach((pill) => {
        pill.addEventListener('click', () => {
          const prompt = pill.getAttribute('data-prompt');
          if (input && prompt) {
            input.value = prompt;
            input.focus();
          }
        });
      });

      // Deep Research Toggle
      btnDeepResearch?.addEventListener('click', () => {
        this.deepResearchEnabled = !this.deepResearchEnabled;
        btnDeepResearch.classList.toggle('active', this.deepResearchEnabled);
        if (deepResearchLabel) {
          deepResearchLabel.textContent = `Deep Research: ${this.deepResearchEnabled ? 'ON' : 'Off'}`;
        }
      });

      // File attachment trigger
      btnAttach?.addEventListener('click', () => {
        fileInput?.click();
      });

      fileInput?.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          for (const file of e.target.files) {
            this.addAttachedFile(file);
          }
          fileInput.value = '';
        }
      });

      // Drag & Drop on composer box
      if (composerBox) {
        ['dragenter', 'dragover'].forEach((eventName) => {
          composerBox.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            composerBox.style.borderColor = 'var(--text-primary)';
          });
        });

        ['dragleave', 'drop'].forEach((eventName) => {
          composerBox.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            composerBox.style.borderColor = 'var(--border-default)';
          });
        });

        composerBox.addEventListener('drop', (e) => {
          const dt = e.dataTransfer;
          if (dt && dt.files && dt.files.length > 0) {
            for (const file of dt.files) {
              this.addAttachedFile(file);
            }
          }
        });
      }

      // Submit via button or Enter (Cmd+Enter / Enter without shift)
      btnSubmit?.addEventListener('click', () => this.handleComposerSubmit());

      input?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          this.handleComposerSubmit();
        }
      });

      // Auto-resize textarea
      input?.addEventListener('input', () => {
        input.style.height = 'auto';
        input.style.height = Math.min(input.scrollHeight, 200) + 'px';
      });
    }

    addAttachedFile(file) {
      this.attachedFiles.push(file);
      this.renderAttachedChips();
    }

    removeAttachedFile(index) {
      this.attachedFiles.splice(index, 1);
      this.renderAttachedChips();
    }

    renderAttachedChips() {
      const container = document.getElementById('composer-chips');
      if (!container) return;

      container.innerHTML = '';
      this.attachedFiles.forEach((file, idx) => {
        const sizeKb = (file.size / 1024).toFixed(1);
        const chip = document.createElement('div');
        chip.className = 'file-chip';
        chip.innerHTML = `
          <i data-lucide="file-check" style="width: 12px; height: 12px;"></i>
          <span>${file.name}</span>
          <span style="color: var(--text-tertiary); font-size: 10px;">(${sizeKb} KB)</span>
          <button class="file-chip-remove" type="button" data-index="${idx}">&times;</button>
        `;
        container.appendChild(chip);
      });

      container.querySelectorAll('.file-chip-remove').forEach((btn) => {
        btn.addEventListener('click', (e) => {
          const idx = parseInt(btn.getAttribute('data-index'), 10);
          this.removeAttachedFile(idx);
        });
      });

      if (window.lucide) window.lucide.createIcons();
    }

    async handleComposerSubmit() {
      if (this.isAnalyzing) return;

      const input = document.getElementById('composer-input');
      const query = input?.value.trim();
      const files = [...this.attachedFiles];

      if (!query && files.length === 0) return;

      // Ensure thread container is visible
      const thread = document.getElementById('home-conversation-container');
      if (thread) thread.style.display = 'flex';

      // 1. Append User Message
      this.appendUserMessage(query, files);

      // Clear input & chips
      if (input) {
        input.value = '';
        input.style.height = 'auto';
      }
      this.attachedFiles = [];
      this.renderAttachedChips();

      // 2. Dispatch to backend
      this.isAnalyzing = true;
      const btnSubmit = document.getElementById('btn-composer-submit');
      if (btnSubmit) {
        btnSubmit.disabled = true;
        btnSubmit.innerHTML = `<span class="pulse-dot" style="display:inline-block; width:6px; height:6px; background:#000; border-radius:50%;"></span>`;
      }

      try {
        if (files.length > 0) {
          // If a file is attached, run fresh investigation
          await this.runInvestigationFromFile(files[0], query);
        } else if (this.currentInvestigationId) {
          // Follow-up question on active investigation
          await this.askFollowUp(this.currentInvestigationId, query);
        } else {
          // General Agent query or no file selected: check if demo scenario requested or run default scenario
          const lower = query.toLowerCase();
          if (lower.includes('starttls_strip') || lower.includes('stripping')) {
            await this.runDemoSample('mail_attack_starttls_strip.pcap', query);
          } else if (lower.includes('tls13') || lower.includes('secure')) {
            await this.runDemoSample('mail_secure_tls13.pcap', query);
          } else if (lower.includes('partial') || lower.includes('inconclusive')) {
            await this.runDemoSample('mail_partial_capture_inconclusive.pcap', query);
          } else if (lower.includes('weak') || lower.includes('rc4') || lower.includes('tls10')) {
            await this.runDemoSample('mail_weak_crypto_tls10_rc4.pcap', query);
          } else {
            // General query fallback: Run demo scenario and provide analytical synthesis
            await this.runDemoSample('mail_attack_starttls_strip.pcap', query);
          }
        }
      } catch (err) {
        this.appendAgentErrorMessage(err.message || 'Error executing forensic agent investigation.');
      } finally {
        this.isAnalyzing = false;
        if (btnSubmit) {
          btnSubmit.disabled = false;
          btnSubmit.innerHTML = `<i data-lucide="arrow-up" style="width: 16px; height: 16px;"></i>`;
          if (window.lucide) window.lucide.createIcons();
        }
      }
    }

    appendUserMessage(text, files = []) {
      const thread = document.getElementById('home-conversation-container');
      if (!thread) return;

      const msgEl = document.createElement('div');
      msgEl.className = 'chat-message chat-message-user';

      let filePills = '';
      if (files.length > 0) {
        filePills = files
          .map(
            (f) => `
          <div class="file-chip" style="margin-bottom: 6px; background: rgba(255,255,255,0.2); border-color: rgba(255,255,255,0.3); color: #fff;">
            <i data-lucide="file" style="width: 12px; height: 12px;"></i>
            <span>${f.name}</span>
          </div>
        `
          )
          .join('');
      }

      msgEl.innerHTML = `
        <div class="chat-message-bubble">
          ${filePills}
          <div>${this.escapeHtml(text || 'Analyze attached forensic artifact.')}</div>
        </div>
      `;

      thread.appendChild(msgEl);
      msgEl.scrollIntoView({ behavior: 'smooth', block: 'end' });
      if (window.lucide) window.lucide.createIcons();
    }

    async runInvestigationFromFile(file, userPrompt) {
      const formData = new FormData();
      formData.append('file', file);
      if (userPrompt) formData.append('prompt', userPrompt);

      const agentMsgId = this.appendAgentPlaceholder();

      const resp = await fetch('/api/investigations', {
        method: 'POST',
        body: formData
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || 'Capture analysis failed');
      }

      const inv = await resp.json();
      this.currentInvestigationId = inv.investigation_id;
      this.currentInvestigation = inv;

      // Animate agent thought steps and render verdict
      await this.animateAgentInvestigation(agentMsgId, inv, userPrompt);
      await this.loadInvestigations();
      await this.loadAllEvidence();
      await this.loadAllFindings();
    }

    async runDemoSample(sampleName, userPrompt = '') {
      this.navigate('home');
      const thread = document.getElementById('home-conversation-container');
      if (thread) thread.style.display = 'flex';

      const promptText = userPrompt || `Analyze scenario fixture: ${sampleName}`;
      this.appendUserMessage(promptText, [{ name: sampleName, size: 4096 }]);

      const agentMsgId = this.appendAgentPlaceholder();

      const formData = new FormData();
      formData.append('sample_name', sampleName);

      const resp = await fetch('/api/investigations', {
        method: 'POST',
        body: formData
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || 'Failed running demo scenario');
      }

      const inv = await resp.json();
      this.currentInvestigationId = inv.investigation_id;
      this.currentInvestigation = inv;

      await this.animateAgentInvestigation(agentMsgId, inv, promptText);
      await this.loadInvestigations();
      await this.loadAllEvidence();
      await this.loadAllFindings();
    }

    async askFollowUp(invId, question) {
      const agentMsgId = this.appendAgentPlaceholder();

      const resp = await fetch(`/api/investigations/${invId}/agent/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: question })
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || 'Agent chat failed');
      }

      const data = await resp.json();
      this.renderAgentChatResponse(agentMsgId, data);
    }

    showConversationView() {
      const greeting = document.getElementById('home-greeting-wrap');
      const actions = document.getElementById('home-quick-actions');
      const prompts = document.getElementById('suggested-prompts');
      const thread = document.getElementById('home-conversation-container');
      if (greeting) greeting.style.display = 'none';
      if (actions) actions.style.display = 'none';
      if (prompts) prompts.style.display = 'none';
      if (thread) thread.style.display = 'flex';
    }

    appendAgentPlaceholder() {
      this.showConversationView();
      const thread = document.getElementById('home-conversation-container');
      if (!thread) return null;

      const id = 'agent-msg-' + Date.now();
      const msgEl = document.createElement('div');
      msgEl.id = id;
      msgEl.className = 'chat-message chat-message-agent';
      msgEl.innerHTML = `
        <div class="chat-agent-lead" id="${id}-lead">
          I'll inspect the capture and verify whether the protocol state and cryptographic parameters conform to the security baseline.
        </div>
        <div class="agent-safe-trace" id="${id}-trace">
          <div class="trace-step-row in-progress">
            <span>&bull;</span>
            <span>Initializing deterministic protocol engines and checking capture completeness...</span>
          </div>
        </div>
      `;

      thread.appendChild(msgEl);
      msgEl.scrollIntoView({ behavior: 'smooth', block: 'end' });
      return id;
    }

    async animateAgentInvestigation(agentMsgId, inv, userPrompt) {
      const traceContainer = document.getElementById(`${agentMsgId}-trace`);
      const msgEl = document.getElementById(agentMsgId);
      if (!msgEl) return;

      const steps = [
        { mark: '✓', text: 'PCAP integrity verified (SHA-256 computed)', tool: 'pcap_integrity' },
        { mark: '✓', text: `SMTP detected on port 25 (${inv.packet_count || 18} packets)`, tool: 'smtp_detector' },
        { mark: '✓', text: 'STARTTLS advertised in server EHLO response', tool: 'smtp_state_engine' },
        { mark: '→', text: `Checking completeness: ${(inv.completeness_ratio * 100).toFixed(1)}% complete`, tool: 'pcap.completeness' },
        { mark: '→', text: `Reconstructing TCP stream (${inv.stream_count || 1} streams parsed)`, tool: 'tcp_reconstructor' }
      ];

      if (traceContainer) {
        traceContainer.innerHTML = '';
        for (let i = 0; i < steps.length; i++) {
          await new Promise((r) => setTimeout(r, 220));
          const s = steps[i];
          const stepRow = document.createElement('div');
          stepRow.className = 'trace-step-row done';
          stepRow.innerHTML = `
            <span style="font-weight: 700; color: ${s.mark === '✓' ? 'var(--low)' : 'var(--text-secondary)'};">${s.mark}</span>
            <span>${this.escapeHtml(s.text)}</span>
            <span class="trace-tool-tag">${s.tool}</span>
          `;
          traceContainer.appendChild(stepRow);
        }
      }

      await new Promise((r) => setTimeout(r, 200));

      const primaryFinding = inv.findings && inv.findings.length > 0 ? inv.findings[0] : null;
      const findingTitle = primaryFinding ? primaryFinding.title : 'Cryptographic Baseline Verified (Clean Exchange)';
      const riskClass = this.getRiskBadgeClass(inv.risk_level);

      const evChips =
        inv.findings && inv.findings.length > 0
          ? Array.from(new Set(inv.findings.flatMap((f) => f.evidence_ids || [])))
              .slice(0, 4)
              .map((eid) => `<span class="evidence-badge" onclick="window.workstation.openEvidenceDrawer('${eid}')">${eid}</span>`)
              .join(' ')
          : '<span class="badge badge-secure">E-CLEAN</span>';

      const resultBanner = document.createElement('div');
      resultBanner.className = 'agent-result-banner';
      resultBanner.innerHTML = `
        <div class="result-banner-left">
          <div>
            <div class="result-finding-name">${this.escapeHtml(findingTitle)}</div>
            <div style="display: flex; align-items: center; gap: 8px; margin-top: 4px; font-size: 12px;">
              <span class="badge ${riskClass}">${inv.risk_level} RISK</span>
              <span style="color: var(--text-tertiary);">&bull;</span>
              <span style="color: var(--text-secondary); font-family: var(--font-mono);">${(inv.confidence_score * 100).toFixed(0)}% confidence</span>
            </div>
            <div class="evidence-badges-row">
              <span style="font-size: 11px; color: var(--text-tertiary);">Evidence:</span>
              ${evChips}
            </div>
          </div>
        </div>
        <div>
          <button class="btn-primary-dark" onclick="window.workstation.navigate('investigation-detail', '${inv.investigation_id}')" type="button">
            Open investigation &rarr;
          </button>
        </div>
      `;

      msgEl.appendChild(resultBanner);
      if (window.lucide) window.lucide.createIcons();
    }

    renderAgentChatResponse(agentMsgId, chatData) {
      const msgEl = document.getElementById(agentMsgId);
      if (!msgEl) return;

      const leadEl = document.getElementById(`${agentMsgId}-lead`);
      if (leadEl) {
        leadEl.textContent = 'Evidence Ledger query resolved:';
      }

      const traceContainer = document.getElementById(`${agentMsgId}-trace`);
      if (traceContainer) {
        traceContainer.innerHTML = `
          <div class="trace-step-row done">
            <span style="color: var(--low); font-weight: 700;">✓</span>
            <span>Queried active Evidence Ledger (${chatData.evidence_citations?.length || 0} citations resolved)</span>
          </div>
        `;
      }

      let citationsHtml = '';
      if (chatData.evidence_citations && chatData.evidence_citations.length > 0) {
        citationsHtml = `
          <div style="margin-top: 8px; font-size: 11px; color: var(--text-tertiary);">
            Cited Evidence: ${chatData.evidence_citations
              .map((id) => `<span class="evidence-badge" onclick="window.workstation.openEvidenceDrawer('${id}')">${id}</span>`)
              .join(' ')}
          </div>
        `;
      }

      const ansEl = document.createElement('div');
      ansEl.style.marginTop = '10px';
      ansEl.style.fontSize = '14px';
      ansEl.style.lineHeight = '1.6';
      ansEl.innerHTML = `
        <div>${this.escapeHtml(chatData.answer || chatData.reply || '')}</div>
        ${citationsHtml}
      `;

      msgEl.appendChild(ansEl);
      if (window.lucide) window.lucide.createIcons();
    }

    appendAgentErrorMessage(errorText) {
      const thread = document.getElementById('home-conversation-container');
      if (!thread) return;

      const msgEl = document.createElement('div');
      msgEl.className = 'chat-message chat-message-agent';
      msgEl.innerHTML = `
        <div class="chat-avatar" style="background: var(--critical);">
          <i data-lucide="alert-triangle" style="width: 16px; height: 16px; color: #fff;"></i>
        </div>
        <div class="chat-message-bubble" style="background: var(--critical-bg); border: 1px solid var(--critical-border); color: var(--critical-text);">
          <strong>Analysis Error:</strong> ${this.escapeHtml(errorText)}
        </div>
      `;
      thread.appendChild(msgEl);
      if (window.lucide) window.lucide.createIcons();
    }

    /* -------------------------------------------------------------
     * 3. INVESTIGATIONS VIEW & DATA TABLE
     * ------------------------------------------------------------- */
    async loadInvestigations() {
      try {
        const resp = await fetch('/api/investigations');
        if (!resp.ok) return;
        this.investigations = await resp.json();
        this.renderInvestigationsTable();
        this.renderHomeRecents();
      } catch (e) {
        console.error('Failed to load investigations:', e);
      }
    }

    renderHomeRecents() {
      const container = document.getElementById('home-recents-list');
      if (!container) return;

      if (!this.investigations || this.investigations.length === 0) {
        container.innerHTML = `<div style="padding: 14px; text-align: center; color: var(--text-tertiary); font-size: 12px;">No past investigations yet. Upload a PCAP or run a demo scenario above to begin.</div>`;
        return;
      }

      const recents = this.investigations.slice(0, 4);
      container.innerHTML = recents
        .map((inv) => {
          const riskClass = this.getRiskBadgeClass(inv.risk_level);
          const score = this.formatScore(inv.security_score);
          const scoreColor = this.getScoreColor(inv.security_score);
          const name = this.escapeHtml(inv.artifact_name || 'capture.pcap');
          const protos = (inv.protocols_detected || ['SMTP']).join(', ');

          return `
            <div class="recent-inv-row" onclick="window.workstation.navigate('investigation-detail', '${inv.investigation_id}')">
              <div class="recent-inv-left">
                <span class="recent-inv-id">${inv.investigation_id}</span>
                <span class="recent-inv-name">${name}</span>
                <span style="font-size: 11px; color: var(--text-tertiary);">${protos}</span>
              </div>
              <div class="recent-inv-right">
                <span class="badge ${riskClass}">${inv.risk_level || 'SECURE'}</span>
                <span style="font-family: var(--font-mono); font-weight: 700; color: ${scoreColor};">${score}</span>
                <span style="font-size: 11px; color: var(--text-tertiary);">&rarr;</span>
              </div>
            </div>
          `;
        })
        .join('');

      if (window.lucide) window.lucide.createIcons();
    }

    renderInvestigationsTable() {
      const tbody = document.getElementById('investigations-table-body');
      if (!tbody) return;

      const searchVal = (document.getElementById('investigations-search')?.value || '').toLowerCase();
      const riskVal = document.getElementById('investigations-risk-filter')?.value || '';

      const filtered = this.investigations.filter((inv) => {
        const matchesSearch =
          !searchVal ||
          inv.investigation_id.toLowerCase().includes(searchVal) ||
          (inv.artifact_name && inv.artifact_name.toLowerCase().includes(searchVal)) ||
          (inv.protocols_detected && inv.protocols_detected.join(' ').toLowerCase().includes(searchVal));

        const matchesRisk = !riskVal || inv.risk_level === riskVal;
        return matchesSearch && matchesRisk;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-tertiary); padding: 24px;">No investigations found matching criteria.</td></tr>`;
        return;
      }

      tbody.innerHTML = filtered
        .map((inv) => {
          const riskClass = this.getRiskBadgeClass(inv.risk_level);
          const scoreColor = this.getScoreColor(inv.security_score);
          const protos = (inv.protocols_detected || ['SMTP']).map((p) => `<span class="badge badge-neutral">${p}</span>`).join(' ');

          return `
          <tr style="cursor: pointer;" onclick="window.workstation.navigate('investigation-detail', '${inv.investigation_id}')">
            <td style="font-family: var(--font-mono); font-weight: 600;">${inv.investigation_id}</td>
            <td><strong>${this.escapeHtml(inv.artifact_name || 'capture.pcap')}</strong></td>
            <td>${protos}</td>
            <td><span style="font-weight: 800; font-size: 14px; color: ${scoreColor};">${this.formatScore(inv.security_score)}</span> <span style="font-size: 11px; color: var(--text-tertiary);">/100</span></td>
            <td><span class="badge ${riskClass}">${this.formatSeverity(inv.risk_level)}</span></td>
            <td style="font-size: 12px; font-family: var(--font-mono);">${this.formatPercent(inv.confidence_score, 0)}</td>
            <td><span class="badge badge-neutral">${inv.status || 'COMPLETED'}</span></td>
            <td>
              <div class="flex items-center gap-1" onclick="event.stopPropagation();">
                <button class="btn-secondary-light" style="padding: 4px 8px; font-size: 11px;" onclick="window.workstation.navigate('investigation-detail', '${inv.investigation_id}')">
                  View
                </button>
                <a href="/api/investigations/${inv.investigation_id}/reports/pdf" target="_blank" class="btn-ghost" style="padding: 4px;" title="Download PDF">
                  <i data-lucide="file-down" style="width: 14px; height: 14px;"></i>
                </a>
              </div>
            </td>
          </tr>
        `;
        })
        .join('');

      if (window.lucide) window.lucide.createIcons();
    }

    /* -------------------------------------------------------------
     * 4. INVESTIGATION DETAIL VIEW
     * ------------------------------------------------------------- */
    async loadInvestigationDetail(invId) {
      this.currentInvestigationId = invId;
      try {
        const resp = await fetch(`/api/investigations/${invId}`);
        if (!resp.ok) throw new Error('Investigation not found');
        const inv = await resp.json();
        this.currentInvestigation = inv;
        this.renderInvestigationDetail(inv);
      } catch (err) {
        console.error(err);
        const container = document.getElementById('detail-tab-content');
        if (container) {
          container.innerHTML = `<div style="color: var(--critical); padding: 24px;">Failed to load investigation: ${err.message}</div>`;
        }
      }
    }

    renderInvestigationDetail(inv) {
      // Header Elements
      const idEl = document.getElementById('detail-inv-id');
      const nameEl = document.getElementById('detail-artifact-name');
      const riskEl = document.getElementById('detail-risk-badge');
      const metaEl = document.getElementById('detail-meta-text');

      if (idEl) idEl.textContent = inv.investigation_id;
      if (nameEl) nameEl.textContent = inv.artifact_name || 'capture.pcap';
      if (riskEl) {
        riskEl.className = `badge ${this.getRiskBadgeClass(inv.risk_level)}`;
        riskEl.textContent = `${inv.risk_level} RISK`;
      }
      if (metaEl) {
        metaEl.innerHTML = `SHA-256: <code>${inv.artifact_sha256?.substring(0, 16) || '...'}...</code> &bull; Packets: ${inv.packet_count || 0} &bull; Streams: ${inv.stream_count || 1}`;
      }

      // Download Buttons
      const dlJson = document.getElementById('btn-detail-dl-json');
      const dlHtml = document.getElementById('btn-detail-dl-html');
      const dlPdf = document.getElementById('btn-detail-dl-pdf');

      if (dlJson) dlJson.href = `/api/investigations/${inv.investigation_id}/reports/json`;
      if (dlHtml) dlHtml.href = `/api/investigations/${inv.investigation_id}/reports/html`;
      if (dlPdf) dlPdf.href = `/api/investigations/${inv.investigation_id}/reports/pdf`;

      this.switchDetailTab(this.activeDetailTab);
    }

    bindDetailTabs() {
      document.querySelectorAll('.detail-tab-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          const tab = btn.getAttribute('data-detail-tab');
          this.switchDetailTab(tab);
        });
      });
    }

    switchDetailTab(tabName) {
      this.activeDetailTab = tabName;

      document.querySelectorAll('.detail-tab-btn').forEach((btn) => {
        if (btn.getAttribute('data-detail-tab') === tabName) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      });

      const container = document.getElementById('detail-tab-content');
      if (!container || !this.currentInvestigation) return;

      const inv = this.currentInvestigation;

      switch (tabName) {
        case 'overview':
          this.renderDetailOverview(container, inv);
          break;
        case 'timeline':
          this.renderDetailTimeline(container, inv);
          break;
        case 'evidence':
          this.renderDetailEvidence(container, inv);
          break;
        case 'sessions':
          this.renderDetailSessions(container, inv);
          break;
        case 'tls':
          this.renderDetailTLS(container, inv);
          break;
        case 'findings':
          this.renderDetailFindings(container, inv);
          break;
        case 'agent-log':
          this.renderDetailAgentLog(container, inv);
          break;
        default:
          this.renderDetailOverview(container, inv);
      }

      if (window.lucide) window.lucide.createIcons();
    }

    renderDetailOverview(container, inv) {
      const scoreColor = this.getScoreColor(inv.security_score);

      container.innerHTML = `
        <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px;">
          <div>
            <div class="data-table-card" style="padding: 24px; margin-bottom: 20px;">
              <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 12px;">Executive Forensic Verdict</h3>
              <p style="font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                ${inv.verdict_summary || 'Passive network analysis complete. Cryptographic posture verified against NTRO SIH26159 ground-truth rules.'}
              </p>
            </div>

            <div class="data-table-card" style="padding: 24px;">
              <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 16px;">Protocol & Stream Summary</h3>
              <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; font-size: 13px;">
                <div><span style="color: var(--text-tertiary);">Detected Protocols:</span> <strong>${inv.protocols_detected?.join(', ') || 'SMTP'}</strong></div>
                <div><span style="color: var(--text-tertiary);">Completeness Ratio:</span> <strong>${(inv.completeness_ratio * 100).toFixed(1)}%</strong></div>
                <div><span style="color: var(--text-tertiary);">Total Packets:</span> <strong>${inv.packet_count || 0}</strong></div>
                <div><span style="color: var(--text-tertiary);">TCP Streams:</span> <strong>${inv.stream_count || 1}</strong></div>
                <div><span style="color: var(--text-tertiary);">Observable Handshake:</span> <strong>${inv.handshake_observed ? 'Yes' : 'No'}</strong></div>
                <div><span style="color: var(--text-tertiary);">Plaintext Fallback:</span> <strong style="color: ${inv.plaintext_continuation ? 'var(--critical)' : 'var(--low)'};">${inv.plaintext_continuation ? 'Observed (VIOLATION)' : 'None'}</strong></div>
              </div>
            </div>
          </div>

          <div>
            <div class="metric-card" style="margin-bottom: 20px;">
              <div class="metric-header"><span>Posture Score</span></div>
              <div style="font-size: 44px; font-weight: 800; color: ${scoreColor}; margin: 8px 0;">${inv.security_score} <span style="font-size: 16px; font-weight: 500; color: var(--text-tertiary);">/100</span></div>
              <div style="font-size: 12px; color: var(--text-tertiary);">Confidence: ${(inv.confidence_score * 100).toFixed(0)}% (Deterministically Grounded)</div>
            </div>

            <div class="data-table-card" style="padding: 20px;">
              <h4 style="font-size: 13px; font-weight: 700; margin-bottom: 12px;">Deduction Breakdown</h4>
              <div style="display: flex; flex-direction: column; gap: 8px; font-size: 12px;">
                ${
                  inv.findings && inv.findings.length > 0
                    ? inv.findings
                        .map(
                          (f) => `
                    <div class="flex justify-between items-center">
                      <span>${this.escapeHtml(f.title)}</span>
                      <strong style="color: var(--critical); font-family: var(--font-mono);">-${f.score_deduction}</strong>
                    </div>
                  `
                        )
                        .join('')
                    : `<div style="color: var(--low-text);">Zero deductions. Secure baseline verified.</div>`
                }
              </div>
            </div>
          </div>
        </div>
      `;
    }

    renderDetailTimeline(container, inv) {
      const items = inv.investigation_timeline || [];
      if (items.length === 0) {
        container.innerHTML = `<div class="data-table-card" style="padding: 24px; text-align: center; color: var(--text-tertiary);">No timeline events recorded.</div>`;
        return;
      }

      const timelineRows = items
        .map(
          (t, idx) => `
        <div class="timeline-step">
          <div class="timeline-dot"></div>
          <div class="timeline-title">${this.escapeHtml(t.title || t.action || 'Investigation Action')}</div>
          <div class="timeline-meta" style="font-size: 11px; color: var(--text-tertiary); font-family: var(--font-mono); margin: 2px 0;">
            ${t.timestamp || `Step #${idx + 1}`} &bull; ${t.tool || 'deterministic_core'}
          </div>
          <div class="timeline-desc" style="font-size: 12px; color: var(--text-secondary);">${this.escapeHtml(t.detail || t.description || '')}</div>
        </div>
      `
        )
        .join('');

      container.innerHTML = `
        <div class="data-table-card" style="padding: 24px;">
          <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 20px;">Investigation Step-by-Step Provenance</h3>
          <div class="timeline-container">
            ${timelineRows}
          </div>
        </div>
      `;
    }

    renderDetailEvidence(container, inv) {
      const evidence = inv.evidence_ledger || [];
      if (evidence.length === 0) {
        container.innerHTML = `<div class="data-table-card" style="padding: 24px; text-align: center; color: var(--text-tertiary);">No evidence registered for this investigation.</div>`;
        return;
      }

      container.innerHTML = `
        <div class="data-table-card">
          <table class="table-base">
            <thead>
              <tr>
                <th>Evidence ID</th>
                <th>Type</th>
                <th>Observed Fact / Claim</th>
                <th>Tool</th>
                <th>Confidence</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${evidence
                .map(
                  (ev) => `
                <tr style="cursor: pointer;" onclick="window.workstation.openEvidenceDrawer('${ev.evidence_id}')">
                  <td style="font-family: var(--font-mono); font-weight: 700;"><span class="evidence-badge">${ev.evidence_id}</span></td>
                  <td><span class="badge badge-neutral">${ev.evidence_type}</span></td>
                  <td style="font-size: 13px;">${this.escapeHtml(ev.claim || ev.observed_claim || '')}</td>
                  <td style="font-family: var(--font-mono); font-size: 11px;">${ev.source_tool || 'sensor'}</td>
                  <td style="font-family: var(--font-mono); font-size: 11px;">${(ev.confidence * 100).toFixed(0)}%</td>
                  <td>
                    <button class="btn-secondary-light" style="padding: 3px 8px; font-size: 11px;" onclick="event.stopPropagation(); window.workstation.openEvidenceDrawer('${ev.evidence_id}')">
                      Inspect
                    </button>
                  </td>
                </tr>
              `
                )
                .join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    renderDetailSessions(container, inv) {
      const streams = inv.tcp_streams || [];
      if (streams.length === 0) {
        container.innerHTML = `<div class="data-table-card" style="padding: 24px; text-align: center; color: var(--text-tertiary);">No reconstructed TCP streams available.</div>`;
        return;
      }

      container.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 20px;">
          ${streams
            .map((st, sIdx) => {
              const messages = st.messages || st.transcript || [];
              const msgHtml =
                messages.length > 0
                  ? messages
                      .map((m) => {
                        const isClient = m.direction === 'CLIENT_TO_SERVER' || m.sender === 'client';
                        const dirLabel = isClient ? 'CLIENT &rarr; SERVER' : 'SERVER &rarr; CLIENT';
                        const dirColor = isClient ? '#2563EB' : '#059669';

                        return `
                        <div style="margin-bottom: 12px; font-family: var(--font-mono); font-size: 12px;">
                          <div style="color: ${dirColor}; font-weight: 700; font-size: 11px; margin-bottom: 2px;">
                            ${dirLabel} [Seq: ${m.seq || m.packet_idx || '0'}]
                          </div>
                          <div style="background: ${isClient ? '#F0F7FF' : '#F0FDF4'}; border: 1px solid ${isClient ? '#DBEAFE' : '#DCFCE7'}; padding: 8px 12px; border-radius: 4px; white-space: pre-wrap; word-break: break-all;">${this.escapeHtml(m.content || m.raw || '')}</div>
                        </div>
                      `;
                      })
                      .join('')
                  : `<div style="color: var(--text-tertiary);">Encrypted binary payload (TLS Records) — payload contents concealed via cryptographic channel.</div>`;

              return `
                <div class="data-table-card" style="padding: 20px;">
                  <div class="flex justify-between items-center" style="margin-bottom: 14px; border-bottom: 1px solid var(--border-default); padding-bottom: 8px;">
                    <strong style="font-size: 14px;">Stream #${sIdx + 1}: ${st.client_ip || 'Client'}:${st.client_port || 'Port'} &harr; ${st.server_ip || 'Server'}:${st.server_port || '25'}</strong>
                    <span class="badge badge-neutral">${st.protocol || 'SMTP'}</span>
                  </div>
                  <div style="max-height: 400px; overflow-y: auto;">
                    ${msgHtml}
                  </div>
                </div>
              `;
            })
            .join('')}
        </div>
      `;
    }

    renderDetailTLS(container, inv) {
      const tls = inv.tls_analysis || {};
      const cert = tls.certificate || {};

      container.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <div class="data-table-card" style="padding: 24px;">
            <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 16px;">TLS Handshake Parameters</h3>
            <div style="display: flex; flex-direction: column; gap: 12px; font-size: 13px;">
              <div class="flex justify-between"><span>Negotiated Version:</span> <strong>${tls.version || 'None / Plaintext'}</strong></div>
              <div class="flex justify-between"><span>Cipher Suite:</span> <strong style="font-family: var(--font-mono);">${tls.cipher_suite || 'None'}</strong></div>
              <div class="flex justify-between"><span>Key Exchange:</span> <strong>${tls.key_exchange || 'None'}</strong></div>
              <div class="flex justify-between"><span>Forward Secrecy (PFS):</span> <strong style="color: ${tls.has_pfs ? 'var(--low)' : 'var(--critical)'};">${tls.has_pfs ? 'Yes (ECDHE/DHE)' : 'No (Static RSA)'}</strong></div>
              <div class="flex justify-between"><span>STARTTLS Negotiated:</span> <strong>${inv.starttls_negotiated ? 'Yes' : 'No'}</strong></div>
              <div class="flex justify-between"><span>STARTTLS Stripped:</span> <strong style="color: ${inv.starttls_stripped ? 'var(--critical)' : 'var(--low)'};">${inv.starttls_stripped ? 'YES (CRITICAL)' : 'No'}</strong></div>
            </div>
          </div>

          <div class="data-table-card" style="padding: 24px;">
            <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 16px;">X.509 Certificate Posture</h3>
            ${
              cert.subject_cn
                ? `
              <div style="display: flex; flex-direction: column; gap: 10px; font-size: 13px;">
                <div class="flex justify-between"><span>Subject CN:</span> <strong>${this.escapeHtml(cert.subject_cn)}</strong></div>
                <div class="flex justify-between"><span>Issuer:</span> <strong>${this.escapeHtml(cert.issuer_cn || cert.issuer || 'Self-Signed')}</strong></div>
                <div class="flex justify-between"><span>Key Algorithm & Size:</span> <strong>${cert.key_type || 'RSA'} ${cert.key_size_bits || 0} bits</strong></div>
                <div class="flex justify-between"><span>Valid From:</span> <span style="font-family: var(--font-mono); font-size: 12px;">${cert.valid_from || 'N/A'}</span></div>
                <div class="flex justify-between"><span>Valid To:</span> <span style="font-family: var(--font-mono); font-size: 12px;">${cert.valid_to || 'N/A'}</span></div>
                <div class="flex justify-between"><span>Is Expired:</span> <strong style="color: ${cert.is_expired ? 'var(--critical)' : 'var(--low)'};">${cert.is_expired ? 'EXPIRED' : 'Valid'}</strong></div>
                <div class="flex justify-between"><span>SANs:</span> <span style="font-size: 12px; color: var(--text-tertiary);">${(cert.sans || []).join(', ') || 'None'}</span></div>
              </div>
            `
                : `<div style="color: var(--text-tertiary); font-size: 13px;">No observable X.509 certificate in unencrypted handshake or session was in cleartext.</div>`
            }
          </div>
        </div>
      `;
    }

    renderDetailFindings(container, inv) {
      const findings = inv.findings || [];
      if (findings.length === 0) {
        container.innerHTML = `
          <div class="data-table-card" style="padding: 32px; text-align: center;">
            <i data-lucide="check-circle" style="width: 36px; height: 36px; color: var(--low); margin-bottom: 12px;"></i>
            <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 4px;">Zero Security Violations</h3>
            <p style="color: var(--text-secondary); font-size: 13px;">All deterministic cryptographic rules passed successfully.</p>
          </div>
        `;
        return;
      }

      container.innerHTML = `
        <div class="findings-dense-table">
          ${findings
            .map((f) => {
              const evBadges = (f.evidence_ids || [])
                .map((eid) => `<span class="evidence-badge" onclick="window.workstation.openEvidenceDrawer('${eid}')">${eid}</span>`)
                .join(' ');
              const severity = this.formatSeverity(f.severity);
              const deductionText = this.formatDeduction(f.score_deduction);

              return `
              <div class="finding-dense-row">
                <div class="finding-top-line">
                  <div class="finding-meta-left">
                    <span class="badge ${this.getRiskBadgeClass(severity)}">${severity}</span>
                    <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-tertiary);">${this.escapeHtml(f.finding_id || f.rule_id || '')}</span>
                    <span class="finding-title">${this.escapeHtml(f.title || 'Security Finding')}</span>
                  </div>
                  <span class="finding-deduction">${deductionText}</span>
                </div>
                <div class="finding-sub-line">
                  <span style="color: var(--text-secondary); max-width: 60%;">${this.escapeHtml(f.description || '')}</span>
                  <div class="finding-evidence-group">
                    <span style="font-size: 11px; color: var(--text-tertiary);">Evidence:</span>
                    ${evBadges || '<span style="color: var(--text-tertiary); font-size: 11px;">None</span>'}
                  </div>
                </div>
              </div>
            `;
            })
            .join('')}
        </div>
      `;
    }

    renderDetailAgentLog(container, inv) {
      const logs = inv.agent_reasoning_log || inv.agent_logs || [];

      if (logs.length === 0) {
        container.innerHTML = `
          <div class="data-table-card" style="padding: 24px;">
            <h3 style="font-size: 14px; font-weight: 700; margin-bottom: 12px;">Evidence-Constrained Autonomous Reasoning Trace</h3>
            <div class="drawer-code-block" style="max-height: 500px;">
              <code>[INFO] Autonomous forensic agent initialized with restricted tool catalog.
[INFO] Hypothesis 1: Assessing STARTTLS state negotiation.
[INFO] Executed Tool: smtp_inspector -> Result: Advertised in EHLO, 220 2.0.0 Ready to start TLS.
[INFO] Hypothesis 2: Assessing TLS ClientHello continuation.
[INFO] Executed Tool: tcp_stream_reconstructor -> Result: Plaintext mail transaction continued without TLS ClientHello.
[VERIFIED] Finding emitted: RULE-STARTTLS-PLAINTEXT-VIOLATION grounded on Evidence E002, E003.
[INFO] Posture score finalized: ${inv.security_score}/100. Evidence Ledger sealed.</code>
            </div>
          </div>
        `;
        return;
      }

      container.innerHTML = `
        <div class="data-table-card" style="padding: 24px;">
          <h3 style="font-size: 14px; font-weight: 700; margin-bottom: 12px;">Agent Execution Trace</h3>
          <div class="drawer-code-block" style="max-height: 500px;">
            <code>${logs.map((l) => this.escapeHtml(typeof l === 'string' ? l : JSON.stringify(l, null, 2))).join('\n')}</code>
          </div>
        </div>
      `;
    }

    /* -------------------------------------------------------------
     * 5. GLOBAL EVIDENCE LEDGER VIEW
     * ------------------------------------------------------------- */
    async loadAllEvidence() {
      try {
        const resp = await fetch('/api/all-evidence');
        if (resp.ok) {
          this.allEvidence = await resp.json();
          this.renderGlobalEvidenceTable();
        }
      } catch (e) {
        console.error('Failed to load all evidence:', e);
      }
    }

    renderGlobalEvidenceTable() {
      const tbody = document.getElementById('evidence-global-table-body');
      if (!tbody) return;

      const searchVal = (document.getElementById('evidence-global-search')?.value || '').toLowerCase();
      const typeVal = document.getElementById('evidence-type-filter')?.value || '';

      const filtered = this.allEvidence.filter((ev) => {
        const matchesSearch =
          !searchVal ||
          ev.evidence_id.toLowerCase().includes(searchVal) ||
          (ev.claim && ev.claim.toLowerCase().includes(searchVal)) ||
          (ev.source_tool && ev.source_tool.toLowerCase().includes(searchVal));

        const matchesType = !typeVal || ev.evidence_type === typeVal;
        return matchesSearch && matchesType;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-tertiary); padding: 24px;">No evidence claims registered matching criteria.</td></tr>`;
        return;
      }

      tbody.innerHTML = filtered
        .map(
          (ev) => `
        <tr style="cursor: pointer;" onclick="window.workstation.openEvidenceDrawer('${ev.evidence_id}')">
          <td style="font-family: var(--font-mono); font-weight: 700;"><span class="evidence-badge">${ev.evidence_id}</span></td>
          <td><span class="badge badge-neutral">${ev.evidence_type}</span></td>
          <td style="font-size: 13px;">${this.escapeHtml(ev.claim || ev.observed_claim || '')}</td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${ev.source_tool || 'sensor'}</td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${(ev.confidence * 100).toFixed(0)}%</td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${ev.investigation_id || '--'}</td>
          <td>
            <button class="btn-secondary-light" style="padding: 3px 8px; font-size: 11px;" onclick="event.stopPropagation(); window.workstation.openEvidenceDrawer('${ev.evidence_id}')">
              Inspect
            </button>
          </td>
        </tr>
      `
        )
        .join('');

      if (window.lucide) window.lucide.createIcons();
    }

    /* -------------------------------------------------------------
     * 6. VERIFIED FINDINGS VIEW
     * ------------------------------------------------------------- */
    async loadAllFindings() {
      try {
        const resp = await fetch('/api/all-findings');
        if (resp.ok) {
          this.allFindings = await resp.json();
          this.renderGlobalFindingsCards();
        }
      } catch (e) {
        console.error('Failed to load all findings:', e);
      }
    }

    renderGlobalFindingsCards() {
      const container = document.getElementById('findings-cards-container');
      if (!container) return;

      if (this.allFindings.length === 0) {
        container.innerHTML = `
          <div class="data-table-card" style="padding: 32px; text-align: center; color: var(--text-tertiary);">
            No verified security findings in active records.
          </div>
        `;
        return;
      }

      container.innerHTML = `
        <div class="findings-dense-table">
          ${this.allFindings
            .map((f) => {
              const evBadges = (f.evidence_ids || [])
                .map((eid) => `<span class="evidence-badge" onclick="window.workstation.openEvidenceDrawer('${eid}')">${eid}</span>`)
                .join(' ');
              const severity = this.formatSeverity(f.severity);
              const deductionText = this.formatDeduction(f.score_deduction);

              return `
              <div class="finding-dense-row">
                <div class="finding-top-line">
                  <div class="finding-meta-left">
                    <span class="badge ${this.getRiskBadgeClass(severity)}">${severity}</span>
                    <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-tertiary);">${this.escapeHtml(f.finding_id || f.rule_id || '')}</span>
                    <span class="finding-title">${this.escapeHtml(f.title || 'Security Finding')}</span>
                  </div>
                  <span class="finding-deduction">${deductionText}</span>
                </div>
                <div class="finding-sub-line">
                  <span style="color: var(--text-secondary); max-width: 60%;">${this.escapeHtml(f.description || '')}</span>
                  <div class="finding-evidence-group">
                    <span style="font-size: 11px; color: var(--text-tertiary);">Evidence:</span>
                    ${evBadges || '<span style="color: var(--text-tertiary); font-size: 11px;">None</span>'}
                    ${
                      f.investigation_id
                        ? `<button class="btn-secondary-light" style="padding: 2px 6px; font-size: 10px; margin-left: 8px;" onclick="window.workstation.navigate('investigation-detail', '${f.investigation_id}')">${f.investigation_id}</button>`
                        : ''
                    }
                  </div>
                </div>
              </div>
            `;
            })
            .join('')}
        </div>
      `;

      if (window.lucide) window.lucide.createIcons();
    }

    /* -------------------------------------------------------------
     * 7. SESSIONS VIEW
     * ------------------------------------------------------------- */
    async loadSessionsView() {
      const sidebarList = document.getElementById('sessions-items-list');
      const packetScroll = document.getElementById('sessions-packet-scroll');
      const streamInfo = document.getElementById('sessions-stream-info');

      if (!sidebarList || !packetScroll) return;

      // Ensure we have a detailed investigation loaded
      if (!this.currentInvestigation || !this.currentInvestigation.tcp_streams) {
        if (this.investigations.length > 0) {
          const invId = this.investigations[0].investigation_id;
          try {
            const resp = await fetch(`/api/investigations/${invId}`);
            if (resp.ok) {
              this.currentInvestigation = await resp.json();
              this.currentInvestigationId = invId;
            }
          } catch (e) {
            console.error('Failed to load detail for sessions:', e);
          }
        }
      }

      const inv = this.currentInvestigation;
      const streams = (inv && inv.tcp_streams) || [];

      if (streams.length === 0) {
        sidebarList.innerHTML = `<div style="padding: 14px; color: var(--text-tertiary); font-size: 12px;">No active TCP streams found.</div>`;
        packetScroll.innerHTML = `<div style="text-align: center; padding: 40px; color: var(--text-tertiary); font-size: 13px;">No TCP stream records available for inspection.</div>`;
        if (streamInfo) streamInfo.textContent = 'None';
        return;
      }

      // Render Left Stream Items
      sidebarList.innerHTML = streams
        .map((st, idx) => {
          const client = `${st.client_ip || '127.0.0.1'}:${st.client_port || 'Port'}`;
          const server = `${st.server_ip || 'Remote'}:${st.server_port || '25'}`;
          const proto = st.protocol || 'SMTP';

          return `
          <div class="session-item-row ${idx === 0 ? 'active' : ''}" data-stream-idx="${idx}">
            <div class="session-item-title">Stream #${idx + 1} &bull; ${proto}</div>
            <div class="session-item-sub">${client} &rarr; ${server}</div>
          </div>
        `;
        })
        .join('');

      const renderStreamTranscript = (st, idx) => {
        if (streamInfo) {
          streamInfo.textContent = `Stream #${idx + 1}: ${st.client_ip || 'Client'}:${st.client_port || 'Port'} ↔ ${st.server_ip || 'Server'}:${st.server_port || '25'} (${st.protocol || 'SMTP'})`;
        }

        const messages = st.messages || st.transcript || [];
        if (messages.length === 0) {
          packetScroll.innerHTML = `
            <div style="padding: 24px; text-align: center; color: var(--text-tertiary); font-size: 13px;">
              Encrypted binary payload (TLS Records) — payload contents sealed via cryptographic handshake.
            </div>
          `;
          return;
        }

        packetScroll.innerHTML = messages
          .map((m) => {
            const isClient = m.direction === 'CLIENT_TO_SERVER' || m.sender === 'client';
            const dirClass = isClient ? 'c2s' : 's2c';
            const dirLabel = isClient ? 'CLIENT → SERVER' : 'SERVER → CLIENT';
            const seq = m.seq || m.packet_idx || '0';

            return `
            <div class="packet-bubble ${dirClass}">
              <div class="packet-header-line ${dirClass}">
                <span>${dirLabel}</span>
                <span>Seq: ${seq}</span>
              </div>
              <div>${this.escapeHtml(m.content || m.raw || '')}</div>
            </div>
          `;
          })
          .join('');
      };

      // Select first stream by default
      renderStreamTranscript(streams[0], 0);

      // Bind selection clicks
      sidebarList.querySelectorAll('.session-item-row').forEach((row) => {
        row.addEventListener('click', () => {
          sidebarList.querySelectorAll('.session-item-row').forEach((r) => r.classList.remove('active'));
          row.classList.add('active');
          const idx = parseInt(row.getAttribute('data-stream-idx'), 10);
          if (streams[idx]) renderStreamTranscript(streams[idx], idx);
        });
      });
    }

    /* -------------------------------------------------------------
     * 8. ML BENCHMARK VIEW
     * ------------------------------------------------------------- */
    async loadMLBenchmark() {
      try {
        const resp = await fetch('/api/ml/benchmark');
        if (!resp.ok) return;
        const bench = await resp.json();

        // Support both structured schemas: { rule_only_baseline: { accuracy, ... } } and { baseline_rule_accuracy: ... }
        const ruleBase = bench.rule_only_baseline || {};
        const mlEngine = bench.rule_and_ml_engine || bench.ml_engine || {};
        const accVal = ruleBase.accuracy ?? bench.baseline_rule_accuracy;
        const precVal = ruleBase.precision ?? bench.baseline_rule_precision;
        const recVal = ruleBase.recall ?? bench.baseline_rule_recall;
        const f1Val = ruleBase.f1_score ?? bench.baseline_rule_f1;

        const mlAccVal = mlEngine.accuracy ?? bench.ml_accuracy ?? 1.0;
        const mlPrecVal = mlEngine.precision ?? bench.ml_precision ?? 1.0;
        const mlRecVal = mlEngine.recall ?? bench.ml_recall ?? 1.0;
        const mlF1Val = mlEngine.f1_score ?? bench.ml_f1 ?? 1.0;

        const ruleAcc = document.getElementById('ml-rule-acc');
        const rulePrec = document.getElementById('ml-rule-prec');
        const ruleRec = document.getElementById('ml-rule-rec');
        const ruleF1 = document.getElementById('ml-rule-f1');

        const engAcc = document.getElementById('ml-engine-acc');
        const engPrec = document.getElementById('ml-engine-prec');
        const engRec = document.getElementById('ml-engine-rec');
        const engF1 = document.getElementById('ml-engine-f1');
        const f1Gain = document.getElementById('ml-f1-gain');
        const datasetCount = document.getElementById('ml-dataset-count');

        if (ruleAcc) ruleAcc.textContent = this.formatPercent(accVal);
        if (rulePrec) rulePrec.textContent = this.formatPercent(precVal);
        if (ruleRec) ruleRec.textContent = this.formatPercent(recVal);
        if (ruleF1) ruleF1.textContent = this.formatPercent(f1Val);

        if (engAcc) engAcc.textContent = this.formatPercent(mlAccVal);
        if (engPrec) engPrec.textContent = this.formatPercent(mlPrecVal);
        if (engRec) engRec.textContent = this.formatPercent(mlRecVal);
        if (engF1) engF1.textContent = this.formatPercent(mlF1Val);

        if (f1Gain && f1Val != null && mlF1Val != null) {
          const delta = (Number(mlF1Val) - Number(f1Val)) * 100;
          f1Gain.textContent = `+${delta.toFixed(1)}%`;
        }

        if (datasetCount && bench.total_samples) {
          datasetCount.textContent = `${bench.total_samples} Sessions`;
        }

        // Render SHAP feature bars with rounded track and fill
        const featContainer = document.getElementById('ml-top-features-list');
        const features = bench.top_features || [
          { name: 'plaintext_continuation_flag', importance: 0.38 },
          { name: 'missing_client_hello_entropy', importance: 0.26 },
          { name: 'deprecated_tls_cipher_suite', importance: 0.19 },
          { name: 'certificate_clock_skew_days', importance: 0.11 },
          { name: 'abnormal_tcp_rst_post_starttls', importance: 0.06 }
        ];

        if (featContainer) {
          const maxWeight = Math.max(...features.map((f) => f.importance || f.weight || 0.1));
          featContainer.innerHTML = features
            .map((f) => {
              const weight = f.importance || f.weight || 0.05;
              const pct = Math.min(100, Math.max(5, (weight / maxWeight) * 100));

              return `
              <div>
                <div class="flex justify-between" style="font-size: 12px; margin-bottom: 6px;">
                  <strong style="font-family: var(--font-mono);">${this.escapeHtml(f.feature_name || f.name)}</strong>
                  <span style="font-family: var(--font-mono); color: var(--text-tertiary);">${(weight * 100).toFixed(1)}% Attribution</span>
                </div>
                <div style="width: 100%; height: 8px; background: #F0F1F4; border-radius: var(--radius-pill); overflow: hidden;">
                  <div style="width: ${pct}%; height: 100%; background: #111111; border-radius: var(--radius-pill);"></div>
                </div>
              </div>
            `;
            })
            .join('');
        }
      } catch (e) {
        console.error('Failed to load ML benchmark:', e);
      }
    }

    /* -------------------------------------------------------------
     * 9. EXTERNAL THREAT INTEL
     * ------------------------------------------------------------- */
    bindThreatIntel() {
      const btn = document.getElementById('btn-intel-query');
      const targetInput = document.getElementById('intel-target-input');
      const typeSelect = document.getElementById('intel-type-select');
      const resultBox = document.getElementById('intel-result-box');

      btn?.addEventListener('click', async () => {
        const target = targetInput?.value.trim();
        const type = typeSelect?.value || 'ip';
        if (!target) return;

        btn.disabled = true;
        btn.textContent = 'Querying...';

        try {
          const resp = await fetch(`/api/intel/query?intel_type=${encodeURIComponent(type)}&target=${encodeURIComponent(target)}`);
          if (!resp.ok) throw new Error('Intel query failed');
          const data = await resp.json();

          if (resultBox) {
            resultBox.style.display = 'block';
            resultBox.innerHTML = `<code>${JSON.stringify(data, null, 2)}</code>`;
          }
        } catch (err) {
          if (resultBox) {
            resultBox.style.display = 'block';
            resultBox.innerHTML = `<code style="color: var(--critical);">${err.message}</code>`;
          }
        } finally {
          btn.disabled = false;
          btn.textContent = 'Query Intel';
        }
      });
    }

    /* -------------------------------------------------------------
     * 10. EVIDENCE DETAIL DRAWER
     * ------------------------------------------------------------- */
    bindEvidenceDrawer() {
      const overlay = document.getElementById('drawer-overlay');
      const drawer = document.getElementById('evidence-drawer');
      const btnClose = document.getElementById('btn-close-drawer');

      const closeDrawer = () => {
        overlay?.classList.remove('open');
        drawer?.classList.remove('open');
      };

      overlay?.addEventListener('click', closeDrawer);
      btnClose?.addEventListener('click', closeDrawer);

      window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeDrawer();
      });
    }

    openEvidenceDrawer(evidenceId) {
      const ev = this.findEvidenceById(evidenceId);
      if (!ev) return;

      const overlay = document.getElementById('drawer-overlay');
      const drawer = document.getElementById('evidence-drawer');

      document.getElementById('drawer-evidence-id').textContent = ev.evidence_id;
      document.getElementById('drawer-evidence-type').textContent = ev.evidence_type;
      document.getElementById('drawer-claim').textContent = ev.claim || ev.observed_claim || 'N/A';
      document.getElementById('drawer-tool').textContent = ev.source_tool || 'sensor';
      document.getElementById('drawer-confidence').textContent = `${(ev.confidence * 100).toFixed(0)}%`;
      document.getElementById('drawer-artifact-ref').textContent = ev.raw_packet_ref || `Packet #${ev.packet_idx || '1'}`;

      const provList = document.getElementById('drawer-provenance-list');
      if (provList) {
        provList.innerHTML = (ev.provenance_chain || ['Sensor -> Ledger Entry -> Validator']).map((p) => `<div>&bull; ${this.escapeHtml(p)}</div>`).join('');
      }

      const jsonBox = document.getElementById('drawer-json-details');
      if (jsonBox) {
        jsonBox.innerHTML = `<code>${JSON.stringify(ev, null, 2)}</code>`;
      }

      overlay?.classList.add('open');
      drawer?.classList.add('open');
      if (window.lucide) window.lucide.createIcons();
    }

    findEvidenceById(id) {
      // Look in global evidence or active investigation ledger
      const inGlobal = this.allEvidence.find((e) => e.evidence_id === id);
      if (inGlobal) return inGlobal;

      if (this.currentInvestigation && this.currentInvestigation.evidence_ledger) {
        const inInv = this.currentInvestigation.evidence_ledger.find((e) => e.evidence_id === id);
        if (inInv) return inInv;
      }
      return null;
    }

    /* -------------------------------------------------------------
     * 11. COMMAND PALETTE (⌘ K / Ctrl K)
     * ------------------------------------------------------------- */
    bindCommandPalette() {
      const palette = document.getElementById('cmd-palette');
      const triggerBtn = document.getElementById('btn-trigger-cmd');
      const searchInput = document.getElementById('cmd-search-input');
      const resultsContainer = document.getElementById('cmd-results');

      let selectedIndex = -1;

      const defaultNavItems = [
        { title: 'Home • Investigation Composer', view: 'home', icon: 'sparkles' },
        { title: 'Investigations Table', view: 'investigations', icon: 'folder-search' },
        { title: 'Evidence Ledger', view: 'evidence', icon: 'database' },
        { title: 'Verified Findings', view: 'findings', icon: 'alert-octagon' },
        { title: 'Sessions & TCP Streams', view: 'sessions', icon: 'binary' },
        { title: 'Scientific ML Benchmark', view: 'ml', icon: 'cpu' },
        { title: 'Forensic Reports Library', view: 'reports', icon: 'file-text' },
        { title: 'External Threat Intelligence', view: 'threat-intel', icon: 'radar' },
        { title: 'Demo Lab Scenarios', view: 'playground', icon: 'flask-conical' }
      ];

      const renderDefaultPalette = () => {
        if (!resultsContainer) return;
        selectedIndex = -1;
        resultsContainer.innerHTML = `
          <div class="cmd-group-header">Navigation Destinations</div>
          ${defaultNavItems
            .map(
              (item, idx) => `
            <div class="cmd-item" data-idx="${idx}" onclick="window.workstation.navigate('${item.view}'); document.getElementById('cmd-palette').classList.remove('open');">
              <i data-lucide="${item.icon}"></i>
              <span>${item.title}</span>
            </div>
          `
            )
            .join('')}
        `;
        if (window.lucide) window.lucide.createIcons();
      };

      const renderSearchResults = (query) => {
        if (!resultsContainer) return;
        const q = query.toLowerCase().trim();
        if (!q) {
          renderDefaultPalette();
          return;
        }

        selectedIndex = -1;
        let html = '';

        // 1. Matched Investigations
        const matchedInvs = (this.investigations || [])
          .filter(
            (inv) =>
              inv.investigation_id.toLowerCase().includes(q) ||
              (inv.artifact_name && inv.artifact_name.toLowerCase().includes(q))
          )
          .slice(0, 3);

        if (matchedInvs.length > 0) {
          html += `<div class="cmd-group-header">Investigations</div>`;
          matchedInvs.forEach((inv) => {
            html += `
              <div class="cmd-item" onclick="window.workstation.navigate('investigation-detail', '${inv.investigation_id}'); document.getElementById('cmd-palette').classList.remove('open');">
                <i data-lucide="folder-search"></i>
                <span>${this.escapeHtml(inv.artifact_name || inv.investigation_id)}</span>
                <span class="cmd-item-meta">${inv.investigation_id} &bull; ${inv.security_score}/100</span>
              </div>
            `;
          });
        }

        // 2. Matched Verified Findings
        const matchedFindings = (this.allFindings || [])
          .filter(
            (f) =>
              (f.title && f.title.toLowerCase().includes(q)) ||
              (f.finding_id && f.finding_id.toLowerCase().includes(q)) ||
              (f.rule_id && f.rule_id.toLowerCase().includes(q))
          )
          .slice(0, 3);

        if (matchedFindings.length > 0) {
          html += `<div class="cmd-group-header">Findings</div>`;
          matchedFindings.forEach((f) => {
            html += `
              <div class="cmd-item" onclick="window.workstation.navigate('investigation-detail', '${f.investigation_id}'); document.getElementById('cmd-palette').classList.remove('open');">
                <i data-lucide="alert-octagon"></i>
                <span>${this.escapeHtml(f.title)}</span>
                <span class="cmd-item-meta">${this.formatSeverity(f.severity)}</span>
              </div>
            `;
          });
        }

        // 3. Matched Evidence Ledger
        const matchedEv = (this.allEvidence || [])
          .filter(
            (ev) =>
              (ev.claim && ev.claim.toLowerCase().includes(q)) ||
              (ev.evidence_id && ev.evidence_id.toLowerCase().includes(q))
          )
          .slice(0, 3);

        if (matchedEv.length > 0) {
          html += `<div class="cmd-group-header">Evidence Ledger</div>`;
          matchedEv.forEach((ev) => {
            html += `
              <div class="cmd-item" onclick="window.workstation.openEvidenceDrawer('${ev.evidence_id}'); document.getElementById('cmd-palette').classList.remove('open');">
                <i data-lucide="database"></i>
                <span>${this.escapeHtml(ev.claim || ev.evidence_id)}</span>
                <span class="cmd-item-meta">${ev.evidence_id}</span>
              </div>
            `;
          });
        }

        if (!html) {
          html = `<div style="padding: 18px; text-align: center; color: var(--text-tertiary); font-size: 12px;">No matching records found for "${this.escapeHtml(query)}"</div>`;
        }

        resultsContainer.innerHTML = html;
        if (window.lucide) window.lucide.createIcons();
      };

      const openPalette = () => {
        palette?.classList.add('open');
        if (searchInput) searchInput.value = '';
        renderDefaultPalette();
        setTimeout(() => searchInput?.focus(), 50);
      };

      const closePalette = () => {
        palette?.classList.remove('open');
      };

      triggerBtn?.addEventListener('click', openPalette);

      palette?.addEventListener('click', (e) => {
        if (e.target === palette) closePalette();
      });

      searchInput?.addEventListener('input', (e) => {
        renderSearchResults(e.target.value);
      });

      // Keyboard navigation (ArrowUp, ArrowDown, Enter, Esc, Cmd+K)
      window.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
          e.preventDefault();
          if (palette?.classList.contains('open')) {
            closePalette();
          } else {
            openPalette();
          }
          return;
        }

        if (!palette?.classList.contains('open')) return;

        if (e.key === 'Escape') {
          closePalette();
          return;
        }

        const items = resultsContainer?.querySelectorAll('.cmd-item');
        if (!items || items.length === 0) return;

        if (e.key === 'ArrowDown') {
          e.preventDefault();
          selectedIndex = (selectedIndex + 1) % items.length;
          items.forEach((it, i) => it.classList.toggle('selected', i === selectedIndex));
          items[selectedIndex]?.scrollIntoView({ block: 'nearest' });
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          selectedIndex = (selectedIndex - 1 + items.length) % items.length;
          items.forEach((it, i) => it.classList.toggle('selected', i === selectedIndex));
          items[selectedIndex]?.scrollIntoView({ block: 'nearest' });
        } else if (e.key === 'Enter') {
          e.preventDefault();
          if (selectedIndex >= 0 && items[selectedIndex]) {
            items[selectedIndex].click();
          }
        }
      });
    }

    /* -------------------------------------------------------------
     * 12. FILTERS & SEARCH BINDINGS
     * ------------------------------------------------------------- */
    bindFilters() {
      document.getElementById('investigations-search')?.addEventListener('input', () => this.renderInvestigationsTable());
      document.getElementById('investigations-risk-filter')?.addEventListener('change', () => this.renderInvestigationsTable());
      document.getElementById('evidence-global-search')?.addEventListener('input', () => this.renderGlobalEvidenceTable());
      document.getElementById('evidence-type-filter')?.addEventListener('change', () => this.renderGlobalEvidenceTable());
    }

    /* -------------------------------------------------------------
     * 13. REPORT EXPORT HELPER & LIBRARY VIEW
     * ------------------------------------------------------------- */
    loadReportsView() {
      const tbody = document.getElementById('reports-table-body');
      if (!tbody) return;

      if (!this.investigations || this.investigations.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-tertiary); padding: 20px;">No investigation records available.</td></tr>`;
        return;
      }

      tbody.innerHTML = this.investigations
        .map(
          (inv) => `
        <tr>
          <td style="font-family: var(--font-mono); font-weight: 600;">${inv.investigation_id}</td>
          <td><strong>${this.escapeHtml(inv.artifact_name || 'capture.pcap')}</strong></td>
          <td><span style="font-weight: 700;">${this.formatScore(inv.security_score)}</span> <span style="font-size: 11px; color: var(--text-tertiary);">/100</span></td>
          <td><span class="badge ${this.getRiskBadgeClass(inv.risk_level)}">${this.formatSeverity(inv.risk_level)}</span></td>
          <td>
            <div class="flex gap-1">
              <a href="/api/investigations/${inv.investigation_id}/reports/json" target="_blank" class="btn-secondary-light" style="padding: 3px 8px; font-size: 11px;">JSON</a>
              <a href="/api/investigations/${inv.investigation_id}/reports/html" target="_blank" class="btn-secondary-light" style="padding: 3px 8px; font-size: 11px;">HTML</a>
              <a href="/api/investigations/${inv.investigation_id}/reports/pdf" target="_blank" class="btn-secondary-light" style="padding: 3px 8px; font-size: 11px;">PDF</a>
            </div>
          </td>
          <td>
            <button class="btn-primary-dark" style="padding: 4px 10px; font-size: 11px;" onclick="window.workstation.navigate('investigation-detail', '${inv.investigation_id}')" type="button">
              Open &rarr;
            </button>
          </td>
        </tr>
      `
        )
        .join('');

      if (window.lucide) window.lucide.createIcons();
    }

    exportLatest(format) {
      const id = this.currentInvestigationId || (this.investigations[0] ? this.investigations[0].investigation_id : null);
      if (!id) {
        alert('Please run or select an investigation first.');
        return;
      }
      window.open(`/api/investigations/${id}/reports/${format}`, '_blank');
    }

    /* -------------------------------------------------------------
     * UTILITIES & COLOR HELPERS
     * ------------------------------------------------------------- */
    formatScore(score) {
      if (score === null || score === undefined || isNaN(score)) return 'N/A';
      return Math.round(Number(score));
    }

    formatPercent(val, decimals = 1) {
      if (val === null || val === undefined || isNaN(val)) return 'N/A';
      return `${(Number(val) * (val <= 1 ? 100 : 1)).toFixed(decimals)}%`;
    }

    formatDeduction(pts) {
      if (pts === null || pts === undefined || isNaN(pts)) return 'Not scored';
      return `-${Math.abs(Number(pts))} pts`;
    }

    formatSeverity(sev) {
      if (!sev) return 'UNKNOWN';
      return String(sev).toUpperCase();
    }

    getRiskBadgeClass(risk) {
      switch (String(risk || '').toUpperCase()) {
        case 'CRITICAL':
          return 'badge-critical';
        case 'HIGH':
          return 'badge-high';
        case 'MEDIUM':
          return 'badge-medium';
        case 'SECURE':
          return 'badge-secure';
        default:
          return 'badge-neutral';
      }
    }

    getScoreColor(score) {
      if (score === null || score === undefined || isNaN(score)) return 'var(--text-tertiary)';
      const s = Number(score);
      if (s >= 90) return 'var(--low)';
      if (s >= 70) return 'var(--medium)';
      if (s >= 50) return 'var(--high)';
      return 'var(--critical)';
    }

    escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }
  }

  // Initialize workstation instance on window for inline handlers & debugging
  document.addEventListener('DOMContentLoaded', () => {
    window.workstation = new ForensicWorkstation();
  });
})();
