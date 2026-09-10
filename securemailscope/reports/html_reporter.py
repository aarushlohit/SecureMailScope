"""
SecureMailScope - Deterministic HTML Forensic Report Generator
"""
from pathlib import Path
from jinja2 import Template
from securemailscope.evidence.ledger import EvidenceLedger

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forensic Report: {{ inv.investigation_id }} - SecureMailScope</title>
  <style>
    :root {
      --bg-main: #0B1120;
      --bg-card: #1E293B;
      --bg-card-alt: #0F172A;
      --accent: #0EA5E9;
      --accent-glow: rgba(14, 165, 233, 0.2);
      --text-main: #F1F5F9;
      --text-muted: #94A3B8;
      --border: #334155;
      --critical: #EF4444;
      --high: #F97316;
      --medium: #EAB308;
      --low: #10B981;
      --secure: #06B6D4;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    body { background: var(--bg-main); color: var(--text-main); line-height: 1.6; padding: 32px 16px; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%); border: 1px solid var(--border); border-radius: 12px; padding: 24px 32px; margin-bottom: 24px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    .header-top { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 16px; }
    .title { font-size: 24px; font-weight: 700; color: #38BDF8; letter-spacing: -0.5px; }
    .subtitle { color: var(--text-muted); font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }
    .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #FCA5A5; border: 1px solid var(--critical); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #FDBA74; border: 1px solid var(--high); }
    .badge-medium { background: rgba(234, 179, 8, 0.2); color: #FDE047; border: 1px solid var(--medium); }
    .badge-low { background: rgba(16, 185, 129, 0.2); color: #6EE7B7; border: 1px solid var(--low); }
    .badge-secure { background: rgba(6, 182, 212, 0.2); color: #67E8F9; border: 1px solid var(--secure); }
    
    .grid-score { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
    .card-title { font-size: 14px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px; font-weight: 600; }
    .score-value { font-size: 38px; font-weight: 800; }
    .score-critical { color: var(--critical); }
    .score-high { color: var(--high); }
    .score-medium { color: var(--medium); }
    .score-secure { color: var(--secure); }
    
    .section-title { font-size: 18px; font-weight: 700; margin: 28px 0 16px 0; color: #E2E8F0; display: flex; align-items: center; gap: 8px; }
    .section-title::before { content: ""; display: inline-block; width: 4px; height: 18px; background: var(--accent); border-radius: 2px; }
    
    table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
    th { background: var(--bg-card-alt); color: var(--text-muted); text-align: left; padding: 12px; border-bottom: 2px solid var(--border); font-weight: 600; }
    td { padding: 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    tr:hover { background: rgba(255,255,255,0.02); }
    
    .timeline-item { position: relative; padding-left: 28px; margin-bottom: 16px; }
    .timeline-item::before { content: ""; position: absolute; left: 6px; top: 6px; width: 10px; height: 10px; border-radius: 50%; background: var(--accent); }
    .timeline-item::after { content: ""; position: absolute; left: 10px; top: 18px; width: 2px; height: calc(100% + 4px); background: var(--border); }
    .timeline-item:last-child::after { display: none; }
    .timeline-actor { font-size: 11px; font-weight: 700; color: var(--accent); text-transform: uppercase; }
    .timeline-time { font-size: 11px; color: var(--text-muted); float: right; }
    .timeline-detail { font-size: 13px; color: var(--text-main); margin-top: 2px; }
    
    .callout { background: rgba(14, 165, 233, 0.1); border-left: 4px solid var(--accent); padding: 14px 18px; border-radius: 0 8px 8px 0; margin-bottom: 16px; font-size: 13px; }
    .callout-warning { background: rgba(249, 115, 22, 0.1); border-left-color: var(--high); }
    .evidence-tag { font-family: monospace; font-size: 11px; background: #334155; padding: 2px 6px; border-radius: 4px; color: #38BDF8; display: inline-block; margin: 2px; }
    code { font-family: monospace; background: #0F172A; padding: 2px 4px; border-radius: 4px; font-size: 12px; color: #E2E8F0; }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div class="header">
      <div class="header-top">
        <div>
          <div class="title">SecureMailScope Forensic Dossier</div>
          <div class="subtitle">SIH26159 | National Technical Research Organisation (NTRO)</div>
        </div>
        <div>
          <span class="badge badge-{{ inv.posture.risk_level.split()[0].lower() if inv.posture else 'medium' }}">
            {{ inv.posture.risk_level if inv.posture else 'PENDING' }}
          </span>
        </div>
      </div>
      <div style="display: flex; gap: 24px; flex-wrap: wrap; font-size: 13px; color: var(--text-muted);">
        <div><strong>Investigation ID:</strong> <code>{{ inv.investigation_id }}</code></div>
        <div><strong>Artifact:</strong> <code>{{ inv.artifact_name }}</code></div>
        <div><strong>SHA-256:</strong> <code>{{ inv.artifact_sha256[:20] }}...</code></div>
        <div><strong>Packets:</strong> {{ inv.packet_count }}</div>
        <div><strong>Generated:</strong> {{ inv.created_at }}</div>
      </div>
    </div>

    <!-- Posture Metrics -->
    <div class="grid-score">
      <div class="card">
        <div class="card-title">Security Posture Score</div>
        <div class="score-value score-{{ inv.posture.risk_level.split()[0].lower() if inv.posture else 'medium' }}">
          {{ inv.posture.overall_posture_score if inv.posture else '--' }}<span style="font-size: 18px; color: var(--text-muted);">/100</span>
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Explainable Rule + ML Metric</div>
      </div>

      <div class="card">
        <div class="card-title">Capture Completeness</div>
        <div class="score-value" style="color: {{ '#10B981' if inv.completeness_percentage >= 95 else ('#EAB308' if inv.completeness_percentage >= 60 else '#EF4444') }};">
          {{ inv.completeness_percentage }}%
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">{{ 'Full Capture Integrity' if inv.completeness_percentage >= 95 else 'Sequence Gaps Detected' }}</div>
      </div>

      <div class="card">
        <div class="card-title">Forensic Confidence</div>
        <div class="score-value" style="color: #38BDF8;">
          {{ inv.posture.confidence_score if inv.posture else '--' }}%
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Evidence Chain Completeness</div>
      </div>

      <div class="card">
        <div class="card-title">ML Risk Probability</div>
        <div class="score-value" style="color: {{ '#EF4444' if inv.posture.ml_risk_probability > 0.5 else '#10B981' }};">
          {{ (inv.posture.ml_risk_probability * 100)|round(1) if inv.posture else '--' }}%
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">XGBoost Anomaly Classification</div>
      </div>
    </div>

    <!-- Score Deductions Breakdown -->
    {% if inv.posture and inv.posture.score_deductions %}
    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">Score Deductions & Attributions</div>
      <table>
        <thead>
          <tr>
            <th>Attribution Source</th>
            <th>Deduction</th>
            <th>Reasoning / Observed Fact</th>
          </tr>
        </thead>
        <tbody>
          {% for d in inv.posture.score_deductions %}
          <tr>
            <td><strong>{{ d.source }}</strong></td>
            <td style="color: var(--critical); font-weight: 700;">{{ d.points }} pts</td>
            <td>{{ d.reason }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    <!-- Verified Findings -->
    <div class="section-title">Verified Findings (No Evidence &rarr; No Finding Gate)</div>
    {% if findings %}
      <div style="display: flex; flex-direction: column; gap: 12px;">
        {% for f in findings %}
        <div class="card" style="border-left: 4px solid {{ 'var(--critical)' if f.severity.value == 'critical' else ('var(--high)' if f.severity.value == 'high' else 'var(--medium)') }};">
          <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <div>
              <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span>
              <strong style="font-size: 16px; margin-left: 8px;">{{ f.title }}</strong>
            </div>
            <div style="font-size: 12px; color: #38BDF8; font-weight: 600;">Status: {{ f.status.value }}</div>
          </div>
          <p style="margin: 12px 0; font-size: 14px; color: var(--text-muted);">{{ f.description }}</p>
          {% if f.remediation %}
          <div style="font-size: 13px; background: rgba(0,0,0,0.2); padding: 8px 12px; border-radius: 6px; margin-bottom: 12px;">
            <strong style="color: #6EE7B7;">Remediation:</strong> {{ f.remediation }}
          </div>
          {% endif %}
          <div style="font-size: 12px; color: var(--text-muted);">
            <strong>Supporting Evidence:</strong>
            {% for eid in f.evidence_ids %}
            <span class="evidence-tag">{{ eid }}</span>
            {% endfor %}
          </div>
        </div>
        {% endfor %}
      </div>
    {% else %}
      <div class="callout">No cryptographic vulnerabilities or anomalies observed. Session conforms to baseline security policies.</div>
    {% endif %}

    <!-- Adaptive Agent Hypotheses & Timeline -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 28px;">
      <!-- Hypotheses -->
      <div class="card">
        <div class="card-title">Agent Hypotheses & Evidence Support</div>
        {% for h in hypotheses %}
        <div style="margin-bottom: 16px; padding-bottom: 16px; border-bottom: 1px solid var(--border);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong style="font-size: 14px; color: #38BDF8;">{{ h.title }}</strong>
            <span class="badge badge-{{ 'secure' if h.status.value == 'CONFIRMED' else ('critical' if h.status.value == 'REFUTED' else 'medium') }}">
              {{ h.status.value }}
            </span>
          </div>
          <p style="font-size: 13px; color: var(--text-muted); margin: 6px 0;">{{ h.description }}</p>
          {% if h.notes %}
          <div style="font-size: 12px; color: #E2E8F0;">
            {% for n in h.notes %}
            <div>&bull; {{ n }}</div>
            {% endfor %}
          </div>
          {% endif %}
        </div>
        {% endfor %}
      </div>

      <!-- Timeline -->
      <div class="card">
        <div class="card-title">Investigation Execution Timeline</div>
        <div style="max-height: 400px; overflow-y: auto; padding-right: 8px;">
          {% for ev in timeline %}
          <div class="timeline-item">
            <div class="timeline-actor">{{ ev.actor }} &bull; {{ ev.phase }}</div>
            <div class="timeline-detail">{{ ev.detail }}</div>
          </div>
          {% endfor %}
        </div>
      </div>
    </div>

    <!-- Evidence Ledger Table -->
    <div class="section-title">Evidence Ledger (Immutable Ground Truth)</div>
    <div class="card" style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Claim / Observed Fact</th>
            <th>Tool Source</th>
            <th>Confidence</th>
            <th>Provenance Ref</th>
          </tr>
        </thead>
        <tbody>
          {% for e in evidence %}
          <tr>
            <td><span class="evidence-tag">{{ e.evidence_id }}</span></td>
            <td><code>{{ e.type.value }}</code></td>
            <td style="color: #F8FAFC;">{{ e.claim }}</td>
            <td>{{ e.source_tool }}</td>
            <td>{{ (e.confidence * 100)|round(0) }}%</td>
            <td><code>{{ e.raw_artifact_ref }}</code></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <!-- Forensic Limitations -->
    {% if inv.limitations %}
    <div class="section-title">Forensic Limitations & Caveats</div>
    <div class="card">
      <ul style="padding-left: 20px; font-size: 13px; color: var(--text-muted);">
        {% for l in inv.limitations %}
        <li style="margin-bottom: 6px;">{{ l }}</li>
        {% endfor %}
      </ul>
    </div>
    {% endif %}

  </div>
</body>
</html>
"""


class HTMLReporter:
    """
    Renders an interactive, standalone HTML forensic dossier for analysts.
    """

    @staticmethod
    def generate_report(investigation_id: str, ledger: EvidenceLedger, output_path: Path) -> Path:
        inv = ledger.get_investigation(investigation_id)
        if not inv:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        evidence = ledger.get_evidence_for_investigation(investigation_id)
        hypotheses = ledger.get_hypotheses_for_investigation(investigation_id)
        findings = ledger.get_findings_for_investigation(investigation_id)
        timeline = ledger.get_timeline(investigation_id)

        template = Template(HTML_TEMPLATE)
        rendered_html = template.render(
            inv=inv,
            evidence=evidence,
            hypotheses=hypotheses,
            findings=findings,
            timeline=timeline
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        return output_path
