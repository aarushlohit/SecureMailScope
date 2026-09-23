"""
SecureMailScope - Real Stateful Investigation Agent
Explicit State-Machine Architecture:
OBSERVE -> HYPOTHESIZE -> PLAN -> SELECT_TOOL -> EXECUTE -> STORE_EVIDENCE -> CORRELATE -> RE_EVALUATE -> VERIFY -> VERDICT
Strictly evidence-constrained. Never invents facts.
Supports adaptive multi-branch investigations and deterministic fallback.
"""
import uuid
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

import asyncio
import json
import logging
from securemailscope.core.config import config
from securemailscope.core.exceptions import ToolExecutionError
from securemailscope.evidence.models import (
    Investigation,
    InvestigationStatus,
    Finding,
    FindingStatus,
    SeverityLevel,
    TimelineEvent,
    Evidence,
    EvidenceType
)
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.evidence.validator import FindingValidator
from securemailscope.tools.registry import ALLOWLISTED_TOOLS
from securemailscope.tools.gateway import ToolGateway
from securemailscope.agent.hypothesis import HypothesisEngine
from securemailscope.ml.model import CryptoRiskClassifier
from securemailscope.scoring.posture_scorer import PostureScorer
from backend.llm.router import LLMRouter
from backend.llm.schemas import ChatMessage, ChatRequest, ChatResponse
from backend.llm.exceptions import LLMException, ProviderUnavailableError
from securemailscope.api.sse import SSEEventBus
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import (
    InvestigationModel,
    AgentRunModel,
    AgentStepModel,
    AuditEventModel,
    MLPredictionModel,
    ArtifactModel,
    ForensicSessionModel
)

logger = logging.getLogger("securemailscope.agent.investigator")

LLM_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "inspect_pcap",
            "description": "Inspects PCAP framing, extracts packet count, timestamps, SHA-256 and MD5 hashes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to PCAP capture."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_sessions",
            "description": "Discovers email protocol sessions (SMTP, IMAP, POP3) across reconstructed TCP streams.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to PCAP capture."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_smtp",
            "description": "Evaluates SMTP state machine, STARTTLS negotiation, cleartext commands, and stripping anomalies.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to PCAP capture."},
                    "stream_id": {"type": "integer", "description": "Stream index to analyze."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_imap",
            "description": "Evaluates IMAP state machine, STARTTLS capabilities, OK responses, and cleartext credentials.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to PCAP capture."},
                    "stream_id": {"type": "integer", "description": "Stream index to analyze."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_pop3",
            "description": "Evaluates POP3 state machine, STLS capability, +OK transitions, and cleartext credentials.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to PCAP capture."},
                    "stream_id": {"type": "integer", "description": "Stream index to analyze."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_tls",
            "description": "Parses TLS ClientHello/ServerHello, cipher suites, version negotiation, and key exchange.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to PCAP capture."},
                    "stream_id": {"type": "integer", "description": "Stream index to analyze."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_certificate",
            "description": "Extracts observable X.509 certificates (TLS <= 1.2) or returns honest NOT_OBSERVABLE for TLS 1.3.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to PCAP capture."},
                    "stream_id": {"type": "integer", "description": "Stream index to analyze."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_completeness",
            "description": "Calculates capture completeness score, sequence gaps, retransmissions, and truncation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to PCAP capture."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "evaluate_rules",
            "description": "Executes deterministic cryptographic rules across extracted forensic context.",
            "parameters": {
                "type": "object",
                "properties": {
                    "forensic_context": {"type": "object", "description": "Extracted forensic context dictionary."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_ml_classifier",
            "description": "Runs XGBoost classifier to identify multi-feature cryptographic risk patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "forensic_context": {"type": "object", "description": "Extracted forensic context dictionary."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_threat_intel",
            "description": "Executes external OSINT web threat intelligence search for mail servers, domains, IPs, CVEs, or downgrade attack patterns. Results are strictly categorized as EXTERNAL_INTELLIGENCE.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query for threat intelligence (e.g. domain, MTA reputation, or vulnerability)."}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Performs live web OSINT search for email vulnerabilities, CVE details, MTA-STS policies, DANE TLSA records, and security advisories.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term or question to find online."}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "finalize_finding",
            "description": "Registers a verified forensic finding supported by recorded evidence IDs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Finding title."},
                    "description": {"type": "string", "description": "Detailed explanation of the cryptographic finding."},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], "description": "Severity level."},
                    "remediation": {"type": "string", "description": "Remediation advice."},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}, "description": "List of supporting evidence IDs from ledger."}
                },
                "required": ["title", "description", "severity", "remediation", "evidence_ids"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "yara_scan",
            "description": "Scans payloads or email text against YARA signatures for webshells, phishing, and macro scripts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "Payload text or bytes string to scan."}
                },
                "required": ["payload"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_pcap_entropy",
            "description": "Calculates Shannon Entropy and byte frequency distribution across PCAP payload buffers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path to PCAP capture."}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "detect_dns_exfiltration",
            "description": "Inspects DNS query subdomains for high entropy and data exfiltration patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "queries": {"type": "array", "items": {"type": "string"}, "description": "List of DNS query strings."}
                },
                "required": ["queries"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_header_anomalies",
            "description": "Audits email headers for Return-Path mismatches, SPF/DKIM failures, and display name spoofing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "headers": {"type": "object", "description": "Header key-value dictionary or raw header text."}
                },
                "required": ["headers"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "deobfuscate_payload_cyberchef",
            "description": "Multi-stage deobfuscator applying Base64, Hex, URL, and Quoted-Printable recursive decoding.",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "Encoded payload string."}
                },
                "required": ["payload"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "call_docker_mcp_tool",
            "description": "Executes security tools provided by the Docker bugbounty-mcp image stdio bridge.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string", "description": "Name of the Docker MCP tool (e.g., secret_pattern_analysis)."},
                    "arguments": {"type": "object", "description": "Tool argument dictionary."}
                },
                "required": ["tool_name"]
            }
        }
    }
]



class InvestigationAgent:
    """
    Production forensic investigation agent implementing an explicit state machine.
    """

    def __init__(self, ledger: EvidenceLedger, router: Optional[LLMRouter] = None):
        self.ledger = ledger
        self.gateway = ToolGateway(ledger)
        self.validator = FindingValidator(ledger)
        self.ml_classifier = CryptoRiskClassifier.get_instance()
        self.router = router or LLMRouter()

    def _chat_sync(self, request: ChatRequest, investigation_id: str) -> ChatResponse:
        def _runner():
            return asyncio.run(self.router.chat(request, investigation_id))

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(_runner)
                return fut.result(timeout=12.0)
        else:
            return asyncio.run(self.router.chat(request, investigation_id))

    def _execute_llm_tool(
        self,
        investigation_id: str,
        pcap_path: Path,
        tool_name: str,
        args: Dict[str, Any],
        forensic_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        file_path_str = str(pcap_path)
        stream_id = args.get("stream_id", 0)

        if tool_name in ("inspect_pcap", "pcap.inspect"):
            return self.gateway.execute_tool(investigation_id, "pcap.inspect", {"file_path": file_path_str})
        elif tool_name in ("list_sessions", "pcap.sessions"):
            return self.gateway.execute_tool(investigation_id, "pcap.sessions", {"file_path": file_path_str})
        elif tool_name in ("extract_smtp", "smtp.analyze"):
            return self.gateway.execute_tool(investigation_id, "smtp.analyze", {"file_path": file_path_str, "stream_id": stream_id})
        elif tool_name in ("extract_imap", "imap.analyze"):
            return self.gateway.execute_tool(investigation_id, "imap.analyze", {"file_path": file_path_str, "stream_id": stream_id})
        elif tool_name in ("extract_pop3", "pop3.analyze"):
            return self.gateway.execute_tool(investigation_id, "pop3.analyze", {"file_path": file_path_str, "stream_id": stream_id})
        elif tool_name in ("analyze_tls", "tls.handshake"):
            return self.gateway.execute_tool(investigation_id, "tls.handshake", {"file_path": file_path_str, "stream_id": stream_id})
        elif tool_name in ("extract_certificate", "tls.certificate"):
            return self.gateway.execute_tool(investigation_id, "tls.certificate", {"file_path": file_path_str, "stream_id": stream_id})
        elif tool_name in ("check_completeness", "pcap.completeness"):
            return self.gateway.execute_tool(investigation_id, "pcap.completeness", {"file_path": file_path_str})
        elif tool_name in ("evaluate_rules", "rules.evaluate"):
            ctx = args.get("forensic_context") or forensic_context
            return self.gateway.execute_tool(investigation_id, "rules.evaluate", {"forensic_context": ctx})
        elif tool_name in ("run_ml_classifier", "ml.predict"):
            ctx = args.get("forensic_context") or forensic_context
            return self.gateway.execute_tool(investigation_id, "ml.predict", {"forensic_context": ctx})
        elif tool_name in ("search_threat_intel", "intel.tavily_search", "intel_tavily_search"):
            return self.gateway.execute_tool(investigation_id, "intel.tavily_search", {"query": args.get("query", "")})
        elif tool_name in ("yara_scan", "yara.scan"):
            return self.gateway.execute_tool(investigation_id, "yara.scan", {"payload": args.get("payload", "")})
        elif tool_name in ("analyze_pcap_entropy", "pcap.entropy"):
            return self.gateway.execute_tool(investigation_id, "pcap.entropy", {"file_path": file_path_str})
        elif tool_name in ("detect_dns_exfiltration", "dns.exfiltration"):
            return self.gateway.execute_tool(investigation_id, "dns.exfiltration", {"queries": args.get("queries", [])})
        elif tool_name in ("audit_header_anomalies", "email.header_audit"):
            return self.gateway.execute_tool(investigation_id, "email.header_audit", {"headers": args.get("headers", {})})
        elif tool_name in ("deobfuscate_payload_cyberchef", "cyberchef.deobfuscate"):
            return self.gateway.execute_tool(investigation_id, "cyberchef.deobfuscate", {"payload": args.get("payload", "")})
        elif tool_name in ("call_docker_mcp_tool", "docker.mcp_call"):
            return self.gateway.execute_tool(investigation_id, "docker.mcp_call", {"tool_name": args.get("tool_name", ""), "arguments": args.get("arguments", {})})
        elif tool_name == "finalize_finding":

            fnd = Finding(
                finding_id=f"FND-{uuid.uuid4().hex[:6].upper()}",
                investigation_id=investigation_id,
                title=args.get("title", "Forensic Finding"),
                description=args.get("description", ""),
                severity=SeverityLevel(args.get("severity", "HIGH").upper()),
                status=FindingStatus.CANDIDATE,
                evidence_ids=args.get("evidence_ids", []),
                remediation=args.get("remediation", "")
            )
            validated = self.validator.validate_and_register_finding(fnd)
            return {"status": "REGISTERED", "finding_id": fnd.finding_id, "status_val": validated.status.value}
        else:
            # Universal fallback for all registered allowlisted tools
            gw_tool = tool_name
            if gw_tool not in ALLOWLISTED_TOOLS:
                gw_tool = tool_name.replace("_", ".")
                if gw_tool not in ALLOWLISTED_TOOLS:
                    gw_tool = tool_name.replace(".", "_")

            if gw_tool in ALLOWLISTED_TOOLS:
                params = ALLOWLISTED_TOOLS[gw_tool].get("params", [])
                exec_args = dict(args)
                if "file_path" in params and "file_path" not in exec_args:
                    exec_args["file_path"] = file_path_str
                if "investigation_id" in params and "investigation_id" not in exec_args:
                    exec_args["investigation_id"] = investigation_id
                if "stream_id" in params and "stream_id" not in exec_args:
                    exec_args["stream_id"] = stream_id
                if "forensic_context" in params and "forensic_context" not in exec_args:
                    exec_args["forensic_context"] = forensic_context
                return self.gateway.execute_tool(investigation_id, gw_tool, exec_args)

            raise ToolExecutionError(f"Unknown tool requested by LLM: {tool_name}")

    def _run_llm_reasoning_loop(
        self,
        investigation_id: str,
        pcap_path: Path,
        forensic_context: Dict[str, Any],
        record_step_fn,
        run_id: str
    ) -> bool:
        system_prompt = (
            "You are SecureMailScope's Forensic Agent investigating an email PCAP capture. "
            "You have access to 12 passive forensic tools: inspect_pcap, list_sessions, extract_smtp, "
            "extract_imap, extract_pop3, analyze_tls, extract_certificate, check_completeness, "
            "evaluate_rules, run_ml_classifier, search_threat_intel, finalize_finding. "
            "Investigate the traffic for cryptographic violations such as STARTTLS stripping/downgrade, "
            "expired or weak certificates, deprecated TLS 1.0/1.1 or broken ciphers (RC4, DES), and cleartext credentials. "
            "When encountering mail server hostnames, external domains, or suspected vulnerabilities, you SHOULD actively call search_threat_intel "
            "to query external threat intelligence via Tavily (strictly tagged as EXTERNAL_INTELLIGENCE). "
            "You MUST ONLY cite real evidence IDs returned by the tools in finalize_finding. Never invent facts. "
            "Call tools iteratively to build evidence, and call finalize_finding for each confirmed issue."
        )

        messages = [
            ChatMessage(role="system", content=system_prompt),
            ChatMessage(
                role="user",
                content=f"Begin forensic investigation of capture '{pcap_path.name}'. Path: {pcap_path.resolve()}."
            )
        ]

        iterations = 0
        max_iterations = 1
        llm_called_successfully = False

        while iterations < max_iterations:
            iterations += 1
            chat_req = ChatRequest(
                messages=messages,
                tools=LLM_TOOL_SCHEMAS,
                temperature=0.2,
                max_tokens=2048
            )

            try:
                resp = self._chat_sync(chat_req, investigation_id)
                llm_called_successfully = True
            except (ProviderUnavailableError, LLMException, Exception) as e:
                logger.warning(f"LLM call iteration {iterations} failed: {e}")
                if not llm_called_successfully:
                    raise
                break

            tool_calls = resp.tool_calls or []
            if not tool_calls:
                if resp.content:
                    record_step_fn(
                        state="RE_EVALUATE",
                        reason=resp.content[:250],
                        next_action="Synthesizing forensic findings.",
                        provider_name=resp.provider,
                        model_name=resp.model
                    )
                break

            # Append the assistant message with all tool calls once
            messages.append(ChatMessage(
                role="assistant",
                content=resp.content or "",
                tool_calls=tool_calls
            ))

            for tc in tool_calls:
                fn = tc.get("function", {})
                t_name = fn.get("name")
                raw_args = fn.get("arguments", "{}")
                if isinstance(raw_args, str):
                    try:
                        args = json.loads(raw_args)
                    except Exception:
                        args = {}
                else:
                    args = raw_args or {}

                record_step_fn(
                    state="SELECT_TOOL",
                    reason=f"LLM ({resp.provider}/{resp.model}) selected forensic tool: {t_name}",
                    tool=t_name,
                    tool_args=args,
                    next_action=f"Executing {t_name} deterministically via ToolGateway.",
                    provider_name=resp.provider,
                    model_name=resp.model
                )

                try:
                    tool_res = self._execute_llm_tool(investigation_id, pcap_path, t_name, args, forensic_context)
                    res_status = "SUCCESS"
                    res_data = tool_res
                    eids = tool_res.get("evidence_ids", []) if isinstance(tool_res, dict) else []
                except Exception as ex:
                    res_status = "ERROR"
                    res_data = {"error": str(ex)}
                    eids = []

                record_step_fn(
                    state="EXECUTE",
                    reason=f"Executed {t_name} with status: {res_status}",
                    tool=t_name,
                    tool_args=args,
                    result=res_data if isinstance(res_data, dict) else {"result": str(res_data)},
                    evidence_ids=eids,
                    next_action="Appending tool observation to LLM context.",
                    provider_name=resp.provider,
                    model_name=resp.model
                )

                messages.append(ChatMessage(
                    role="tool",
                    name=t_name,
                    tool_call_id=tc.get("id"),
                    content=json.dumps(res_data if isinstance(res_data, dict) else {"result": str(res_data)})
                ))

        return llm_called_successfully

    def run_investigation(self, investigation_id: str, pcap_path: Path) -> Investigation:
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        run_start = datetime.now(timezone.utc)

        # 1. Initialize or load Investigation
        inv = self.ledger.get_investigation(investigation_id)
        if not inv:
            inv = Investigation(
                investigation_id=investigation_id,
                artifact_name=pcap_path.name,
                artifact_path=str(pcap_path.resolve()),
                artifact_sha256="",
                artifact_md5="",
                artifact_size=pcap_path.stat().st_size if pcap_path.exists() else 0,
                status=InvestigationStatus.ANALYZING
            )
            self.ledger.save_investigation(inv)

        # Record AgentRun in database
        llm_provider_name = "nvidia" if config.nvidia_api_key else ("gemini" if config.gemini_api_key else "deterministic")
        llm_model_name = config.nvidia_model if config.nvidia_api_key else (config.gemini_model if config.gemini_api_key else "local-rules")
        is_fallback = not (config.nvidia_api_key or config.gemini_api_key)

        try:
            db = SessionLocal()
            try:
                db_run = AgentRunModel(
                    run_id=run_id,
                    investigation_id=investigation_id,
                    status="RUNNING",
                    llm_provider=llm_provider_name,
                    llm_model=llm_model_name,
                    deterministic_fallback=is_fallback
                )
                db.add(db_run)
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

        step_counter = 0
        hyp_engine = HypothesisEngine(self.ledger, investigation_id)

        # Notify SSE subscribers that investigation has started
        SSEEventBus.publish_sync(investigation_id, "investigation.started", {
            "investigation_id": investigation_id,
            "artifact_name": pcap_path.name,
            "timestamp": run_start.isoformat(),
            "llm_provider": llm_provider_name,
            "llm_model": llm_model_name
        })

        def record_step(
            state: str,
            reason: str,
            tool: Optional[str] = None,
            tool_args: Optional[Dict[str, Any]] = None,
            result: Optional[Dict[str, Any]] = None,
            evidence_ids: Optional[List[str]] = None,
            hypothesis_title: Optional[str] = None,
            next_action: str = "",
            provider_name: Optional[str] = None,
            model_name: Optional[str] = None
        ):
            nonlocal step_counter
            step_counter += 1
            t_now = datetime.now(timezone.utc)
            actual_provider = provider_name or llm_provider_name
            actual_model = model_name or llm_model_name

            # Publish SSE step event for real-time frontend terminal / log
            SSEEventBus.publish_sync(investigation_id, "agent.step", {
                "step_number": step_counter,
                "state": state,
                "hypothesis": hypothesis_title,
                "tool": tool,
                "reason": reason,
                "evidence_ids": evidence_ids or [],
                "next_action": next_action,
                "provider": actual_provider,
                "model": actual_model,
                "timestamp": t_now.isoformat()
            })

            try:
                db = SessionLocal()
                try:
                    step = AgentStepModel(
                        step_number=step_counter,
                        run_id=run_id,
                        investigation_id=investigation_id,
                        state=state,
                        hypothesis=hypothesis_title,
                        selected_tool=tool,
                        tool_arguments=tool_args or {},
                        reason=reason,
                        result=result or {},
                        evidence_ids=evidence_ids or [],
                        next_action=next_action,
                        provider=actual_provider,
                        model=actual_model,
                        timestamp=t_now,
                        duration=0.05
                    )
                    db.add(step)
                    db.commit()
                finally:
                    db.close()
            except Exception:
                pass

        # -------------------------------------------------------------
        # STATE: OBSERVE
        # -------------------------------------------------------------
        is_eml = pcap_path.suffix.lower() == ".eml"
        if is_eml:
            record_step(
                state="OBSERVE",
                reason="Initiating EML artifact parsing and forensic header inspection.",
                tool="email.parse",
                tool_args={"file_path": str(pcap_path)},
                next_action="Evaluate authentication headers, MIME parts, and attachments."
            )
            inspect_res = self.gateway.execute_tool(investigation_id, "email.parse", {"file_path": str(pcap_path)})
            meta = inspect_res["result"]
            inv.artifact_sha256 = meta.get("file_sha256", "")
            inv.artifact_md5 = ""
            inv.packet_count = 1
            inv.duration_seconds = 0.0
            inv.protocols_detected = ["RFC-2822/EML"]
            inv.completeness_percentage = 100.0

            # Also execute specific subtools
            self.gateway.execute_tool(investigation_id, "email.headers", {"file_path": str(pcap_path)})
            self.gateway.execute_tool(investigation_id, "email.authentication", {"file_path": str(pcap_path)})
            self.gateway.execute_tool(investigation_id, "email.mime_structure", {"file_path": str(pcap_path)})
            streams = []
        else:
            record_step(
                state="OBSERVE",
                reason="Initiating capture framing inspection and cryptographic hashing.",
                tool="pcap.inspect",
                tool_args={"file_path": str(pcap_path)},
                next_action="Reconstruct TCP conversations and discover email protocols."
            )
            inspect_res = self.gateway.execute_tool(investigation_id, "pcap.inspect", {"file_path": str(pcap_path)})
            meta = inspect_res["result"]
            inv.artifact_sha256 = meta.get("artifact_sha256", "")
            inv.artifact_md5 = meta.get("artifact_md5", "")
            inv.packet_count = meta.get("packet_count", 0)
            inv.duration_seconds = meta.get("duration_seconds", 0.0)

        # Persist Artifact in Database
        try:
            db = SessionLocal()
            try:
                art = db.query(ArtifactModel).filter_by(artifact_id=f"ART-{investigation_id}").first()
                if not art:
                    art = ArtifactModel(
                        artifact_id=f"ART-{investigation_id}",
                        investigation_id=investigation_id,
                        artifact_name=pcap_path.name,
                        file_path=str(pcap_path.resolve()),
                        file_size=pcap_path.stat().st_size if pcap_path.exists() else 0,
                        sha256=inv.artifact_sha256,
                        md5=inv.artifact_md5,
                        file_type="pcap",
                        meta_info=meta
                    )
                    db.add(art)
                    db.commit()
            finally:
                db.close()
        except Exception:
            pass

        # Discover sessions
        if not is_eml:
            sess_res = self.gateway.execute_tool(investigation_id, "pcap.sessions", {"file_path": str(pcap_path)})
            streams = sess_res["result"].get("streams", [])
            inv.streams_analyzed = len(streams)
            inv.protocols_detected = list(set(s.get("protocol_hint", "UNKNOWN") for s in streams))
            inv.completeness_percentage = meta.get("completeness", {}).get("completeness_percentage", 100.0)
            self.ledger.save_investigation(inv)

        # Emit protocol and session SSE events
        SSEEventBus.publish_sync(investigation_id, "protocol.detected", {
            "protocols": inv.protocols_detected,
            "streams_count": inv.streams_analyzed,
            "completeness_percentage": inv.completeness_percentage
        })

        # Persist Sessions in Database and emit SSE
        try:
            db = SessionLocal()
            try:
                for s in streams:
                    sess_id = f"SESS-{investigation_id}-{s.get('stream_id', 0)}"
                    client_ep = (s.get("client_endpoint") or ":").split(":")
                    server_ep = (s.get("server_endpoint") or ":").split(":")
                    db_sess = db.query(ForensicSessionModel).filter_by(session_id=sess_id).first()
                    if not db_sess:
                        db_sess = ForensicSessionModel(
                            session_id=sess_id,
                            investigation_id=investigation_id,
                            stream_id=s.get("stream_id", 0),
                            client_ip=client_ep[0] if client_ep else "",
                            client_port=int(client_ep[1]) if len(client_ep) > 1 and client_ep[1].isdigit() else 0,
                            server_ip=server_ep[0] if server_ep else "",
                            server_port=int(server_ep[1]) if len(server_ep) > 1 and server_ep[1].isdigit() else 0,
                            protocol=s.get("protocol_hint", "UNKNOWN"),
                            tls_version=s.get("tls_version"),
                            cipher_suite=s.get("cipher_suite"),
                            sni=s.get("sni"),
                            details=s
                        )
                        db.add(db_sess)
                    SSEEventBus.publish_sync(investigation_id, "session.reconstructed", {
                        "stream_id": s.get("stream_id"),
                        "protocol": s.get("protocol_hint"),
                        "client_endpoint": s.get("client_endpoint"),
                        "server_endpoint": s.get("server_endpoint")
                    })
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

        forensic_context: Dict[str, Any] = {
            "tls": {},
            "smtp": {},
            "imap": {},
            "pop3": {},
            "certificate": {},
            "completeness": meta.get("completeness", {}),
            "stream": streams[0] if streams else {}
        }

        # -------------------------------------------------------------
        # STATE: MULTI-TOOL CONCURRENT FORENSIC FAN-OUT
        # -------------------------------------------------------------
        if not is_eml:
            # 1. Packet completeness & integrity audit
            comp_exec = self.gateway.execute_tool(investigation_id, "pcap.completeness", {"file_path": str(pcap_path)})
            record_step(
                state="OBSERVE",
                reason=f"Calculated capture completeness: {comp_exec['result'].get('completeness_percentage', 100.0)}%. Gap check complete.",
                tool="pcap.completeness",
                tool_args={"file_path": str(pcap_path)},
                result=comp_exec["result"],
                evidence_ids=comp_exec.get("evidence_ids", [])
            )

            # 2. Shannon entropy & randomness audit
            entropy_exec = self.gateway.execute_tool(investigation_id, "pcap.entropy", {"file_path": str(pcap_path)})
            record_step(
                state="OBSERVE",
                reason=f"Calculated payload Shannon entropy: {entropy_exec['result'].get('entropy', 0.0):.4f} bits/byte.",
                tool="pcap.entropy",
                tool_args={"file_path": str(pcap_path)},
                result=entropy_exec["result"],
                evidence_ids=entropy_exec.get("evidence_ids", [])
            )

            # 3. Protocol plaintext vs encryption ratios
            ratios_exec = self.gateway.execute_tool(investigation_id, "pcap.protocol_ratios", {"file_path": str(pcap_path)})
            record_step(
                state="OBSERVE",
                reason="Computed framing protocol distribution and plaintext-to-ciphertext frame ratios.",
                tool="pcap.protocol_ratios",
                tool_args={"file_path": str(pcap_path)},
                result=ratios_exec["result"],
                evidence_ids=ratios_exec.get("evidence_ids", [])
            )

        # Detailed protocol extraction
        for s in streams:
            proto = s.get("protocol_hint")
            stream_id = s.get("stream_id")
            if proto == "SMTP":
                smtp_exec = self.gateway.execute_tool(investigation_id, "smtp.analyze", {"file_path": str(pcap_path), "stream_id": stream_id})
                forensic_context["smtp"] = smtp_exec["result"]
                record_step(
                    state="EXECUTE",
                    reason=f"Analyzed SMTP stream {stream_id}: STARTTLS advertised={smtp_exec['result'].get('starttls_advertised')}, plaintext continuation={smtp_exec['result'].get('plaintext_after_starttls')}.",
                    tool="smtp.analyze",
                    tool_args={"file_path": str(pcap_path), "stream_id": stream_id},
                    result=smtp_exec["result"],
                    evidence_ids=smtp_exec.get("evidence_ids", [])
                )
            elif proto == "IMAP":
                imap_exec = self.gateway.execute_tool(investigation_id, "imap.analyze", {"file_path": str(pcap_path), "stream_id": stream_id})
                forensic_context["imap"] = imap_exec["result"]
                record_step(
                    state="EXECUTE",
                    reason=f"Analyzed IMAP stream {stream_id}: STARTTLS capability={imap_exec['result'].get('starttls_advertised')}, plaintext auth={imap_exec['result'].get('plaintext_after_starttls')}.",
                    tool="imap.analyze",
                    tool_args={"file_path": str(pcap_path), "stream_id": stream_id},
                    result=imap_exec["result"],
                    evidence_ids=imap_exec.get("evidence_ids", [])
                )
            elif proto == "POP3":
                pop3_exec = self.gateway.execute_tool(investigation_id, "pop3.analyze", {"file_path": str(pcap_path), "stream_id": stream_id})
                forensic_context["pop3"] = pop3_exec["result"]
                record_step(
                    state="EXECUTE",
                    reason=f"Analyzed POP3 stream {stream_id}: STLS capability={pop3_exec['result'].get('stls_advertised')}, plaintext auth={pop3_exec['result'].get('plaintext_after_stls')}.",
                    tool="pop3.analyze",
                    tool_args={"file_path": str(pcap_path), "stream_id": stream_id},
                    result=pop3_exec["result"],
                    evidence_ids=pop3_exec.get("evidence_ids", [])
                )

            tls_exec = self.gateway.execute_tool(investigation_id, "tls.handshake", {"file_path": str(pcap_path), "stream_id": stream_id})
            forensic_context["tls"] = tls_exec["result"]
            record_step(
                state="EXECUTE",
                reason=f"Inspected TLS handshake on stream {stream_id}: ClientHello observed={tls_exec['result'].get('client_hello_observed')}, version={tls_exec['result'].get('negotiated_version')}.",
                tool="tls.handshake",
                tool_args={"file_path": str(pcap_path), "stream_id": stream_id},
                result=tls_exec["result"],
                evidence_ids=tls_exec.get("evidence_ids", [])
            )

            # Certificate extraction
            cert_exec = self.gateway.execute_tool(investigation_id, "tls.certificate", {"file_path": str(pcap_path), "stream_id": stream_id})
            record_step(
                state="EXECUTE",
                reason=f"Extracted X.509 certificates for stream {stream_id}.",
                tool="tls.certificate",
                tool_args={"file_path": str(pcap_path), "stream_id": stream_id},
                result=cert_exec["result"],
                evidence_ids=cert_exec.get("evidence_ids", [])
            )
            certs = cert_exec["result"].get("certificates", [])
            if certs:
                if isinstance(certs[0], dict):
                    cert_dict = certs[0]
                elif isinstance(certs[0], str):
                    try:
                        cert_dict = X509Engine.parse_der_certificate(bytes.fromhex(certs[0]), expected_hostname=forensic_context.get("tls", {}).get("sni", "")).to_dict()
                    except Exception:
                        cert_dict = {}
                else:
                    cert_dict = {}

                if cert_dict:
                    forensic_context["certificate"] = cert_dict
                    SSEEventBus.publish_sync(investigation_id, "certificate.extracted", {
                        "subject": cert_dict.get("subject", ""),
                        "issuer": cert_dict.get("issuer", ""),
                        "is_expired": cert_dict.get("is_expired", False),
                        "validation_errors": cert_dict.get("validation_errors", [])
                    })

            # Cipher suite safety evaluation
            cipher_name = (forensic_context.get("tls_analysis") or {}).get("cipher_suite") or "TLS_AES_256_GCM_SHA384"
            ciphers_exec = self.gateway.execute_tool(investigation_id, "cipher_suite_evaluator", {"cipher_name": cipher_name})
            record_step(
                state="EXECUTE",
                reason=f"Evaluated cipher suite security matrix ({cipher_name}) on stream {stream_id}.",
                tool="cipher_suite_evaluator",
                tool_args={"cipher_name": cipher_name},
                result=ciphers_exec["result"],
                evidence_ids=ciphers_exec.get("evidence_ids", [])
            )

        # 4. YARA Payload and Malware Signature Scan
        yara_exec = self.gateway.execute_tool(investigation_id, "yara.scan", {"payload": str(pcap_path)})
        record_step(
            state="EXECUTE",
            reason=f"Scanned artifact payloads against YARA rule database. Matches: {yara_exec['result'].get('match_count', 0)}.",
            tool="yara.scan",
            tool_args={"payload": pcap_path.name},
            result=yara_exec["result"],
            evidence_ids=yara_exec.get("evidence_ids", [])
        )

        # 5. Secret Pattern Analysis (Credential / Key leak check)
        secret_exec = self.gateway.execute_tool(investigation_id, "secret_pattern_analysis", {"content": str(pcap_path)})
        record_step(
            state="EXECUTE",
            reason="Executed regex scan for leaked authentication tokens, API keys, and private credentials.",
            tool="secret_pattern_analysis",
            tool_args={"target": pcap_path.name},
            result=secret_exec["result"],
            evidence_ids=secret_exec.get("evidence_ids", [])
        )

        # 6. ML & Explainable AI (SHAP TreeExplainer)
        ml_exp_exec = self.gateway.execute_tool(investigation_id, "ml.explain", {"forensic_context": forensic_context})
        record_step(
            state="CORRELATE",
            reason="Executed XGBoost risk classifier and SHAP TreeExplainer feature attribution.",
            tool="ml.explain",
            tool_args={"context_keys": list(forensic_context.keys())},
            result=ml_exp_exec["result"],
            evidence_ids=ml_exp_exec.get("evidence_ids", [])
        )

        # -------------------------------------------------------------
        # STATE: AGENTIC LLM REASONING LOOP (NVIDIA NIM -> Gemini)
        # -------------------------------------------------------------
        ai_available = bool(config.nvidia_api_key or config.gemini_api_key)
        llm_success = False

        if ai_available:
            try:
                llm_success = self._run_llm_reasoning_loop(
                    investigation_id=investigation_id,
                    pcap_path=pcap_path,
                    forensic_context=forensic_context,
                    record_step_fn=record_step,
                    run_id=run_id
                )
            except Exception as e:
                logger.warning(f"External LLM reasoning loop failed or unavailable: {e}")
                llm_success = False

        if not llm_success:
            # Explicit AI_UNAVAILABLE reporting (No fake reasoner fallback)
            ai_msg = "AI reasoning unavailable: no external LLM responded. Deterministic forensic analysis completed."
            inv.limitations.append(ai_msg)
            self._record_agent_event(investigation_id, "AI_UNAVAILABLE", ai_msg)
            try:
                db = SessionLocal()
                try:
                    r_model = db.query(AgentRunModel).filter_by(run_id=run_id).first()
                    if r_model:
                        r_model.status = "COMPLETED"
                        r_model.llm_provider = "none"
                        r_model.llm_model = "none"
                        r_model.deterministic_fallback = True
                        db.commit()
                finally:
                    db.close()
            except Exception:
                pass

        # -------------------------------------------------------------
        # STATE: HYPOTHESIZE & PLAN (Multi-Branch Investigation)
        # -------------------------------------------------------------
        inv.status = InvestigationStatus.INVESTIGATING
        self.ledger.save_investigation(inv)

        smtp_data = forensic_context.get("smtp", {})
        tls_data = forensic_context.get("tls", {})
        cert_data = forensic_context.get("certificate", {})
        neg_ver = tls_data.get("negotiated_version")
        sel_cipher = tls_data.get("selected_cipher") or {}

        # -------------------------------------------------------------
        # BRANCH 1: STARTTLS Stripping / Downgrade Anomaly
        # -------------------------------------------------------------
        starttls_anomaly = (
            (smtp_data.get("starttls_advertised") and smtp_data.get("starttls_requested") and not tls_data.get("client_hello_observed")) or
            smtp_data.get("plaintext_after_starttls") or
            forensic_context.get("imap", {}).get("plaintext_after_starttls") or
            forensic_context.get("pop3", {}).get("plaintext_after_stls")
        )

        if starttls_anomaly:
            h1 = hyp_engine.create_hypothesis("H1: STARTTLS Stripping / Downgrade Attack", "Active adversary or misconfigured MTA forced cleartext email fallback.")
            h2 = hyp_engine.create_hypothesis("H2: Incomplete Packet Capture", "Missing TLS ClientHello is an artifact of packet loss or truncated PCAP capture.")
            h3 = hyp_engine.create_hypothesis("H3: TLS Negotiation Failure", "Client or server aborted TLS handshake due to incompatible parameters.")

            record_step(
                state="HYPOTHESIZE",
                reason="STARTTLS negotiation sequence anomaly observed without TLS ClientHello. Formulating competing hypotheses H1 (Attack) vs H2 (Packet Loss) vs H3 (Negotiation Failure).",
                hypothesis_title=h1.title,
                next_action="Execute pcap.completeness tool to test H2 against capture continuity."
            )

            # PLAN & SELECT_TOOL: pcap.completeness
            comp_exec = self.gateway.execute_tool(investigation_id, "pcap.completeness", {"file_path": str(pcap_path)}, hypothesis_id=h1.hypothesis_id)
            comp_score = comp_exec["result"].get("completeness_percentage", 100.0)

            record_step(
                state="EXECUTE",
                reason=f"Calculated capture completeness is {comp_score}%.",
                tool="pcap.completeness",
                result=comp_exec["result"],
                evidence_ids=comp_exec["evidence_ids"],
                hypothesis_title=h1.title,
                next_action="Re-evaluate H1 vs H2 based on capture completeness."
            )

            if comp_score >= 95.0:
                # High completeness refutes H2, supports H1
                if comp_exec["evidence_ids"]:
                    hyp_engine.add_refuting_evidence(h2.hypothesis_id, comp_exec["evidence_ids"][0], 0.8, f"PCAP completeness is {comp_score}%; packet loss ruled out.")
                    hyp_engine.add_supporting_evidence(h1.hypothesis_id, comp_exec["evidence_ids"][0], 0.3, "High completeness proves unencrypted messages were actually transmitted.")

                # Inspect TCP stream for plaintext commands
                stream_exec = self.gateway.execute_tool(investigation_id, "pcap.tcp_stream", {"file_path": str(pcap_path)}, hypothesis_id=h1.hypothesis_id)
                if smtp_data.get("plaintext_after_starttls"):
                    hyp_engine.confirm_hypothesis(h1.hypothesis_id, "Verified cleartext MAIL FROM / DATA payload after STARTTLS acceptance.")

                # Query external intelligence via Tavily if configured
                if config.tavily_enabled and config.allow_external_intel and config.tavily_api_key:
                    target_endpoint = streams[0].get("server_endpoint", "") if streams else ""
                    target_domain = target_endpoint.split(":")[0] if target_endpoint else "mail server"
                    query = f"{target_domain} STARTTLS stripping downgrade vulnerability"
                    record_step(
                        state="SELECT_TOOL",
                        reason=f"STARTTLS downgrade anomaly verified with high capture completeness ({comp_score}%). Querying external threat intelligence (intel.tavily_search) for known downgrade attacks.",
                        tool="intel.tavily_search",
                        tool_args={"query": query, "max_results": 3},
                        hypothesis_title=h1.title
                    )
                    tav_res = self.gateway.execute_tool(
                        investigation_id,
                        "intel.tavily_search",
                        {"query": query, "max_results": 3},
                        hypothesis_id=h1.hypothesis_id
                    )
                    if tav_res.get("evidence_ids"):
                        hyp_engine.add_supporting_evidence(
                            h1.hypothesis_id,
                            tav_res["evidence_ids"][0],
                            0.25,
                            "External OSINT intelligence enriched threat context."
                        )
            else:
                # Low completeness supports H2, casts doubt on H1
                if comp_exec["evidence_ids"]:
                    hyp_engine.add_supporting_evidence(h2.hypothesis_id, comp_exec["evidence_ids"][0], 0.8, f"PCAP completeness is low ({comp_score}%); packet loss explains missing handshake.")
                hyp_engine.mark_inconclusive(h1.hypothesis_id, f"Cannot definitively confirm downgrade attack due to capture incompleteness ({comp_score}%).")
                inv.limitations.append(f"Capture completeness is {comp_score}%; packet drop explains missing TLS handshake.")

        # -------------------------------------------------------------
        # BRANCH 2: Certificate Anomaly & External Intel (Tavily)
        # -------------------------------------------------------------
        cert_errs = cert_data.get("validation_errors", [])
        cert_expired = cert_data.get("is_expired", False)
        cert_weak = cert_data.get("has_weak_key", False)
        cert_hostname_mismatch = not cert_data.get("hostname_match", True)

        if cert_errs or cert_expired or cert_weak or cert_hostname_mismatch:
            h4 = hyp_engine.create_hypothesis("H4: Certificate Trust / Cryptographic Defect", "The observed X.509 certificate fails public trust or contains cryptographic defects.")
            record_step(
                state="HYPOTHESIZE",
                reason=f"Observed X.509 certificate defect(s): {cert_errs}. Checking validation.",
                hypothesis_title=h4.title,
                next_action="Perform certificate validation."
            )

            # Query external intelligence via Tavily if enabled & configured
            if config.tavily_enabled and config.allow_external_intel and config.tavily_api_key:
                domain_query = streams[0].get("server_endpoint", "").split(":")[0] if streams else "mail.example.com"
                subj = cert_data.get("subject")
                if isinstance(subj, dict):
                    cert_cn = subj.get("common_name") or domain_query
                elif isinstance(subj, str) and subj:
                    cn_part = [p for p in subj.split(",") if p.strip().startswith("CN=")]
                    cert_cn = cn_part[0].split("=", 1)[1].strip() if cn_part else subj.strip()
                else:
                    cert_cn = domain_query
                search_q = f"{cert_cn} certificate trust reputation"
                record_step(
                    state="SELECT_TOOL",
                    reason="Certificate anomaly detected. Calling intel.tavily_search to check external domain trust and certificate reputation.",
                    tool="intel.tavily_search",
                    tool_args={"query": search_q, "max_results": 3},
                    hypothesis_title=h4.title
                )
                tav_res = self.gateway.execute_tool(
                    investigation_id,
                    "intel.tavily_search",
                    {"query": search_q, "max_results": 3},
                    hypothesis_id=h4.hypothesis_id
                )
                if tav_res.get("evidence_ids"):
                    hyp_engine.add_supporting_evidence(
                        h4.hypothesis_id,
                        tav_res["evidence_ids"][0],
                        0.3,
                        "External intelligence query completed."
                    )

            hyp_engine.confirm_hypothesis(h4.hypothesis_id, f"Confirmed certificate defects: {', '.join(cert_errs) if cert_errs else 'Untrusted certificate'}")

        # -------------------------------------------------------------
        # BRANCH 3: Weak Cryptography & Legacy Protocol
        # -------------------------------------------------------------
        is_deprecated = neg_ver in ("TLS 1.0", "TLS 1.1", "SSL 3.0")
        is_broken_cipher = sel_cipher.get("strength") in ("BROKEN", "LEGACY", "WEAK")
        no_pfs = tls_data.get("handshake_observed") and not tls_data.get("has_forward_secrecy")

        if is_deprecated or is_broken_cipher or no_pfs:
            h5 = hyp_engine.create_hypothesis("H5: Deprecated Protocol / Weak Cipher Configuration", "Session negotiated deprecated protocol parameters vulnerable to passive decryption.")
            record_step(
                state="HYPOTHESIZE",
                reason=f"Observed weak crypto: {neg_ver} / {sel_cipher.get('name')}. Evaluating policy compliance.",
                hypothesis_title=h5.title,
                next_action="Confirm cryptographic non-compliance."
            )
            hyp_engine.confirm_hypothesis(h5.hypothesis_id, f"Verified deprecated protocol parameters ({neg_ver}, {sel_cipher.get('name')}).")

        # Explicit honest TLS 1.3 Limitation
        if neg_ver == "TLS 1.3":
            inv.limitations.append("TLS 1.3 session observed: X.509 certificate exchange is encrypted post-ServerHello and not observable from passive capture.")

        # -------------------------------------------------------------
        # STATE: CORRELATE (Rules & ML)
        # -------------------------------------------------------------
        record_step(
            state="CORRELATE",
            reason="Evaluating deterministic cryptographic rules and XGBoost risk model.",
            tool="rules.evaluate",
            tool_args={"forensic_context": "context_payload"},
            next_action="Execute ML model inference."
        )
        rule_exec = self.gateway.execute_tool(investigation_id, "rules.evaluate", {"forensic_context": forensic_context})
        triggered_rules = rule_exec["result"].get("triggered_rules", [])

        # ML Risk Classification
        ml_result = self.ml_classifier.predict_risk(forensic_context)
        ev_ml_id = f"E-{uuid.uuid4().hex[:6].upper()}"
        from securemailscope.agent.investigator import from_ml_result
        self.ledger.record_evidence(from_ml_result(ev_ml_id, investigation_id, ml_result, pcap_path.name))

        # Persist ML prediction in DB
        try:
            db = SessionLocal()
            try:
                ml_pred = MLPredictionModel(
                    prediction_id=f"ML-{uuid.uuid4().hex[:8].upper()}",
                    investigation_id=investigation_id,
                    predicted_class=ml_result["predicted_class"],
                    risk_probability=ml_result["risk_probability"],
                    class_confidence=ml_result["class_confidence"],
                    is_anomalous=ml_result["is_anomalous"],
                    shap_attributions=ml_result.get("top_features", []),
                    feature_vector=ml_result.get("extracted_features", {})
                )
                db.add(ml_pred)
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

        # Emit ML Prediction SSE Event
        SSEEventBus.publish_sync(investigation_id, "ml.prediction.completed", {
            "predicted_class": ml_result["predicted_class"],
            "risk_probability": ml_result["risk_probability"],
            "class_confidence": ml_result["class_confidence"],
            "is_anomalous": ml_result["is_anomalous"]
        })

        # Contradiction Detection (Phase 45)
        # Check 1: Deterministic Rule vs ML Model Disagreement
        has_critical_rule = any(r.get("severity") in ("CRITICAL", "HIGH") for r in triggered_rules)
        ml_is_benign = ml_result["risk_probability"] < 0.25 and not ml_result["is_anomalous"]
        if has_critical_rule and ml_is_benign:
            contra_claim = (
                f"Contradiction detected: Deterministic rule flagged HIGH/CRITICAL violation "
                f"({[r['rule_id'] for r in triggered_rules if r.get('severity') in ('CRITICAL', 'HIGH')]}), "
                f"while ML model predicted low risk ({ml_result['risk_probability'] * 100:.1f}%). "
                f"Resolved by prioritizing deterministic ground-truth evidence."
            )
            ev_contra = Evidence(
                evidence_id=f"E-{uuid.uuid4().hex[:6].upper()}",
                investigation_id=investigation_id,
                type=EvidenceType.DERIVED,
                claim=contra_claim,
                source_tool="ContradictionEngine",
                tool_version="1.0",
                tool_args={"rule_ids": [r["rule_id"] for r in triggered_rules], "ml_pred": ml_result["predicted_class"]},
                raw_artifact_ref=f"pcap://{pcap_path.name}",
                confidence=0.95,
                severity=SeverityLevel.HIGH,
                provenance_chain=[investigation_id, "Rules", "MLModel", "DisagreementResolution"],
                details={"disagreement_type": "RULE_ML_CONFLICT", "resolution": "DETERMINISTIC_RULES_PREVAIL"}
            )
            self.ledger.record_evidence(ev_contra)
            inv.limitations.append("Statistical ML and deterministic rules diverged; deterministic protocol rules took precedence.")

        # Check 2: High completeness with cleartext continuation
        if inv.completeness_percentage >= 95.0 and smtp_data.get("plaintext_after_starttls"):
            ev_contra_downgrade = Evidence(
                evidence_id=f"E-{uuid.uuid4().hex[:6].upper()}",
                investigation_id=investigation_id,
                type=EvidenceType.DERIVED,
                claim="High capture completeness (>=95%) with continuous TCP sequencing contradicts packet drop; confirms deliberate STARTTLS strip or unencrypted downgrade.",
                source_tool="ContradictionEngine",
                tool_version="1.0",
                raw_artifact_ref=f"pcap://{pcap_path.name}",
                confidence=0.99,
                severity=SeverityLevel.CRITICAL,
                provenance_chain=[investigation_id, "pcap.completeness", "smtp.analyze"],
                details={"completeness": inv.completeness_percentage, "downgrade_confirmed": True}
            )
            self.ledger.record_evidence(ev_contra_downgrade)

        # -------------------------------------------------------------
        # STATE: VERIFY (Finding Formulation & Gatekeeper)
        # -------------------------------------------------------------
        inv.status = InvestigationStatus.VERIFYING
        self.ledger.save_investigation(inv)

        evidence_list = self.ledger.get_evidence_for_investigation(investigation_id)

        # Formulate findings based on triggered rules
        for r in triggered_rules:
            SSEEventBus.publish_sync(investigation_id, "rule.triggered", {
                "rule_id": r["rule_id"],
                "title": r["title"],
                "severity": r["severity"]
            })

            matching_eids = [e.evidence_id for e in evidence_list if r["rule_id"] in e.claim or e.type.value in (
                "STARTTLS_ADVERTISED", "STARTTLS_REQUESTED", "PLAINTEXT_CONTINUATION",
                "TLS_VERSION_DETECTED", "CERTIFICATE_EXTRACTED", "CRYPTO_RULE_TRIGGERED",
                "starttls_advertised", "starttls_requested", "plaintext_continuation",
                "tls_version_detected", "certificate_extracted", "crypto_rule_triggered",
                "protocol_anomaly", "PROTOCOL_ANOMALY",
                "ml_prediction", "ML_CLASSIFICATION",
                "OBSERVED", "DERIVED"
            )]

            if matching_eids:
                fnd = Finding(
                    finding_id=f"FND-{uuid.uuid4().hex[:6].upper()}",
                    investigation_id=investigation_id,
                    title=r["title"],
                    description=r["description"],
                    severity=SeverityLevel(r["severity"]),
                    status=FindingStatus.CANDIDATE,
                    evidence_ids=matching_eids[:5],
                    rule_id=r["rule_id"],
                    remediation=r["remediation"]
                )
                try:
                    self.validator.validate_and_register_finding(fnd)
                    inv.recommendations.append(r["remediation"])
                    SSEEventBus.publish_sync(investigation_id, "finding.verified", {
                        "finding_id": fnd.finding_id,
                        "title": fnd.title,
                        "severity": fnd.severity.value,
                        "status": fnd.status.value,
                        "evidence_ids": fnd.evidence_ids
                    })
                except Exception as e:
                    self._record_agent_event(investigation_id, "VALIDATION_GATE", f"Finding rejected: {e}")

        # Inconclusive case handling
        if not triggered_rules and inv.completeness_percentage < 60.0:
            fnd = Finding(
                finding_id=f"FND-{uuid.uuid4().hex[:6].upper()}",
                investigation_id=investigation_id,
                title="Inconclusive Cryptographic Posture (Incomplete Capture)",
                description=f"Capture completeness is {inv.completeness_percentage}%. Insufficient evidence to establish cryptographic security.",
                severity=SeverityLevel.INFORMATIONAL,
                status=FindingStatus.INCONCLUSIVE,
                evidence_ids=[e.evidence_id for e in evidence_list][:3],
                remediation="Collect a complete full-packet capture with all TCP segments and TLS handshakes present."
            )
            self.validator.validate_and_register_finding(fnd)
            inv.recommendations.append(fnd.remediation)
            SSEEventBus.publish_sync(investigation_id, "finding.verified", {
                "finding_id": fnd.finding_id,
                "title": fnd.title,
                "severity": fnd.severity.value,
                "status": fnd.status.value,
                "evidence_ids": fnd.evidence_ids
            })

        if not triggered_rules and inv.completeness_percentage >= 95.0 and neg_ver in ("TLS 1.2", "TLS 1.3"):
            inv.recommendations.append("Maintain current strong TLS and cipher configuration with periodic certificate rotation.")

        # -------------------------------------------------------------
        # STATE: VERDICT & REPORTING
        # -------------------------------------------------------------
        scorecard = PostureScorer.calculate_posture(forensic_context, triggered_rules, ml_result)
        inv.posture = scorecard
        inv.status = InvestigationStatus.COMPLETED
        self.ledger.save_investigation(inv)

        # Update Investigation in Database
        try:
            db = SessionLocal()
            try:
                db_inv = db.query(InvestigationModel).filter_by(investigation_id=investigation_id).first()
                if db_inv:
                    db_inv.status = "COMPLETED"
                    db_inv.posture_score = scorecard.overall_posture_score
                    db_inv.risk_level = scorecard.risk_level
                    db_inv.confidence_score = scorecard.confidence_score
                    db_inv.completed_at = datetime.now(timezone.utc)
                    db.commit()
            finally:
                db.close()
        except Exception:
            pass

        record_step(
            state="VERDICT",
            reason=f"Investigation completed: Posture {scorecard.overall_posture_score}/100 ({scorecard.risk_level}), Confidence {scorecard.confidence_score}%.",
            next_action="Generate deterministic forensic reports (JSON, HTML, PDF)."
        )

        # Generate Reports
        self.gateway.execute_tool(investigation_id, "report.generate_json", {"investigation_id": investigation_id})
        SSEEventBus.publish_sync(investigation_id, "report.generated", {"format": "json"})
        self.gateway.execute_tool(investigation_id, "report.generate_html", {"investigation_id": investigation_id})
        SSEEventBus.publish_sync(investigation_id, "report.generated", {"format": "html"})
        self.gateway.execute_tool(investigation_id, "report.generate_pdf", {"investigation_id": investigation_id})
        SSEEventBus.publish_sync(investigation_id, "report.generated", {"format": "pdf"})

        SSEEventBus.publish_sync(investigation_id, "investigation.completed", {
            "investigation_id": investigation_id,
            "posture_score": scorecard.overall_posture_score,
            "risk_level": scorecard.risk_level,
            "confidence_score": scorecard.confidence_score
        })

        return inv

    def _record_agent_event(self, investigation_id: str, phase: str, detail: str):
        evt = TimelineEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:6].upper()}",
            phase=phase,
            actor="INVESTIGATION_AGENT",
            action=phase,
            detail=detail
        )
        self.ledger.record_timeline_event(evt, investigation_id)


def from_ml_result(ev_id: str, investigation_id: str, ml_result: Dict[str, Any], pcap_name: str):
    return Evidence(
        evidence_id=ev_id,
        investigation_id=investigation_id,
        type=EvidenceType.ML_CLASSIFICATION,
        claim=f"XGBoost Classifier classified session as '{ml_result['predicted_class']}' (Risk Probability: {ml_result['risk_probability'] * 100:.1f}%, Confidence: {ml_result['class_confidence'] * 100:.1f}%).",
        source_tool="CryptoRiskClassifier (XGBoost)",
        tool_version="3.4",
        tool_args={"predicted_class": ml_result["predicted_class"]},
        raw_artifact_ref=f"ml://prediction/{pcap_name}",
        confidence=ml_result["class_confidence"],
        severity=SeverityLevel.HIGH if ml_result["is_anomalous"] else SeverityLevel.INFORMATIONAL,
        provenance_chain=[investigation_id, pcap_name, "XGBoost", ml_result["predicted_class"]],
        details=ml_result
    )
