"""
SecureMailScope - Multi-Format Email Artifact Forensic Parser
Supports RFC-2822 (.eml), Outlook (.msg), and Unix Mailbox (.mbox) message artifacts.
Extracts message headers, received hop chain, authentication results (SPF/DKIM/DMARC),
MIME structure, URL IOCs, and attachments with SHA-256 hashes.
"""
import hashlib
import logging
import mailbox
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
import email
import email.policy

logger = logging.getLogger("securemailscope.forensics.email_parser")


class EMLParser:
    """Forensic parser for email (.eml, .msg, .mbox) message artifacts."""

    @classmethod
    def parse_eml(cls, file_path: Path) -> Dict[str, Any]:
        """
        Parses an email artifact (.eml, .msg, .mbox) and returns structured forensic extraction.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Email artifact does not exist: {file_path}")

        raw_bytes = file_path.read_bytes()
        file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        suffix = file_path.suffix.lower()

        # Handle Unix MBOX format
        if suffix == ".mbox":
            return cls._from_mbox(file_path, file_sha256, raw_bytes)

        # Handle Outlook MSG or try standard parser
        try:
            try:
                import mailparser as mp
            except ImportError:
                import mail_parser as mp
            parsed_mail = mp.parse_from_file(str(file_path))
            return cls._from_mail_parser(parsed_mail, file_path, file_sha256, raw_bytes)
        except Exception as err:
            logger.debug(f"mailparser fallback to stdlib: {err}")

        return cls._from_stdlib(file_path, file_sha256, raw_bytes)

    @classmethod
    def _extract_auth_headers(cls, headers_dict: Dict[str, Any]) -> Dict[str, Any]:
        auth_data = {
            "spf_observed": None,
            "dkim_observed": None,
            "dmarc_observed": None,
            "dkim_signature_present": False,
            "dkim_signatures": [],
            "auth_results_raw": [],
            "note": "Authentication results are OBSERVED from message headers, not independently re-verified."
        }

        for k, v in headers_dict.items():
            k_low = k.lower()
            if "dkim-signature" in k_low:
                auth_data["dkim_signature_present"] = True
                auth_data["dkim_signatures"].append(str(v))
            elif "authentication-results" in k_low:
                v_str = str(v)
                auth_data["auth_results_raw"].append(v_str)
                v_low = v_str.lower()
                if "spf=pass" in v_low:
                    auth_data["spf_observed"] = "PASS"
                elif "spf=fail" in v_low or "spf=softfail" in v_low:
                    auth_data["spf_observed"] = "FAIL"
                elif "spf=" in v_low:
                    auth_data["spf_observed"] = "OTHER"

                if "dkim=pass" in v_low:
                    auth_data["dkim_observed"] = "PASS"
                elif "dkim=fail" in v_low:
                    auth_data["dkim_observed"] = "FAIL"
                elif "dkim=" in v_low:
                    auth_data["dkim_observed"] = "OTHER"

                if "dmarc=pass" in v_low:
                    auth_data["dmarc_observed"] = "PASS"
                elif "dmarc=fail" in v_low:
                    auth_data["dmarc_observed"] = "FAIL"
                elif "dmarc=" in v_low:
                    auth_data["dmarc_observed"] = "OTHER"

        return auth_data

    @classmethod
    def _extract_urls(cls, text: str) -> List[str]:
        if not text:
            return []
        urls = re.findall(r'https?://[^\s<>"\']+', text)
        return list(set(urls))

    @classmethod
    def _from_mail_parser(cls, mail, file_path: Path, file_sha256: str, raw_bytes: bytes) -> Dict[str, Any]:
        headers = mail.headers if hasattr(mail, "headers") else {}
        auth_headers = cls._extract_auth_headers(headers)

        attachments = []
        if hasattr(mail, "attachments"):
            for att in mail.attachments or []:
                payload = att.get("payload", b"")
                if isinstance(payload, str):
                    payload = payload.encode("utf-8", errors="replace")
                att_hash = hashlib.sha256(payload).hexdigest() if payload else ""
                attachments.append({
                    "filename": att.get("filename", "unknown"),
                    "content_type": att.get("mail_content_type", "application/octet-stream"),
                    "size_bytes": len(payload),
                    "sha256": att_hash
                })

        body_text = str(getattr(mail, "body", "") or "")
        urls = cls._extract_urls(body_text)

        from_str = str(mail.from_[0][1]) if getattr(mail, "from_", None) and mail.from_ and isinstance(mail.from_[0], tuple) and len(mail.from_[0]) > 1 else str(getattr(mail, "from_", ""))
        to_list = [t[1] if isinstance(t, tuple) and len(t) > 1 else str(t) for t in (getattr(mail, "to", []) or [])]

        return {
            "parser": "mail_parser",
            "file_path": str(file_path),
            "file_sha256": file_sha256,
            "size_bytes": len(raw_bytes),
            "from_address": from_str,
            "to_addresses": to_list,
            "subject": getattr(mail, "subject", "") or "",
            "date": str(getattr(mail, "date", "")) if getattr(mail, "date", None) else None,
            "message_id": getattr(mail, "message_id", "") or "",
            "received_chain": getattr(mail, "received", []) or [],
            "authentication": auth_headers,
            "attachments": attachments,
            "attachment_count": len(attachments),
            "urls_extracted": urls,
            "has_html_body": bool(getattr(mail, "text_html", None)),
            "has_plain_body": bool(getattr(mail, "text_plain", None)),
            "defects": getattr(mail, "defects", []) or []
        }

    @classmethod
    def _from_stdlib(cls, file_path: Path, file_sha256: str, raw_bytes: bytes) -> Dict[str, Any]:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        headers_dict = {k: str(msg[k]) for k in msg.keys()}
        auth_headers = cls._extract_auth_headers(headers_dict)

        attachments = []
        body_parts = []
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                payload = part.get_payload(decode=True) or b""
                att_hash = hashlib.sha256(payload).hexdigest()
                attachments.append({
                    "filename": part.get_filename() or "unnamed_attachment",
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                    "sha256": att_hash
                })
            elif part.get_content_type() in ("text/plain", "text/html"):
                p_text = part.get_payload(decode=True)
                if p_text:
                    body_parts.append(p_text.decode('utf-8', errors='ignore'))

        full_body = "\n".join(body_parts)
        urls = cls._extract_urls(full_body)
        received_headers = [str(r) for r in msg.get_all("Received", [])]

        return {
            "parser": "stdlib_email",
            "file_path": str(file_path),
            "file_sha256": file_sha256,
            "size_bytes": len(raw_bytes),
            "from_address": str(msg.get("From", "")),
            "to_addresses": [str(msg.get("To", ""))],
            "subject": str(msg.get("Subject", "")),
            "date": str(msg.get("Date", "")),
            "message_id": str(msg.get("Message-ID", "")),
            "received_chain": received_headers,
            "authentication": auth_headers,
            "attachments": attachments,
            "attachment_count": len(attachments),
            "urls_extracted": urls,
            "has_html_body": any(p.get_content_type() == "text/html" for p in msg.walk()),
            "has_plain_body": any(p.get_content_type() == "text/plain" for p in msg.walk()),
            "defects": [str(d) for d in msg.defects]
        }

    @classmethod
    def _from_mbox(cls, file_path: Path, file_sha256: str, raw_bytes: bytes) -> Dict[str, Any]:
        mbox = mailbox.mbox(str(file_path))
        messages_count = len(mbox)
        first_msg = mbox[0] if messages_count > 0 else None

        if first_msg:
            first_bytes = first_msg.as_bytes()
            res = cls._from_stdlib(file_path, file_sha256, first_bytes)
            res["parser"] = "mailbox_mbox"
            res["mbox_total_messages"] = messages_count
            return res

        return {
            "parser": "mailbox_mbox",
            "file_path": str(file_path),
            "file_sha256": file_sha256,
            "size_bytes": len(raw_bytes),
            "mbox_total_messages": 0,
            "from_address": "",
            "to_addresses": [],
            "subject": "Empty MBOX",
            "attachments": [],
            "attachment_count": 0,
            "urls_extracted": [],
            "authentication": {}
        }
