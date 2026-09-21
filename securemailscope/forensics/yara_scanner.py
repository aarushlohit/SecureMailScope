"""
SecureMailScope - YARA & Signature Pattern Scanner
Performs pattern matching on stream payloads, MIME attachments, and email text.
"""
import re
from typing import Dict, Any, List

# Core regex signature patterns for phishing, webshells, credential harvesting, obfuscated scripts
DEFAULT_SIGNATURE_PATTERNS = {
    "YARA_RULE_WEBSHELL_INDICATOR": r"(?i)(c99shell|r57shell|WSO_VERSION|cmd\.exe|/bin/sh|passthru\s*\(|shell_exec\s*\(|eval\s*\(\s*base64_decode)",
    "YARA_RULE_CREDENTIAL_HARVESTER": r"(?i)(type=[\"']password[\"']|name=[\"']passwd[\"']|login_pass|auth_pass|verify_account_details|account_suspended_action_required)",
    "YARA_RULE_SUSPICIOUS_ATTACHMENT_MACRO": r"(?i)(AutoOpen|Document_Open|ShellExecute|WScript\.Shell|CreateObject\s*\(\s*[\"']WScript\.Shell)",
    "YARA_RULE_POWERVIEW_EMBEDDED": r"(?i)(Get-NetDomain|Get-NetUser|Invoke-Kerberoast|Invoke-BloodHound)",
    "YARA_RULE_STARTTLS_STRIP_EXPLOIT": r"(?i)(554 TLS not available|STARTTLS_REMOVED|PLAIN_AUTH_FORCED)",
}


class YaraScannerEngine:
    def __init__(self):
        self.patterns = DEFAULT_SIGNATURE_PATTERNS

    def scan_content(self, text_or_bytes: Any) -> Dict[str, Any]:
        content = ""
        if isinstance(text_or_bytes, bytes):
            content = text_or_bytes.decode('utf-8', errors='ignore')
        else:
            content = str(text_or_bytes)

        matches: List[Dict[str, Any]] = []
        for rule_name, pattern in self.patterns.items():
            found = re.findall(pattern, content)
            if found:
                matches.append({
                    "rule": rule_name,
                    "match_count": len(found),
                    "samples": [str(m)[:50] for m in found[:3]]
                })

        return {
            "has_matches": len(matches) > 0,
            "match_count": len(matches),
            "matches": matches,
            "scanned_length": len(content)
        }


def scan_payload_yara(payload: Any) -> Dict[str, Any]:
    scanner = YaraScannerEngine()
    return scanner.scan_content(payload)
