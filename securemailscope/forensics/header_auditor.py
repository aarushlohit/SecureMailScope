"""
SecureMailScope - Email Header Forging & Anomaly Auditor
Inspects raw MIME headers for Message-ID vs Return-Path mismatches, SPF/DKIM/DMARC status,
Received hop counts, and display-name spoofing.
"""
import re
import email
from email.parser import HeaderParser
from typing import Dict, Any, Union, List


def audit_email_headers(raw_headers_or_msg: Union[str, Dict[str, str]]) -> Dict[str, Any]:
    """
    Parses and checks email headers for security anomalies, spoofing, and protocol mismatches.
    """
    if isinstance(raw_headers_or_msg, dict):
        headers_dict = {k.lower(): str(v) for k, v in raw_headers_or_msg.items()}
        raw_text = "\n".join([f"{k}: {v}" for k, v in raw_headers_or_msg.items()])
    else:
        parser = HeaderParser()
        msg = parser.parsestr(str(raw_headers_or_msg))
        headers_dict = {k.lower(): msg.get(k, "") for k in msg.keys()}
        raw_text = str(raw_headers_or_msg)

    anomalies: List[Dict[str, Any]] = []
    
    # 1. From vs Return-Path / Reply-To domain mismatch
    from_hdr = headers_dict.get("from", "")
    return_path = headers_dict.get("return-path", "")
    reply_to = headers_dict.get("reply-to", "")

    def extract_domain(addr_str: str) -> str:
        match = re.search(r'@([\w.-]+)', addr_str)
        return match.group(1).lower() if match else ""

    from_domain = extract_domain(from_hdr)
    return_domain = extract_domain(return_path)
    reply_domain = extract_domain(reply_to)

    if from_domain and return_domain and from_domain != return_domain:
        anomalies.append({
            "type": "RETURN_PATH_MISMATCH",
            "severity": "HIGH",
            "details": f"Header From domain '{from_domain}' mismatches Return-Path domain '{return_domain}'"
        })

    if from_domain and reply_domain and from_domain != reply_domain:
        anomalies.append({
            "type": "REPLY_TO_MISMATCH",
            "severity": "MEDIUM",
            "details": f"Header From domain '{from_domain}' mismatches Reply-To domain '{reply_domain}'"
        })

    # 2. Message-ID domain mismatch
    msg_id = headers_dict.get("message-id", "")
    msg_id_domain = extract_domain(msg_id)
    if from_domain and msg_id_domain and from_domain not in msg_id_domain:
        anomalies.append({
            "type": "MESSAGE_ID_DOMAIN_MISMATCH",
            "severity": "MEDIUM",
            "details": f"Message-ID domain '{msg_id_domain}' does not align with From domain '{from_domain}'"
        })

    # 3. Authentication Results (SPF / DKIM / DMARC)
    auth_results = headers_dict.get("authentication-results", "").lower()
    auth_status = {
        "spf": "pass" if "spf=pass" in auth_results else ("fail" if ("spf=fail" in auth_results or "spf=softfail" in auth_results) else "unknown"),
        "dkim": "pass" if "dkim=pass" in auth_results else ("fail" if "dkim=fail" in auth_results else "unknown"),
        "dmarc": "pass" if "dmarc=pass" in auth_results else ("fail" if "dmarc=fail" in auth_results else "unknown")
    }

    if "spf=fail" in auth_results or "spf=softfail" in auth_results:
        anomalies.append({
            "type": "SPF_AUTH_FAILURE",
            "severity": "HIGH",
            "details": "Authentication-Results header indicates SPF failure or softfail."
        })

    if "dkim=fail" in auth_results:
        anomalies.append({
            "type": "DKIM_AUTH_FAILURE",
            "severity": "HIGH",
            "details": "Authentication-Results header indicates DKIM signature verification failure."
        })

    # 4. Received chain count
    received_count = len(re.findall(r'(?i)^received:', raw_text, re.MULTILINE))

    # 5. Display Name Spoofing Check
    display_name_match = re.search(r'["\']?([^"\'<>]+)["\']?\s*<([^>]+)>', from_hdr)
    if display_name_match:
        display_name, email_addr = display_name_match.groups()
        if "@" in display_name and extract_domain(display_name) != extract_domain(email_addr):
            anomalies.append({
                "type": "DISPLAY_NAME_SPOOFING",
                "severity": "CRITICAL",
                "details": f"Display name contains email '{display_name}' targeting user trust while actual sender is '{email_addr}'"
            })

    risk_score = min(100, len(anomalies) * 25)

    return {
        "is_suspicious": len(anomalies) > 0,
        "anomaly_count": len(anomalies),
        "header_risk_score": risk_score,
        "from_domain": from_domain,
        "return_path_domain": return_domain,
        "received_hop_count": received_count,
        "auth_status": auth_status,
        "anomalies": anomalies
    }
