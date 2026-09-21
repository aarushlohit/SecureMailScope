"""
SecureMailScope - CyberChef Payload Multi-Stage Deobfuscator
Applies recursive decoding (Base64, Hex, URL, Quoted-Printable) to expose obfuscated commands,
URLs, shellcode, and embedded scripts.
"""
import base64
import binascii
import urllib.parse
import quopri
import re
from typing import Dict, Any, List


def deobfuscate_payload_cyberchef(encoded_payload: str) -> Dict[str, Any]:
    """
    Executes a CyberChef-style multi-stage decoding pipeline on obfuscated strings/payloads.
    """
    stages: List[Dict[str, str]] = []
    current = encoded_payload.strip()
    
    # Pre-clean strings like b'...' or "..."
    if (current.startswith("b'") and current.endswith("'")) or (current.startswith('b"') and current.endswith('"')):
        current = current[2:-1]

    changed = True
    max_depth = 5
    depth = 0

    while changed and depth < max_depth:
        changed = False
        depth += 1

        # 1. URL Decoding
        if "%" in current:
            try:
                decoded_url = urllib.parse.unquote(current)
                if decoded_url != current:
                    stages.append({"stage": depth, "recipe": "URL_Decode", "output": decoded_url})
                    current = decoded_url
                    changed = True
                    continue
            except Exception:
                pass

        # 2. Quoted-Printable Decoding
        if "=\n" in current or "=3D" in current or "=20" in current:
            try:
                decoded_qp = quopri.decodestring(current.encode('utf-8')).decode('utf-8', errors='ignore')
                if decoded_qp != current:
                    stages.append({"stage": depth, "recipe": "Quoted_Printable_Decode", "output": decoded_qp})
                    current = decoded_qp
                    changed = True
                    continue
            except Exception:
                pass

        # 3. Base64 Decoding
        # Check if valid base64 pattern
        b64_candidate = re.sub(r'\s+', '', current)
        if len(b64_candidate) >= 8 and len(b64_candidate) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', b64_candidate):
            try:
                decoded_bytes = base64.b64decode(b64_candidate)
                decoded_b64 = decoded_bytes.decode('utf-8', errors='ignore')
                # Require printable ASCII text
                if any(c.isalnum() for c in decoded_b64) and decoded_b64 != current:
                    stages.append({"stage": depth, "recipe": "Base64_Decode", "output": decoded_b64})
                    current = decoded_b64
                    changed = True
                    continue
            except Exception:
                pass

        # 4. Hex Decoding
        hex_candidate = re.sub(r'[\s\\x:]+', '', current)
        if len(hex_candidate) >= 8 and len(hex_candidate) % 2 == 0 and re.match(r'^[0-9a-fA-F]+$', hex_candidate):
            try:
                decoded_hex = binascii.unhexlify(hex_candidate).decode('utf-8', errors='ignore')
                if any(c.isalnum() for c in decoded_hex) and decoded_hex != current:
                    stages.append({"stage": depth, "recipe": "Hex_Decode", "output": decoded_hex})
                    current = decoded_hex
                    changed = True
                    continue
            except Exception:
                pass

    # Extract indicators from final decoded string
    extracted_urls = re.findall(r'https?://[^\s<>"\']+', current)
    extracted_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', current)
    extracted_cmds = re.findall(r'(?i)(powershell|cmd\.exe|/bin/sh|wscript|cscript|curl|wget|certutil)', current)

    return {
        "original_payload": encoded_payload[:200],
        "final_decoded_payload": current,
        "stages_applied": len(stages),
        "pipeline_recipe": [s["recipe"] for s in stages],
        "indicators": {
            "urls": extracted_urls,
            "ips": extracted_ips,
            "commands": extracted_cmds
        }
    }
