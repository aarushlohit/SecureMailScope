"""
SecureMailScope - Shannon Entropy Calculator & Covert Channel Detector
Calculates H = -sum(p(x) * log2(p(x))) for payloads and PCAP captures to identify encryption anomalies.
"""
import math
from pathlib import Path
from typing import Dict, Any, Union


def calculate_shannon_entropy(data: Any) -> Dict[str, Any]:
    if isinstance(data, str):
        payload_bytes = data.encode('utf-8')
    elif isinstance(data, bytes):
        payload_bytes = data
    else:
        payload_bytes = str(data).encode('utf-8')

    if not payload_bytes:
        return {
            "entropy": 0.0,
            "byte_count": 0,
            "is_high_entropy": False,
            "assessment": "EMPTY_PAYLOAD"
        }

    length = len(payload_bytes)
    freq = {}
    for b in payload_bytes:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    # Shannon entropy max is 8.0 bits per byte
    is_high_entropy = entropy >= 7.2
    assessment = "HIGH_ENTROPY_ENCRYPTED_OR_PACKED" if is_high_entropy else "PLAINTEXT_OR_STRUCTURED"

    return {
        "entropy": round(entropy, 4),
        "byte_count": length,
        "is_high_entropy": is_high_entropy,
        "assessment": assessment,
        "unique_bytes": len(freq)
    }


def calculate_pcap_payload_entropy(file_path_or_data: Union[str, Path, bytes]) -> Dict[str, Any]:
    p = Path(file_path_or_data) if isinstance(file_path_or_data, (str, Path)) else None
    if p and p.exists() and p.is_file():
        try:
            content = p.read_bytes()
            res = calculate_shannon_entropy(content)
            res["artifact_name"] = p.name
            return res
        except Exception as e:
            return {"entropy": 0.0, "error": str(e), "is_high_entropy": False, "assessment": "ERROR"}
    return calculate_shannon_entropy(file_path_or_data)
