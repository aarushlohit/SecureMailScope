"""
SecureMailScope - DNS Exfiltration & Tunneling Detector
Inspects DNS queries for high subdomain entropy and covert data exfiltration.
"""
import re
import math
from typing import Dict, Any, List


def detect_dns_exfiltration_in_queries(queries: List[str]) -> Dict[str, Any]:
    suspicious_domains = []
    total_entropy = 0.0

    for query in queries:
        subdomain = query.split('.')[0] if '.' in query else query
        if len(subdomain) > 20:
            # Calculate subdomain entropy
            freq = {}
            for char in subdomain:
                freq[char] = freq.get(char, 0) + 1
            entropy = -sum((c / len(subdomain)) * math.log2(c / len(subdomain)) for c in freq.values())
            if entropy > 3.8:
                suspicious_domains.append({
                    "query": query,
                    "subdomain_length": len(subdomain),
                    "entropy": round(entropy, 3)
                })

    is_exfil = len(suspicious_domains) > 0
    return {
        "is_dns_exfiltration_detected": is_exfil,
        "suspicious_query_count": len(suspicious_domains),
        "suspicious_queries": suspicious_domains,
        "total_queries_analyzed": len(queries)
    }
