"""
SecureMailScope - DNS & Email Security Policy Tools
Performs real DNS queries for MX, SPF, DMARC, MTA-STS, and TLSA (DANE).
"""
import re
import ipaddress
from typing import Dict, Any, List
try:
    import dns.resolver
except ImportError:
    dns = None


BLOCKED_HOSTNAMES = {"localhost", "127.0.0.1", "0.0.0.0", "metadata.google.internal", "instance-data"}


def _clean_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if "@" in domain:
        domain = domain.split("@")[-1]
    return re.sub(r"[^a-z0-9\.\-]", "", domain)


def is_ssrf_safe_domain(domain: str) -> bool:
    cleaned = _clean_domain(domain)
    if not cleaned or cleaned in BLOCKED_HOSTNAMES or cleaned.endswith(".local") or cleaned.endswith(".internal"):
        return False
    try:
        ip = ipaddress.ip_address(cleaned)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False
    except ValueError:
        pass
    return True



class DNSSecurityTools:
    """Queries public DNS records for email domain authentication."""

    @classmethod
    def query_mx(cls, domain: str) -> Dict[str, Any]:
        if not is_ssrf_safe_domain(domain):
            return {"status": "BLOCKED", "domain": domain, "error": "Domain blocked by SSRF protection policy.", "records": [], "has_mx": False}
        domain = _clean_domain(domain)
        if not dns:
            return {"status": "UNAVAILABLE", "domain": domain, "records": []}
        try:
            answers = dns.resolver.resolve(domain, 'MX', lifetime=5.0)
            records = [{"preference": r.preference, "exchange": str(r.exchange).rstrip(".")} for r in answers]
            records.sort(key=lambda x: x["preference"])
            return {"status": "SUCCESS", "domain": domain, "records": records, "has_mx": len(records) > 0}
        except Exception as e:
            return {"status": "ERROR", "domain": domain, "error": str(e), "has_mx": False}

    @classmethod
    def query_spf(cls, domain: str) -> Dict[str, Any]:
        if not is_ssrf_safe_domain(domain):
            return {"status": "BLOCKED", "domain": domain, "error": "Domain blocked by SSRF protection policy.", "has_spf": False}
        domain = _clean_domain(domain)
        if not dns:
            return {"status": "UNAVAILABLE", "domain": domain, "record": None}
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=5.0)
            spf_record = None
            for r in answers:
                txt = "".join([part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part) for part in r.strings])
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break
            return {
                "status": "SUCCESS",
                "domain": domain,
                "has_spf": spf_record is not None,
                "spf_record": spf_record
            }
        except Exception as e:
            return {"status": "ERROR", "domain": domain, "error": str(e), "has_spf": False}

    @classmethod
    def query_dmarc(cls, domain: str) -> Dict[str, Any]:
        if not is_ssrf_safe_domain(domain):
            return {"status": "BLOCKED", "domain": domain, "error": "Domain blocked by SSRF protection policy.", "has_dmarc": False}
        domain = _clean_domain(domain)
        if not dns:
            return {"status": "UNAVAILABLE", "domain": domain, "record": None}
        dmarc_target = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_target, 'TXT', lifetime=5.0)
            dmarc_record = None
            for r in answers:
                txt = "".join([part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part) for part in r.strings])
                if txt.startswith("v=DMARC1"):
                    dmarc_record = txt
                    break
            return {
                "status": "SUCCESS",
                "domain": domain,
                "has_dmarc": dmarc_record is not None,
                "dmarc_record": dmarc_record
            }
        except Exception as e:
            return {"status": "ERROR", "domain": domain, "error": str(e), "has_dmarc": False}

    @classmethod
    def query_mta_sts(cls, domain: str) -> Dict[str, Any]:
        if not is_ssrf_safe_domain(domain):
            return {"status": "BLOCKED", "domain": domain, "error": "Domain blocked by SSRF protection policy.", "has_mta_sts": False}
        domain = _clean_domain(domain)
        if not dns:
            return {"status": "UNAVAILABLE", "domain": domain, "record": None}
        mta_sts_target = f"_mta-sts.{domain}"
        try:
            answers = dns.resolver.resolve(mta_sts_target, 'TXT', lifetime=5.0)
            sts_record = None
            for r in answers:
                txt = "".join([part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part) for part in r.strings])
                if "v=STSv1" in txt:
                    sts_record = txt
                    break
            return {
                "status": "SUCCESS",
                "domain": domain,
                "has_mta_sts": sts_record is not None,
                "record": sts_record
            }
        except Exception as e:
            return {"status": "ERROR", "domain": domain, "error": str(e), "has_mta_sts": False}

    @classmethod
    def query_tlsa(cls, domain: str, port: int = 25) -> Dict[str, Any]:
        if not is_ssrf_safe_domain(domain):
            return {"status": "BLOCKED", "domain": domain, "error": "Domain blocked by SSRF protection policy.", "has_dane_tlsa": False}
        domain = _clean_domain(domain)
        if not dns:
            return {"status": "UNAVAILABLE", "domain": domain, "record": None}
        tlsa_target = f"_{port}._tcp.{domain}"
        try:
            answers = dns.resolver.resolve(tlsa_target, 'TLSA', lifetime=5.0)
            records = [str(r) for r in answers]
            return {
                "status": "SUCCESS",
                "domain": domain,
                "port": port,
                "has_dane_tlsa": len(records) > 0,
                "records": records
            }
        except Exception as e:
            return {"status": "ERROR", "domain": domain, "port": port, "error": str(e), "has_dane_tlsa": False}
