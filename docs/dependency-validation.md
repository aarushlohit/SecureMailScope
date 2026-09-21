# SecureMailScope — Dependency & Environment Validation

## 1. System Binary Dependencies

| Binary | System Path | Verified Version | Purpose | Graceful Degradation |
|---|---|---|---|---|
| `tshark` | `/usr/bin/tshark` | 4.6.8 | Deep packet dissection, certificate extraction | Falls back to pure Python Scapy dissector |
| `capinfos` | `/usr/bin/capinfos` | 4.6.8 | Capture framing statistics and packet timing | Falls back to internal Scapy packet metadata |
| `openssl` | `/usr/bin/openssl` | 3.5.8 | Direct X.509 certificate parsing | Falls back to `cryptography.x509` |
| `zeek` | `N/A` | `Optional` | High-level connection logging | Optional enhancement; graceful degradation active |

## 2. Python Package Dependencies

| Package | Version | Import | Purpose |
|---|---|---|---|
| `fastapi` | 0.115.14 | `fastapi` | REST API framework |
| `uvicorn` | 0.41.0 | `uvicorn` | ASGI server |
| `pydantic` | 2.13.0 | `pydantic` | Data validation and schemas |
| `scapy` | 2.7.0 | `scapy` | Passive PCAP dissection and synthesis |
| `xgboost` | 3.4.1 | `xgboost` | Gradient boosted tree risk classifier |
| `scikit-learn` | 1.9.0 | `sklearn` | Machine learning metrics and benchmark splits |
| `shap` | 0.52.0 | `shap` | TreeExplainer feature attribution |
| `mail-parser` | 4.6.5 | `mailparser` | RFC-2822 email artifact parsing |
| `cryptography` | 46.0.7 | `cryptography` | X.509 certificate parsing and key inspection |
| `sqlalchemy` | 2.0.48 | `sqlalchemy` | SQL database persistence and ORM |
| `sse-starlette`| 3.4.11 | `sse_starlette` | Real-time Server-Sent Events |
| `reportlab` | 4.4.14 | `reportlab` | Audit-grade PDF report compilation |
| `jinja2` | 3.1.6 | `jinja2` | Standalone HTML report templating |
| `dnspython` | 2.8.0 | `dns` | DNS security record resolution (SPF, DMARC, TLSA, MTA-STS) |
| `pytest` | 9.1.1 | `pytest` | Automated test suite execution |

## 3. System Verification Command
Run the built-in system verification tool:
```bash
python -m securemailscope.cli system-check
```
