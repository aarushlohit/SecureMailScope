"""
Generates local demo fixtures under demo/ folder:
demo/clean/
demo/starttls-anomaly/
demo/weak-crypto/
demo/incomplete-capture/
demo/tls13/
"""
from pathlib import Path
from securemailscope.core.config import BASE_DIR
from securemailscope.ml.dataset_generator import DatasetGenerator

DEMO_DIR = BASE_DIR / "demo"

def generate_fixtures():
    scenarios = {
        "clean": ("SECURE_BASELINE", DEMO_DIR / "clean" / "clean_smtp_tls12.pcap", "DEMO FIXTURE: Clean SMTP with valid TLS negotiation."),
        "starttls-anomaly": ("STARTTLS_STRIPPING", DEMO_DIR / "starttls-anomaly" / "starttls_stripping_attack.pcap", "DEMO FIXTURE: STARTTLS accepted followed by plaintext cleartext fallback."),
        "weak-crypto": ("DEPRECATED_TLS", DEMO_DIR / "weak-crypto" / "legacy_tls10_rc4.pcap", "DEMO FIXTURE: Deprecated TLS 1.0 with broken RC4 cipher."),
        "incomplete-capture": ("INCOMPLETE_HANDSHAKE", DEMO_DIR / "incomplete-capture" / "truncated_capture.pcap", "DEMO FIXTURE: Incomplete capture packet drop simulating missing TLS handshake."),
        "tls13": ("SECURE_BASELINE", DEMO_DIR / "tls13" / "modern_tls13_encrypted_cert.pcap", "DEMO FIXTURE: Modern TLS 1.3 with honest NOT_OBSERVABLE certificate exchange.")
    }

    for name, (scen, path, note) in scenarios.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        DatasetGenerator.build_pcap_scenario(scen, path)
        readme = path.parent / "README.md"
        readme.write_text(f"# {name.upper()}\n\n{note}\n\nFile: `{path.name}`\n")
    print("All demo fixtures generated successfully!")

if __name__ == "__main__":
    generate_fixtures()
