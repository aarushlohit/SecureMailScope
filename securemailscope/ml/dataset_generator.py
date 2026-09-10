"""
SecureMailScope - Synthetic PCAP & Feature Dataset Generator
"""
import struct
import random
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from scapy.all import wrpcap, Ether, IP, TCP, Raw
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone, timedelta
from securemailscope.core.config import SAMPLES_DIR

CLASS_NAMES = [
    "SECURE_BASELINE",
    "DEPRECATED_TLS",
    "WEAK_CIPHER",
    "WEAK_CERTIFICATE",
    "CERTIFICATE_ANOMALY",
    "STARTTLS_STRIPPING",
    "PLAINTEXT_FALLBACK",
    "INCOMPLETE_HANDSHAKE"
]


class DatasetGenerator:
    """
    Generates synthetic PCAP files and tabular training datasets
    representing the 8 cryptographic email communication scenarios.
    """

    @staticmethod
    def generate_self_signed_cert_der(expired: bool = False, weak_key: bool = False, weak_sig: bool = False, hostname: str = "mail.example.com") -> bytes:
        key_size = 1024 if weak_key else 2048
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Demo Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        now = datetime.now(timezone.utc)
        if expired:
            not_before = now - timedelta(days=365)
            not_after = now - timedelta(days=10)
        else:
            not_before = now - timedelta(days=1)
            not_after = now + timedelta(days=365)

        sig_hash = hashes.SHA256()

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .sign(key, sig_hash)
        )
        return cert.public_bytes(serialization.Encoding.DER)

    @staticmethod
    def create_tls_client_hello_payload(tls_version: int = 0x0303, cipher_codes: List[int] = None, sni: str = "mail.example.com") -> bytes:
        if cipher_codes is None:
            cipher_codes = [0xC02F, 0xC030, 0x1301]
        
        rand_bytes = b"\x00" * 32
        sess_id = b"\x00"
        c_bytes = b"".join(struct.pack("!H", c) for c in cipher_codes)
        c_len = struct.pack("!H", len(c_bytes))
        comp = b"\x01\x00"

        # Extensions: SNI
        sni_bytes = sni.encode("utf-8")
        sni_ext = struct.pack("!HHH", 0x0000, len(sni_bytes) + 5, len(sni_bytes) + 3) + b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes

        # Extension: supported_versions if TLS 1.3
        supp_ver_ext = b""
        if 0x1301 in cipher_codes or tls_version == 0x0304:
            supp_ver_ext = struct.pack("!HHB", 0x002B, 3, 2) + struct.pack("!H", 0x0304)

        extensions = sni_ext + supp_ver_ext
        ext_len = struct.pack("!H", len(extensions))

        ch_body = struct.pack("!H", tls_version) + rand_bytes + sess_id + c_len + c_bytes + comp + ext_len + extensions
        ch_header = b"\x01" + struct.pack("!I", len(ch_body))[1:]
        handshake_msg = ch_header + ch_body

        # TLS Record Header
        rec_header = struct.pack("!BHH", 0x16, 0x0301, len(handshake_msg))
        return rec_header + handshake_msg

    @staticmethod
    def create_tls_server_hello_payload(tls_version: int = 0x0303, selected_cipher: int = 0xC02F, cert_der: Optional[bytes] = None) -> bytes:
        rand_bytes = b"\x01" * 32
        sess_id = b"\x00"
        sh_body = struct.pack("!H", tls_version) + rand_bytes + sess_id + struct.pack("!H", selected_cipher) + b"\x00"
        
        # Extensions for TLS 1.3
        if tls_version == 0x0304 or selected_cipher in (0x1301, 0x1302, 0x1303):
            supp_ver_ext = struct.pack("!HHH", 0x002B, 2, 0x0304)
            sh_body += struct.pack("!H", len(supp_ver_ext)) + supp_ver_ext

        sh_msg = b"\x02" + struct.pack("!I", len(sh_body))[1:] + sh_body
        records = struct.pack("!BHH", 0x16, 0x0303, len(sh_msg)) + sh_msg

        # If TLS <= 1.2, append Certificate Record
        if cert_der and selected_cipher not in (0x1301, 0x1302, 0x1303):
            cert_msg_body = struct.pack("!I", len(cert_der))[1:] + cert_der
            certs_body = struct.pack("!I", len(cert_msg_body))[1:] + cert_msg_body
            cert_handshake = b"\x0B" + struct.pack("!I", len(certs_body))[1:] + certs_body
            cert_record = struct.pack("!BHH", 0x16, 0x0303, len(cert_handshake)) + cert_handshake
            
            # ServerHelloDone
            sh_done = b"\x0E\x00\x00\x00"
            sh_done_rec = struct.pack("!BHH", 0x16, 0x0303, len(sh_done)) + sh_done
            records += cert_record + sh_done_rec

        return records

    @staticmethod
    def build_pcap_scenario(scenario_name: str, output_path: Path) -> Path:
        packets = []
        c_mac = "02:00:00:00:00:01"
        s_mac = "02:00:00:00:00:02"
        c_ip = "192.168.1.105"
        s_ip = "198.51.100.25"
        c_port = 49152
        s_port = 25
        t = time.time() - 300.0

        c_seq = 1000
        s_seq = 2000

        def send_c2s(payload: bytes, flags: str = "PA"):
            nonlocal c_seq, t
            pkt = Ether(src=c_mac, dst=s_mac)/IP(src=c_ip, dst=s_ip)/TCP(sport=c_port, dport=s_port, flags=flags, seq=c_seq, ack=s_seq)/Raw(load=payload)
            pkt.time = t
            t += 0.02
            c_seq += max(1 if ("S" in flags or "F" in flags) else 0, len(payload))
            packets.append(pkt)

        def send_s2c(payload: bytes, flags: str = "PA"):
            nonlocal s_seq, t
            pkt = Ether(src=s_mac, dst=c_mac)/IP(src=s_ip, dst=c_ip)/TCP(sport=s_port, dport=c_port, flags=flags, seq=s_seq, ack=c_seq)/Raw(load=payload)
            pkt.time = t
            t += 0.02
            s_seq += max(1 if ("S" in flags or "F" in flags) else 0, len(payload))
            packets.append(pkt)

        # 1. TCP 3-Way Handshake
        send_c2s(b"", flags="S")
        send_s2c(b"", flags="SA")
        send_c2s(b"", flags="A")

        if scenario_name in ("STARTTLS_STRIPPING", "PLAINTEXT_FALLBACK"):
            send_s2c(b"220 mail.securebank.com ESMTP Postfix\r\n")
            send_c2s(b"EHLO client.internal.org\r\n")
            send_s2c(b"250-mail.securebank.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 OK\r\n")
            send_c2s(b"STARTTLS\r\n")
            send_s2c(b"220 2.0.0 Ready to start TLS\r\n")
            # ATTACK: Plaintext continues
            send_c2s(b"MAIL FROM:<ceo@internal.org>\r\n")
            send_s2c(b"250 2.1.0 Ok\r\n")
            send_c2s(b"RCPT TO:<finance@securebank.com>\r\n")
            send_s2c(b"250 2.1.5 Ok\r\n")
            send_c2s(b"DATA\r\n")
            send_s2c(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            send_c2s(b"Subject: Urgent Wire Transfer\r\nPlease transfer funds to ACCT-991283.\r\n.\r\n")

        elif scenario_name == "SECURE_BASELINE":
            send_s2c(b"220 mail.defense.gov ESMTP Postfix\r\n")
            send_c2s(b"EHLO workstation.defense.gov\r\n")
            send_s2c(b"250-mail.defense.gov\r\n250-STARTTLS\r\n250 OK\r\n")
            send_c2s(b"STARTTLS\r\n")
            send_s2c(b"220 2.0.0 Ready to start TLS\r\n")
            # TLS 1.3 Handshake
            ch_raw = DatasetGenerator.create_tls_client_hello_payload(tls_version=0x0303, cipher_codes=[0x1301, 0x1302, 0xC02F], sni="mail.defense.gov")
            send_c2s(ch_raw)
            sh_raw = DatasetGenerator.create_tls_server_hello_payload(tls_version=0x0304, selected_cipher=0x1301)
            send_s2c(sh_raw)
            # TLS 1.3 Encrypted Application Data
            app_data = b"\x17\x03\x03\x00\x40" + b"\xFF" * 64
            send_c2s(app_data)

        elif scenario_name in ("DEPRECATED_TLS", "WEAK_CIPHER"):
            send_s2c(b"220 legacy-mail.org ESMTP\r\n")
            send_c2s(b"EHLO oldclient.org\r\n")
            send_s2c(b"250-STARTTLS\r\n250 OK\r\n")
            send_c2s(b"STARTTLS\r\n")
            send_s2c(b"220 Ready\r\n")
            ch_raw = DatasetGenerator.create_tls_client_hello_payload(tls_version=0x0301, cipher_codes=[0x0004, 0x0005, 0x000A], sni="legacy-mail.org")
            send_c2s(ch_raw)
            cert_der = DatasetGenerator.generate_self_signed_cert_der(expired=False, weak_key=True, weak_sig=True, hostname="legacy-mail.org")
            sh_raw = DatasetGenerator.create_tls_server_hello_payload(tls_version=0x0301, selected_cipher=0x0004, cert_der=cert_der)
            send_s2c(sh_raw)

        elif scenario_name in ("WEAK_CERTIFICATE", "CERTIFICATE_ANOMALY"):
            send_s2c(b"* OK IMAP4rev1 Ready\r\n")
            send_c2s(b"a001 STARTTLS\r\n")
            send_s2c(b"a001 OK Begin TLS now\r\n")
            ch_raw = DatasetGenerator.create_tls_client_hello_payload(tls_version=0x0303, cipher_codes=[0xC02F, 0xC030], sni="imap.corporate.net")
            send_c2s(ch_raw)
            cert_der = DatasetGenerator.generate_self_signed_cert_der(expired=True, weak_key=False, weak_sig=False, hostname="unrelated.domain.com")
            sh_raw = DatasetGenerator.create_tls_server_hello_payload(tls_version=0x0303, selected_cipher=0xC02F, cert_der=cert_der)
            send_s2c(sh_raw)

        elif scenario_name == "INCOMPLETE_HANDSHAKE":
            send_s2c(b"+OK POP3 server ready\r\n")
            send_c2s(b"STLS\r\n")
            send_s2c(b"+OK Begin TLS\r\n")
            # Dropped packets simulation: sequence jumps abruptly
            c_seq += 45000
            send_c2s(b"")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), packets)
        return output_path

    @staticmethod
    def generate_all_samples():
        sample_files = {
            "mail_attack_starttls_strip.pcap": "STARTTLS_STRIPPING",
            "mail_secure_tls13.pcap": "SECURE_BASELINE",
            "mail_partial_capture_inconclusive.pcap": "INCOMPLETE_HANDSHAKE",
            "mail_weak_crypto_tls10_rc4.pcap": "DEPRECATED_TLS",
            "mail_imap_cert_expired.pcap": "WEAK_CERTIFICATE",
            "mail_pop3_plaintext_auth.pcap": "PLAINTEXT_FALLBACK"
        }
        for fname, scenario in sample_files.items():
            p = SAMPLES_DIR / fname
            DatasetGenerator.build_pcap_scenario(scenario, p)

    @staticmethod
    def generate_tabular_dataset(num_samples: int = 800) -> Tuple[List[List[float]], List[int]]:
        X = []
        y = []

        for _ in range(num_samples):
            cls_idx = random.randint(0, len(CLASS_NAMES) - 1)
            cls_name = CLASS_NAMES[cls_idx]
            
            if cls_name == "SECURE_BASELINE":
                v = [1.3 if random.random() > 0.3 else 1.2, 1.0, 1.0, 2048.0 if random.random() > 0.5 else 4096.0,
                     0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, random.uniform(98.0, 100.0), random.uniform(20.0, 60.0), random.uniform(2000, 15000)]
            elif cls_name == "DEPRECATED_TLS":
                v = [1.0 if random.random() > 0.5 else 1.1, random.choice([0.2, 0.3, 0.0]), 0.0, 1024.0 if random.random() > 0.5 else 2048.0,
                     random.choice([0.0, 1.0]), 0.0, random.choice([0.0, 1.0]), 1.0, 1.0, 1.0, 0.0, 0.0, random.uniform(95.0, 100.0), random.uniform(40.0, 120.0), random.uniform(1500, 8000)]
            elif cls_name == "WEAK_CIPHER":
                v = [1.2, 0.0 if random.random() > 0.5 else 0.2, 0.0, 2048.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, random.uniform(95.0, 100.0), random.uniform(30.0, 90.0), random.uniform(1500, 9000)]
            elif cls_name == "WEAK_CERTIFICATE":
                v = [1.2, 0.6, 1.0, 1024.0 if random.random() > 0.5 else 512.0, 1.0, 1.0 if random.random() > 0.5 else 0.0, 1.0 if random.random() > 0.4 else 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, random.uniform(95.0, 100.0), random.uniform(30.0, 80.0), random.uniform(2000, 10000)]
            elif cls_name == "CERTIFICATE_ANOMALY":
                v = [1.2, 0.6, 1.0, 2048.0, 1.0, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, random.uniform(95.0, 100.0), random.uniform(30.0, 80.0), random.uniform(2000, 10000)]
            elif cls_name == "STARTTLS_STRIPPING":
                v = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, random.uniform(96.0, 100.0), 0.0, random.uniform(800, 4000)]
            elif cls_name == "PLAINTEXT_FALLBACK":
                v = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0 if random.random() > 0.5 else 0.0, random.uniform(96.0, 100.0), 0.0, random.uniform(1200, 5000)]
            else:  # INCOMPLETE_HANDSHAKE
                v = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, random.uniform(30.0, 58.0), 0.0, random.uniform(300, 1500)]

            X.append(v)
            y.append(cls_idx)

        return X, y
