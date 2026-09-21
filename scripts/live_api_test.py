import httpx
import time

BASE_URL = "http://127.0.0.1:8000"
client = httpx.Client()

print("1. Creating User & Logging in")
signup_res = client.post(f"{BASE_URL}/api/auth/signup", json={"email": "live_test2@soc.internal", "password": "password123"})
login_res = client.post(f"{BASE_URL}/api/auth/login", data={"username": "live_test2@soc.internal", "password": "password123"})
client.headers.update({"Authorization": f"Bearer {login_res.json().get('access_token')}"})
print(f"Login Status: {login_res.status_code}")

def test_pcap(filepath, label):
    print(f"\n--- Testing {label} ({filepath}) ---")
    with open(filepath, "rb") as f:
        upload_res = client.post(f"{BASE_URL}/api/investigations", files={"file": (filepath.split("/")[-1], f, "application/vnd.tcpdump.pcap")})
    
    if upload_res.status_code != 200:
        print("Upload failed:", upload_res.text)
        return
        
    inv_id = upload_res.json()["investigation_id"]
    print(f"Uploaded! ID: {inv_id}")
    
    # Poll for completion
    for _ in range(15):
        time.sleep(2)
        status_res = client.get(f"{BASE_URL}/api/investigations/{inv_id}")
        data = status_res.json()
        status = data.get("status")
        print(f"Status: {status}")
        if status in ("COMPLETED", "FAILED"):
            break
            
    # Fetch findings
    findings = client.get(f"{BASE_URL}/api/investigations/{inv_id}/findings").json()
    print(f"Findings ({len(findings)}):")
    for f in findings:
        print(f" - {f.get('title')} (Sev: {f.get('severity')})")
        
    # Fetch AI Run details
    try:
        import sqlite3
        conn = sqlite3.connect('data/securemailscope.db')
        cur = conn.cursor()
        cur.execute("SELECT llm_provider, llm_model, steps_count FROM agent_runs WHERE investigation_id=?", (inv_id,))
        run_data = cur.fetchone()
        if run_data:
            print(f"LLM Provider: {run_data[0]}, Model: {run_data[1]}, Steps: {run_data[2]}")
        conn.close()
    except Exception as e:
        print("DB check failed", e)

test_pcap("samples/wireshark_real_smtp.pcap", "SMTP PCAP")
test_pcap("samples/wireshark_real_imap.pcap", "IMAP PCAP")
