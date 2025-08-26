import os
import subprocess
import requests
from collections import defaultdict
from datetime import datetime, timedelta
from dotenv import load_dotenv
from log_parser import SSHLogParser

load_dotenv()

# Konfigurasi
MAX_FAILED = 5
TIME_WINDOW = timedelta(minutes=2)
failed_attempts = defaultdict(list)
ALERT_LOG_PATH = os.getenv("ALERT_LOG_PATH", "alert.log")

# Telegram
TELEGRAM_ENABLED = os.getenv("TELEGRAM_ENABLED", "True") == "True"
TELEGRAM_TOKEN = os.getenv("YOUR_TOKEN_BOT")
TELEGRAM_CHAT_ID = os.getenv("YOUR_ID_CHAAT")

def log_alert(msg):
    print(f"[ALERT] {msg}")
    with open(ALERT_LOG_PATH, "a") as f:
        f.write(f"{datetime.now()} - {msg}\n")

def send_telegram(msg):
    if not TELEGRAM_ENABLED:
        return
    url = f"YOUR_URL_BOT"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": f" IDS Alert:\n{msg}"}
    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"[!] Gagal kirim Telegram: {e}")

def send_alert(msg):
    log_alert(msg)
    send_telegram(msg)

def monitor_ssh_log():
    print("📡 IDS aktif... Mendeteksi aktivitas SSH...\n")
    parser = SSHLogParser()
    process = subprocess.Popen(
        # ["journalctl", "-f", "-n", "0"],
        ["journalctl", "-u", "sshd", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    recent_failures = defaultdict(list)

    while True:
        line = process.stdout.readline()
        if not line:
            continue

        print(f"[LOG] {line.strip()}")
        parsed = parser.parse(line)
        if not parsed:
            continue

        ip = parsed["ip"]
        now = datetime.now()

        # Brute-force
        if parsed["event"] == "failed_ssh":
            failed_attempts[ip].append(now)
            recent = [t for t in failed_attempts[ip] if now - t <= TIME_WINDOW]
            failed_attempts[ip] = recent

            if len(recent) >= MAX_FAILED:
                send_alert(f"Brute-force dari IP {ip} sebanyak {len(recent)}x")
                failed_attempts[ip].clear()

        # Deteksi login mencurigakan
        elif parsed["event"] == "successful_ssh":
            recent = [t for t in failed_attempts[ip] if now - t <= TIME_WINDOW]
            if len(recent) > 0:
                send_alert(f"Login mencurigakan: IP {ip} berhasil login setelah beberapa gagal sebelumnya.")
                failed_attempts[ip].clear()

        # Deteksi user tidak valid
        elif parsed["event"] == "invalid_user":
            send_alert(f"Login dengan user tidak valid dari IP {ip}.")

    
        if len(recent) >= 3 and all((recent[i] - recent[i-1]) > timedelta(seconds=15) for i in range(1, len(recent))):
            send_alert(f"Slow brute-force terdeteksi dari IP {ip}.")
            failed_attempts[ip].clear() 

        # Distributed brute-force
        elif parsed["event"] == "distributed_brute_force":
            send_alert(f"Distributed brute-force terdeteksi dari IP {ip}.")

        # Login ke root
        elif parsed["event"] == "login_root":
            send_alert(f"Login ke user root terdeteksi dari IP {ip}.")

if __name__ == "__main__":
    try:
        monitor_ssh_log()
    except KeyboardInterrupt:
        print(" IDS dihentikan.")
