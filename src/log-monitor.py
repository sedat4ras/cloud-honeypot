import time
import subprocess
import requests
import threading
import re
import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# SETTINGS
CONTAINER_NAME = "sentinel-honey"

# Retrieve Webhook URL from environment variables (Security Best Practice)
WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL")

if not WEBHOOK_URL:
    print(">> ERROR: N8N_WEBHOOK_URL not found in .env file.")
    print(">> Please create a .env file and add your webhook URL.")
    sys.exit(1)

sessions = {}

def send_to_n8n(session_id):
    if session_id in sessions:
        data = sessions[session_id]
        if len(data['logs']) > 0:
            try:
                payload = {
                    "ip": data['ip'],
                    "session": session_id,
                    "event_count": len(data['logs']),
                    "full_logs": "\n".join(data['logs'])
                }
                # Sending session summary to n8n
                response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
                print(f">> SUCCESS: Session for {data['ip']} sent to n8n. Status: {response.status_code}")
            except Exception as e:
                print(f">> ERROR: Failed to send data: {e}")
        del sessions[session_id]

def watch_logs():
    print(f">> Sentinel v2.2 Global: Monitoring '{CONTAINER_NAME}' logs...")
    print(f">> Mode: Credit Saver Active (Only real-time logs)")
    
    # We use '--since 1s' to prevent n8n credit exhaustion from old logs
    # Note: Requires user to have docker permissions or run as root
    try:
        process = subprocess.Popen(
            ['docker', 'logs', '--since', '1s', '-f', CONTAINER_NAME],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
    except FileNotFoundError:
        print(">> ERROR: Docker command not found. Make sure Docker is installed.")
        return

    for line in process.stdout:
        line = line.strip()
        if not line: continue
        
        # Parse logs using Regex
        match = re.search(r'\[HoneyPotSSHTransport,(\d+),([\d.]+)\]\s+(.*)', line)
        
        if match:
            session_id = match.group(1)
            ip_addr = match.group(2)
            message = match.group(3)

            if session_id not in sessions:
                sessions[session_id] = {"ip": ip_addr, "logs": [], "timer": None}
                print(f">> NEW INTRUSION: {ip_addr} (Session: {session_id})")

            # Collect log messages for this session
            sessions[session_id]["logs"].append(message)

            # Reset the 120-second timer on every new activity
            if sessions[session_id]["timer"]:
                sessions[session_id]["timer"].cancel()

            # Wait 120 seconds of inactivity before sending the final report
            t = threading.Timer(120, send_to_n8n, [session_id])
            sessions[session_id]["timer"] = t
            t.start()

if __name__ == "__main__":
    watch_logs()