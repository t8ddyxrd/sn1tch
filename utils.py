import os
import json
import subprocess  
import requests 
from datetime import datetime

DATA_DIR = "data"
OUTPUT_FILE = os.path.join(DATA_DIR, "output.json")
BLOCKED_FILE = os.path.join(DATA_DIR, "blocked.txt")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")


def save_results(results):
    """Save IPs + attempts + location to data/output.json"""
    os.makedirs(DATA_DIR, exist_ok=True)

    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "entries": results
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[+] Results saved to {OUTPUT_FILE}")


def is_blocked(ip):
    """Check if IP has already been blocked"""
    if not os.path.exists(BLOCKED_FILE):
        return False
    with open(BLOCKED_FILE, "r") as f:
        return ip in f.read()


def block_ip(ip):
    """Block the given IP using ufw (skips if already blocked)"""
    if is_blocked(ip):
        print(f"[-] IP {ip} already blocked. Skipping.")
        return

    try:
        result = subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(BLOCKED_FILE, "a") as f:
                f.write(f"{ip} - blocked at {datetime.now()}\n")
            print(f"[+] Blocked IP: {ip}")
        else:
            print(f"[!] Failed to block IP {ip}:\n{result.stderr}")
    except Exception as e:
        print(f"[!] Error blocking IP {ip}: {e}")


def get_stats(failed_attempts):
    """Return stats: total attempts, unique IPs"""
    total_attempts = sum(failed_attempts.values())
    unique_ips = len(failed_attempts)
    return {
        "total_failed_attempts": total_attempts,
        "unique_ips": unique_ips
    }


def load_config():
    """Load country/ISP ignore config + Discord webhook"""
    if not os.path.exists(CONFIG_FILE):
        return {
            "ignore_countries": [],
            "ignore_isps": [],
            "discord_webhook": ""
        }

    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {
            "ignore_countries": [],
            "ignore_isps": [],
            "discord_webhook": ""
        }


def send_discord_alert(ip, attempts, location):
    """Send Discord alert using webhook in config.json"""
    config = load_config()
    webhook_url = config.get("discord_webhook")

    if not webhook_url:
        print("[!] No Discord webhook URL set in config.json.")
        return

    message = {
        "embeds": [
            {
                "title": "🚨 Brute Force Detected",
                "color": 16711680,
                "fields": [
                    {"name": "IP Address", "value": ip, "inline": True},
                    {"name": "Failed Attempts", "value": str(attempts), "inline": True},
                    {"name": "Location", "value": location, "inline": False}
                ],
                "footer": {
                    "text": "sN1TCH v1.0 by t8ddy"
                },
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
    }

    try:
        res = requests.post(webhook_url, json=message)
        if res.status_code == 204:
            print(f"[+] Alert sent to Discord for {ip}")
        else:
            print(f"[!] Failed to send alert: {res.status_code} - {res.text}")
    except Exception as e:
        print(f"[!] Error sending Discord alert: {e}")
