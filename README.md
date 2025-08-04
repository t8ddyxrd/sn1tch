<h1 align="center">🕵️‍♂️ sN1TCH</h1>
<p align="center">⚡ Real-Time Log Monitoring & Threat Detection for Linux Servers ⚡</p>

---

## 🚀 Features

✨ Real-time log monitoring  
🌍 GeoIP location tagging  
🛑 Auto-block malicious IPs via UFW or iptables  
🧠 Threat stats: failed logins, unique IPs, timestamps  
📤 Export logs with `--save`  
🎯 Filter by country, ISP, and more  
📡 Discord webhook alerts  

---

## 📸 Sneak Peek

> 🔔 **Real-time alerts in your Discord server**  
<img width="1263" height="719" alt="image" src="https://github.com/user-attachments/assets/130b8b6f-6204-494e-a306-c6e99538445d" />

## 🛠️ Usage

~~~bash
# 🕵️ Monitor a log file live
python3 sn1tch.py --file /var/log/auth.log

# 💾 Save detected events to a file
python3 sn1tch.py --file /var/log/auth.log --save alerts.txt

# 🔐 Auto-block brute-force IPs
python3 sn1tch.py --file /var/log/auth.log --block

# 🌐 Country/ISP filter
python3 sn1tch.py --file /var/log/auth.log --country "RU" --isp "EvilCorp"

# 📡 Discord webhook alerts
python3 sn1tch.py --file /var/log/auth.log --webhook https://discord.com/api/webhooks/XXXX
~~~
🔧 Requirements:

    Python 3.8+

    requests

    geoip2 or pygeoip

    argparse

🧠 Permissions:

You might need sudo for:

    UFW/IPTables blocking

    Reading protected log files like /var/log/auth.log

👤 Author:

Built with ❤️ by @t8ddyxrd
💼 Cybersecurity Enthusiast • SOC Ready • Terminal Samurai



