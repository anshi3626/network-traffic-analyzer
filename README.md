PACKET SENTINEL
===============
Run:
  1. pip install -r requirements.txt
  2. python app.py
  3. Open http://127.0.0.1:5000

CSV:
  - App pehle uploaded file, phir app.py ke folder ki .csv, phir data/sample_packets.csv use karta hai.
  - Wireshark export (No., Time, Source, Destination, Protocol, Length, Info) ya
    Source IP / Destination IP / Protocol / Length / Src Port / Dst Port wali CSV chalti hai.
  - Sidebar ke "Upload CSV" se koi bhi CSV chala sakte ho.

Detection rules (app.py ke upar numbers badal sakte ho):
  - Port scan, SYN flood, ICMP flood, High traffic, Suspicious ports (4444, 6667, 31337 ...)

Files:
  app.py, templates/index.html, static/style.css, static/app.js, data/sample_packets.csv

IP LOOKUP (internet chahiye)
  - Location (country, city, provider) ip-api.com se aata hai, key ki zaroorat nahi.
  - Reputation (AbuseIPDB) ke liye free key lo: https://www.abuseipdb.com (account -> API).
    Windows CMD mein server chalane se pehle:
        set ABUSEIPDB_KEY=teri_key_yahan
        python app.py
    PowerShell mein:
        $env:ABUSEIPDB_KEY="teri_key_yahan"
        python app.py
  - Note: lookup ki gayi IPs in third-party services ko bheji jaati hain.
  - Packets page par kisi IP par click karo -> upar details card khulta hai.

NAYE DETECTIONS (offline)
  - IP risk score (0-100): har finding ke points jodke. Overview par "Riskiest devices".
  - DNS analysis: top domains chart + random-looking (malware-style) domains flag.
  - Beaconing: ek hi outside server ko bahut regular timing se contact (app.py: BEACON_*).
  - Data exfiltration: local device se ek outside IP par bahut zyada upload (app.py: EXFIL_MIN_BYTES).

IGNORE LIST
  - Alerts page par "Ignore <IP>" dabao, ya Packets page par IP card ka "Ignore alerts for this IP".
  - Entries data/whitelist.txt mein save hoti hain (IP ya range jaise 192.168.1.0/24). Alerts page par Remove kar sakte ho.
