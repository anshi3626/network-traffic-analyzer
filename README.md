# 🌐 Network Traffic Analyzer

A Flask web app that analyzes network packet captures (CSV) and highlights suspicious activity such as port scans, SYN floods, beaconing, data exfiltration, and malware-style DNS lookups. Upload a Wireshark CSV export and get an interactive dashboard with a network map, charts, risk scores, and alerts.

## Features

- **Overview dashboard**: verdict summary, key stats, network map, traffic timeline, protocol breakdown, top sending IPs, top destination ports
- **Packets view**: searchable, sortable, filterable packet table with risk labels and CSV download of filtered rows
- **Alerts view**: all findings sorted by severity, downloadable as CSV, printable report
- **IP risk score (0-100)**: points from every finding added up per IP, shown as "Riskiest devices"
- **DNS analysis**: most requested domains and detection of random-looking domains
- **IP lookup**: click any public IP to see country, city and ISP (uses the free ip-api.com service, internet required)
- **Country traffic chart**: data volume uploaded/downloaded per country
- **Ignore list**: whitelist trusted IPs or ranges (e.g. `192.168.1.0/24`) so they never raise alerts

## Detection Rules

| Detection | What it looks for |
|---|---|
| Port scan | One IP touching many different destination ports |
| SYN flood | Many SYN-only packets from one IP |
| ICMP flood | Many ICMP (ping) packets from one IP |
| High traffic | An IP sending far more packets than normal |
| Suspicious ports | Known risky ports (23, 1337, 3389, 4444, 5555, 6667, 9001, 12345, 31337) |
| Suspicious domains | Random-looking DNS names (DGA-style, common in malware) |
| Beaconing | Very regular timing of contacts to one outside server |
| Large upload | A local device sending a lot of data to one outside IP (possible data exfiltration) |

All detection runs offline on your machine. Only the IP lookup and country chart need internet.

## Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, JavaScript, Chart.js (loaded from CDN)

## Project Structure

```
network-traffic-analyzer/
├── app.py                  # Flask server, CSV parsing, detection logic, API routes
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # Dashboard page
├── static/
│   ├── app.js              # Frontend logic (charts, map, tables, filters)
│   └── style.css           # Styling
└── data/
    └── sample_packets.csv  # Sample capture used as default data
```

`data/uploaded.csv` and `data/whitelist.txt` are created automatically at runtime.

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/anshi3626/network-traffic-analyzer
cd network-traffic-analyzer
```

### 2. (Optional) Create a virtual environment

```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS / Linux
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser. To use a different port, set the `PORT` environment variable.

## Usage

1. Click **Upload CSV** in the sidebar and choose your capture file.
2. Explore the **Overview**, **Packets**, and **Alerts** pages.
3. Click any IP to see its packets and look up its location.
4. Use **Ignore** on trusted IPs to remove them from alerts.
5. Click **Use default data** to go back to the sample file.

**Which file gets analyzed?** The app picks the first available in this order: uploaded file, then any `.csv` next to `app.py`, then `data/sample_packets.csv`.

## Supported CSV Format

**Wireshark export**: `No., Time, Source, Destination, Protocol, Length, Info`

**Simple CSV**: `Source IP, Destination IP, Protocol, Length, Src Port, Dst Port`

- `Source` and `Destination` columns are required. Column names are matched flexibly (case and symbols are ignored).
- Ports are read from the `Info` column (e.g. `49822 → 443 [SYN]`) if there are no port columns.
- Max upload size is 25 MB, and only the first 50,000 rows are analyzed.

## Configuration

Detection thresholds are constants at the top of `app.py`:

```python
PORT_SCAN_MIN_PORTS = 15
SYN_FLOOD_MIN = 25
ICMP_FLOOD_MIN = 25
HIGH_TRAFFIC_MIN = 60
EXFIL_MIN_BYTES = 500_000
BEACON_MIN_EVENTS = 6
BEACON_MAX_JITTER = 0.15
```

Lower values make detection stricter, higher values make it looser.

### Optional: IP reputation (AbuseIPDB)

This is **off by default**. To also show an abuse score in the IP details card, get a free API key from [abuseipdb.com](https://www.abuseipdb.com) and set it before starting the server:

```bash
# Windows CMD
set ABUSEIPDB_KEY=your_key_here

# PowerShell
$env:ABUSEIPDB_KEY="your_key_here"

# macOS / Linux
export ABUSEIPDB_KEY=your_key_here

python app.py
```

## API Endpoints

| Method | Route | Description |
|---|---|---|
| GET | `/` | Dashboard page |
| GET | `/api/data` | Stats, alerts and packets for the current dataset |
| POST | `/upload` | Upload a CSV file |
| POST | `/reset` | Remove uploaded file, go back to default data |
| GET | `/api/ip/<ip>` | IP location lookup (and reputation if enabled) |
| GET | `/api/countries` | Traffic volume per country |
| POST | `/api/whitelist` | Add an IP/range to the ignore list |
| POST | `/api/whitelist/remove` | Remove an entry from the ignore list |
| GET | `/export/alerts.csv` | Download alerts as CSV |

## Privacy Note

IP lookups send the looked-up public IP addresses to ip-api.com (and to AbuseIPDB if you enable it). Local/private IPs are never sent. Uploaded files are processed on your own machine.

