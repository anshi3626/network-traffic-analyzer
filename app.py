"""
Packet Sentinel - network packet CSV analyzer (Flask)

Run:   python app.py
Open:  http://127.0.0.1:5000

Works with Wireshark CSV exports (No., Time, Source, Destination, Protocol,
Length, Info) and also with simple CSVs that have columns like
Source IP, Destination IP, Protocol, Length, Src Port, Dst Port.
"""
import csv
import glob
import io
import ipaddress
import json
import math
import os
import re
import statistics
import urllib.request
from collections import Counter, defaultdict

from flask import Flask, Response, jsonify, render_template, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_PATH = os.path.join(DATA_DIR, "uploaded.csv")
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB upload limit

# ----------------------------------------------------------------------------
# Detection settings - change these numbers to make detection stricter/looser
# ----------------------------------------------------------------------------
PORT_SCAN_MIN_PORTS = 15      # one IP touching this many different ports = port scan
SYN_FLOOD_MIN = 25            # this many SYN-only packets from one IP = SYN flood
ICMP_FLOOD_MIN = 25           # this many ICMP packets from one IP = ping flood
HIGH_TRAFFIC_MIN = 60         # an IP must send at least this many packets to count as "high traffic"
EXFIL_MIN_BYTES = 500_000     # a local device uploading this much to ONE outside IP (and far more than it downloads)
BEACON_MIN_EVENTS = 6         # contacts to the same server/port before we check timing
BEACON_MIN_INTERVAL = 2.0     # ignore fast chatter; beacons are usually seconds or minutes apart
BEACON_MAX_JITTER = 0.15      # timing this regular (15% variation or less) looks automated
MAX_ROWS = 50000              # safety cap for very large files

SUSPICIOUS_PORTS = {
    23: "Telnet (unencrypted remote login)",
    1337: "Common backdoor port",
    3389: "RDP (remote desktop)",
    4444: "Metasploit default port",
    5555: "Android debug / RAT port",
    6667: "IRC (often used by botnets)",
    9001: "Tor relay port",
    12345: "NetBus trojan port",
    31337: "Back Orifice trojan port",
}

# How many risk points each finding adds to an IP (score is capped at 100)
POINTS = {"Port scan": 40, "SYN flood": 30, "Large upload": 20, "Beaconing": 25,
          "ICMP flood": 15, "Suspicious port": 15, "Suspicious domain": 15, "High traffic": 10}

# Header names we recognise (compared after lowercasing and removing symbols)
ALIASES = {
    "src": ["source", "sourceip", "srcip", "src", "ipsrc", "sourceaddress", "srcaddress"],
    "dst": ["destination", "destinationip", "dstip", "dst", "ipdst", "destinationaddress", "dstaddress", "destip"],
    "proto": ["protocol", "proto"],
    "length": ["length", "len", "size", "bytes", "framelen", "framelength", "packetsize"],
    "time": ["time", "timestamp", "frametime", "framerelativetime"],
    "sport": ["srcport", "sourceport", "sport", "tcpsrcport", "udpsrcport"],
    "dport": ["dstport", "destinationport", "dport", "destport", "tcpdstport", "udpdstport"],
    "info": ["info", "description", "summary"],
}

# Wireshark puts ports inside Info, like "49822 → 443 [SYN] Seq=0"
PORT_RE = re.compile(r"(\d{1,5})\s*(?:→|->|>)\s*(\d{1,5})")


# ----------------------------------------------------------------------------
# CSV reading
# ----------------------------------------------------------------------------
def _norm(header):
    return re.sub(r"[^a-z0-9]", "", (header or "").lower())


def _map_headers(fieldnames):
    normed = {_norm(f): f for f in fieldnames if f}
    mapping = {}
    for key, names in ALIASES.items():
        for name in names:
            if name in normed:
                mapping[key] = normed[name]
                break
    return mapping


DOMAIN_RE = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _entropy(text):
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values()) if n else 0.0


def _extract_domain(r):
    """Domain name from a DNS *query* row, or None."""
    info = r["info"].lower()
    if r["proto"] not in ("DNS", "MDNS") or "query" not in info or "response" in info:
        return None
    for token in DOMAIN_RE.findall(info):
        token = token.rstrip(".")
        if token.endswith((".local", ".arpa")) or re.fullmatch(r"[0-9.]+", token):
            continue
        return token
    return None


def _looks_generated(domain):
    """Random-looking names like xk3j9qz2plmv.com (typical of malware, called DGA)."""
    parts = domain.split(".")
    if len(parts) < 2 or len(parts[-2]) < 10:
        return False
    name = parts[-2]
    digits = sum(ch.isdigit() for ch in name)
    vowels = sum(ch in "aeiou" for ch in name) / len(name)
    return _entropy(name) >= 3.3 and (digits >= 2 or vowels < 0.25)


def _is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_multicast   # multicast (e.g. 239.x) is local discovery, not a server
    except ValueError:
        return False


def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _to_port(value):
    try:
        n = int(float(value))
        return n if 0 <= n <= 65535 else None
    except (TypeError, ValueError):
        return None


def _to_int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def load_packets(path):
    """Return (rows, error_message). rows is a list of dicts."""
    try:
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return [], "The CSV file is empty."
            mapping = _map_headers(reader.fieldnames)
            if "src" not in mapping or "dst" not in mapping:
                cols = ", ".join(reader.fieldnames)
                return [], ("Could not find Source and Destination columns. "
                            f"Columns in this file: {cols}")

            rows = []
            for i, raw in enumerate(reader, 1):
                if i > MAX_ROWS:
                    break

                def get(key):
                    col = mapping.get(key)
                    return (raw.get(col) or "").strip() if col else ""

                info = get("info")
                sport, dport = _to_port(get("sport")), _to_port(get("dport"))
                if (sport is None or dport is None) and info:
                    m = PORT_RE.search(info)
                    if m:
                        if sport is None:
                            sport = _to_port(m.group(1))
                        if dport is None:
                            dport = _to_port(m.group(2))

                rows.append({
                    "id": i,
                    "time": get("time"),
                    "src": get("src"),
                    "dst": get("dst"),
                    "proto": (get("proto") or "Unknown").upper(),
                    "length": _to_int(get("length")),
                    "sport": sport,
                    "dport": dport,
                    "info": info[:200],
                })
            if not rows:
                return [], "The CSV has headers but no packet rows."
            return rows, None
    except Exception as exc:  # noqa: BLE001 - show any read problem to the user
        return [], f"Could not read the file: {exc}"


def find_dataset():
    """Pick which CSV to analyse: uploaded file first, then any CSV near app.py."""
    candidates = []
    if os.path.exists(UPLOAD_PATH):
        candidates.append(UPLOAD_PATH)
    candidates += sorted(glob.glob(os.path.join(BASE_DIR, "*.csv")))
    candidates += sorted(glob.glob(os.path.join(DATA_DIR, "*.csv")))

    first_error = None
    for path in candidates:
        if path == UPLOAD_PATH and not os.path.exists(path):
            continue
        rows, err = load_packets(path)
        if rows:
            return path, rows, None
        first_error = first_error or f"{os.path.basename(path)}: {err}"
    return None, [], first_error or "No CSV file found. Upload one from the sidebar."


# ----------------------------------------------------------------------------
# Analysis / detection
# ----------------------------------------------------------------------------
def analyze(rows, ignored=()):
    is_ignored = _matcher(ignored)
    src_count = Counter(r["src"] for r in rows)
    ports_by_src = defaultdict(set)
    syn_by_src = Counter()
    icmp_by_src = Counter()
    bad_port_hits = Counter()  # (src, port) -> packets

    for r in rows:
        if r["dport"] is not None:
            ports_by_src[r["src"]].add(r["dport"])
        info = r["info"]
        if "[SYN]" in info and "ACK" not in info:
            syn_by_src[r["src"]] += 1
        if r["proto"].startswith("ICMP"):
            icmp_by_src[r["src"]] += 1
        for p in (r["sport"], r["dport"]):
            if p in SUSPICIOUS_PORTS:
                bad_port_hits[(r["src"], p)] += 1
                break

    alerts = []
    ip_risk = {}          # ip -> "threat" or "watch"
    ip_reasons = defaultdict(list)
    ip_score = Counter()
    rules = defaultdict(list)   # which packets each alert marks: key -> [(level, kind)]

    def add(severity, kind, source, detail, count, related=None, ignore=None, key=None):
        """key says which packets get marked: ("src", ip) = everything the IP sends (default),
        ("pair", a, b) = only packets between a and b, ("port", ip, port), ("dom", ip, domain)."""
        if is_ignored(source) or (related and is_ignored(related)):
            return  # IP is on the ignore list
        key = key or ("src", source)
        ip_score[source] = min(100, ip_score[source] + POINTS.get(kind, 10))
        alerts.append({"severity": severity, "type": kind, "source": source,
                       "detail": detail, "count": count, "ignore": ignore or source})
        level = "threat" if severity == "high" else "watch"
        rules[key].append((level, kind))
        if key[0] == "src" and ip_risk.get(source) != "threat":
            ip_risk[source] = level   # whole IP looks bad only for IP-wide findings
        ip_reasons[source].append(kind)

    for ip, ports in ports_by_src.items():
        if len(ports) >= PORT_SCAN_MIN_PORTS:
            add("high", "Port scan", ip,
                f"Tried {len(ports)} different destination ports", src_count[ip])

    for ip, n in syn_by_src.items():
        if n >= SYN_FLOOD_MIN:
            add("high", "SYN flood", ip, f"Sent {n} SYN packets without completing handshakes", n)

    for ip, n in icmp_by_src.items():
        if n >= ICMP_FLOOD_MIN:
            add("medium", "ICMP flood", ip, f"Sent {n} ICMP (ping) packets", n)

    # If one local device is in most packets, it is the capturing laptop and everyone else is just
    # its peer, so "high traffic" would only flag the servers it talks to (meaningless).
    local_seen = Counter()
    for r in rows:
        for ip in (r["src"], r["dst"]):
            if _is_private(ip):
                local_seen[ip] += 1
    hub = bool(local_seen) and local_seen.most_common(1)[0][1] >= 0.7 * len(rows)

    counts = list(src_count.values())
    if len(counts) >= 3 and not hub:
        threshold = max(HIGH_TRAFFIC_MIN, statistics.mean(counts) + 2 * statistics.pstdev(counts))
        for ip, n in src_count.items():
            # Skip local (private) IPs: the capturing laptop is always the top sender
            if n > threshold and not _is_private(ip):
                add("medium", "High traffic", ip,
                    f"Sent {n} packets (normal level is about {int(statistics.mean(counts))})", n)

    for (ip, port), n in bad_port_hits.items():
        add("medium", "Suspicious port", ip, f"Port {port}: {SUSPICIOUS_PORTS[port]}", n, key=("port", ip, port))

    # --- DNS: top domains + random-looking names ---
    dns_counter = Counter()
    dns_by_src = defaultdict(Counter)
    for r in rows:
        d = _extract_domain(r)
        if d:
            dns_counter[d] += 1
            dns_by_src[r["src"]][d] += 1
    sus_domains = []
    for ip, doms in dns_by_src.items():
        for d, n in doms.items():
            if _looks_generated(d):
                add("medium", "Suspicious domain", ip,
                    f"Looked up {d} (random-looking name, common in malware)", n,
                    key=("dom", ip, d))
                if d not in sus_domains:
                    sus_domains.append(d)

    # --- Beaconing: very regular contacts to one outside server ---
    flows = defaultdict(list)
    for r in rows:
        t = _to_float(r["time"])
        if t is not None and _is_public(r["dst"]):
            flows[(r["src"], r["dst"], r["dport"])].append(t)
    for (src, dst, port), times in flows.items():
        if len(times) < BEACON_MIN_EVENTS:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.mean(gaps)
        if mean >= BEACON_MIN_INTERVAL and statistics.pstdev(gaps) / mean <= BEACON_MAX_JITTER:
            where = f"{dst}:{port}" if port is not None else dst
            add("medium", "Beaconing", src,
                f"Contacts {where} every ~{mean:.0f}s, {len(times)} times, with very regular timing", len(times),
                related=dst, ignore=dst, key=("pair", src, dst))

    # --- Data exfiltration: local device uploads a lot to one outside IP ---
    out_bytes, out_pkts, in_bytes = Counter(), Counter(), Counter()
    for r in rows:
        if _is_private(r["src"]) and _is_public(r["dst"]):
            out_bytes[(r["src"], r["dst"])] += r["length"]
            out_pkts[(r["src"], r["dst"])] += 1
        elif _is_public(r["src"]) and _is_private(r["dst"]):
            in_bytes[(r["dst"], r["src"])] += r["length"]
    for (src, dst), b in out_bytes.items():
        if b >= EXFIL_MIN_BYTES and b >= 5 * max(in_bytes[(src, dst)], 1):
            add("medium", "Large upload", src,
                f"Uploaded {b // 1024} KB to {dst}, far more than it downloaded. Normal for video calls "
                f"and cloud uploads, but also how stolen data leaves a network.",
                out_pkts[(src, dst)], related=dst, ignore=dst, key=("pair", src, dst))

    order = {"high": 0, "medium": 1, "low": 2}
    alerts.sort(key=lambda a: (order[a["severity"]], -a["count"]))

    # Mark every packet
    risk_counts = Counter()
    for r in rows:
        keys = [("src", r["src"]), ("pair", r["src"], r["dst"]), ("pair", r["dst"], r["src"])]
        for p in (r["sport"], r["dport"]):
            if p is not None:
                keys.append(("port", r["src"], p))
        if r["proto"] in ("DNS", "MDNS"):
            dom = _extract_domain(r)
            if dom:
                keys.append(("dom", r["src"], dom))
        risk, reasons = "ok", []
        for k in keys:
            for level, kind in rules.get(k, ()):
                if level == "threat" or risk == "ok":
                    risk = level
                if kind not in reasons:
                    reasons.append(kind)
        r["risk"] = risk
        r["reason"] = ", ".join(reasons)
        risk_counts[risk] += 1

    # Summary numbers
    protocols = Counter(r["proto"] for r in rows)
    dports = Counter(r["dport"] for r in rows if r["dport"] is not None)

    # Timeline: split packets (in file order) into up to 24 equal groups
    groups = min(24, len(rows))
    size = -(-len(rows) // groups)
    timeline = []
    for i in range(0, len(rows), size):
        chunk = rows[i:i + size]
        label = chunk[0]["time"] or f"#{chunk[0]['id']}"
        c = Counter(r["risk"] for r in chunk)
        timeline.append({"label": label[-12:], "ok": c["ok"],
                         "watch": c["watch"], "threat": c["threat"]})

    # Network map: top 40 IPs and who talks to whom
    conv = Counter((r["src"], r["dst"]) for r in rows)
    traffic = Counter()
    for (s, d), n in conv.items():
        traffic[s] += n
        traffic[d] += n
    top = [ip for ip, _ in traffic.most_common(40)]
    topset = set(top)
    graph = {
        "nodes": [{"id": ip, "count": traffic[ip], "risk": ip_risk.get(ip, "ok"),
                   "private": _is_private(ip)} for ip in top],
        "links": [{"s": s, "t": d, "n": n,
                   "risk": max((lv for lv, _ in rules.get(("pair", s, d), [])),
                               key=lambda x: x == "threat", default="ok")}
                  for (s, d), n in conv.items()
                  if s in topset and d in topset],
    }

    stats = {
        "total": len(rows),
        "unique_src": len(src_count),
        "unique_dst": len({r["dst"] for r in rows}),
        "total_bytes": sum(r["length"] for r in rows),
        "top_protocol": protocols.most_common(1)[0][0] if protocols else "-",
        "alerts_high": sum(1 for a in alerts if a["severity"] == "high"),
        "alerts_medium": sum(1 for a in alerts if a["severity"] == "medium"),
        "risk": {"ok": risk_counts["ok"], "watch": risk_counts["watch"], "threat": risk_counts["threat"]},
        "protocols": protocols.most_common(8),
        "top_sources": [(ip, n, ip_risk.get(ip, "ok")) for ip, n in src_count.most_common(10)],
        "graph": graph,
        "ip_scores": dict(ip_score),
        "risk_ranking": [
            {"ip": ip, "score": sc, "level": "high" if sc >= 60 else "medium" if sc >= 25 else "low",
             "reasons": list(dict.fromkeys(ip_reasons.get(ip, [])))}
            for ip, sc in ip_score.most_common(8)
        ],
        "dns": {"total": sum(dns_counter.values()), "top": dns_counter.most_common(8), "suspicious": sus_domains},
        "top_ports": [(str(p), n) for p, n in dports.most_common(8)],
        "timeline": timeline,
    }
    return stats, alerts


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# Ignore list (whitelist): IPs or ranges like 192.168.1.0/24 that never raise alerts.
# Stored in data/whitelist.txt, one entry per line.
# ----------------------------------------------------------------------------
WHITELIST_PATH = os.path.join(DATA_DIR, "whitelist.txt")


def load_whitelist():
    items = []
    if os.path.exists(WHITELIST_PATH):
        with open(WHITELIST_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()
                try:
                    ipaddress.ip_network(line, strict=False)
                    items.append(line)
                except ValueError:
                    pass
    return items


def _matcher(items):
    nets = [ipaddress.ip_network(i, strict=False) for i in items]

    def check(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in nets)
    return check


def _save_whitelist(items):
    with open(WHITELIST_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(items) + ("\n" if items else ""))


@app.route("/api/whitelist", methods=["POST"])
def whitelist_add():
    value = str((request.get_json(silent=True) or {}).get("ip", "")).strip()
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return jsonify({"error": "Enter a valid IP address or range."}), 400
    items = load_whitelist()
    if value not in items:
        items.append(value)
        _save_whitelist(items)
    return jsonify({"ok": True})


@app.route("/api/whitelist/remove", methods=["POST"])
def whitelist_remove():
    value = str((request.get_json(silent=True) or {}).get("ip", "")).strip()
    _save_whitelist([i for i in load_whitelist() if i != value])
    return jsonify({"ok": True})


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/data")
def api_data():
    path, rows, error = find_dataset()
    if not rows:
        return jsonify({"error": error, "file": None}), 200
    stats, alerts = analyze(rows, load_whitelist())
    return jsonify({"error": None, "file": os.path.basename(path),
                    "stats": stats, "alerts": alerts, "packets": rows,
                    "whitelist": load_whitelist()})


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith(".csv"):
        return jsonify({"error": "Choose a .csv file."}), 400
    tmp = UPLOAD_PATH + ".tmp"
    f.save(tmp)
    rows, err = load_packets(tmp)
    if not rows:
        os.remove(tmp)
        return jsonify({"error": err}), 400
    os.replace(tmp, UPLOAD_PATH)
    return jsonify({"ok": True, "rows": len(rows)})


@app.route("/reset", methods=["POST"])
def reset():
    if os.path.exists(UPLOAD_PATH):
        os.remove(UPLOAD_PATH)
    return jsonify({"ok": True})


# ----------------------------------------------------------------------------
# IP lookups (need internet). Geolocation uses the free ip-api.com service.
# Reputation uses AbuseIPDB and only works if you set ABUSEIPDB_KEY.
# Note: the IP addresses you look up are sent to these third-party services.
# ----------------------------------------------------------------------------
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "").strip()
IP_CACHE = {}
COUNTRY_CACHE = {}


def _http_json(url, data=None, headers=None, timeout=6):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _valid_ip(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


@app.route("/api/ip/<ip>")
def api_ip(ip):
    addr = _valid_ip(ip)
    if addr is None:
        return jsonify({"error": "That is not a valid IP address."}), 400
    if not addr.is_global or addr.is_multicast:
        return jsonify({"local": True})
    if ip in IP_CACHE:
        return jsonify(IP_CACHE[ip])

    out = {"ip": ip, "geo": None, "abuse": {"enabled": bool(ABUSEIPDB_KEY)}, "error": None}
    try:
        g = _http_json("http://ip-api.com/json/" + ip +
                       "?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting")
        if g.get("status") == "success":
            out["geo"] = g
        else:
            out["error"] = g.get("message", "Lookup failed.")
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"Could not reach the lookup service ({exc}). Check your internet."

    if ABUSEIPDB_KEY:
        try:
            r = _http_json("https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + ip,
                           headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"})
            d = r.get("data", {})
            out["abuse"].update({"score": d.get("abuseConfidenceScore"),
                                 "reports": d.get("totalReports"),
                                 "usage": d.get("usageType"),
                                 "last": d.get("lastReportedAt")})
        except Exception as exc:  # noqa: BLE001
            out["abuse"]["error"] = f"AbuseIPDB check failed ({exc})"

    if out["geo"]:  # cache only successful lookups
        IP_CACHE[ip] = out
    return jsonify(out)


@app.route("/api/countries")
def api_countries():
    """Data volume (bytes) per country, split into uploaded and downloaded, for the busiest public IPs."""
    _, rows, _ = find_dataset()
    up, down = Counter(), Counter()
    for r in rows:
        if _is_private(r["src"]) and _is_public(r["dst"]):
            up[r["dst"]] += r["length"]
        elif _is_public(r["src"]) and _is_private(r["dst"]):
            down[r["src"]] += r["length"]
    volume = up + down
    if not volume:
        return jsonify({"countries": [], "note": "No traffic between local and public IPs in this capture."})
    top = [ip for ip, _ in volume.most_common(60)]
    missing = [ip for ip in top if ip not in COUNTRY_CACHE]
    if missing:
        try:
            res = _http_json("http://ip-api.com/batch?fields=query,status,country",
                             data=json.dumps(missing).encode("utf-8"),
                             headers={"Content-Type": "application/json"}, timeout=8)
            for item in res:
                COUNTRY_CACHE[item.get("query")] = item.get("country") if item.get("status") == "success" else "Unknown"
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": f"Could not reach the lookup service ({exc})."})
    by_up, by_down = Counter(), Counter()
    for ip in top:
        c = COUNTRY_CACHE.get(ip, "Unknown")
        by_up[c] += up[ip]
        by_down[c] += down[ip]
    total = Counter()
    for c in set(by_up) | set(by_down):
        total[c] = by_up[c] + by_down[c]
    return jsonify({"countries": [[c, by_up[c], by_down[c]] for c, _ in total.most_common(8)],
                    "total": sum(total.values())})


@app.route("/export/alerts.csv")
def export_alerts():
    _, rows, _ = find_dataset()
    _, alerts = analyze(rows, load_whitelist()) if rows else ({}, [])
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Severity", "Type", "Source IP", "Packets", "Detail"])
    for a in alerts:
        w.writerow([a["severity"], a["type"], a["source"], a["count"], a["detail"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=alerts_report.csv"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
