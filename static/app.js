(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const PAGE_SIZE = 25;
  const RISK_RANK = { ok: 0, watch: 1, threat: 2 };
  const RISK_LABEL = { ok: "Normal", watch: "Watch", threat: "Threat" };
  const COLORS = { ok: "#4cc3a4", watch: "#f0b44c", threat: "#ff6a55", blue: "#6cb2ff", grid: "#243040", text: "#8c9bb0" };
  const PROTO_COLORS = ["#6cb2ff", "#4cc3a4", "#f0b44c", "#b58cff", "#ff8fb1", "#7fd1e8", "#c3cf6a", "#9aa7b8"];

  let DATA = null;
  let filtered = [];
  let page = 0;
  let sortKey = "id";
  let sortDir = 1;
  const charts = {};

  // ---------- helpers ----------
  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text; // textContent keeps CSV data from running as HTML
    return n;
  }
  const fmt = (n) => Number(n).toLocaleString();
  function fmtBytes(b) {
    if (b < 1024) return b + " B";
    if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
    return (b / 1048576).toFixed(1) + " MB";
  }
  function showNotice(msg) {
    const n = $("notice");
    n.textContent = msg;
    n.hidden = !msg;
  }

  function ipEl(tag, cls, ip) {
    const n = el(tag, (cls ? cls + " " : "") + "link", ip);
    n.title = "Show packets for " + ip;
    n.addEventListener("click", () => investigate(ip));
    return n;
  }
  function investigate(ip) {
    $("search").value = ip;
    $("f-proto").value = "";
    $("f-risk").value = "";
    document.querySelector('.nav-btn[data-view="packets"]').click();
    applyFilters();
  }

  async function ignoreIp(ip, remove) {
    try {
      await fetch(remove ? "/api/whitelist/remove" : "/api/whitelist", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: ip }),
      });
    } catch (e) { showNotice("Could not save. Is the server running?"); return; }
    cardIp = "";
    await load();
  }

  // ---------- IP details card (location + reputation) ----------
  let cardIp = "";
  const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]*:[0-9a-f:]+$/i;
  async function updateIpCard(q) {
    const box = $("ip-card");
    if (!IP_RE.test(q)) { cardIp = ""; box.hidden = true; return; }
    if (q === cardIp) return;
    cardIp = q;
    box.hidden = false;
    box.replaceChildren(el("p", "muted small", "Looking up " + q + "..."));
    let d;
    try { d = await (await fetch("/api/ip/" + encodeURIComponent(q))).json(); }
    catch (e) { d = { error: "Lookup failed. Is the server running?" }; }
    if (cardIp !== q) return;
    box.replaceChildren(el("h3", "", q));
    const ig = el("button", "btn ghost tiny", "Ignore alerts for this IP");
    ig.addEventListener("click", () => ignoreIp(q, false));
    box.appendChild(ig);
    const sc = DATA && DATA.stats.ip_scores[q];
    if (sc !== undefined) {
      const lv = sc >= 60 ? "high" : sc >= 25 ? "medium" : "low";
      const p = el("p", "small");
      p.style.marginBottom = "10px";
      p.appendChild(el("span", "tag " + lv, "Risk score " + sc + "/100"));
      box.appendChild(p);
    }
    if (d.local) { box.appendChild(el("p", "muted", "Private address on a local network. It has no public location or reputation.")); return; }
    if (d.error && !d.geo) { box.appendChild(el("p", "muted small", d.error)); return; }
    const kv = el("dl", "kv");
    function add(k, v) { if (!v) return; const w = el("div"); w.appendChild(el("dt", "", k)); w.appendChild(el("dd", "", v)); kv.appendChild(w); }
    const g = d.geo || {};
    add("Country", g.country);
    add("Region / city", [g.city, g.regionName].filter(Boolean).join(", "));
    add("Provider", g.isp || g.org);
    add("Network", g.as);
    add("Type", [g.hosting ? "Hosting / data centre" : "", g.proxy ? "VPN / proxy" : ""].filter(Boolean).join(", ") || "Regular");
    if (d.abuse && d.abuse.score !== undefined) {
      const sev = d.abuse.score >= 50 ? "high" : d.abuse.score >= 15 ? "medium" : "low";
      const w = el("div"); w.appendChild(el("dt", "", "AbuseIPDB score"));
      const dd = el("dd"); dd.appendChild(el("span", "tag " + sev, d.abuse.score + "% abuse confidence"));
      dd.appendChild(document.createTextNode(" " + fmt(d.abuse.reports || 0) + " reports"));
      w.appendChild(dd); kv.appendChild(w);
    }
    box.appendChild(kv);
    if (d.abuse && d.abuse.error) box.appendChild(el("p", "muted small", d.abuse.error));
    else if (d.abuse && !d.abuse.enabled) box.appendChild(el("p", "muted small", "Reputation check is off. Set the ABUSEIPDB_KEY environment variable to turn it on (see README)."));
  }

  let countryData = null;
  let countryLog = true;

  async function loadCountries() {
    const box = $("country-box");
    if (!window.Chart) { box.replaceChildren(el("p", "muted small", "Charts need an internet connection.")); return; }
    let d;
    try { d = await (await fetch("/api/countries")).json(); } catch (e) { d = { error: "Lookup failed." }; }
    if (d.error || !d.countries.length) {
      countryData = null;
      $("country-note").textContent = "";
      box.replaceChildren(el("p", "muted small", d.error || d.note || "No data."));
      return;
    }
    countryData = d;
    drawCountries();
  }

  function drawCountries() {
    const d = countryData;
    if (!d) return;
    const box = $("country-box");
    if (!$("c-country")) { const c = el("canvas"); c.id = "c-country"; box.replaceChildren(c); }
    if (charts["c-country"]) charts["c-country"].destroy();
    const top = d.countries[0];
    const share = d.total ? Math.round(((top[1] + top[2]) / d.total) * 100) : 0;
    $("country-note").textContent = top[0] + " has " + share + "% of the data. " +
      (countryLog ? "Log scale: each gridline is 10x the previous one, so small countries stay visible." : "Linear scale: small countries look tiny.");
    $("scale-btn").textContent = countryLog ? "Switch to linear scale" : "Switch to log scale";
    const isPow10 = (v) => Math.abs(Math.log10(v) - Math.round(Math.log10(v))) < 1e-9;
    charts["c-country"] = new Chart($("c-country"), {
      type: "bar",
      data: {
        labels: d.countries.map((c) => c[0]),
        datasets: [
          { label: "Downloaded to you", data: d.countries.map((c) => c[2] || null), backgroundColor: COLORS.blue, borderRadius: 3 },
          { label: "Uploaded from you", data: d.countries.map((c) => c[1] || null), backgroundColor: "#b58cff", borderRadius: 3 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false, indexAxis: "y",
        plugins: {
          legend: { position: "bottom", labels: { usePointStyle: true, boxWidth: 8 } },
          tooltip: { callbacks: { label: (c) => c.dataset.label + ": " + fmtBytes(c.parsed.x) } },
        },
        scales: {
          x: { type: countryLog ? "logarithmic" : "linear", ticks: { callback: (v) => (countryLog && !isPow10(v) ? "" : fmtBytes(v)) } },
          y: { grid: { display: false } },
        },
      },
    });
  }
  $("scale-btn").addEventListener("click", () => { countryLog = !countryLog; drawCountries(); });

  // ---------- navigation ----------
  document.querySelectorAll(".nav-btn").forEach((b) =>
    b.addEventListener("click", () => {
      document.querySelectorAll(".nav-btn").forEach((x) => x.classList.toggle("active", x === b));
      document.querySelectorAll(".view").forEach((v) => (v.hidden = v.id !== "view-" + b.dataset.view));
    })
  );

  // ---------- load ----------
  async function load() {
    try {
      const res = await fetch("/api/data");
      DATA = await res.json();
    } catch (e) {
      showNotice("Could not reach the server. Is app.py still running?");
      return;
    }
    if (DATA.error) {
      showNotice(DATA.error);
      $("verdict").textContent = "No data to show yet";
      $("verdict-sub").textContent = "Upload a packet CSV from the sidebar.";
      $("file-name").textContent = "-";
      return;
    }
    showNotice("");
    $("file-name").textContent = DATA.file;
    renderOverview();
    renderAlerts();
    setupPacketFilters();
    applyFilters();
  }

  // ---------- overview ----------
  function renderOverview() {
    const s = DATA.stats;
    const v = $("verdict");
    v.className = "";
    if (s.alerts_high > 0) {
      v.className = "bad";
      v.textContent = s.alerts_high + (s.alerts_high === 1 ? " serious threat found" : " serious threats found");
    } else if (s.alerts_medium > 0) {
      v.className = "warn";
      v.textContent = "No serious threats, " + s.alerts_medium + (s.alerts_medium === 1 ? " item" : " items") + " worth a look";
    } else {
      v.className = "good";
      v.textContent = "No suspicious activity found";
    }
    $("verdict-sub").textContent =
      fmt(s.total) + " packets from " + fmt(s.unique_src) + " sending IPs in " + DATA.file + ".";

    // risk bar + legend
    const bar = $("riskbar");
    bar.replaceChildren();
    const legend = $("risk-legend");
    legend.replaceChildren();
    ["ok", "watch", "threat"].forEach((k) => {
      const n = s.risk[k];
      const seg = el("span");
      seg.style.width = (n / s.total) * 100 + "%";
      seg.style.background = COLORS[k];
      bar.appendChild(seg);
      const li = el("li");
      const dot = el("span", "dot");
      dot.style.background = COLORS[k];
      li.appendChild(dot);
      li.appendChild(document.createTextNode(RISK_LABEL[k] + " " + fmt(n)));
      legend.appendChild(li);
    });

    // facts row
    const facts = $("facts");
    facts.replaceChildren();
    [
      ["Packets", fmt(s.total)],
      ["Sending IPs", fmt(s.unique_src)],
      ["Receiving IPs", fmt(s.unique_dst)],
      ["Data volume", fmtBytes(s.total_bytes)],
      ["Main protocol", s.top_protocol],
    ].forEach(([k, val]) => {
      const d = el("div", "fact");
      d.appendChild(el("dt", "", k));
      d.appendChild(el("dd", "", val));
      facts.appendChild(d);
    });

    // top findings
    const tf = $("top-findings");
    tf.replaceChildren();
    if (!DATA.alerts.length) {
      tf.appendChild(el("p", "empty", "Nothing suspicious in this capture."));
    }
    DATA.alerts.slice(0, 4).forEach((a) => tf.appendChild(findingRow(a)));

    drawCharts(s);
    drawDns(s);
    renderRiskRank(s);
    drawMap(s.graph);
    loadCountries();
  }

  function findingRow(a) {
    const row = el("div", "finding");
    row.appendChild(el("span", "tag " + a.severity, a.severity));
    row.appendChild(el("span", "what", a.type));
    row.appendChild(ipEl("span", "ip", a.source));
    row.appendChild(el("span", "muted", a.detail));
    return row;
  }

  function drawCharts(s) {
    if (!window.Chart) {
      document.querySelectorAll(".chart").forEach((c) => {
        c.replaceChildren(el("p", "muted small", "Charts need an internet connection (Chart.js could not load)."));
      });
      return;
    }
    Chart.defaults.color = COLORS.text;
    Chart.defaults.font.family = '"IBM Plex Sans", system-ui, sans-serif';
    Chart.defaults.borderColor = COLORS.grid;
    const base = { responsive: true, maintainAspectRatio: false };

    function make(id, config) {
      if (charts[id]) charts[id].destroy();
      charts[id] = new Chart($(id), config);
    }

    make("c-timeline", {
      type: "bar",
      data: {
        labels: s.timeline.map((t) => t.label),
        datasets: [
          { label: "Normal", data: s.timeline.map((t) => t.ok), backgroundColor: COLORS.ok, borderRadius: 2 },
          { label: "Watch", data: s.timeline.map((t) => t.watch), backgroundColor: COLORS.watch, borderRadius: 2 },
          { label: "Threat", data: s.timeline.map((t) => t.threat), backgroundColor: COLORS.threat, borderRadius: 2 },
        ],
      },
      options: { ...base, interaction: { mode: "index" }, plugins: { legend: { position: "bottom", labels: { usePointStyle: true, boxWidth: 8 } } },
        scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: { stacked: true, beginAtZero: true } } },
    });

    make("c-proto", {
      type: "doughnut",
      data: { labels: s.protocols.map((p) => p[0]), datasets: [{ data: s.protocols.map((p) => p[1]), backgroundColor: PROTO_COLORS, borderColor: "#151c25", borderWidth: 2 }] },
      options: { ...base, cutout: "66%", plugins: { legend: { position: "right", labels: { usePointStyle: true, boxWidth: 8 } } } },
      plugins: [{
        id: "centre",
        afterDraw(ch) {
          const a = ch.chartArea, ctx = ch.ctx, x = (a.left + a.right) / 2, y = (a.top + a.bottom) / 2;
          ctx.save();
          ctx.textAlign = "center";
          ctx.fillStyle = "#e7ecf3";
          ctx.font = "600 24px 'IBM Plex Sans', sans-serif";
          ctx.fillText(fmt(s.total), x, y + 4);
          ctx.fillStyle = COLORS.text;
          ctx.font = "12px 'IBM Plex Sans', sans-serif";
          ctx.fillText("packets", x, y + 22);
          ctx.restore();
        },
      }],
    });

    make("c-src", {
      type: "bar",
      data: { labels: s.top_sources.map((p) => p[0]), datasets: [{ data: s.top_sources.map((p) => p[1]), backgroundColor: s.top_sources.map((p) => (p[2] === "ok" ? COLORS.blue : COLORS[p[2]])), borderRadius: 3 }] },
      options: { ...base, indexAxis: "y", plugins: { legend: { display: false } },
        scales: { y: { grid: { display: false } } },
        onClick: (e, els) => { if (els.length) investigate(s.top_sources[els[0].index][0]); },
        onHover: (e, els) => { e.native.target.style.cursor = els.length ? "pointer" : "default"; } },
    });

    make("c-ports", {
      type: "bar",
      data: { labels: s.top_ports.map((p) => p[0]), datasets: [{ data: s.top_ports.map((p) => p[1]), backgroundColor: "#4cc3a4", borderRadius: 3 }] },
      options: { ...base, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false } } } },
    });
  }

  // ---------- network map (simple force layout, no library) ----------
  function drawMap(g) {
    const box = $("map");
    box.replaceChildren();
    if (!g || !g.nodes.length) return;
    const W = 900, H = 440, NS = "http://www.w3.org/2000/svg";
    const idx = {};
    const nodes = g.nodes.map((n, i) => {
      idx[n.id] = i;
      const a = i * 2.4, d = 40 + i * 6;
      return { ...n, x: W / 2 + Math.cos(a) * d, y: H / 2 + Math.sin(a) * d, vx: 0, vy: 0, r: Math.min(22, 6 + Math.sqrt(n.count) * 1.5) };
    });
    const links = g.links.filter((l) => l.s in idx && l.t in idx).map((l) => ({ a: nodes[idx[l.s]], b: nodes[idx[l.t]], n: l.n, risk: l.risk }));

    for (let it = 0; it < 280; it++) {
      const k = 1 - it / 280;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y;
          const d2 = dx * dx + dy * dy + 0.01, d = Math.sqrt(d2), f = 3200 / d2;
          dx /= d; dy /= d;
          a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
        }
      }
      links.forEach((l) => {
        let dx = l.b.x - l.a.x, dy = l.b.y - l.a.y;
        const d = Math.sqrt(dx * dx + dy * dy) + 0.01, f = (d - 100) * 0.015;
        dx /= d; dy /= d;
        l.a.vx += dx * f; l.a.vy += dy * f; l.b.vx -= dx * f; l.b.vy -= dy * f;
      });
      nodes.forEach((n) => {
        n.vx += (W / 2 - n.x) * 0.004; n.vy += (H / 2 - n.y) * 0.008;
        n.x += Math.max(-12, Math.min(12, n.vx)) * k; n.y += Math.max(-12, Math.min(12, n.vy)) * k;
        n.vx = n.vy = 0;
        n.x = Math.max(n.r + 12, Math.min(W - n.r - 12, n.x));
        n.y = Math.max(n.r + 16, Math.min(H - n.r - 16, n.y));
      });
    }

    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    function mk(tag, attrs) {
      const e = document.createElementNS(NS, tag);
      Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
      return e;
    }
    links.forEach((l) =>
      svg.appendChild(mk("line", { x1: l.a.x, y1: l.a.y, x2: l.b.x, y2: l.b.y, "stroke-width": l.risk && l.risk !== "ok" ? 2.5 : Math.min(4, 0.6 + Math.log10(l.n + 1)),
        style: l.risk && l.risk !== "ok" ? "stroke:" + COLORS[l.risk] : "" }))
    );
    nodes.forEach((n, i) => {
      const c = mk("circle", { cx: n.x, cy: n.y, r: n.r, fill: COLORS[n.risk], "fill-opacity": 0.85, stroke: n.private ? COLORS.blue : "none", "stroke-width": 3 });
      const t = document.createElementNS(NS, "title");
      t.textContent = n.id + " - " + fmt(n.count) + " packets - " + RISK_LABEL[n.risk];
      c.appendChild(t);
      c.addEventListener("click", () => investigate(n.id));
      svg.appendChild(c);
      if (n.risk !== "ok" || n.private || i < 5) {
        const tx = mk("text", { x: n.x, y: n.y - n.r - 5, "text-anchor": "middle" });
        tx.textContent = n.id;
        svg.appendChild(tx);
      }
    });
    box.appendChild(svg);
  }

  function renderRiskRank(s) {
    const box = $("risk-rank");
    box.replaceChildren();
    if (!s.risk_ranking.length) { box.appendChild(el("p", "empty", "No device has any risk points. Looks clean.")); return; }
    const color = { high: COLORS.threat, medium: COLORS.watch, low: COLORS.ok };
    s.risk_ranking.forEach((r) => {
      const row = el("div", "rankrow");
      row.appendChild(ipEl("span", "ip", r.ip));
      const track = el("div", "track");
      const fill = el("span");
      fill.style.width = r.score + "%";
      fill.style.background = color[r.level];
      track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(el("span", "score", r.score));
      row.appendChild(el("span", "why", r.reasons.join(", ")));
      box.appendChild(row);
    });
  }

  function drawDns(s) {
    const box = $("dns-box");
    const note = $("dns-note");
    const d = s.dns;
    note.textContent = d.suspicious.length
      ? "Random-looking domains found: " + d.suspicious.join(", ")
      : d.total ? "No random-looking (malware-style) domains found." : "";
    if (!window.Chart) return;
    if (!d.top.length) { box.replaceChildren(el("p", "muted small", "No DNS lookups in this capture.")); return; }
    if (!$("c-dns")) { const c = el("canvas"); c.id = "c-dns"; box.replaceChildren(c); }
    if (charts["c-dns"]) charts["c-dns"].destroy();
    charts["c-dns"] = new Chart($("c-dns"), {
      type: "bar",
      data: { labels: d.top.map((x) => x[0]), datasets: [{ data: d.top.map((x) => x[1]), backgroundColor: d.top.map((x) => (d.suspicious.includes(x[0]) ? COLORS.threat : "#7fd1e8")), borderRadius: 3 }] },
      options: { responsive: true, maintainAspectRatio: false, indexAxis: "y", plugins: { legend: { display: false } }, scales: { y: { grid: { display: false } } } },
    });
  }

  // ---------- alerts ----------
  function renderAlerts() {
    const list = $("alert-list");
    list.replaceChildren();
    const wl = $("ignored");
    wl.replaceChildren();
    $("ignored-box").hidden = !DATA.whitelist.length;
    DATA.whitelist.forEach((ip) => {
      const row = el("div", "ignored-row");
      row.appendChild(el("span", "", ip));
      const rb = el("button", "btn ghost tiny", "Remove");
      rb.addEventListener("click", () => ignoreIp(ip, true));
      row.appendChild(rb);
      wl.appendChild(row);
    });
    const badge = $("alert-badge");
    badge.hidden = !DATA.alerts.length;
    badge.textContent = DATA.alerts.length;
    if (!DATA.alerts.length) {
      list.appendChild(el("p", "empty", "No alerts. Detection rules found nothing suspicious."));
      return;
    }
    DATA.alerts.forEach((a) => {
      const card = el("div", "alert " + a.severity);
      card.appendChild(el("span", "tag " + a.severity, a.severity));
      const title = el("div", "title", a.type);
      title.appendChild(ipEl("span", "ip", a.source));
      card.appendChild(title);
      const cnt = el("div", "cnt");
      cnt.appendChild(el("div", "", fmt(a.count) + " packets"));
      const ib = el("button", "btn ghost tiny", "Ignore " + a.ignore);
      ib.title = "Stop raising alerts for " + a.ignore;
      ib.addEventListener("click", () => ignoreIp(a.ignore, false));
      cnt.appendChild(ib);
      card.appendChild(cnt);
      card.appendChild(el("div", "detail", a.detail));
      list.appendChild(card);
    });
  }

  // ---------- packets table ----------
  function setupPacketFilters() {
    const sel = $("f-proto");
    const current = sel.value;
    sel.replaceChildren(new Option("All protocols", ""));
    [...new Set(DATA.packets.map((p) => p.proto))].sort().forEach((p) => sel.appendChild(new Option(p, p)));
    sel.value = current;
  }

  function applyFilters() {
    const q = $("search").value.trim().toLowerCase();
    updateIpCard(q);
    const proto = $("f-proto").value;
    const risk = $("f-risk").value;
    filtered = DATA.packets.filter((p) => {
      if (proto && p.proto !== proto) return false;
      if (risk && p.risk !== risk) return false;
      if (!q) return true;
      return (p.src + " " + p.dst + " " + p.proto + " " + p.sport + " " + p.dport + " " + p.info + " " + p.reason)
        .toLowerCase()
        .includes(q);
    });
    sortRows();
    page = 0;
    renderTable();
  }

  function sortRows() {
    const numeric = ["id", "length", "sport", "dport"];
    filtered.sort((a, b) => {
      let x = a[sortKey], y = b[sortKey];
      if (sortKey === "risk") { x = RISK_RANK[x]; y = RISK_RANK[y]; }
      else if (numeric.includes(sortKey)) { x = x === null ? -1 : x; y = y === null ? -1 : y; }
      else { x = String(x); y = String(y); }
      return (x < y ? -1 : x > y ? 1 : 0) * sortDir;
    });
  }

  function renderTable() {
    const body = $("tbody");
    body.replaceChildren();
    const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    page = Math.min(page, pages - 1);
    const slice = filtered.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);

    if (!slice.length) {
      const tr = el("tr");
      const td = el("td", "empty", "No packets match these filters.");
      td.colSpan = 8;
      tr.appendChild(td);
      body.appendChild(tr);
    }
    slice.forEach((p) => {
      const tr = el("tr", "r-" + p.risk);
      tr.title = p.info || "";
      tr.appendChild(el("td", "num", p.id));
      tr.appendChild(el("td", "mono", p.time || "-"));
      tr.appendChild(ipEl("td", "mono", p.src));
      tr.appendChild(ipEl("td", "mono", p.dst));
      tr.appendChild(el("td", "", p.proto));
      tr.appendChild(el("td", "num", p.length));
      tr.appendChild(el("td", "mono", (p.sport ?? "-") + " > " + (p.dport ?? "-")));
      const rt = el("td");
      const tag = el("span", "tag " + p.risk, RISK_LABEL[p.risk]);
      if (p.reason) tag.title = p.reason;
      rt.appendChild(tag);
      tr.appendChild(rt);
      body.appendChild(tr);
    });

    $("count").textContent = fmt(filtered.length) + " of " + fmt(DATA.packets.length) + " packets";
    $("page-info").textContent = "Page " + (page + 1) + " of " + pages;
    $("prev").disabled = page === 0;
    $("next").disabled = page >= pages - 1;

    document.querySelectorAll("th[data-sort]").forEach((th) => {
      th.classList.toggle("sorted", th.dataset.sort === sortKey);
      th.classList.toggle("desc", th.dataset.sort === sortKey && sortDir === -1);
    });
  }

  $("search").addEventListener("input", applyFilters);
  $("f-proto").addEventListener("change", applyFilters);
  $("f-risk").addEventListener("change", applyFilters);
  $("prev").addEventListener("click", () => { page--; renderTable(); });
  $("next").addEventListener("click", () => { page++; renderTable(); });
  document.querySelectorAll("th[data-sort]").forEach((th) =>
    th.addEventListener("click", () => {
      const k = th.dataset.sort;
      if (sortKey === k) sortDir = -sortDir; else { sortKey = k; sortDir = 1; }
      sortRows();
      renderTable();
    })
  );

  // ---------- export filtered rows ----------
  function csvCell(v) {
    let s = v === null || v === undefined ? "" : String(v);
    if (/^[=+\-@]/.test(s)) s = "'" + s; // stops spreadsheet formula injection
    return '"' + s.replace(/"/g, '""') + '"';
  }
  $("export-packets").addEventListener("click", () => {
    if (!DATA) return;
    const head = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Src port", "Dst port", "Risk", "Reason", "Info"];
    const lines = [head.map(csvCell).join(",")];
    filtered.forEach((p) =>
      lines.push([p.id, p.time, p.src, p.dst, p.proto, p.length, p.sport, p.dport, RISK_LABEL[p.risk], p.reason, p.info].map(csvCell).join(","))
    );
    const blob = new Blob([lines.join("\r\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "filtered_packets.csv";
    a.click();
    URL.revokeObjectURL(a.href);
  });

  // ---------- sidebar actions ----------
  $("file-input").addEventListener("change", async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const fd = new FormData();
    fd.append("file", f);
    try {
      const res = await fetch("/upload", { method: "POST", body: fd });
      const out = await res.json();
      if (!res.ok) { showNotice(out.error || "Upload failed."); }
      else { showNotice(""); await load(); }
    } catch (err) {
      showNotice("Upload failed. Is the server running?");
    }
    e.target.value = "";
  });
  $("reset-btn").addEventListener("click", async () => { await fetch("/reset", { method: "POST" }); load(); });
  $("refresh-btn").addEventListener("click", load);
  $("print-btn").addEventListener("click", () => window.print());

  load();
})();
