#!/usr/bin/env python3
"""HomeSIEM unified agent (command-and-control).

Endesha MARA MOJA kwenye host. Inajisajili (enroll), inahifadhi config, kisha
inabaki inaendesha ikisubiri "jobs" kutoka dashboard (scan, forensics). Mtu
habonyezi command tena, anabonyeza device kwenye HomeSIEM.

Mara ya kwanza (inahitaji token):
    set HOMESIEM_URL=http://localhost:8000/api/v1
    set HOMESIEM_SENSOR_TOKEN=hs_xxxxx
    python agent.py

Baada ya hapo config imehifadhiwa (sensor/agent_config.json), endesha tu:
    python agent.py

Forensics inahitaji: pip install psutil
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

#: Baadhi ya PC zina CA store ya zamani, hivyo cheti cha Let's Encrypt kinaonekana
#: "expired". Kwa server ya mtumiaji mwenyewe + token kama auth, tunarudi bila
#: uthibitisho wa cheti badala ya kushindwa kabisa.
_INSECURE_CTX: "ssl.SSLContext | None" = None


def _urlopen(req: urllib.request.Request, timeout: int = 30):
    global _INSECURE_CTX
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLError) or isinstance(exc, ssl.SSLError):
            if _INSECURE_CTX is None:
                _INSECURE_CTX = ssl.create_default_context()
                _INSECURE_CTX.check_hostname = False
                _INSECURE_CTX.verify_mode = ssl.CERT_NONE
                print("   (Cheti cha SSL hakikuthibitishwa; naendelea — token ndio ulinzi)", flush=True)
            return urllib.request.urlopen(req, timeout=timeout, context=_INSECURE_CTX)
        raise

CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_config.json")
POLL_SECONDS = 4
TSHARK = os.environ.get("TSHARK_PATH", r"C:\Program Files\Wireshark\tshark.exe")
_SEP = "\x1f"

# --- scan (ports za kawaida) ----------------------------------------------
_KNOWN = {
    21: ("FTP", "medium", "FTP often unencrypted", "Use SFTP/FTPS."),
    22: ("SSH", "low", "SSH open", "Key-only auth + strong password."),
    23: ("Telnet", "critical", "Telnet is plaintext", "Disable Telnet, use SSH."),
    25: ("SMTP", "low", "Mail open", "Restrict relay."),
    53: ("DNS", "low", "DNS open", "Restrict recursion."),
    80: ("HTTP", "low", "Unencrypted web", "Serve over HTTPS."),
    110: ("POP3", "medium", "Legacy mail", "Use POP3S/IMAPS."),
    135: ("MSRPC", "medium", "Windows RPC exposed", "Firewall if unused."),
    139: ("NetBIOS", "high", "Legacy SMB/NetBIOS", "Disable SMBv1/NetBIOS."),
    443: ("HTTPS", "info", "Encrypted web", "Keep TLS current."),
    445: ("SMB", "high", "SMB exposed", "Restrict to LAN, disable SMBv1."),
    1433: ("MSSQL", "high", "Database exposed", "Never expose DBs."),
    3306: ("MySQL", "high", "Database exposed", "Bind to localhost."),
    3389: ("RDP", "high", "RDP exposed", "Restrict + NLA + MFA."),
    5432: ("PostgreSQL", "high", "Database exposed", "Bind to localhost."),
    5900: ("VNC", "high", "Remote control exposed", "Tunnel VNC."),
    8080: ("HTTP-alt", "low", "Alt web", "Serve over HTTPS."),
}


def _post(url: str, token: str, path: str, body: dict) -> dict | None:
    req = urllib.request.Request(
        url.rstrip("/") + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "X-Sensor-Token": token},
        method="POST",
    )
    try:
        with _urlopen(req) as r:
            return json.loads(r.read())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"   POST {path} error: {exc}", flush=True)
        return None


def _get(url: str, token: str, path: str) -> list | dict | None:
    req = urllib.request.Request(
        url.rstrip("/") + path, headers={"X-Sensor-Token": token}, method="GET"
    )
    try:
        with _urlopen(req) as r:
            return json.loads(r.read())
    except (urllib.error.URLError, OSError, ValueError):
        return None


def run_scan(params: dict) -> dict:
    target = params.get("target", "")
    ports = params.get("ports") or list(_KNOWN.keys())
    findings = []
    for port in ports:
        try:
            with socket.create_connection((target, int(port)), timeout=0.8):
                pass
        except OSError:
            continue
        name, sev, detail, fix = _KNOWN.get(int(port), (f"port {port}", "info", "Open port", "Close if unused."))
        findings.append({"port": int(port), "service": name, "severity": sev,
                         "title": f"{name} open on port {port}", "detail": detail, "fix": fix})
    return {"target": target, "findings": findings}


def run_forensics(_params: dict) -> dict:
    import psutil  # inahitaji: pip install psutil

    host = os.environ.get("COMPUTERNAME") or socket.gethostname()
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "exe", "cmdline"]):
        try:
            i = p.info
            procs.append({"pid": i.get("pid"), "name": i.get("name") or "?", "user": i.get("username") or "?",
                          "exe": i.get("exe") or "", "cmd": " ".join(i.get("cmdline") or [])[:200]})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr:
                continue
            try:
                pn = psutil.Process(c.pid).name() if c.pid else "?"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pn = "?"
            conns.append({"local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                          "remote": f"{c.raddr.ip}:{c.raddr.port}", "state": c.status, "process": pn})
    except (psutil.AccessDenied, PermissionError):
        pass
    return {"host": host, "processes": procs[:300], "connections": conns[:300]}


#: Zinawekwa na main(), zinatumika na handlers zinazohitaji kutuma data.
_URL = ""
_TOKEN = ""


def _is_private(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast


def run_capture(params: dict) -> dict:
    """Kamata packets kwa `duration` sekunde, tuma flows kwa /ingest/events."""
    iface = str(params.get("iface", ""))
    duration = int(params.get("duration", 30))
    if not iface:
        raise ValueError("iface haijawekwa (namba kutoka: tshark -D)")
    cmd = [TSHARK, "-i", iface, "-a", f"duration:{duration}", "-n", "-f", "ip",
           "-T", "fields", "-E", f"separator={_SEP}",
           "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
           "-e", "tcp.dstport", "-e", "udp.dstport"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30).stdout
    agg: dict = {}
    for line in out.splitlines():
        c = line.split(_SEP)
        if len(c) < 5 or not c[0] or not c[1]:
            continue
        port_raw = (c[3] or c[4] or "").split(",")[0]
        key = (c[0], c[1], int(port_raw) if port_raw.isdigit() else None, c[2] or "?")
        agg[key] = agg.get(key, 0) + 1
    now = datetime.now(timezone.utc).timestamp()
    events = [{"kind": "flow", "srcIp": s, "dstIp": d, "dstPort": p, "protocol": pr, "ts": now}
              for (s, d, p, pr) in agg.keys()]
    if events:
        _post(_URL, _TOKEN, "/ingest/events", {"events": events[:400]})
    return {"flows": len(events), "duration": duration}


_QTYPE_LEVEL = {"error": "error", "critical": "error", "warning": "warn"}


def run_logs(params: dict) -> dict:
    """Soma Windows Event Log (channel) mara moja, tuma kwa /ingest/logs."""
    channel = str(params.get("channel", "System"))
    count = int(params.get("count", 20))
    host = os.environ.get("COMPUTERNAME") or socket.gethostname()
    out = subprocess.run(["wevtutil", "qe", channel, f"/c:{count}", "/rd:true", "/f:text"],
                         capture_output=True, text=True, timeout=25).stdout
    entries = []
    now = datetime.now(timezone.utc).timestamp()
    for block in out.split("Event["):
        block = block.strip()
        if not block:
            continue
        src = eid = lvl = ""
        desc = []
        in_desc = False
        for ln in block.splitlines():
            s = ln.strip()
            if s.startswith("Source:"):
                src = s.split(":", 1)[1].strip()
            elif s.startswith("Event ID:"):
                eid = s.split(":", 1)[1].strip()
            elif s.startswith("Level:"):
                lvl = s.split(":", 1)[1].strip().lower()
            elif s.startswith("Description:"):
                in_desc = True
            elif in_desc and s:
                desc.append(s)
        level = "error" if ("error" in lvl or "critical" in lvl) else "warn" if "warn" in lvl else "info"
        msg = f"[{src} #{eid}] {' '.join(desc)}".replace("\x00", "").strip()[:4000]
        entries.append({"source": f"win-{channel.lower()}", "host": host, "level": level, "message": msg, "ts": now})
    if entries:
        _post(_URL, _TOKEN, "/ingest/logs", {"entries": entries})
    return {"lines": len(entries), "channel": channel}


def _local_subnet() -> str:
    """Kisia subnet /24 ya mtandao wa ndani kutoka IP ya host."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except OSError:
        ip = socket.gethostbyname(socket.gethostname())
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24"


def _arp_table() -> dict:
    """IP -> MAC kutoka jedwali la ARP la mfumo (Windows au Unix)."""
    table: dict = {}
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return table
    import re

    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    mac_re = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")
    for line in out.splitlines():
        ipm = ip_re.search(line)
        macm = mac_re.search(line)
        if ipm and macm:
            mac = macm.group(1).replace("-", ":").lower()
            if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                table[ipm.group(1)] = mac
    return table


def _host_alive(ip: str, ports: list[int], timeout: float) -> bool:
    """Host iko hai kama port yoyote ime-connect au ime-refuse (RST = host up)."""
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    return False


def run_discovery(params: dict) -> dict:
    """Sweep ya subnet: gundua hosts hai, MAC (kutoka ARP) na hostname."""
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor

    subnet = str(params.get("subnet", "")).strip() or _local_subnet()
    ports = params.get("ports") or [135, 139, 445, 22, 80, 443, 3389, 53, 8080]
    timeout = float(params.get("timeout", 0.4))
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"subnet si sahihi: {subnet}") from exc

    candidates = [str(h) for h in net.hosts()][:1024]

    def probe(ip: str) -> str | None:
        return ip if _host_alive(ip, ports, timeout) else None

    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=100) as pool:
        for res in pool.map(probe, candidates):
            if res:
                alive.append(res)

    arp = _arp_table()
    hosts = []
    for ip in alive:
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror):
            pass
        hosts.append({"ip": ip, "mac": arp.get(ip), "hostname": hostname})
    return {"subnet": subnet, "hostsScanned": len(candidates), "hosts": hosts}


def _software_windows() -> list[dict]:
    import winreg  # Windows pekee

    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    seen: set = set()
    items: list[dict] = []
    for hive, path in roots:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        count = winreg.QueryInfoKey(key)[0]
        for i in range(count):
            try:
                sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
            except OSError:
                continue

            def val(name: str) -> str | None:
                try:
                    return str(winreg.QueryValueEx(sub, name)[0])
                except OSError:
                    return None

            name = val("DisplayName")
            if not name:
                continue
            try:
                if winreg.QueryValueEx(sub, "SystemComponent")[0] == 1:
                    continue
            except OSError:
                pass
            key_id = (name, val("DisplayVersion") or "")
            if key_id in seen:
                continue
            seen.add(key_id)
            items.append({"name": name[:200], "version": (val("DisplayVersion") or "")[:60],
                          "publisher": (val("Publisher") or "")[:120]})
    return items


def _software_unix() -> list[dict]:
    for cmd, sep in ((["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], "\t"),
                     (["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"], "\t")):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        items = []
        for line in out.splitlines():
            parts = line.split(sep)
            if parts and parts[0]:
                items.append({"name": parts[0][:200], "version": (parts[1] if len(parts) > 1 else "")[:60], "publisher": ""})
        if items:
            return items
    return []


def run_software(_params: dict) -> dict:
    """Orodhesha programu zilizosakinishwa kwenye host."""
    host = os.environ.get("COMPUTERNAME") or socket.gethostname()
    try:
        items = _software_windows() if os.name == "nt" else _software_unix()
    except Exception:  # noqa: BLE001
        items = []
    items.sort(key=lambda s: s["name"].lower())
    return {"host": host, "software": items[:800]}


_HANDLERS = {"scan": run_scan, "forensics": run_forensics, "capture": run_capture,
             "logs": run_logs, "discovery": run_discovery, "software": run_software}


def load_config() -> dict:
    if os.path.isfile(CONFIG):
        with open(CONFIG, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def enroll(url: str, token: str) -> str:
    host = os.environ.get("COMPUTERNAME") or socket.gethostname()
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        ip = None
    body = {"hostname": host, "os": os.name, "ip": ip,
            "capabilities": ["scan", "forensics", "capture", "logs", "discovery", "software"]}
    res = _post(url, token, "/agent/enroll", body)
    if not res or "agentId" not in res:
        raise SystemExit("Enrollment imeshindwa. Angalia HOMESIEM_URL / token.")
    return res["agentId"]


def main() -> None:
    cfg = load_config()
    env_url = os.environ.get("HOMESIEM_URL", "").strip()
    env_token = os.environ.get("HOMESIEM_SENSOR_TOKEN", "").strip()
    url = env_url or cfg.get("url", "")
    token = env_token or cfg.get("token", "")
    agent_id = cfg.get("agentId", "")

    if not url or not token:
        raise SystemExit("Mara ya kwanza weka HOMESIEM_URL na HOMESIEM_SENSOR_TOKEN.")

    # Kama token (au URL) imebadilika tofauti na config, sajili UPYA — huenda ni
    # akaunti/workspace tofauti. Bila hii, config ya zamani inashinda token mpya.
    if (env_token and cfg.get("token") and env_token != cfg.get("token")) or (
        env_url and cfg.get("url") and env_url != cfg.get("url")
    ):
        print("Token/URL imebadilika, nasajili upya…", flush=True)
        agent_id = ""

    global _URL, _TOKEN
    _URL, _TOKEN = url, token

    if not agent_id:
        print("Enrolling agent…", flush=True)
        agent_id = enroll(url, token)
        with open(CONFIG, "w", encoding="utf-8") as fh:
            json.dump({"url": url, "token": token, "agentId": agent_id}, fh)
        print(f"Enrolled. agentId={agent_id[:8]}… (config imehifadhiwa)", flush=True)

    print(f"HomeSIEM agent inaendesha. Inasubiri jobs kila {POLL_SECONDS}s. Ctrl+C kusimamisha.\n")
    try:
        while True:
            jobs = _get(url, token, f"/agent/{agent_id}/jobs")
            for job in jobs or []:
                kind = job.get("kind")
                jid = job.get("id")
                print(f"[job {jid[:8]}] {kind} …", flush=True)
                handler = _HANDLERS.get(kind)
                if handler is None:
                    _post(url, token, f"/agent/jobs/{jid}/result",
                          {"status": "error", "error": f"unsupported kind {kind}"})
                    continue
                try:
                    result = handler(job.get("params") or {})
                    _post(url, token, f"/agent/jobs/{jid}/result", {"status": "done", "result": result})
                    print(f"[job {jid[:8]}] done", flush=True)
                except Exception as exc:  # noqa: BLE001
                    _post(url, token, f"/agent/jobs/{jid}/result", {"status": "error", "error": str(exc)[:500]})
                    print(f"[job {jid[:8]}] error: {exc}", flush=True)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nImesimama.")


if __name__ == "__main__":
    main()
