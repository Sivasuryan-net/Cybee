# sniffer.py
# Lightweight live packet sniffer + heuristic detectors that POST alerts to backend /ingest
# Requires: scapy, requests
# Run as admin / with Npcap on Windows

from scapy.all import sniff, IP, TCP, UDP, Raw
import time, threading, hashlib, math, requests, json
from collections import defaultdict, deque

BACKEND_INGEST = "http://127.0.0.1:8000/ingest"
# Adjust thresholds to taste
PORTSCAN_WINDOW = 10      # seconds to consider for port scan
PORTSCAN_PORT_THRESHOLD = 20  # unique dst ports within window -> suspicious
DEDUP_WINDOW = 30         # seconds to avoid duplicate alerts

# simple local threat list (optional local check)
LOCAL_THREATS = {
    "ips": {"192.168.1.10", "10.0.0.5", "172.16.0.7"},
    "hashes": {"deadbeef","badc0ffee","cafebabe"},
    "ports": {22,23,3389,445}
}

# flow tracking for port-scan detection: src_ip -> deque of (dst_port, ts)
flows = defaultdict(lambda: deque())

# recently emitted alerts to avoid spam: (key)->timestamp
recent_alerts = {}

def sha256_hex(b: bytes):
    import hashlib
    return hashlib.sha256(b).hexdigest()

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math, collections
    counts = collections.Counter(data)
    length = len(data)
    ent = 0.0
    for cnt in counts.values():
        p = cnt / length
        ent -= p * math.log2(p)
    return ent

def mark_recent(alert_key):
    recent_alerts[alert_key] = time.time()

def is_recent(alert_key):
    ts = recent_alerts.get(alert_key)
    if not ts:
        return False
    return (time.time() - ts) < DEDUP_WINDOW

def send_alert_to_backend(event):
    try:
        r = requests.post(BACKEND_INGEST, json=event, timeout=3)
        if r.status_code == 200 or r.status_code == 201:
            print("[+] Sent alert:", event.get("alert_type","generic"), event.get("src_ip"), "->", event.get("dst_ip"))
        else:
            print("[-] Backend responded:", r.status_code, r.text)
    except Exception as e:
        print("[-] Failed to send alert:", e)

def analyze_and_maybe_alert(packet_info):
    """packet_info: dict with src_ip,dst_ip,src_port,dst_port,proto,payload_bytes"""
    src = packet_info["src_ip"]
    dst = packet_info["dst_ip"]
    dst_port = packet_info.get("dst_port")
    payload = packet_info.get("payload_bytes", b"")
    p_hash = sha256_hex(payload) if payload else None
    ent = shannon_entropy(payload) if payload else 0.0

    # register flow (portscan detection)
    now = time.time()
    if dst_port:
        flows[src].append((dst_port, now))

    # remove old entries
    while flows[src] and (now - flows[src][0][1] > PORTSCAN_WINDOW):
        flows[src].popleft()

    # Check for portscan: unique dst ports in WINDOW
    unique_ports = {p for p, ts in flows[src]}
    if len(unique_ports) >= PORTSCAN_PORT_THRESHOLD:
        key = f"portscan:{src}"
        if not is_recent(key):
            event = {
                "src_ip": src, "dst_ip": dst,
                "src_port": packet_info.get("src_port"),
                "dst_port": dst_port,
                "protocol": packet_info.get("proto"),
                "bytes": len(payload) if payload else 0,
                "payload_hash": p_hash,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "alert_type": "port_scan",
                "severity": "high",
                "note": f"{len(unique_ports)} unique dst ports in last {PORTSCAN_WINDOW}s"
            }
            mark_recent(key)
            send_alert_to_backend(event)

    # Check sensitive/common risky ports
    if dst_port and dst_port in LOCAL_THREATS["ports"]:
        key = f"riskyport:{src}:{dst_port}"
        if not is_recent(key):
            event = {
                "src_ip": src, "dst_ip": dst, "dst_port": dst_port,
                "protocol": packet_info.get("proto"),
                "payload_hash": p_hash,
                "alert_type": "risky_port_connection",
                "severity": "medium",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            mark_recent(key)
            send_alert_to_backend(event)

    # Check high-entropy payload (possible exfil or encryption)
    if ent and ent > 7.5 and len(payload) > 50:
        key = f"highentropy:{src}:{p_hash}"
        if not is_recent(key):
            event = {
                "src_ip": src, "dst_ip": dst, "dst_port": dst_port,
                "protocol": packet_info.get("proto"),
                "payload_hash": p_hash,
                "entropy": ent,
                "alert_type": "high_entropy_payload",
                "severity": "medium",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            mark_recent(key)
            send_alert_to_backend(event)

    # Keyword-based suspicious content (e.g., PowerShell, wget)
    if payload:
        try:
            s = payload.decode('utf-8', errors='ignore').lower()
            suspicious_keywords = ["powershell", "cmd.exe", "exec(", "wget ", "curl ", "base64", "nc -l", "reverse", "meterpreter"]
            for kw in suspicious_keywords:
                if kw in s:
                    key = f"keyword:{src}:{kw}"
                    if not is_recent(key):
                        event = {
                            "src_ip": src, "dst_ip": dst, "dst_port": dst_port,
                            "protocol": packet_info.get("proto"),
                            "payload_hash": p_hash,
                            "alert_type": "suspicious_keyword",
                            "keyword": kw,
                            "severity": "high" if kw in ["powershell","cmd.exe","meterpreter"] else "medium",
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        }
                        mark_recent(key)
                        send_alert_to_backend(event)
                        break
        except Exception:
            pass

    # Local threat list IP/hash quick check (optional)
    if src in LOCAL_THREATS["ips"] or dst in LOCAL_THREATS["ips"] or (p_hash and p_hash in LOCAL_THREATS["hashes"]):
        key = f"localthreat:{src}:{dst}:{p_hash}"
        if not is_recent(key):
            event = {
                "src_ip": src, "dst_ip": dst, "dst_port": dst_port,
                "protocol": packet_info.get("proto"),
                "payload_hash": p_hash,
                "alert_type": "local_threat_match",
                "severity": "high",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            mark_recent(key)
            send_alert_to_backend(event)

def process_packet(pkt):
    """Scapy callback for each sniffed packet"""
    try:
        if IP not in pkt:
            return
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = None
        src_port = None
        dst_port = None
        payload_bytes = b""

        if pkt.haslayer(TCP):
            proto = "TCP"
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
        else:
            proto = str(ip.proto)

        if pkt.haslayer(Raw):
            payload_bytes = bytes(pkt[Raw].load)

        packet_info = {
            "src_ip": src, "dst_ip": dst,
            "src_port": src_port, "dst_port": dst_port,
            "proto": proto, "payload_bytes": payload_bytes
        }

        # Run analyzers (non-blocking is ideal; here it's quick)
        analyze_and_maybe_alert(packet_info)

    except Exception as e:
        print("Error processing packet:", e)

if __name__ == "__main__":
    print("[*] Starting sniffer - you must run as Administrator (Windows) or root (Linux)")
    print("[*] Backend ingest:", BACKEND_INGEST)
    # sniff on all interfaces; you can set iface="Ethernet" etc.
    sniff(prn=process_packet, store=False)
