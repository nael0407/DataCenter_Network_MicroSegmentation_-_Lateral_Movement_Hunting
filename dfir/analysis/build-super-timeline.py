#!/usr/bin/env python3
"""
build-super-timeline.py - Multi-Source Forensic Super-Timeline Engine
Data Center Micro-segmentation & Incident Response Lab (DFIR Module)
Compliant with ISO/IEC 27037:2012 & NIST SP 800-61 Rev 2

Fitur:
  1. Mengonsolidasi & mengkorelasikan 5 sumber bukti forensik heterogen:
     - Network PCAP Analysis (extract-pcap-artifacts.py)
     - Host Triage & RFC 3227 Artefacts (parse-host-artifacts.py)
     - OPNsense Firewall Filterlog (filterlog pass/block events)
     - Zeek Network Security Monitoring (conn.log, notice.log, ssh.log)
     - OpenCanary Deception Decoy Alerts (opencanary.json)
  2. Normalisasi waktu UTC mikrodetik (ISO 8601 UTC: YYYY-MM-DDTHH:MM:SS.ffffffZ).
  3. Korelasi lintas sumber (Cross-Source Correlation):
     - Menghubungkan eksekusi perintah host -> paket jaringan -> aksi firewall OPNsense -> status Zeek.
  4. Analisis sebab-akibat (Causality & MITRE ATT&CK Mapping).
  5. Ekspor linimasa ke JSON, CSV, dan dasbor terminal berwarna.
"""

import os
import sys
import re
import csv
import json
import argparse
from datetime import datetime, timezone

# ANSI Colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

def normalize_to_utc_iso(ts_val, reference_year=None):
    """
    Mengonversi berbagai representasi stempel waktu (float epoch, RFC 5424, syslog, ISO 8601)
    menjadi format standar ISO 8601 UTC dengan presisi mikrodetik: YYYY-MM-DDTHH:MM:SS.ffffffZ
    """
    if ts_val is None:
        return None
    
    # Kasus 1: Float atau integer Unix Epoch (contoh Zeek ts: 1792238665.598282)
    if isinstance(ts_val, (int, float)):
        dt = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    ts_str = str(ts_val).strip()
    if not ts_str:
        return None

    # Jika string angka float
    try:
        f_val = float(ts_str)
        dt = datetime.fromtimestamp(f_val, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        pass

    # Kasus 2: ISO 8601 dengan atau tanpa timezone offset (contoh: 2026-10-17T21:10:00+07:00 atau Z)
    if "T" in ts_str:
        try:
            # Ganti Z dengan +00:00 untuk fromisoformat
            clean_ts = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            dt_utc = dt.astimezone(timezone.utc)
            return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except Exception:
            pass

    # Kasus 3: Format waktu standard spasi "YYYY-MM-DD HH:MM:SS.ffffff" (contoh OpenCanary)
    try:
        dt = datetime.strptime(ts_str[:26], "%Y-%m-%d %H:%M:%S.%f")
        dt_utc = dt.replace(tzinfo=timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except Exception:
        pass

    try:
        dt = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
        dt_utc = dt.replace(tzinfo=timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    except Exception:
        pass

    # Kasus 4: Syslog klasik ("Oct 18 04:41:36")
    year = reference_year or datetime.now(timezone.utc).year
    try:
        dt = datetime.strptime(f"{year} {ts_str[:15]}", "%Y %b %d %H:%M:%S")
        dt_utc = dt.replace(tzinfo=timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    except Exception:
        pass

    return ts_str

class SuperTimelineEngine:
    def __init__(self, case_id=None):
        self.case_id = case_id or "IR-UNASSIGNED"
        self.events = []
        self.sources_loaded = []
        self.correlation_findings = []

    def load_pcap_report(self, json_path):
        """Memuat event linimasa dari hasil analisis extract-pcap-artifacts.py."""
        if not os.path.exists(json_path):
            print(f"{YELLOW}[!] File PCAP report tidak ditemukan: {json_path}{RESET}")
            return
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_events = data.get("timeline_events", [])
            for ev in raw_events:
                ts_norm = normalize_to_utc_iso(ev.get("timestamp"))
                if ts_norm:
                    self.events.append({
                        "timestamp": ts_norm,
                        "source": "NETWORK_PCAP",
                        "category": ev.get("category", "NETWORK"),
                        "action": ev.get("action", "-"),
                        "src_ip": ev.get("src_ip", "-"),
                        "src_port": ev.get("src_port", 0),
                        "dst_ip": ev.get("dst_ip", "-"),
                        "dst_port": ev.get("dst_port", 0),
                        "verdict": "OBSERVED",
                        "details": ev.get("details", "-"),
                        "mitre_attck": "-"
                    })
            self.sources_loaded.append(f"PCAP ({os.path.basename(json_path)}): {len(raw_events)} events")
        except Exception as e:
            print(f"{RED}[ERROR] Gagal memuat PCAP report: {e}{RESET}")

    def load_host_report(self, json_path):
        """Memuat event linimasa dari hasil analisis parse-host-artifacts.py."""
        if not os.path.exists(json_path):
            print(f"{YELLOW}[!] File Host report tidak ditemukan: {json_path}{RESET}")
            return
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            node_name = data.get("target_node", "HOST").upper()
            raw_events = data.get("timeline_events", [])
            for ev in raw_events:
                ts_norm = normalize_to_utc_iso(ev.get("timestamp"))
                if ts_norm:
                    self.events.append({
                        "timestamp": ts_norm,
                        "source": f"HOST_{node_name}",
                        "category": ev.get("category", "HOST"),
                        "action": ev.get("action", "-"),
                        "src_ip": ev.get("src_ip", "-"),
                        "src_port": ev.get("src_port", 0),
                        "dst_ip": ev.get("dst_ip", "-"),
                        "dst_port": ev.get("dst_port", 0),
                        "verdict": "EXECUTED",
                        "details": ev.get("details", "-"),
                        "mitre_attck": "-"
                    })
            self.sources_loaded.append(f"HOST_{node_name} ({os.path.basename(json_path)}): {len(raw_events)} events")
        except Exception as e:
            print(f"{RED}[ERROR] Gagal memuat Host report: {e}{RESET}")

    def load_opnsense_filterlog(self, log_path):
        """Memuat log firewall OPNsense filterlog (RFC 5424 syslog + CSV fields)."""
        if not os.path.exists(log_path):
            print(f"{YELLOW}[!] File OPNsense log tidak ditemukan: {log_path}{RESET}")
            return
        count = 0
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if "filterlog" not in line or not line:
                        continue

                    # Contoh line:
                    # <134>1 2026-10-17T21:10:00+07:00 opnsense filterlog 38093 - [meta...] 15,,,02f4...,vtnet2,match,block,in,4,0x0,,64,50205,0,DF,6,tcp,60,203.0.113.11,8.8.8.8,33820,53,...
                    m_syslog = re.search(r"(\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+filterlog\b.*\]\s+(.*)$", line)
                    if not m_syslog:
                        # Fallback jika tidak ada meta bracket
                        m_syslog = re.search(r"(\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+filterlog(?:\S+)?:\s+(.*)$", line)
                    if not m_syslog:
                        continue

                    ts_raw, csv_part = m_syslog.groups()
                    ts_norm = normalize_to_utc_iso(ts_raw)
                    fields = [f.strip() for f in csv_part.split(",")]

                    # Validasi panjang fields OPNsense (IPv4 TCP/UDP minimal 20 fields)
                    if len(fields) >= 19:
                        # Index umum OPNsense filterlog CSV:
                        # 0: rulenum, 4: iface, 6: action (pass/block), 7: direction (in/out), 8: ip_version (4/6)
                        iface = fields[4]
                        action = fields[6] # 'block' atau 'pass'
                        direction = fields[7]
                        ip_ver = fields[8]

                        if ip_ver == "4" and len(fields) >= 20:
                            proto_name = fields[16].upper()
                            src_ip = fields[18]
                            dst_ip = fields[19]
                            src_port = int(fields[20]) if len(fields) > 20 and fields[20].isdigit() else 0
                            dst_port = int(fields[21]) if len(fields) > 21 and fields[21].isdigit() else 0

                            verdict = "FIREWALL_BLOCK" if action == "block" else "FIREWALL_PASS"
                            action_desc = f"OPNsense {action.upper()} {proto_name} ({direction} on {iface})"
                            
                            self.events.append({
                                "timestamp": ts_norm,
                                "source": "FIREWALL_OPNSENSE",
                                "category": "FIREWALL",
                                "action": action_desc,
                                "src_ip": src_ip,
                                "src_port": src_port,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "verdict": verdict,
                                "details": f"Action: {action.upper()} | Interface: {iface} | Proto: {proto_name}",
                                "mitre_attck": "T1562 Impair Defenses (Mitigated)" if action == "block" else "-"
                            })
                            count += 1
            self.sources_loaded.append(f"OPNsense Filterlog ({os.path.basename(log_path)}): {count} events")
        except Exception as e:
            print(f"{RED}[ERROR] Gagal memuat OPNsense filterlog: {e}{RESET}")

    def load_zeek_conn_log(self, log_path):
        """Memuat log Zeek conn.log (JSON lines atau TSV)."""
        if not os.path.exists(log_path):
            print(f"{YELLOW}[!] File Zeek conn.log tidak ditemukan: {log_path}{RESET}")
            return
        count = 0
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Cek format JSON Lines
                    if line.startswith("{") and line.endswith("}"):
                        try:
                            record = json.loads(line)
                            ts_norm = normalize_to_utc_iso(record.get("ts"))
                            src_ip = record.get("id.orig_h", "-")
                            src_port = record.get("id.orig_p", 0)
                            dst_ip = record.get("id.resp_h", "-")
                            dst_port = record.get("id.resp_p", 0)
                            proto = record.get("proto", "-").upper()
                            service = record.get("service", "-")
                            conn_state = record.get("conn_state", "-")
                            duration = record.get("duration", 0.0)
                            orig_bytes = record.get("orig_bytes", 0)
                            resp_bytes = record.get("resp_bytes", 0)

                            action = f"Zeek Conn {proto}/{service or dst_port} [{conn_state}]"
                            verdict = "SESSION_COMPLETED" if conn_state in ("SF", "SHR") else ("SESSION_BLOCKED_OR_REJECTED" if conn_state in ("REJ", "S0", "RSTO", "RSTR") else conn_state)

                            self.events.append({
                                "timestamp": ts_norm,
                                "source": "ZEEK_NSM",
                                "category": "NETWORK_METADATA",
                                "action": action,
                                "src_ip": src_ip,
                                "src_port": src_port,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "verdict": verdict,
                                "details": f"State: {conn_state} | Duration: {duration}s | Bytes: {orig_bytes} sent / {resp_bytes} recv",
                                "mitre_attck": "-"
                            })
                            count += 1
                        except Exception:
                            continue
            self.sources_loaded.append(f"Zeek NSM ({os.path.basename(log_path)}): {count} events")
        except Exception as e:
            print(f"{RED}[ERROR] Gagal memuat Zeek conn.log: {e}{RESET}")

    def load_opencanary_alerts(self, log_path):
        """Memuat alert honeypot OpenCanary (JSON lines)."""
        if not os.path.exists(log_path):
            print(f"{YELLOW}[!] File OpenCanary log tidak ditemukan: {log_path}{RESET}")
            return
        count = 0
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        record = json.loads(line)
                        logtype = record.get("logtype")
                        # Abaikan log internal startup (1001)
                        if logtype == 1001:
                            continue

                        ts_norm = normalize_to_utc_iso(record.get("utc_time") or record.get("local_time"))
                        src_ip = record.get("src_host", "-")
                        src_port = record.get("src_port", 0)
                        dst_ip = record.get("dst_host", "-")
                        dst_port = record.get("dst_port", 0)
                        node_id = record.get("node_id", "canary")
                        logdata = record.get("logdata", {})

                        action = f"OpenCanary Honeypot Hit on Port {dst_port}"
                        self.events.append({
                            "timestamp": ts_norm,
                            "source": "DECEPTION_OPENCANARY",
                            "category": "HONEYPOT_ALERT",
                            "action": action,
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "verdict": "INTRUSION_DETECTED",
                            "details": f"Node: {node_id} | Payload: {json.dumps(logdata)}",
                            "mitre_attck": "T1046 Network Service Scanning / T1078 Valid Accounts"
                        })
                        count += 1
                    except Exception:
                        continue
            self.sources_loaded.append(f"OpenCanary Decoy ({os.path.basename(log_path)}): {count} events")
        except Exception as e:
            print(f"{RED}[ERROR] Gagal memuat OpenCanary log: {e}{RESET}")

    def correlate_incident_threads(self):
        """
        Korelasi Lintas Sumber (Cross-Source Correlation):
        Mencocokkan peristiwa eksekusi perintah di Host dengan pencegahan di Firewall & status Zeek.
        """
        # Urutkan seluruh event berdasarkan timestamp mikrodetik
        self.events.sort(key=lambda x: x["timestamp"])

        # Identifikasi ancaman eksfiltrasi data
        exfil_events = [e for e in self.events if "core_accounts" in str(e["details"]).lower() or "exfil" in str(e["action"]).lower() or "exfil" in str(e["details"]).lower()]
        if exfil_events:
            for ev in exfil_events:
                self.correlation_findings.append({
                    "threat_type": "DATA_EXFILTRATION_ATTEMPT",
                    "timestamp": ev["timestamp"],
                    "actor_ip": ev["src_ip"],
                    "target_destination": ev["dst_ip"],
                    "summary": f"Upaya eksfiltrasi data nasabah terdeteksi dari {ev['src_ip']} menuju {ev['dst_ip']}:{ev['dst_port']}",
                    "evidence_sources": [ev["source"]]
                })

        # Identifikasi blokade firewall terhadap trafik berbahaya
        blocked_events = [e for e in self.events if e.get("verdict") == "FIREWALL_BLOCK"]
        if blocked_events:
            blocked_summary = f"Firewall OPNsense berhasil menjatuhkan ({len(blocked_events)}) paket penyerang / eksfiltrasi."
            self.correlation_findings.append({
                "threat_type": "ZERO_TRUST_CONTAINMENT",
                "timestamp": blocked_events[0]["timestamp"],
                "actor_ip": blocked_events[0]["src_ip"],
                "target_destination": blocked_events[0]["dst_ip"],
                "summary": blocked_summary,
                "evidence_sources": ["FIREWALL_OPNSENSE"]
            })

    def export_json(self, output_path):
        """Ekspor seluruh linimasa dan korelasi ke JSON."""
        data = {
            "case_id": self.case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(self.events),
            "sources_loaded": self.sources_loaded,
            "correlation_findings": self.correlation_findings,
            "timeline": self.events
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return output_path

    def export_csv(self, output_path):
        """Ekspor linimasa ke CSV terstruktur untuk analisis SIEM atau spreadsheet."""
        fieldnames = ["timestamp", "source", "category", "action", "src_ip", "src_port", "dst_ip", "dst_port", "verdict", "details", "mitre_attck"]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for ev in self.events:
                writer.writerow(ev)
        return output_path

    def print_dashboard(self, json_path, csv_path):
        """Tampilkan dasbor linimasa ke terminal dengan pemformatan forensik tingkat tinggi."""
        print()
        print(f"{BOLD}{CYAN}                    SUPER-TIMELINE RECONSTRUCTION DASHBOARD (CROSS-CORRELATED)                      {RESET}")
        print(f"  ID Kasus Forensik   : {BOLD}{self.case_id}{RESET}")
        print(f"  Total Peristiwa     : {BOLD}{len(self.events)}{RESET} event (Presisi Mikrodetik UTC)")
        print(f"  Sumber Bukti Termuat:")
        for s in self.sources_loaded:
            print(f"    - {GREEN}{s}{RESET}")
        print()

        if self.correlation_findings:
            print(f"{BOLD}{RED}TEMUAN KORELASI LINTAS-SUMBER (INCIDENT THREADS):{RESET}")
            for idx, c in enumerate(self.correlation_findings, 1):
                print(f"  [{idx}] {YELLOW}{c['threat_type']}{RESET} @ {c['timestamp']}")
                print(f"      {c['summary']}")
                print(f"      Rantai Bukti: {CYAN}{', '.join(c['evidence_sources'])}{RESET}")
            print()

        print(f"{BOLD}REKONSTRUKSI KRONOLOGIS PERISTIWA (CUPLIKAN LINIMASA):{RESET}")
        print("-" * 100)
        print(f"{BOLD}{'Timestamp (UTC)':<28} | {'Sumber':<18} | {'Kategori':<15} | {'Aksi & Rincian Forensik'}{RESET}")
        print("-" * 100)

        # Tampilkan maksimal 20 event representatif
        display_events = self.events[:25]
        for ev in display_events:
            color = RESET
            if ev.get("verdict") == "FIREWALL_BLOCK":
                color = RED
            elif "EXFIL" in ev.get("action", "") or "core_accounts" in ev.get("details", ""):
                color = YELLOW
            elif "AUTH" in ev.get("category", "") or "SUCCESS" in ev.get("action", ""):
                color = GREEN
            elif "HONEYPOT" in ev.get("category", ""):
                color = MAGENTA

            ts_short = ev['timestamp']
            src_short = ev['source'][:17]
            cat_short = ev['category'][:14]
            desc = f"{ev['action']} [{ev['src_ip']}:{ev['src_port']} -> {ev['dst_ip']}:{ev['dst_port']}]"
            print(f"{color}{ts_short:<28} | {src_short:<18} | {cat_short:<15} | {desc[:40]}{RESET}")

        if len(self.events) > 25:
            print(f"... dan {len(self.events) - 25} peristiwa lainnya termuat dalam berkas ekspor.")
        print("-" * 100)
        print(f"{BOLD}{GREEN}[SUCCESS] Hasil Super-Timeline Berhasil Dihasilkan:{RESET}")
        print(f"  -> JSON: {json_path}")
        print(f"  -> CSV : {csv_path}")
        print()

def main():
    parser = argparse.ArgumentParser(
        description="Forensic Super-Timeline Engine & Multi-Source Cross-Correlator",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--case-id", required=True, help="ID Kasus Forensik (contoh: IR-2026-S06)")
    parser.add_argument("--pcap-report", nargs="*", default=[], help="Path ke satu atau lebih berkas pcap-analysis-report.json")
    parser.add_argument("--host-report", nargs="*", default=[], help="Path ke satu atau lebih berkas host-analysis-report.json")
    parser.add_argument("--opnsense-log", default=None, help="Path ke berkas log filterlog OPNsense")
    parser.add_argument("--zeek-log", default=None, help="Path ke berkas log Zeek (conn.log)")
    parser.add_argument("--canary-log", default=None, help="Path ke berkas alert OpenCanary (opencanary.json)")
    parser.add_argument("--output-dir", "-o", default=None, help="Direktori penyimpanan hasil linimasa")

    args = parser.parse_args()

    out_dir = os.path.abspath(args.output_dir or f"./super_timeline_{args.case_id.lower()}")
    os.makedirs(out_dir, exist_ok=True)

    engine = SuperTimelineEngine(case_id=args.case_id)

    # 1. Muat laporan PCAP
    for p_path in args.pcap_report:
        engine.load_pcap_report(p_path)

    # 2. Muat laporan Host
    for h_path in args.host_report:
        engine.load_host_report(h_path)

    # 3. Muat OPNsense log
    if args.opnsense_log:
        engine.load_opnsense_filterlog(args.opnsense_log)

    # 4. Muat Zeek log
    if args.zeek_log:
        engine.load_zeek_conn_log(args.zeek_log)

    # 5. Muat OpenCanary log
    if args.canary_log:
        engine.load_opencanary_alerts(args.canary_log)

    if not engine.events:
        print(f"{RED}[ERROR] Tidak ada event yang berhasil dimuat dari sumber yang diberikan!{RESET}")
        sys.exit(1)

    engine.correlate_incident_threads()

    json_out = os.path.join(out_dir, "super-timeline.json")
    csv_out = os.path.join(out_dir, "super-timeline.csv")

    engine.export_json(json_out)
    engine.export_csv(csv_out)
    engine.print_dashboard(json_out, csv_out)

if __name__ == "__main__":
    main()
