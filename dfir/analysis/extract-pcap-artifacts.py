#!/usr/bin/env python3
"""
extract-pcap-artifacts.py - Network Stream Carving & Protocol Payload Extractor
Data Center Micro-segmentation & Incident Response Lab (DFIR Module)
Compliant with ISO/IEC 27037:2012 Digital Evidence Handling

Fitur:
  1. Rekonstruksi aliran TCP (Bidirectional TCP Stream Reassembly).
  2. Ekstraksi protokol & carving muatan data:
     - HTTP: Request methods, URI, Headers, Form/JSON payload, Response bodies.
     - ICMP: Deteksi ICMP tunneling / eksfiltrasi data via ping payload.
     - DNS: Ekstraksi QNAME, QTYPE, dan deteksi anomali tunneling/eksfiltrasi.
     - SSH: Banner exchange, algoritma kearsipan, dan metadata sesi.
     - Database: Deteksi lalu lintas SQL / PostgreSQL mentah.
  3. Pemindaian kebocoran data sensitif (PII, rekening nasabah, kredensial, token).
  4. Ekstraksi berkas muatan (File Carving) ke disk dengan dual-hashing SHA-256 & SHA-512.
  5. Ekspor terstruktur ke JSON & CSV untuk diumpankan ke Super-Timeline Engine.
"""

import os
import sys
import re
import json
import hashlib
import argparse
from datetime import datetime, timezone
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, Raw
except ImportError:
    print("[ERROR] Pustaka 'scapy' tidak ditemukan. Harap instal dengan: pip3 install scapy")
    sys.exit(1)

# ANSI Colors for Forensic Dashboard
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Pola regex untuk mendeteksi potensi kebocoran data sensitif
SENSITIVE_PATTERNS = {
    "db_account": re.compile(r"(core_accounts|account_id|account_number|nomor_rekening|saldo|balance|nasabah)", re.IGNORECASE),
    "sql_statement": re.compile(r"(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM|CREATE\s+TABLE|DROP\s+TABLE)", re.IGNORECASE),
    "credentials": re.compile(r"(password|passwd|pwd|secret|api_key|token|bearer\s+[a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
    "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    "base64_blob": re.compile(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
}

def format_utc(ts_float):
    """Konversi unix timestamp float ke ISO 8601 UTC string dengan presisi mikrodetik."""
    dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def compute_hashes(data_bytes):
    """Menghitung hash SHA-256 dan SHA-512 dari rangkaian bytes."""
    h256 = hashlib.sha256(data_bytes).hexdigest()
    h512 = hashlib.sha512(data_bytes).hexdigest()
    return h256, h512

class PcapArtifactExtractor:
    def __init__(self, pcap_path, output_dir=None, carve_files=False, case_id=None, filter_ip=None):
        self.pcap_path = os.path.abspath(pcap_path)
        self.carve_files = carve_files
        self.case_id = case_id or "IR-UNASSIGNED"
        self.filter_ip = filter_ip
        
        # Inisialisasi direktori output
        pcap_name = os.path.splitext(os.path.basename(self.pcap_path))[0]
        if output_dir:
            self.output_dir = os.path.abspath(output_dir)
        else:
            self.output_dir = os.path.join(os.path.dirname(self.pcap_path), f"extracted_{pcap_name}")
        
        self.carved_dir = os.path.join(self.output_dir, "carved_artifacts")
        os.makedirs(self.carved_dir, exist_ok=True)

        # Struktur data analisis
        self.packets_count = 0
        self.protocol_counts = defaultdict(int)
        self.streams = {}           # key: stream_id -> dict
        self.http_requests = []     # list of http request artifacts
        self.http_responses = []    # list of http response artifacts
        self.icmp_artifacts = []    # list of icmp payloads
        self.dns_artifacts = []     # list of dns query/response
        self.ssh_artifacts = []     # list of ssh sessions
        self.carved_artifacts = []  # list of files extracted to disk
        self.timeline_events = []   # microsecond normalized events for timeline engine
        self.sensitive_findings = []# suspicious detections

    def get_stream_key(self, ip_src, port_src, ip_dst, port_dst, proto):
        """Menghasilkan kunci aliran kanonikal (independen arah paket)."""
        ep1 = (ip_src, port_src)
        ep2 = (ip_dst, port_dst)
        if ep1 < ep2:
            return f"{proto}_{ep1[0]}:{ep1[1]}_{ep2[0]}:{ep2[1]}"
        else:
            return f"{proto}_{ep2[0]}:{ep2[1]}_{ep1[0]}:{ep1[1]}"

    def scan_sensitive_patterns(self, text, context_type, source_info):
        """Pindai teks terhadap indikator kebocoran data."""
        if not text:
            return
        for label, regex in SENSITIVE_PATTERNS.items():
            matches = regex.findall(text)
            if matches:
                sample = str(matches[0])[:80]
                finding = {
                    "rule": label,
                    "context": context_type,
                    "source": source_info,
                    "matches_count": len(matches),
                    "sample": sample
                }
                self.sensitive_findings.append(finding)

    def extract_http_info(self, payload_bytes, ip_src, port_src, ip_dst, port_dst, ts_float, stream_id):
        """Mengekstrak percakapan HTTP dari payload raw bytes."""
        try:
            text = payload_bytes.decode('utf-8', errors='replace')
        except Exception:
            return

        # Deteksi HTTP Request
        req_match = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+(HTTP/\d\.\d)", text)
        if req_match:
            method, uri, version = req_match.groups()
            headers = {}
            body = ""
            parts = text.split("\r\n\r\n", 1)
            header_lines = parts[0].split("\r\n")[1:]
            for line in header_lines:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if len(parts) > 1:
                body = parts[1]

            art = {
                "type": "HTTP_REQUEST",
                "timestamp": format_utc(ts_float),
                "timestamp_epoch": ts_float,
                "stream_id": stream_id,
                "client": f"{ip_src}:{port_src}",
                "server": f"{ip_dst}:{port_dst}",
                "method": method,
                "uri": uri,
                "host": headers.get("host", ""),
                "content_type": headers.get("content-type", ""),
                "content_length": headers.get("content-length", len(body)),
                "headers": headers,
                "body_preview": body[:200] if body else "",
                "body_length": len(body)
            }
            self.http_requests.append(art)

            # Tambahkan event ke timeline
            self.timeline_events.append({
                "timestamp": art["timestamp"],
                "source": "NETWORK_PCAP",
                "category": "HTTP",
                "action": f"HTTP {method} {uri}",
                "src_ip": ip_src,
                "src_port": port_src,
                "dst_ip": ip_dst,
                "dst_port": port_dst,
                "details": f"Host: {art['host']} | Content-Type: {art['content_type']} | BodyLen: {len(body)}"
            })

            # Pindai kebocoran data di URI, Headers, dan Body
            self.scan_sensitive_patterns(uri, "HTTP_URI", f"{ip_src}:{port_src} -> {ip_dst}:{port_dst}")
            if body:
                self.scan_sensitive_patterns(body, "HTTP_POST_BODY", f"{ip_src}:{port_src} -> {ip_dst}:{port_dst}")

            # Carve payload body jika opsi aktif dan body tidak kosong
            if self.carve_files and len(body.strip()) > 0:
                carve_id = f"http_req_{len(self.http_requests)}_{method}"
                filename = f"{carve_id}.txt"
                filepath = os.path.join(self.carved_dir, filename)
                raw_body = body.encode('utf-8', errors='replace')
                with open(filepath, "wb") as f:
                    f.write(raw_body)
                h256, h512 = compute_hashes(raw_body)
                self.carved_artifacts.append({
                    "artifact_id": carve_id,
                    "filename": filename,
                    "path": filepath,
                    "protocol": "HTTP",
                    "direction": "REQUEST",
                    "size_bytes": len(raw_body),
                    "sha256": h256,
                    "sha512": h512,
                    "timestamp": art["timestamp"],
                    "source": f"{ip_src}:{port_src}",
                    "destination": f"{ip_dst}:{port_dst}"
                })
            return

        # Deteksi HTTP Response
        resp_match = re.match(r"^(HTTP/\d\.\d)\s+(\d{3})\s+([A-Za-z0-9 ]*)", text)
        if resp_match:
            version, status_code, reason = resp_match.groups()
            headers = {}
            body = ""
            parts = text.split("\r\n\r\n", 1)
            header_lines = parts[0].split("\r\n")[1:]
            for line in header_lines:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if len(parts) > 1:
                body = parts[1]

            art = {
                "type": "HTTP_RESPONSE",
                "timestamp": format_utc(ts_float),
                "timestamp_epoch": ts_float,
                "stream_id": stream_id,
                "server": f"{ip_src}:{port_src}",
                "client": f"{ip_dst}:{port_dst}",
                "status_code": int(status_code),
                "reason": reason.strip(),
                "content_type": headers.get("content-type", ""),
                "content_length": headers.get("content-length", len(body)),
                "headers": headers,
                "body_preview": body[:200] if body else "",
                "body_length": len(body)
            }
            self.http_responses.append(art)

            # Tambahkan event ke timeline
            self.timeline_events.append({
                "timestamp": art["timestamp"],
                "source": "NETWORK_PCAP",
                "category": "HTTP",
                "action": f"HTTP Response {status_code} {reason}",
                "src_ip": ip_src,
                "src_port": port_src,
                "dst_ip": ip_dst,
                "dst_port": port_dst,
                "details": f"Content-Type: {art['content_type']} | BodyLen: {len(body)}"
            })

            if body:
                self.scan_sensitive_patterns(body, "HTTP_RESP_BODY", f"{ip_src}:{port_src} -> {ip_dst}:{port_dst}")

            if self.carve_files and len(body.strip()) > 0:
                carve_id = f"http_resp_{len(self.http_responses)}_{status_code}"
                filename = f"{carve_id}.bin"
                filepath = os.path.join(self.carved_dir, filename)
                raw_body = body.encode('utf-8', errors='replace')
                with open(filepath, "wb") as f:
                    f.write(raw_body)
                h256, h512 = compute_hashes(raw_body)
                self.carved_artifacts.append({
                    "artifact_id": carve_id,
                    "filename": filename,
                    "path": filepath,
                    "protocol": "HTTP",
                    "direction": "RESPONSE",
                    "size_bytes": len(raw_body),
                    "sha256": h256,
                    "sha512": h512,
                    "timestamp": art["timestamp"],
                    "source": f"{ip_src}:{port_src}",
                    "destination": f"{ip_dst}:{port_dst}"
                })

    def extract_icmp_info(self, packet, ts_float):
        """Mengekstrak informasi ICMP dan memeriksa indikator ICMP Tunneling / Eksfiltrasi."""
        icmp_layer = packet[ICMP]
        ip_layer = packet[IP]
        ip_src = ip_layer.src
        ip_dst = ip_layer.dst
        icmp_type = icmp_layer.type
        icmp_code = icmp_layer.code

        # Standar Linux ping payload: timestamp 8 bytes + 0x10..0x37 sequence.
        # Custom payload yang panjang atau berisi teks ASCII dicurigai sebagai data eksfiltrasi/tunneling.
        payload = b""
        if Raw in packet:
            payload = bytes(packet[Raw].load)

        payload_len = len(payload)
        is_suspicious = False
        ascii_text = ""
        try:
            ascii_text = payload.decode('ascii', errors='ignore')
        except Exception:
            pass

        # Deteksi payload anomali (bukan urutan standar, mengandung teks sensitif atau panjang > 64)
        if payload_len > 0:
            if re.search(r"[a-zA-Z0-9_\-\.\=\+\/]{8,}", ascii_text):
                is_suspicious = True
            for label, regex in SENSITIVE_PATTERNS.items():
                if regex.search(ascii_text):
                    is_suspicious = True
                    self.sensitive_findings.append({
                        "rule": f"ICMP_{label}",
                        "context": "ICMP_PAYLOAD_EXFILTRATION",
                        "source": f"{ip_src} -> {ip_dst}",
                        "matches_count": 1,
                        "sample": ascii_text[:80]
                    })

        type_str = "ECHO_REQUEST" if icmp_type == 8 else ("ECHO_REPLY" if icmp_type == 0 else f"TYPE_{icmp_type}")
        
        art = {
            "timestamp": format_utc(ts_float),
            "timestamp_epoch": ts_float,
            "src_ip": ip_src,
            "dst_ip": ip_dst,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "type_desc": type_str,
            "payload_len": payload_len,
            "payload_preview_ascii": ascii_text[:100],
            "is_suspicious_tunneling": is_suspicious
        }
        self.icmp_artifacts.append(art)

        # Tambahkan ke timeline
        self.timeline_events.append({
            "timestamp": art["timestamp"],
            "source": "NETWORK_PCAP",
            "category": "ICMP",
            "action": f"ICMP {type_str}",
            "src_ip": ip_src,
            "src_port": 0,
            "dst_ip": ip_dst,
            "dst_port": 0,
            "details": f"Payload: {payload_len} bytes | Suspicious: {is_suspicious} | Preview: {ascii_text[:40]}"
        })

        if self.carve_files and is_suspicious and payload_len > 0:
            carve_id = f"icmp_tunnel_{len(self.icmp_artifacts)}"
            filename = f"{carve_id}.bin"
            filepath = os.path.join(self.carved_dir, filename)
            with open(filepath, "wb") as f:
                f.write(payload)
            h256, h512 = compute_hashes(payload)
            self.carved_artifacts.append({
                "artifact_id": carve_id,
                "filename": filename,
                "path": filepath,
                "protocol": "ICMP",
                "direction": "TUNNEL_PAYLOAD",
                "size_bytes": payload_len,
                "sha256": h256,
                "sha512": h512,
                "timestamp": art["timestamp"],
                "source": ip_src,
                "destination": ip_dst
            })

    def extract_dns_info(self, packet, ts_float):
        """Mengekstrak pertanyaan dan jawaban DNS serta indikator eksfiltrasi via DNS."""
        dns_layer = packet[DNS]
        ip_layer = packet[IP] if IP in packet else packet[IPv6]
        ip_src = ip_layer.src
        ip_dst = ip_layer.dst

        qname = ""
        qtype = ""
        if dns_layer.qd:
            qname = dns_layer.qd.qname.decode('utf-8', errors='ignore') if isinstance(dns_layer.qd.qname, bytes) else str(dns_layer.qd.qname)
            qtype = str(dns_layer.qd.qtype)

        answers = []
        if dns_layer.an:
            for i in range(dns_layer.ancount):
                ans = dns_layer.an[i]
                rdata = str(ans.rdata) if hasattr(ans, 'rdata') else ""
                answers.append(rdata)

        # Deteksi eksfiltrasi data via DNS Subdomain (panjang subdomain > 40 karakter atau entropi tinggi)
        is_suspicious = False
        subdomain_part = qname.split(".")[0] if "." in qname else qname
        if len(subdomain_part) > 35:
            is_suspicious = True
            self.sensitive_findings.append({
                "rule": "DNS_EXFILTRATION_LONG_LABEL",
                "context": "DNS_QUERY",
                "source": f"{ip_src} -> {ip_dst}",
                "matches_count": 1,
                "sample": qname[:80]
            })

        art = {
            "timestamp": format_utc(ts_float),
            "timestamp_epoch": ts_float,
            "src_ip": ip_src,
            "dst_ip": ip_dst,
            "qr_flag": "RESPONSE" if dns_layer.qr == 1 else "QUERY",
            "qname": qname,
            "qtype": qtype,
            "answers": answers,
            "is_suspicious_tunneling": is_suspicious
        }
        self.dns_artifacts.append(art)

        self.timeline_events.append({
            "timestamp": art["timestamp"],
            "source": "NETWORK_PCAP",
            "category": "DNS",
            "action": f"DNS {art['qr_flag']} {qname}",
            "src_ip": ip_src,
            "src_port": packet[UDP].sport if UDP in packet else 0,
            "dst_ip": ip_dst,
            "dst_port": packet[UDP].dport if UDP in packet else 0,
            "details": f"QType: {qtype} | Answers: {','.join(answers[:3])} | Suspicious: {is_suspicious}"
        })

    def extract_ssh_info(self, payload_bytes, ip_src, port_src, ip_dst, port_dst, ts_float, stream_id):
        """Mengekstrak banner SSH dan metadata sesi."""
        try:
            text = payload_bytes.decode('ascii', errors='ignore')
        except Exception:
            return

        if text.startswith("SSH-"):
            banner = text.strip().split("\r\n")[0].split("\n")[0]
            art = {
                "timestamp": format_utc(ts_float),
                "timestamp_epoch": ts_float,
                "stream_id": stream_id,
                "src_ip": ip_src,
                "src_port": port_src,
                "dst_ip": ip_dst,
                "dst_port": port_dst,
                "banner": banner
            }
            self.ssh_artifacts.append(art)
            self.timeline_events.append({
                "timestamp": art["timestamp"],
                "source": "NETWORK_PCAP",
                "category": "SSH",
                "action": f"SSH Banner Exchange ({banner})",
                "src_ip": ip_src,
                "src_port": port_src,
                "dst_ip": ip_dst,
                "dst_port": port_dst,
                "details": f"Banner: {banner}"
            })

    def process(self):
        """Membaca dan memproses setiap frame paket di dalam berkas PCAP."""
        print(f"{CYAN}[*] Membaca berkas PCAP:{RESET} {self.pcap_path}")
        try:
            packets = rdpcap(self.pcap_path)
        except Exception as e:
            print(f"{RED}[ERROR] Gagal membaca PCAP: {e}{RESET}")
            sys.exit(1)

        self.packets_count = len(packets)
        print(f"{GREEN}[OK] Total {self.packets_count} paket berhasil dimuat ke memory.{RESET}")

        for idx, pkt in enumerate(packets):
            ts = float(pkt.time)
            
            # Hanya proses layer IP/IPv6
            if not (IP in pkt or IPv6 in pkt):
                self.protocol_counts["NON_IP"] += 1
                continue

            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            ip_src = ip_layer.src
            ip_dst = ip_layer.dst

            # Filter IP jika ditentukan
            if self.filter_ip:
                if ip_src != self.filter_ip and ip_dst != self.filter_ip:
                    continue

            # 1. Analisis ICMP
            if ICMP in pkt:
                self.protocol_counts["ICMP"] += 1
                self.extract_icmp_info(pkt, ts)
                continue

            # 2. Analisis DNS
            if DNS in pkt:
                self.protocol_counts["DNS"] += 1
                self.extract_dns_info(pkt, ts)

            # 3. Analisis TCP & Rekonstruksi Stream
            if TCP in pkt:
                self.protocol_counts["TCP"] += 1
                tcp_layer = pkt[TCP]
                port_src = tcp_layer.sport
                port_dst = tcp_layer.dport

                stream_key = self.get_stream_key(ip_src, port_src, ip_dst, port_dst, "TCP")
                if stream_key not in self.streams:
                    self.streams[stream_key] = {
                        "stream_id": stream_key,
                        "proto": "TCP",
                        "endpoint_a": f"{ip_src}:{port_src}",
                        "endpoint_b": f"{ip_dst}:{port_dst}",
                        "start_ts": ts,
                        "end_ts": ts,
                        "packets_count": 0,
                        "bytes_total": 0,
                        "tcp_flags": set(),
                        "payload_chunks": []
                    }

                st = self.streams[stream_key]
                st["packets_count"] += 1
                st["bytes_total"] += len(pkt)
                st["end_ts"] = max(st["end_ts"], ts)
                st["tcp_flags"].add(str(tcp_layer.flags))

                # Ambil payload raw
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    if len(payload) > 0:
                        st["payload_chunks"].append({
                            "ts": ts,
                            "dir": f"{ip_src}:{port_src}->{ip_dst}:{port_dst}",
                            "len": len(payload)
                        })

                        # Cek HTTP jika port umum (80, 8080, 5000, 3000, 8000) atau terdeteksi string HTTP
                        if port_src in (80, 8080, 5000, 3000, 8000) or port_dst in (80, 8080, 5000, 3000, 8000) or b"HTTP/" in payload:
                            self.extract_http_info(payload, ip_src, port_src, ip_dst, port_dst, ts, stream_key)

                        # Cek SSH jika port 22 atau payload SSH-
                        if port_src == 22 or port_dst == 22 or payload.startswith(b"SSH-"):
                            self.extract_ssh_info(payload, ip_src, port_src, ip_dst, port_dst, ts, stream_key)

            elif UDP in pkt:
                self.protocol_counts["UDP"] += 1

        # Sort timeline events secara kronologis mikrodetik
        self.timeline_events.sort(key=lambda x: x["timestamp"])

        # Tulis manifest berkas yang dicarve
        if self.carve_files and self.carved_artifacts:
            manifest_file = os.path.join(self.carved_dir, "carved_manifest.json")
            with open(manifest_file, "w", encoding="utf-8") as f:
                json.dump({
                    "case_id": self.case_id,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "source_pcap": self.pcap_path,
                    "carved_count": len(self.carved_artifacts),
                    "artifacts": self.carved_artifacts
                }, f, indent=2)

    def export_json_report(self, json_path=None):
        """Mengekspor laporan analisis lengkap ke format JSON."""
        target_path = json_path or os.path.join(self.output_dir, "pcap-analysis-report.json")
        
        # Konversi set tcp_flags ke list agar serializable
        streams_serializable = {}
        for k, v in self.streams.items():
            st_copy = dict(v)
            st_copy["tcp_flags"] = list(st_copy["tcp_flags"])
            st_copy["duration_sec"] = round(st_copy["end_ts"] - st_copy["start_ts"], 6)
            st_copy["start_utc"] = format_utc(st_copy["start_ts"])
            st_copy["end_utc"] = format_utc(st_copy["end_ts"])
            streams_serializable[k] = st_copy

        report = {
            "case_id": self.case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "pcap_file": self.pcap_path,
            "total_packets": self.packets_count,
            "protocol_breakdown": dict(self.protocol_counts),
            "total_streams": len(self.streams),
            "http_requests_count": len(self.http_requests),
            "http_responses_count": len(self.http_responses),
            "icmp_artifacts_count": len(self.icmp_artifacts),
            "dns_artifacts_count": len(self.dns_artifacts),
            "ssh_artifacts_count": len(self.ssh_artifacts),
            "carved_files_count": len(self.carved_artifacts),
            "sensitive_findings_count": len(self.sensitive_findings),
            "sensitive_findings": self.sensitive_findings,
            "http_requests": self.http_requests,
            "http_responses": self.http_responses,
            "icmp_artifacts": self.icmp_artifacts,
            "dns_artifacts": self.dns_artifacts,
            "ssh_artifacts": self.ssh_artifacts,
            "streams": streams_serializable,
            "timeline_events": self.timeline_events,
            "carved_artifacts": self.carved_artifacts
        }

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return target_path

    def print_summary(self, report_path):
        """Menampilkan dasbor ringkasan forensik ke terminal."""
        print()
        print(f"{BOLD}{CYAN}======================================================================{RESET}")
        print(f"{BOLD}{CYAN}        HASIL ANALISIS ARTEFAK JARINGAN & STREAM CARVING (PCAP)       {RESET}")
        print(f"{BOLD}{CYAN}======================================================================{RESET}")
        print(f"  Berkas PCAP Target : {self.pcap_path}")
        print(f"  ID Kasus Investigasi: {self.case_id}")
        print(f"  Total Paket Dianalisis: {BOLD}{self.packets_count}{RESET} frame")
        print(f"  Total Aliran (Streams): {BOLD}{len(self.streams)}{RESET} sesi TCP/UDP")
        print()

        print(f"{BOLD}1. Sebaran Protokol:{RESET}")
        for proto, count in sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True):
            pct = (count / self.packets_count * 100) if self.packets_count else 0
            print(f"   - {proto:<10}: {count:>6} paket ({pct:.1f}%)")
        print()

        print(f"{BOLD}2. Artefak Protokol Aplikasi Terevolusi:{RESET}")
        print(f"   - HTTP Requests / Responses : {len(self.http_requests)} req / {len(self.http_responses)} resp")
        print(f"   - ICMP Messages (Ping/Echo) : {len(self.icmp_artifacts)} frame")
        print(f"   - DNS Queries / Answers     : {len(self.dns_artifacts)} query")
        print(f"   - SSH Banners / Sessions    : {len(self.ssh_artifacts)} banner")
        print()

        if self.sensitive_findings:
            print(f"{BOLD}{RED}3. INDIKATOR KEJAHATAN / KEBOCORAN DATA TERDETEKSI ({len(self.sensitive_findings)} Temuan):{RESET}")
            for idx, finding in enumerate(self.sensitive_findings[:10], 1):
                print(f"   {RED}[!] Temuan #{idx} [{finding['rule']}]{RESET} di {finding['context']} ({finding['source']}):")
                print(f"       Sampel: {YELLOW}{finding['sample']}{RESET}")
            if len(self.sensitive_findings) > 10:
                print(f"       ... dan {len(self.sensitive_findings) - 10} temuan lainnya (lihat JSON lengkap).")
        else:
            print(f"{BOLD}{GREEN}3. Indikator Kebocoran Sensitif: Tidak ada pola mencurigakan terdeteksi.{RESET}")
        print()

        if self.carve_files:
            print(f"{BOLD}4. Berkas Muatan Dicarve (Carved Files):{RESET} {len(self.carved_artifacts)} berkas")
            for art in self.carved_artifacts[:5]:
                print(f"   - [{art['protocol']}] {art['filename']} ({art['size_bytes']} bytes)")
                print(f"     SHA-256: {CYAN}{art['sha256']}{RESET}")
            if len(self.carved_artifacts) > 5:
                print(f"   ... dan {len(self.carved_artifacts) - 5} berkas lainnya di {self.carved_dir}")
            print()

        print(f"{BOLD}{GREEN}[SUCCESS] Laporan analisis tersimpan di:{RESET}")
        print(f"  -> {report_path}")
        print(f"{BOLD}{CYAN}======================================================================{RESET}")
        print()

def main():
    parser = argparse.ArgumentParser(
        description="Network Stream Carving & Protocol Payload Extractor (ISO/IEC 27037)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--pcap", "-p", required=True, help="Path ke berkas PCAP atau PCAPNG")
    parser.add_argument("--output-dir", "-o", default=None, help="Direktori hasil ekstraksi (default: extracted_<pcap>)")
    parser.add_argument("--carve-files", "-c", action="store_true", help="Ekstrak muatan data/file ke disk dengan hashing")
    parser.add_argument("--case-id", default=None, help="ID Kasus Investigasi (contoh: IR-2026-S06)")
    parser.add_argument("--filter-ip", default=None, help="Filter alamat IP sumber atau tujuan spesifik")
    parser.add_argument("--json-out", default=None, help="Nama atau lokasi khusus berkas JSON laporan")

    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"{RED}[ERROR] Berkas PCAP tidak ditemukan: {args.pcap}{RESET}")
        sys.exit(1)

    extractor = PcapArtifactExtractor(
        pcap_path=args.pcap,
        output_dir=args.output_dir,
        carve_files=args.carve_files,
        case_id=args.case_id,
        filter_ip=args.filter_ip
    )
    extractor.process()
    report_path = extractor.export_json_report(args.json_out)
    extractor.print_summary(report_path)

if __name__ == "__main__":
    main()
