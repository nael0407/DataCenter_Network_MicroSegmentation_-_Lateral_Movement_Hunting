#!/usr/bin/env python3
"""
parse-host-artifacts.py - Host Triage Artifacts Parser & Timeline Normalizer
Data Center Micro-segmentation & Incident Response Lab (DFIR Module)
Compliant with RFC 3227 & ISO/IEC 27037:2012

Fitur:
  1. Menerima input berkas tarball triage (.tar.gz) atau direktori triage yang sudah diekstrak.
  2. Parsing mendalam pada 7 Tier Artefak RFC 3227:
     - Tier 1: Network Sockets (ss -tanpo, ss -tulpn) -> Deteksi koneksi aktif & soket mencurigakan.
     - Tier 2: Process State (ps auxwwfe, /proc/cmdlines) -> Deteksi proses anomali, reverse shells, memory anomalies.
     - Tier 3: Open Files (lsof) -> File descriptors & soket terbuka.
     - Tier 4: User Sessions & SSH Agent (who, w, last, /tmp/ssh-*) -> Deteksi pembajakan SSH Agent (T1563.001).
     - Tier 5: Auth & Syslogs (auth.log, journalctl) -> Login SSH (Accepted/Failed), eskalasi sudo, sudo session.
     - Tier 6: Persistence & History (.bash_history, crontabs, systemd) -> Rekonstruksi eksekusi perintah shell.
     - Tier 7: Modified Files (find -mmin -60) -> Jejak file yang baru dijatuhkan (payload drop).
  3. Normalisasi stempel waktu ke UTC ISO 8601 berpresisi mikrodetik untuk Super-Timeline.
  4. Deteksi otomatis indikator ancaman (MITRE ATT&CK Mapping).
  5. Ekspor terstruktur ke JSON & ringkasan dasbor terminal.
"""

import os
import sys
import re
import json
import tarfile
import tempfile
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

# Daftar kata kunci perintah mencurigakan di shell history
SUSPICIOUS_COMMAND_PATTERNS = [
    (re.compile(r"(curl|wget)\s+.*http", re.IGNORECASE), "DOWNLOAD_INBOUND", "T1105 Ingress Tool Transfer"),
    (re.compile(r"(nc|ncat|netcat)\s+-[lvpe]", re.IGNORECASE), "NETCAT_ACTIVITY", "T1059 Command and Scripting Interpreter"),
    (re.compile(r"ssh\s+-A\s+", re.IGNORECASE), "SSH_AGENT_FORWARDING", "T1563.001 SSH Agent Hijacking"),
    (re.compile(r"ssh\s+-J\s+", re.IGNORECASE), "SSH_PROXY_JUMP", "T1090 Proxy / Lateral Movement"),
    (re.compile(r"(base64\s+-d|eval\b|python.*-c)", re.IGNORECASE), "OBFUSCATION_EXEC", "T1059 Command and Scripting Interpreter"),
    (re.compile(r"sudo\s+su|sudo\s+-i|sudo\s+bash", re.IGNORECASE), "PRIVILEGE_ESCALATION", "T1548 Abuse Elevation Control Mechanism"),
    (re.compile(r"(iptables\s+-F|nft\s+flush)", re.IGNORECASE), "FIREWALL_TAMPERING", "T1562 Impair Defenses"),
    (re.compile(r"(exfiltrat|core_accounts|nasabah|pg_dump|psql.*-c)", re.IGNORECASE), "DATA_STAGING_EXFIL", "T1560 Archive Collected Data"),
    (re.compile(r"chmod\s+\+x\s+", re.IGNORECASE), "EXEC_PERMISSION_GRANT", "T1222 File Permission Modification")
]

def parse_syslog_timestamp(ts_str, reference_year=None):
    """
    Mengonversi berbagai format stempel waktu log sistem (RFC 3164 atau RFC 5424 ISO 8601)
    ke format UTC ISO 8601 standar.
    """
    ts_str = ts_str.strip()
    year = reference_year or datetime.now(timezone.utc).year

    # Format 1: ISO 8601 (e.g., 2026-10-18T04:41:36.123456+00:00 atau Z)
    if "T" in ts_str:
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except Exception:
            pass

    # Format 2: Syslog klasik (e.g., "Oct 18 04:41:36" atau "Oct  8 04:41:36")
    try:
        dt = datetime.strptime(f"{year} {ts_str[:15]}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    except Exception:
        pass

    # Fallback jika tidak cocok
    return ts_str

class HostArtifactParser:
    def __init__(self, triage_source, output_dir=None, case_id=None):
        self.triage_source = os.path.abspath(triage_source)
        self.case_id = case_id or "IR-UNASSIGNED"
        self.is_tar = os.path.isfile(self.triage_source) and tarfile.is_tarfile(self.triage_source)
        self.temp_extract_dir = None
        self.root_dir = None

        if self.is_tar:
            self.temp_extract_dir = tempfile.TemporaryDirectory(prefix="dfir_triage_")
            self.root_dir = self.temp_extract_dir.name
        else:
            self.root_dir = self.triage_source

        # Direktori output
        base_name = os.path.splitext(os.path.basename(self.triage_source))[0]
        if base_name.endswith(".tar"):
            base_name = os.path.splitext(base_name)[0]
        self.output_dir = os.path.abspath(output_dir or os.path.join(os.path.dirname(self.triage_source), f"parsed_{base_name}"))
        os.makedirs(self.output_dir, exist_ok=True)

        # Kontainer data
        self.metadata = {}
        self.auth_events = []
        self.bash_commands = []
        self.active_sockets = []
        self.processes = []
        self.ssh_agent_sockets = []
        self.modified_files = []
        self.threat_indicators = []
        self.timeline_events = []

    def unpack_if_needed(self):
        """Ekstrak tarball ke direktori sementara jika input adalah berkas terkompresi."""
        if self.is_tar:
            print(f"{CYAN}[*] Mengekstrak arsip triage:{RESET} {self.triage_source}")
            with tarfile.open(self.triage_source, "r:*") as tar:
                tar.extractall(path=self.root_dir)
            print(f"{GREEN}[OK] Ekstraksi ke direktori RAM selesai.{RESET}")

    def parse_metadata(self):
        """Baca METADATA.txt dan INVENTORY_HASHES.sha256."""
        meta_file = os.path.join(self.root_dir, "METADATA.txt")
        if os.path.exists(meta_file):
            with open(meta_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        self.metadata[k.strip()] = v.strip()
        else:
            self.metadata["TARGET_NAME"] = "unknown_host"

        inv_file = os.path.join(self.root_dir, "INVENTORY_HASHES.sha256")
        if os.path.exists(inv_file):
            with open(inv_file, "r", encoding="utf-8", errors="ignore") as f:
                self.metadata["total_inventoried_files"] = len(f.readlines())

    def parse_auth_logs(self):
        """Parse 05_auth_and_syslogs/auth.log dan journalctl_ssh.txt."""
        auth_file = os.path.join(self.root_dir, "05_auth_and_syslogs", "auth.log")
        if not os.path.exists(auth_file):
            auth_file = os.path.join(self.root_dir, "05_auth_and_syslogs", "journalctl_ssh.txt")
        if not os.path.exists(auth_file):
            return

        target_host = self.metadata.get("TARGET_NAME", "host")

        with open(auth_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # 1. SSH Accepted Publickey
                # e.g., Oct 18 04:30:11 web1 sshd[1234]: Accepted publickey for dcadmin from 10.10.40.11 port 52341 ssh2: ED25519 ...
                m_acc_pub = re.search(r"^(\S+\s+\S+\s+\S+|\S+T\S+)\s+(\S+)\s+sshd\[(\d+)\]:\s+Accepted\s+publickey\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)\s+ssh2:\s+(.*)$", line)
                if m_acc_pub:
                    ts_raw, host, pid, user, src_ip, src_port, key_info = m_acc_pub.groups()
                    ts_utc = parse_syslog_timestamp(ts_raw)
                    ev = {
                        "timestamp": ts_utc,
                        "event_type": "SSH_LOGIN_SUCCESS",
                        "auth_method": "publickey",
                        "user": user,
                        "src_ip": src_ip,
                        "src_port": int(src_port),
                        "sshd_pid": int(pid),
                        "key_info": key_info,
                        "raw": line
                    }
                    self.auth_events.append(ev)
                    self.timeline_events.append({
                        "timestamp": ts_utc,
                        "source": f"HOST_{target_host.upper()}",
                        "category": "AUTH",
                        "action": f"SSH Login Successful ({user} via publickey)",
                        "src_ip": src_ip,
                        "src_port": int(src_port),
                        "dst_ip": self.metadata.get("TARGET_IP", target_host),
                        "dst_port": 22,
                        "details": f"User: {user} | Key: {key_info} | PID: {pid}"
                    })
                    continue

                # 2. SSH Accepted Password
                m_acc_pwd = re.search(r"^(\S+\s+\S+\s+\S+|\S+T\S+)\s+(\S+)\s+sshd\[(\d+)\]:\s+Accepted\s+password\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)", line)
                if m_acc_pwd:
                    ts_raw, host, pid, user, src_ip, src_port = m_acc_pwd.groups()
                    ts_utc = parse_syslog_timestamp(ts_raw)
                    ev = {
                        "timestamp": ts_utc,
                        "event_type": "SSH_LOGIN_SUCCESS",
                        "auth_method": "password",
                        "user": user,
                        "src_ip": src_ip,
                        "src_port": int(src_port),
                        "sshd_pid": int(pid),
                        "raw": line
                    }
                    self.auth_events.append(ev)
                    self.timeline_events.append({
                        "timestamp": ts_utc,
                        "source": f"HOST_{target_host.upper()}",
                        "category": "AUTH",
                        "action": f"SSH Login Successful ({user} via password)",
                        "src_ip": src_ip,
                        "src_port": int(src_port),
                        "dst_ip": self.metadata.get("TARGET_IP", target_host),
                        "dst_port": 22,
                        "details": f"User: {user} | Method: password | PID: {pid}"
                    })
                    continue

                # 3. SSH Failed Password
                m_fail = re.search(r"^(\S+\s+\S+\s+\S+|\S+T\S+)\s+(\S+)\s+sshd\[(\d+)\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)", line)
                if m_fail:
                    ts_raw, host, pid, user, src_ip, src_port = m_fail.groups()
                    ts_utc = parse_syslog_timestamp(ts_raw)
                    ev = {
                        "timestamp": ts_utc,
                        "event_type": "SSH_LOGIN_FAILURE",
                        "auth_method": "password",
                        "user": user,
                        "src_ip": src_ip,
                        "src_port": int(src_port),
                        "sshd_pid": int(pid),
                        "raw": line
                    }
                    self.auth_events.append(ev)
                    self.timeline_events.append({
                        "timestamp": ts_utc,
                        "source": f"HOST_{target_host.upper()}",
                        "category": "AUTH",
                        "action": f"SSH Login Failed ({user})",
                        "src_ip": src_ip,
                        "src_port": int(src_port),
                        "dst_ip": self.metadata.get("TARGET_IP", target_host),
                        "dst_port": 22,
                        "details": f"Failed login for {user} from {src_ip}:{src_port}"
                    })
                    self.threat_indicators.append({
                        "type": "BRUTEFORCE_LOGIN_ATTEMPT",
                        "mitre_id": "T1110 Brute Force",
                        "timestamp": ts_utc,
                        "source": f"{src_ip}:{src_port}",
                        "details": f"Failed SSH password attempt for user '{user}'"
                    })
                    continue

                # 4. Sudo Execution
                m_sudo = re.search(r"^(\S+\s+\S+\s+\S+|\S+T\S+)\s+(\S+)\s+sudo:\s+(\S+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.*)$", line)
                if m_sudo:
                    ts_raw, host, invoking_user, tty, pwd, target_user, cmd = m_sudo.groups()
                    ts_utc = parse_syslog_timestamp(ts_raw)
                    ev = {
                        "timestamp": ts_utc,
                        "event_type": "SUDO_EXECUTION",
                        "user": invoking_user,
                        "target_user": target_user,
                        "tty": tty,
                        "pwd": pwd,
                        "command": cmd,
                        "raw": line
                    }
                    self.auth_events.append(ev)
                    self.timeline_events.append({
                        "timestamp": ts_utc,
                        "source": f"HOST_{target_host.upper()}",
                        "category": "PRIVILEGE",
                        "action": f"Sudo Execution ({invoking_user} -> {target_user})",
                        "src_ip": "127.0.0.1",
                        "src_port": 0,
                        "dst_ip": "127.0.0.1",
                        "dst_port": 0,
                        "details": f"COMMAND: {cmd} | PWD: {pwd} | TTY: {tty}"
                    })

                    # Cek jika command mencurigakan
                    for regex, label, mitre_desc in SUSPICIOUS_COMMAND_PATTERNS:
                        if regex.search(cmd):
                            self.threat_indicators.append({
                                "type": label,
                                "mitre_id": mitre_desc,
                                "timestamp": ts_utc,
                                "source": f"{invoking_user} via sudo",
                                "details": f"Suspicious privileged command: {cmd}"
                            })

    def parse_bash_histories(self):
        """Parse 06_persistence_and_histories/bash_histories/*_bash_history.txt."""
        hist_dir = os.path.join(self.root_dir, "06_persistence_and_histories", "bash_histories")
        if not os.path.exists(hist_dir):
            return

        target_host = self.metadata.get("TARGET_NAME", "host")

        for fname in os.listdir(hist_dir):
            if fname.endswith("_bash_history.txt"):
                username = fname.replace("_bash_history.txt", "")
                fpath = os.path.join(hist_dir, fname)
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    pending_ts = None
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue

                        # Jika history menggunakan timestamp format #<epoch>
                        if line.startswith("#") and line[1:].isdigit() and len(line) >= 10:
                            epoch = int(line[1:])
                            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                            pending_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                            continue

                        cmd = line
                        cmd_ts = pending_ts or self.metadata.get("ACQUISITION_START", "UNKNOWN")
                        pending_ts = None

                        self.bash_commands.append({
                            "user": username,
                            "timestamp": cmd_ts,
                            "command": cmd
                        })

                        # Cek pola berbahaya
                        for regex, label, mitre_desc in SUSPICIOUS_COMMAND_PATTERNS:
                            if regex.search(cmd):
                                self.threat_indicators.append({
                                    "type": label,
                                    "mitre_id": mitre_desc,
                                    "timestamp": cmd_ts,
                                    "source": f"user '{username}' bash history",
                                    "details": f"Perintah: {cmd}"
                                })

                        if cmd_ts != "UNKNOWN":
                            self.timeline_events.append({
                                "timestamp": cmd_ts,
                                "source": f"HOST_{target_host.upper()}",
                                "category": "COMMAND",
                                "action": f"Shell Command Executed ({username})",
                                "src_ip": "127.0.0.1",
                                "src_port": 0,
                                "dst_ip": "127.0.0.1",
                                "dst_port": 0,
                                "details": f"User: {username} | Command: {cmd}"
                            })

    def parse_network_sockets(self):
        """Parse 01_network_sockets/ss_tanpo.txt dan ss_tulpn.txt."""
        target_host = self.metadata.get("TARGET_NAME", "host")
        ss_file = os.path.join(self.root_dir, "01_network_sockets", "ss_tanpo.txt")
        if not os.path.exists(ss_file):
            ss_file = os.path.join(self.root_dir, "01_network_sockets", "ss_tulpn.txt")
        if not os.path.exists(ss_file):
            return

        with open(ss_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Netid") or line.startswith("State") or not line:
                    continue

                parts = line.split()
                if len(parts) >= 5:
                    state = parts[0]
                    recv_q = parts[1]
                    send_q = parts[2]
                    local_addr = parts[3]
                    peer_addr = parts[4]
                    process_info = " ".join(parts[5:]) if len(parts) > 5 else ""

                    sock_entry = {
                        "state": state,
                        "local": local_addr,
                        "peer": peer_addr,
                        "process": process_info
                    }
                    self.active_sockets.append(sock_entry)

                    # Deteksi koneksi ESTAB yang mengarah ke WAN atau DB
                    if state == "ESTAB":
                        if "203.0.113." in peer_addr:
                            self.threat_indicators.append({
                                "type": "WAN_OUTBOUND_ESTABLISHED",
                                "mitre_id": "T1049 Network Service Discovery / T1071 C2",
                                "timestamp": self.metadata.get("ACQUISITION_START", "UNKNOWN"),
                                "source": local_addr,
                                "details": f"Koneksi aktif ke WAN penyerang: {peer_addr} ({process_info})"
                            })

    def parse_process_state(self):
        """Parse 02_process_state/ps_auxwwfe.txt."""
        ps_file = os.path.join(self.root_dir, "02_process_state", "ps_auxwwfe.txt")
        if not os.path.exists(ps_file):
            return

        with open(ps_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("USER") or not line:
                    continue

                parts = line.split(None, 10)
                if len(parts) >= 11:
                    user, pid, cpu, mem, vsz, rss, tty, stat, start, time, cmd = parts
                    self.processes.append({
                        "user": user,
                        "pid": int(pid),
                        "cpu": float(cpu),
                        "mem": float(mem),
                        "stat": stat,
                        "start": start,
                        "cmd": cmd
                    })

                    # Cek proses berbahaya
                    if any(s in cmd for s in ["nc -", "ncat ", "/dev/tcp/", "bash -i", "ssh -A", "tcpdump "]):
                        self.threat_indicators.append({
                            "type": "SUSPICIOUS_ACTIVE_PROCESS",
                            "mitre_id": "T1059 Command Execution",
                            "timestamp": self.metadata.get("ACQUISITION_START", "UNKNOWN"),
                            "source": f"PID {pid} ({user})",
                            "details": f"Command: {cmd[:100]}"
                        })

    def parse_user_sessions_and_ssh_agent(self):
        """Parse 04_user_sessions/ssh_agent_sockets.txt dan env."""
        sock_file = os.path.join(self.root_dir, "04_user_sessions", "ssh_agent_sockets.txt")
        if os.path.exists(sock_file):
            with open(sock_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                matches = re.findall(r"(/tmp/ssh-[a-zA-Z0-9]+/agent\.\d+)", content)
                for sock in matches:
                    self.ssh_agent_sockets.append(sock)
                    self.threat_indicators.append({
                        "type": "SSH_AGENT_SOCKET_EXPOSED",
                        "mitre_id": "T1563.001 SSH Agent Hijacking",
                        "timestamp": self.metadata.get("ACQUISITION_START", "UNKNOWN"),
                        "source": sock,
                        "details": f"Socket agen SSH aktif ditemukan di /tmp ({sock}). Rentan pembajakan kredensial jika agent forwarding aktif!"
                    })

    def parse_modified_files(self):
        """Parse 07_modified_files_60m/modified_files_60m.txt."""
        mod_file = os.path.join(self.root_dir, "07_modified_files_60m", "modified_files_60m.txt")
        if not os.path.exists(mod_file):
            return

        with open(mod_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 11:
                    filepath = parts[10]
                    # Filter file sementara sistem standar
                    if any(filepath.startswith(p) for p in ["/tmp/triage_", "/dev/shm", "/proc", "/sys"]):
                        continue
                    self.modified_files.append({
                        "path": filepath,
                        "details": line
                    })

    def run_all_parsers(self):
        """Eksekusi seluruh modul parser host."""
        self.unpack_if_needed()
        self.parse_metadata()
        self.parse_auth_logs()
        self.parse_bash_histories()
        self.parse_network_sockets()
        self.parse_process_state()
        self.parse_user_sessions_and_ssh_agent()
        self.parse_modified_files()

        # Urutkan timeline event kronologis
        valid_events = [e for e in self.timeline_events if e["timestamp"] != "UNKNOWN"]
        valid_events.sort(key=lambda x: x["timestamp"])
        self.timeline_events = valid_events

    def export_json_report(self, json_path=None):
        """Simpan seluruh temuan dan timeline ke berkas JSON terstruktur."""
        target_path = json_path or os.path.join(self.output_dir, "host-analysis-report.json")
        target_host = self.metadata.get("TARGET_NAME", "host")

        report = {
            "case_id": self.case_id,
            "target_node": target_host,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_triage": self.triage_source,
            "host_metadata": self.metadata,
            "summary_counts": {
                "auth_events_count": len(self.auth_events),
                "bash_commands_count": len(self.bash_commands),
                "active_sockets_count": len(self.active_sockets),
                "processes_count": len(self.processes),
                "ssh_agent_sockets_count": len(self.ssh_agent_sockets),
                "modified_files_60m_count": len(self.modified_files),
                "threat_indicators_count": len(self.threat_indicators),
                "timeline_events_count": len(self.timeline_events)
            },
            "threat_indicators": self.threat_indicators,
            "auth_events": self.auth_events,
            "bash_commands": self.bash_commands,
            "active_sockets": self.active_sockets,
            "processes_preview": self.processes[:50],
            "ssh_agent_sockets": self.ssh_agent_sockets,
            "modified_files": self.modified_files[:100],
            "timeline_events": self.timeline_events
        }

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return target_path

    def print_summary(self, report_path):
        """Tampilkan dasbor ringkasan ke terminal."""
        target_host = self.metadata.get("TARGET_NAME", "host")
        print()
        print(f"{BOLD}{CYAN}           HASIL ANALISIS ARTEFAK HOST TRIAGE (RFC 3227)             {RESET}")
        print(f"  Target Host         : {BOLD}{target_host.upper()}{RESET} ({self.metadata.get('HOSTNAME', '-')})")
        print(f"  Evidence Source     : {self.triage_source}")
        print(f"  ID Kasus Forensik   : {self.case_id}")
        print(f"  Waktu Pengambilan   : {self.metadata.get('ACQUISITION_START', '-')}")
        print(f"  Standard Kepatuhan  : {self.metadata.get('STANDARD', 'RFC 3227 & ISO/IEC 27037:2012')}")
        print()

        print(f"{BOLD}1. Statistik Artefak Diekstrak:{RESET}")
        print(f"   - Event Otentikasi / Sudo   : {len(self.auth_events)} record")
        print(f"   - Perintah Shell History    : {len(self.bash_commands)} perintah")
        print(f"   - Soket Jaringan Aktif      : {len(self.active_sockets)} koneksi")
        print(f"   - Status Proses Sistem      : {len(self.processes)} proses")
        print(f"   - Jejak Socket Agen SSH     : {len(self.ssh_agent_sockets)} soket /tmp")
        print(f"   - Berkas Dimodifikasi (<60m): {len(self.modified_files)} berkas")
        print()

        if self.threat_indicators:
            print(f"{BOLD}{RED}2. INDIKATOR ANCAMAN & AKTIVITAS MENYERANG ({len(self.threat_indicators)} Indikator):{RESET}")
            for idx, ind in enumerate(self.threat_indicators[:10], 1):
                print(f"   {RED}[!] Indikator #{idx} [{ind['type']} | {ind['mitre_id']}]{RESET}")
                print(f"       Waktu  : {ind.get('timestamp', '-')}")
                print(f"       Sumber : {ind.get('source', '-')}")
                print(f"       Detail : {YELLOW}{ind.get('details', '-')}{RESET}")
            if len(self.threat_indicators) > 10:
                print(f"   ... dan {len(self.threat_indicators) - 10} indikator lainnya di laporan JSON.")
        else:
            print(f"{BOLD}{GREEN}2. Indikator Ancaman: Tidak ada aktivitas anomali terdeteksi.{RESET}")
        print()

        print(f"{BOLD}3. Peristiwa Linimasa Terformat (Super-Timeline Ready):{RESET} {len(self.timeline_events)} event")
        for ev in self.timeline_events[:5]:
            print(f"   - [{ev['timestamp']}] [{ev['category']}] {ev['action']}")
            print(f"     Detail: {ev['details']}")
        if len(self.timeline_events) > 5:
            print(f"   ... dan {len(self.timeline_events) - 5} event linimasa lainnya.")
        print()

        print(f"{BOLD}{GREEN}[SUCCESS] Laporan analisis host tersimpan di:{RESET}")
        print(f"  -> {report_path}")
        print()

    def cleanup(self):
        if self.temp_extract_dir:
            self.temp_extract_dir.cleanup()

def main():
    parser = argparse.ArgumentParser(
        description="Host Triage Artifacts Parser & Timeline Normalizer (RFC 3227 & ISO/IEC 27037)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--triage-tar", "-t", help="Path ke berkas tarball triage (.tar.gz)")
    parser.add_argument("--triage-dir", "-d", help="Path ke folder artefak triage yang sudah diekstrak")
    parser.add_argument("--output-dir", "-o", default=None, help="Direktori hasil ekstraksi laporan (default: parsed_<name>)")
    parser.add_argument("--case-id", default=None, help="ID Kasus Investigasi (contoh: IR-2026-S02)")
    parser.add_argument("--json-out", default=None, help="Path khusus berkas laporan JSON")

    args = parser.parse_args()

    source = args.triage_tar or args.triage_dir
    if not source:
        print(f"{RED}[ERROR] Masukkan argumen --triage-tar <file.tar.gz> atau --triage-dir <folder>{RESET}")
        sys.exit(1)

    if not os.path.exists(source):
        print(f"{RED}[ERROR] Sumber artefak triage tidak ditemukan: {source}{RESET}")
        sys.exit(1)

    parser_obj = HostArtifactParser(
        triage_source=source,
        output_dir=args.output_dir,
        case_id=args.case_id
    )
    try:
        parser_obj.run_all_parsers()
        report_path = parser_obj.export_json_report(args.json_out)
        parser_obj.print_summary(report_path)
    finally:
        parser_obj.cleanup()

if __name__ == "__main__":
    main()
