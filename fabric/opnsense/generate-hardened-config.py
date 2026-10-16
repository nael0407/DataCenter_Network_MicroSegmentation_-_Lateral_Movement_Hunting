#!/usr/bin/env python3
"""
fabric/opnsense/generate-hardened-config.py
Menghasilkan konfigurasi OPNsense yang diperkeras (Hardened Microsegmentation Rules)
Berdasarkan traffic matrix pada policies/opnsense/traffic-matrix.md
"""

import xml.etree.ElementTree as ET
import uuid
import base64
import os
import sys

ORIG_CONFIG = "fabric/opnsense/config.orig.xml"
OUT_HARDENED = "fabric/opnsense/config.hardened.xml"
SSH_PUB_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMaKmY7Bn57wupXyImtIHmwior/AfdzyXvVhq7SGBWb6 k8s-lab"

def make_rule(interface, action, proto, src_dict, dst_dict, descr, log=True, quick=True):
    r = ET.Element("rule", {"uuid": str(uuid.uuid4())})
    
    t = ET.SubElement(r, "type")
    t.text = action
    
    iface = ET.SubElement(r, "interface")
    iface.text = interface
    
    ipproto = ET.SubElement(r, "ipprotocol")
    ipproto.text = "inet"
    
    if proto != "any":
        p = ET.SubElement(r, "protocol")
        p.text = proto
        
    state = ET.SubElement(r, "statetype")
    state.text = "keep state"
    
    direction = ET.SubElement(r, "direction")
    direction.text = "in"
    
    category = ET.SubElement(r, "category")
    category.text = "Microsegmentation Hardening"
    
    if log:
        l = ET.SubElement(r, "log")
        l.text = "1"
        
    if quick:
        q = ET.SubElement(r, "quick")
        q.text = "1"
        
    # Source
    src = ET.SubElement(r, "source")
    if "network" in src_dict:
        net = ET.SubElement(src, "network")
        net.text = src_dict["network"]
    elif "address" in src_dict:
        addr = ET.SubElement(src, "address")
        addr.text = src_dict["address"]
    elif "any" in src_dict:
        a = ET.SubElement(src, "any")
        a.text = "1"
        
    # Destination
    dst = ET.SubElement(r, "destination")
    if "network" in dst_dict:
        net = ET.SubElement(dst, "network")
        net.text = dst_dict["network"]
    elif "address" in dst_dict:
        addr = ET.SubElement(dst, "address")
        addr.text = dst_dict["address"]
    elif "any" in dst_dict:
        a = ET.SubElement(dst, "any")
        a.text = "1"
        
    if "port" in dst_dict:
        port = ET.SubElement(dst, "port")
        port.text = str(dst_dict["port"])
        
    d = ET.SubElement(r, "descr")
    d.text = descr
    
    return r

def main():
    if not os.path.exists(ORIG_CONFIG):
        print(f"[ERROR] Berkas {ORIG_CONFIG} tidak ditemukan.")
        sys.exit(1)
        
    tree = ET.parse(ORIG_CONFIG)
    root = tree.getroot()
    
    # 1. Pastikan root user memiliki SSH public key
    system = root.find("system")
    if system is not None:
        for user in system.findall("user"):
            if user.findtext("name") == "root":
                keys_elem = user.find("authorizedkeys")
                if keys_elem is None:
                    keys_elem = ET.SubElement(user, "authorizedkeys")
                # OPNsense menyimpan base64-encoded SSH public key
                keys_elem.text = base64.b64encode(SSH_PUB_KEY.encode()).decode()
                print("  [OK] SSH public key diinjeksikan ke user root.")

    # 2. Rekayasa Aturan Filter Microsegmentation
    filter_elem = root.find("filter")
    if filter_elem is None:
        print("[ERROR] Elemen <filter> tidak ditemukan di config.xml")
        sys.exit(1)
        
    # Ambil aturan yang bukan opt1-opt5 (pertahankan rules WAN, LAN, dan NAT Web)
    existing_rules = filter_elem.findall("rule")
    non_opt_rules = []
    removed_count = 0
    for r in existing_rules:
        iface = r.findtext("interface", "")
        if iface in ["opt1", "opt2", "opt3", "opt4", "opt5"]:
            filter_elem.remove(r)
            removed_count += 1
            
    print(f"  [OK] Menghapus {removed_count} aturan permisif lama pada opt1-opt5.")

    # Daftarkan aturan baru sesuai matriks kebijakan:
    new_rules = [
        # --- ZONA WEB (opt1) ---
        make_rule("opt1", "pass", "tcp", {"network": "opt1"}, {"network": "opt2", "port": 8080}, "Allow Web to App tier (TCP 8080)"),
        make_rule("opt1", "pass", "udp", {"network": "opt1"}, {"address": "10.10.40.11", "port": 1514}, "Allow Syslog to SecOps (UDP 1514)"),
        make_rule("opt1", "pass", "icmp", {"network": "opt1"}, {"address": "10.10.10.1"}, "Allow Gateway ICMP ping"),
        make_rule("opt1", "pass", "udp", {"network": "opt1"}, {"address": "10.10.10.1", "port": 53}, "Allow Gateway DNS (UDP 53)"),
        make_rule("opt1", "block", "any", {"network": "opt1"}, {"any": 1}, "Default Deny: Drop unauthorized Web traffic"),

        # --- ZONA APP (opt2) ---
        make_rule("opt2", "pass", "tcp", {"network": "opt2"}, {"address": "10.10.30.11", "port": 5432}, "Allow App to DB tier (TCP 5432)"),
        make_rule("opt2", "pass", "udp", {"network": "opt2"}, {"address": "10.10.40.11", "port": 1514}, "Allow Syslog to SecOps (UDP 1514)"),
        make_rule("opt2", "pass", "icmp", {"network": "opt2"}, {"address": "10.10.20.1"}, "Allow Gateway ICMP ping"),
        make_rule("opt2", "pass", "udp", {"network": "opt2"}, {"address": "10.10.20.1", "port": 53}, "Allow Gateway DNS (UDP 53)"),
        make_rule("opt2", "block", "any", {"network": "opt2"}, {"any": 1}, "Default Deny: Drop unauthorized App traffic"),

        # --- ZONA DB (opt3) ---
        make_rule("opt3", "pass", "udp", {"network": "opt3"}, {"address": "10.10.40.11", "port": 1514}, "Allow Syslog to SecOps (UDP 1514)"),
        make_rule("opt3", "pass", "icmp", {"network": "opt3"}, {"address": "10.10.30.1"}, "Allow Gateway ICMP ping"),
        make_rule("opt3", "block", "any", {"network": "opt3"}, {"any": 1}, "Zero-Trust Egress: Drop all DB outbound"),

        # --- ZONA SECOPS (opt4) ---
        make_rule("opt4", "pass", "tcp", {"network": "opt4"}, {"any": 1, "port": 22}, "Allow Bastion SSH administration to all nodes (TCP 22)"),
        make_rule("opt4", "pass", "icmp", {"network": "opt4"}, {"address": "10.10.40.1"}, "Allow Gateway ICMP ping"),
        make_rule("opt4", "pass", "udp", {"network": "opt4"}, {"address": "10.10.40.1", "port": 53}, "Allow Gateway DNS (UDP 53)"),
        make_rule("opt4", "block", "any", {"network": "opt4"}, {"any": 1}, "Default Deny: Drop unauthorized SecOps traffic"),

        # --- ZONA DECOY (opt5) ---
        make_rule("opt5", "pass", "udp", {"network": "opt5"}, {"address": "10.10.40.11", "port": 1514}, "Allow OpenCanary Syslog to SecOps"),
        make_rule("opt5", "block", "any", {"network": "opt5"}, {"any": 1}, "Default Deny: Drop unauthorized Decoy traffic"),
    ]

    for r in new_rules:
        filter_elem.append(r)

    print(f"  [OK] Menambahkan {len(new_rules)} aturan microsegmentation baru ke <filter>.")

    tree.write(OUT_HARDENED, encoding="utf-8", xml_declaration=True)
    print(f"[SUKSES] Berkas konfigurasi OPNsense yang diperkeras disimpan di: {OUT_HARDENED}")

if __name__ == "__main__":
    main()
