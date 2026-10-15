#!/usr/bin/env python3
"""
fabric/opnsense/sanitize-config.py
Mensanitasi berkas konfigurasi OPNsense (config.orig.xml) sebelum di-commit ke Git.
Menghapus: hash password bcrypt, kunci privat TLS/SSH, token rahasia, dan kredensial.
Memenuhi kepatuhan Mitigasi Risiko R12 (Mencegah Kebocoran Rahasia ke Git).
"""

import sys
import re
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(SCRIPT_DIR, "config.orig.xml")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "config.xml")

def sanitize_xml(content: str) -> str:
    redactions = 0

    # 1. Hapus hash password pengguna (<password>...</password>)
    def redact_password(match):
        nonlocal redactions
        redactions += 1
        return "<password>REDACTED_PASSWORD_HASH</password>"
    content = re.sub(r"<password>.*?</password>", redact_password, content)

    # 2. Hapus kunci privat sertifikat/TLS (<prv>...</prv>)
    def redact_prv(match):
        nonlocal redactions
        redactions += 1
        return "<prv>REDACTED_PRIVATE_KEY</prv>"
    content = re.sub(r"<prv>.*?</prv>", redact_prv, content, flags=re.DOTALL)

    # 3. Hapus SSH Host Keys
    for key_tag in ["ssh_host_rsa_key", "ssh_host_ecdsa_key", "ssh_host_ed25519_key", "ssh_host_dsa_key"]:
        pattern = rf"<{key_tag}>.*?</{key_tag}>"
        def redact_ssh_key(match):
            nonlocal redactions
            redactions += 1
            return f"<{key_tag}>REDACTED_SSH_KEY</{key_tag}>"
        content = re.sub(pattern, redact_ssh_key, content, flags=re.DOTALL)

    # 4. Hapus token/secret jika ada
    content = re.sub(r"<secret>.*?</secret>", "<secret>REDACTED_SECRET</secret>", content)

    print(f"[SANITASI] Berhasil menyamarkan {redactions} elemen rahasia.")
    return content

def main():
    input_path = sys.argv[1] if len(sys.argv) > 1 else INPUT_FILE
    output_path = sys.argv[2] if len(sys.argv) > 2 else OUTPUT_FILE

    if not os.path.isfile(input_path):
        print(f"ERROR: Berkas masukan '{input_path}' tidak ditemukan!")
        print("Silakan unduh atau salin konfigurasi dari OPNsense terlebih dahulu:")
        print(f"  scp root@192.168.122.20:/conf/config.xml {input_path}")
        print("Atau unduh melalui Web GUI (System > Configuration > Backups).")
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        raw_xml = f.read()

    sanitized_xml = sanitize_xml(raw_xml)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(sanitized_xml)

    print(f"[OK] Berkas terkonfigurasi aman tersimpan di: {output_path}")
    print(f"Ukuran berkas bersih: {os.path.getsize(output_path)} byte")

if __name__ == "__main__":
    main()
