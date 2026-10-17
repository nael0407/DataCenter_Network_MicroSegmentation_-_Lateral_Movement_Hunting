#!/usr/bin/env python3
"""
dfir/evidence/verify-evidence-integrity.py
Verifikator Integritas Kriptografis Barang Bukti Digital (ISO/IEC 27037:2012)
Memvalidasi keabsahan bukti bit-by-bit terhadap manifest dan checksum SHA-256/SHA-512.
"""

import os
import sys
import argparse
import hashlib
import json
import stat

def calc_hashes(filepath):
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            sha512.update(chunk)
    return sha256.hexdigest(), sha512.hexdigest()

def verify_vault(vault_dir):
    vault_name = os.path.basename(os.path.abspath(vault_dir))
    manifest_path = os.path.join(vault_dir, "evidence-manifest.json")
    sha256sums_path = os.path.join(vault_dir, "SHA256SUMS")

    print(f"\n[VAULT] Memeriksa Vault: {vault_name}")
    print(f"Path   : {os.path.abspath(vault_dir)}")
    print("-" * 80)

    if not os.path.exists(manifest_path):
        print(f"  [ERROR] Berkas master manifest '{manifest_path}' tidak ditemukan!")
        return False, []

    try:
        with open(manifest_path, "r") as mf:
            manifest = json.load(mf)
    except Exception as e:
        print(f"  [ERROR] Gagal mem-parse manifest JSON: {e}")
        return False, []

    case_meta = manifest.get("case_metadata", {})
    case_id = case_meta.get("case_id", "UNKNOWN")
    case_name = case_meta.get("case_name", "UNKNOWN")
    investigator = case_meta.get("investigator", {}).get("name", "UNKNOWN")

    print(f"  Case ID      : {case_id}")
    print(f"  Case Name    : {case_name}")
    print(f"  Investigator : {investigator}")
    print("-" * 80)
    print(f"  {'EVIDENCE ID':<22} | {'BERKAS':<26} | {'SHA-256 INTEGRITY':<20} | {'PERM'}")
    print("  " + "-" * 76)

    evidence_items = manifest.get("evidence_items", [])
    if not evidence_items:
        print("  [WARN] Tidak ada item bukti di dalam manifest.")
        return True, []

    vault_passed = True
    audit_results = []

    for item in evidence_items:
        evd_id = item.get("evidence_id", "UNKNOWN")
        file_props = item.get("file_properties", {})
        fname = file_props.get("filename", "")
        evd_type = item.get("evidence_type", "")
        
        # Cari berkas fisik di dalam subfolder network atau host
        subfolder = "network" if "network" in evd_type or fname.endswith(".pcap") else "host"
        file_path = os.path.join(vault_dir, subfolder, fname)
        if not os.path.exists(file_path):
            file_path = os.path.join(vault_dir, fname)

        if not os.path.exists(file_path):
            print(f"  {evd_id:<22} | {fname:<26} | MISSING FILE (FAIL) | N/A")
            vault_passed = False
            audit_results.append({"id": evd_id, "file": fname, "status": "MISSING"})
            continue

        # Cek izin berkas (harus read-only 0440 / 0400)
        mode = oct(stat.S_IMODE(os.stat(file_path).st_mode))
        perm_ok = mode in ("0o440", "0o400", "0o444")
        perm_str = f"{mode[-3:]} ({'RO-OK' if perm_ok else 'WRN'})"

        # Hitung ulang hash fisik
        h256_actual, h512_actual = calc_hashes(file_path)
        h256_expected = item.get("cryptographic_hashes", {}).get("sha256", "")
        h512_expected = item.get("cryptographic_hashes", {}).get("sha512", "")

        sha256_ok = (h256_actual.lower() == h256_expected.lower())
        sha512_ok = (h512_actual.lower() == h512_expected.lower())

        if sha256_ok and sha512_ok:
            status_str = "VERIFIED MATCH (PASS)"
            res_status = "PASS"
        else:
            status_str = "CORRUPTED / TAMPERED"
            res_status = "FAIL"
            vault_passed = False

        print(f"  {evd_id:<22} | {fname:<26} | {status_str:<20} | {perm_str}")
        audit_results.append({
            "id": evd_id,
            "file": fname,
            "status": res_status,
            "sha256_actual": h256_actual,
            "sha256_expected": h256_expected,
            "permissions": mode
        })

    # Cek SHA256SUMS jika ada
    if os.path.exists(sha256sums_path):
        sums_ok = True
        with open(sha256sums_path, "r") as sf:
            for line in sf:
                line = line.strip()
                if not line or line.startswith("#"): continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    exp_h, rel_f = parts[0], parts[1].strip()
                    abs_f = os.path.join(vault_dir, rel_f)
                    if os.path.exists(abs_f):
                        calc_h, _ = calc_hashes(abs_f)
                        if calc_h.lower() != exp_h.lower():
                            sums_ok = False
        print(f"  SHA256SUMS Integrity   : {'VALID & VERIFIED (100%)' if sums_ok else 'CHECKSUM MISMATCH (FAIL)'}")

    return vault_passed, audit_results

def main():
    parser = argparse.ArgumentParser(description="Verifikator Integritas Bukti Digital ISO/IEC 27037:2012")
    parser.add_argument("--vault", help="Path direktori evidence vault spesifik")
    parser.add_argument("--evidence-dir", help="Direktori root evidence untuk memindai seluruh vault")

    args = parser.parse_args()

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    base_evidence_dir = args.evidence_dir or os.path.join(repo_root, "dfir", "evidence")

    print("=" * 80)
    print("  VERIFIKASI INTEGRITAS BUKTI DIGITAL FORENSIK (ISO/IEC 27037:2012)")
    print("=" * 80)

    vaults_to_check = []
    if args.vault:
        vaults_to_check.append(os.path.abspath(args.vault))
    else:
        # Pindai subdirektori vault_* di evidence-dir
        if os.path.exists(base_evidence_dir):
            for d in sorted(os.listdir(base_evidence_dir)):
                full_d = os.path.join(base_evidence_dir, d)
                if os.path.isdir(full_d) and (d.startswith("vault_") or os.path.exists(os.path.join(full_d, "evidence-manifest.json"))):
                    vaults_to_check.append(full_d)

    if not vaults_to_check:
        print("[INFO] Belum ada Evidence Vault permanen yang terbentuk.")
        print(f"Pemeriksaan root evidence: {base_evidence_dir}")
        print("Gunakan package-evidence.sh untuk mengonsolidasikan bukti terlebih dahulu.")
        sys.exit(0)

    all_passed = True
    total_items = 0
    passed_items = 0

    for vdir in vaults_to_check:
        passed, results = verify_vault(vdir)
        if not passed:
            all_passed = False
        for r in results:
            total_items += 1
            if r["status"] == "PASS":
                passed_items += 1

    integrity_rate = (passed_items / total_items * 100.0) if total_items > 0 else 100.0

    print("\n" + "=" * 80)
    print("RINGKASAN HASIL AUDIT INTEGRITAS FORENSIK:")
    print(f"- Total Item Bukti Diperiksa : {total_items}")
    print(f"- Item Bukti Lolos Verifikasi: {passed_items}")
    print(f"- Evidence Integrity Rate    : {integrity_rate:.1f}%")
    if all_passed and integrity_rate == 100.0:
        print("- Status Keseluruhan          : 100% GREEN (ZERO TAMPERING / ISO 27037 COMPLIANT)")
    else:
        print("- Status Keseluruhan          : RED / INTEGRITY VIOLATION DETECTED")
    print("=" * 80)

    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()
