#!/usr/bin/env bash
# telemetry/setup-logging-stack.sh
# Memasang dan mengonfigurasi stack telemetri lengkap (Loki, Grafana, Grafana Alloy)
# pada VM secops (192.168.122.81 / 10.10.40.11) untuk Fase 5 (Langkah 5.4)
set -euo pipefail

SSH_KEY="$HOME/.ssh/k8s-lab"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5"

echo "Penyebaran Stack Telemetri Sentral (Loki + Grafana + Alloy)"
echo "Target Node: secops (192.168.122.81 / 10.10.40.11)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scp $SSH_OPTS "$SCRIPT_DIR/loki-grafana/microseg-dashboard.json" "dcadmin@192.168.122.81:/tmp/microseg-dashboard.json"

ssh $SSH_OPTS "dcadmin@192.168.122.81" 'sudo bash -s' << 'EOF'
set -euo pipefail

# 1. Konfigurasi Loki (Penyimpanan Persisten di /var/lib/loki)
echo "--- [1/3] Mengonfigurasi & Menyalakan Loki ---"
mkdir -p /var/lib/loki/chunks /var/lib/loki/rules
chown -R loki:nogroup /var/lib/loki
sed -i 's|/tmp/loki|/var/lib/loki|g' /etc/loki/config.yml

systemctl daemon-reload
systemctl enable loki
systemctl restart loki

# 2. Konfigurasi Grafana & Provisioning Datasource & Dashboard Otomatis
echo "--- [2/3] Mengonfigurasi & Menyalakan Grafana Server ---"
mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards
cat > /etc/grafana/provisioning/datasources/loki.yaml << 'DATASOURCE'
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://127.0.0.1:3100
    isDefault: true
    jsonData:
      maxLines: 5000
DATASOURCE

cat > /etc/grafana/provisioning/dashboards/dashboards.yaml << 'DASHBOARDS'
apiVersion: 1
providers:
  - name: 'dc-microseg-dashboards'
    orgId: 1
    folder: 'DC Microsegmentation'
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
DASHBOARDS

if [ -f /tmp/microseg-dashboard.json ]; then
    mv /tmp/microseg-dashboard.json /var/lib/grafana/dashboards/microseg-dashboard.json
    chown -R grafana:grafana /var/lib/grafana/dashboards
fi

systemctl daemon-reload
systemctl enable grafana-server
systemctl restart grafana-server

# 3. Konfigurasi Grafana Alloy (Kolektor Zeek JSON Logs & OPNsense Syslog Port 1514)
echo "--- [3/3] Mengonfigurasi & Menyalakan Grafana Alloy ---"
usermod -aG adm alloy 2>/dev/null || true
chmod 755 /var/log/zeek
chmod 644 /var/log/zeek/*.log 2>/dev/null || true

cat > /etc/alloy/config.alloy << 'CONFIG'
// Grafana Alloy Configuration - Telemetri DC Microsegmentation Lab (SecOps Node)

logging {
  level  = "info"
  format = "logfmt"
}

// 1. Destinasi Pengiriman Log ke Loki Lokal
loki.write "local_loki" {
  endpoint {
    url = "http://127.0.0.1:3100/loki/api/v1/push"
  }
}

// 2. Pengumpul & Pemroses Berkas Log Zeek (Format JSON Lines)
local.file_match "zeek_files" {
  path_targets = [
    { "__path__" = "/var/log/zeek/*.log", "job" = "zeek" },
  ]
}

loki.source.file "zeek_collector" {
  targets    = local.file_match.zeek_files.targets
  forward_to = [loki.process.zeek_pipeline.receiver]
}

loki.process "zeek_pipeline" {
  stage.regex {
    source     = "filename"
    expression = ".*/(?P<log_type>[^/]+)\\.log"
  }

  stage.labels {
    values = {
      log_type = "",
    }
  }

  forward_to = [loki.write.local_loki.receiver]
}

// 3. Syslog Listener (RFC 3164 / RFC 5424) untuk OPNsense Firewall & Host Logs (Port 1514 UDP/TCP)
loki.relabel "syslog_parser" {
  forward_to = []

  rule {
    action      = "labelmap"
    regex       = "__syslog_message_hostname"
    replacement = "hostname"
  }

  rule {
    action      = "labelmap"
    regex       = "__syslog_message_app_name"
    replacement = "app_name"
  }

  rule {
    action      = "labelmap"
    regex       = "__syslog_message_facility"
    replacement = "facility"
  }

  rule {
    action      = "labelmap"
    regex       = "__syslog_message_severity"
    replacement = "severity"
  }
}

loki.source.syslog "syslog_receiver" {
  listener {
    address  = "0.0.0.0:1514"
    protocol = "udp"
    labels   = { "job" = "opnsense-syslog", "transport" = "udp" }
  }

  listener {
    address  = "0.0.0.0:1514"
    protocol = "tcp"
    labels   = { "job" = "opnsense-syslog", "transport" = "tcp" }
  }

  relabel_rules = loki.relabel.syslog_parser.rules
  forward_to    = [loki.write.local_loki.receiver]
}
CONFIG

systemctl daemon-reload
systemctl enable alloy
systemctl restart alloy

sleep 4
echo "[OK] Status Layanan Telemetri di secops:"
echo " - Loki           : $(systemctl is-active loki)"
echo " - Grafana Server : $(systemctl is-active grafana-server)"
echo " - Grafana Alloy  : $(systemctl is-active alloy)"
EOF

echo
echo "Stack Telemetri Sentral (Loki + Grafana + Alloy) Berhasil Terpasang!"
echo "Dashboard Grafana siap diakses di: http://192.168.122.81:3000"
echo "Kredensial Default: admin / admin"
