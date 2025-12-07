#!/usr/bin/env bash
# CTHULHU Setup    create service and cth command

set -euo pipefail

# configuration
SERVICE_PATH="/etc/systemd/system/cthulhu.service"
ENGINE_PATH="/cthulhu/src/engine.py"
CLI_PATH="/cthulhu/src/cli.py"
CTH_WRAPPER_PATH="/usr/local/bin/cth"


# ensure script is run as root
ensure_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "this script must be run as root (try: sudo bash setup_cthulhu.sh)" >&2
        exit 1
    fi
}


# write the systemd service unit for the cthulhu engine
write_service_file() {
    cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=CTHULHU SIEM Engine
After=network.target systemd-journald.service auditd.service

[Service]
Type=simple

# run the engine unbuffered so logs hit journald immediately
Environment=PYTHONUNBUFFERED=1
# "pyt" represents python 3.13 threading build, change to python3 for normal python
ExecStart=/usr/bin/env pyt /cthulhu/src/engine.py
WorkingDirectory=/cthulhu/src

User=root
Group=root

Restart=on-failure
RestartSec=5

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}


# write the cth command wrapper that launches the cthulhu cli
write_cth_wrapper() {
    cat > "$CTH_WRAPPER_PATH" <<EOF
#!/usr/bin/env bash
# CTHULHU SIEM CLI launcher
cd /cthulhu/src
exec python3 /cthulhu/src/cli.py "$@"
EOF
    chmod +x "$CTH_WRAPPER_PATH"
    chown root:root "$CTH_WRAPPER_PATH"
}


# reload systemd units and enable the cthulhu service
reload_and_enable_service() {
    systemctl daemon-reload || true
    systemctl enable cthulhu.service || true
    systemctl restart cthulhu.service || true
}


main() {
    ensure_root

    echo "[setup] writing systemd unit: $SERVICE_PATH"
    write_service_file

    echo "[setup] writing cli wrapper: $CTH_WRAPPER_PATH"
    write_cth_wrapper

    echo "[setup] reloading systemd, enabling and starting cthulhu.service"
    reload_and_enable_service

    echo
    echo "^(;,;)^ CTHULHU Installed"
    echo
    echo "  service : systemctl status cthulhu.service"
    echo "  cli     : run 'cth' from any shell"
    echo
}

main "$@"
