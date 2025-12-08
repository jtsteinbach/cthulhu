#!/usr/bin/env bash
# CTHULHU Setup    create service and cth command

set -euo pipefail

# configuration
SERVICE_PATH="/etc/systemd/system/cthulhu.service"
ENGINE_PATH="/cthulhu/src/engine.py"
CLI_PATH="/cthulhu/src/cli.py"
CTH_WRAPPER_PATH="/usr/local/bin/cth"
CTH_ROOT="/cthulhu"


# ensure script is run as root
ensure_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "[CTHULHU Setup] this script must be run as root (try: sudo bash setup.sh)" >&2
        exit 1
    fi
}


ensure_journald_and_auditd_installed() {
    # journald check: look for journalctl as a proxy for systemd-journald
    if ! command -v journalctl >/dev/null 2>&1; then
        echo "    [1/2] journald not found; attempting to install systemd/journald"

        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y systemd
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y systemd
        elif command -v yum >/dev/null 2>&1; then
            yum install -y systemd
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm systemd
        else
            echo "    [ERROR] cannot install journald: no supported package manager (apt/dnf/yum/pacman)" >&2
            exit 1
        fi
    fi

    # auditd check: auditctl binary or auditd.service unit
    if ! command -v auditctl >/dev/null 2>&1 && \
       ! systemctl list-unit-files --type=service 2>/dev/null | grep -q '^auditd\.service'; then
        echo "    /[2/2] auditd not found; attempting install"

        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y auditd
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y audit
        elif command -v yum >/dev/null 2>&1; then
            yum install -y audit
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm audit
        else
            echo "    [ERROR] cannot install auditd: no supported package manager (apt/dnf/yum/pacman)" >&2
            exit 1
        fi
    fi
}


# copy repo contents (src/ + alert.rules) into /cthulhu
sync_repo_to_cthulhu() {
    # directory where this setup.sh lives
    local repo_root src_dir rules_file dest_root dest_src
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    src_dir="$repo_root/src"
    rules_file="$repo_root/alert.rules"
    dest_root="$CTH_ROOT"
    dest_src="$CTH_ROOT/src"

    echo "    [1/2] src/         -> $dest_src"
    echo "    [2/2] alert.rules  -> $dest_root/alert.rules"

    if [[ ! -d "$src_dir" ]]; then
        echo "    [ERROR] src directory not found at: $src_dir" >&2
        exit 1
    fi

    mkdir -p "$dest_src"

    # copy all files from src/ into /cthulhu/src
    cp -r "$src_dir"/. "$dest_src"/

    # copy alert.rules to /cthulhu/alert.rules if present
    if [[ -f "$rules_file" ]]; then
        cp "$rules_file" "$dest_root/alert.rules"
    else
        echo "    [ERROR] alert.rules not found at: $rules_file (skipping copy)" >&2
    fi

    # make sure everything under /cthulhu is owned by root
    chown -R root:root "$dest_root"
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
ExecStart=/usr/bin/env pyt $ENGINE_PATH
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
exec python3 $CLI_PATH "\$@"
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
    
    echo
    echo "^(;,;)^ CTHULHU Setup Installer"
    echo "https://jts.gg/cthulhu"
    echo
    echo "[1/5] verifying/installing dependancies (auditd & journald)"
    ensure_journald_and_auditd_installed
    sleep 2
    
    echo "[2/5] syncing repo into: $CTH_ROOT"
    sync_repo_to_cthulhu
    sleep 2

    echo "[3/5] writing systemd unit: $SERVICE_PATH"
    write_service_file
    sleep 2

    echo "[4/5] writing cli wrapper: $CTH_WRAPPER_PATH"
    write_cth_wrapper
    sleep 2

    echo "[5/5] reloading systemd, enabling and starting cthulhu.service"
    reload_and_enable_service
    sleep 2

    echo
    echo "^(;,;)^ CTHULHU Installed"
    echo "https://jts.gg/cthulhu"
    echo
    echo "  service : systemctl status cthulhu.service"
    echo "  cli     : run 'cth' from any shell"
    echo
}

main "$@"
