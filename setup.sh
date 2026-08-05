#!/usr/bin/env bash
#  ^(;,;)^  CTHULHU SIEM — installer
#
#  Usage:
#    sudo bash setup.sh              install, or upgrade an existing install
#    sudo bash setup.sh --no-audit   skip installing the auditd policy
#
#  Safe to re-run. Existing alerts, triage history and a locally edited
#  ruleset are preserved (the previous ruleset is backed up before upgrade).
#  A v1 install is detected and migrated automatically.
#
#  To remove CTHULHU:  sudo bash uninstall.sh

set -euo pipefail

ROOT="${CTHULHU_ROOT:-/cthulhu}"
SERVICE="/etc/systemd/system/cthulhu.service"
WRAPPER="/usr/local/bin/cth"
AUDIT_RULES="/etc/audit/rules.d/50-cthulhu.rules"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INSTALL_AUDIT=1
for arg in "$@"; do
    case "$arg" in
        --no-audit)  INSTALL_AUDIT=0 ;;
        --uninstall) echo "use: sudo bash uninstall.sh" >&2; exit 2 ;;
        -h|--help)   sed -n '2,14p' "$0" | sed 's/^#\s\?//'; exit 0 ;;
    esac
done

# ── output helpers ───────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_ACC=$'\033[38;2;94;234;212m'; C_OK=$'\033[38;2;74;222;128m'
    C_WARN=$'\033[38;2;251;191;36m'; C_ERR=$'\033[38;2;248;113;113m'
    C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_ACC=""; C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_OFF=""
fi
step() { printf '  %s›%s %s\n' "$C_ACC" "$C_OFF" "$1"; }
ok()   { printf '  %s✓%s %s\n' "$C_OK" "$C_OFF" "$1"; }
warn() { printf '  %s!%s %s\n' "$C_WARN" "$C_OFF" "$1"; }
die()  { printf '  %s✗%s %s\n' "$C_ERR" "$C_OFF" "$1" >&2; exit 1; }

banner() {
    printf '\n  %s^(;,;)^%s  %sCTHULHU%s %sSIEM v2.0%s   %s·%s  %s\n\n' \
        "$C_ACC" "$C_OFF" "$C_ACC" "$C_OFF" "$C_DIM" "$C_OFF" \
        "$C_DIM" "$C_OFF" "$1"
}

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "must run as root (try: sudo bash setup.sh)"

banner "installer"

# ── preflight ────────────────────────────────────────────────────────────
step "checking prerequisites"

command -v python3 >/dev/null 2>&1 || die "python3 not found"
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 - <<'PY' || die "Python 3.10+ required (found $PYV)"
import sys
sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY
ok "python $PYV"

pkg_install() {
    if   command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
    elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q "$@"
    elif command -v yum     >/dev/null 2>&1; then yum install -y -q "$@"
    elif command -v zypper  >/dev/null 2>&1; then zypper --non-interactive install "$@"
    elif command -v pacman  >/dev/null 2>&1; then pacman -Sy --noconfirm "$@"
    elif command -v apk     >/dev/null 2>&1; then apk add --no-cache "$@"
    else return 1; fi
}

if ! command -v journalctl >/dev/null 2>&1; then
    warn "journalctl not found — journald feed will be unavailable"
else
    ok "journald available"
fi

if ! command -v auditctl >/dev/null 2>&1; then
    warn "auditd not installed; attempting install"
    if   command -v apt-get >/dev/null 2>&1; then pkg_install auditd || true
    elif command -v pacman  >/dev/null 2>&1; then pkg_install audit  || true
    else pkg_install audit || true; fi
fi
if command -v auditctl >/dev/null 2>&1; then
    ok "auditd available"
else
    warn "auditd unavailable — auditd-backed rules will not fire"
fi

# ── migrate a v1 install ─────────────────────────────────────────────────
# v1 laid its modules out flat as /cthulhu/src/{engine,cli,rule_handler,
# ingest_events,alert_handler}.py. v2 ships a package at /cthulhu/src/cthulhu/.
# Both directories are on PYTHONPATH, so a leftover flat engine.py would
# shadow the new package — the old modules must be removed, not just skipped.
V1_MODULES=(engine.py cli.py rule_handler.py ingest_events.py alert_handler.py)

detect_v1() {
    [[ -f "$ROOT/alert.rules" ]] && return 0
    local m
    for m in "${V1_MODULES[@]}"; do
        [[ -f "$ROOT/src/$m" ]] && return 0
    done
    return 1
}

if detect_v1; then
    step "migrating an earlier install"
    STAMP=$(date +%Y%m%d-%H%M%S)
    ARCHIVE="$ROOT/backup-$STAMP"
    mkdir -p "$ARCHIVE"

    systemctl stop cthulhu.service 2>/dev/null || true

    moved=0
    for m in "${V1_MODULES[@]}"; do
        if [[ -f "$ROOT/src/$m" ]]; then
            mv "$ROOT/src/$m" "$ARCHIVE/" && moved=$((moved + 1))
        fi
    done
    rm -rf "$ROOT/src/__pycache__" 2>/dev/null || true
    [[ "$moved" -gt 0 ]] && ok "archived $moved legacy module(s) — they would have shadowed the new package"

    # v1 rules are readable by v2 (legacy field names are aliased), but the
    # shipped baseline supersedes them. Keep the original for reference.
    if [[ -f "$ROOT/alert.rules" ]]; then
        mv "$ROOT/alert.rules" "$ARCHIVE/alert.rules"
        ok "previous ruleset archived to ${ARCHIVE#$ROOT/}/alert.rules"
        warn "previous rules are NOT carried over — the v2 baseline replaces them"
        warn "see the README before reusing them (see README, 'Upgrading from v1')"
    fi

    # v1 alerts stay in place; the format is a superset and cth reads both.
    [[ -f "$ROOT/alerts.jsonl" ]] && ok "existing alerts preserved"
    ok "migration complete — backup at ${ARCHIVE#$ROOT/}/"
fi

# ── install files ────────────────────────────────────────────────────────
step "installing to $ROOT"

[[ -d "$REPO/src/cthulhu" ]] || die "src/cthulhu not found next to setup.sh"

mkdir -p "$ROOT/src" "$ROOT/state" "$ROOT/feeds.d"

# Python package — replaced wholesale so stale modules cannot linger.
rm -rf "$ROOT/src/cthulhu"
cp -r "$REPO/src/cthulhu" "$ROOT/src/cthulhu"
find "$ROOT/src" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
ok "engine installed"

# Ruleset — never clobber local edits without a backup.
if [[ -f "$ROOT/alerts.jrl" ]]; then
    if ! cmp -s "$REPO/alerts.jrl" "$ROOT/alerts.jrl"; then
        STAMP=$(date +%Y%m%d-%H%M%S)
        cp "$ROOT/alerts.jrl" "$ROOT/alerts.jrl.backup-$STAMP"
        cp "$REPO/alerts.jrl" "$ROOT/alerts.jrl.new"
        warn "existing ruleset differs — kept yours, backup: alerts.jrl.backup-$STAMP"
        warn "new baseline written to alerts.jrl.new (diff and merge when ready)"
    else
        ok "ruleset already current"
    fi
else
    cp "$REPO/alerts.jrl" "$ROOT/alerts.jrl"
    ok "baseline ruleset installed ($(grep -cE '^[a-z_]+\(' "$ROOT/alerts.jrl") rules)"
fi

# Feed descriptor examples (never overwrite live descriptors).
if [[ -d "$REPO/feeds.d" ]]; then
    cp -n "$REPO/feeds.d"/*.example "$ROOT/feeds.d/" 2>/dev/null || true
    cp -n "$REPO/feeds.d/README.md" "$ROOT/feeds.d/" 2>/dev/null || true
fi

# Data files — created if absent, NEVER truncated. v1 wiped alerts on
# every setup run; re-running the installer must not destroy history.
for f in alerts.jsonl triage.jsonl; do
    [[ -f "$ROOT/$f" ]] || : > "$ROOT/$f"
done
ok "data files preserved"

chown -R root:root "$ROOT"
chmod 750 "$ROOT"
chmod 640 "$ROOT/alerts.jsonl" "$ROOT/triage.jsonl" "$ROOT/alerts.jrl" 2>/dev/null || true

# ── audit policy ─────────────────────────────────────────────────────────
if [[ "$INSTALL_AUDIT" -eq 1 && -f "$REPO/auditd/50-cthulhu.rules" ]] && command -v auditctl >/dev/null 2>&1; then
    step "installing auditd policy"
    mkdir -p /etc/audit/rules.d
    if [[ -f "$AUDIT_RULES" ]] && ! cmp -s "$REPO/auditd/50-cthulhu.rules" "$AUDIT_RULES"; then
        cp "$AUDIT_RULES" "$AUDIT_RULES.backup-$(date +%Y%m%d-%H%M%S)"
    fi
    cp "$REPO/auditd/50-cthulhu.rules" "$AUDIT_RULES"
    chmod 640 "$AUDIT_RULES"
    if augenrules --load >/dev/null 2>&1 || auditctl -R "$AUDIT_RULES" >/dev/null 2>&1; then
        LOADED=$(auditctl -l 2>/dev/null | grep -c . || echo 0)
        ok "audit policy loaded ($LOADED rules active)"
    else
        warn "audit policy installed but not loaded (immutable mode, or reboot required)"
    fi
else
    warn "skipping audit policy — auditd rules in alerts.jrl will stay silent"
fi

# ── systemd unit ─────────────────────────────────────────────────────────
step "writing systemd unit"
cat > "$SERVICE" <<EOF
[Unit]
Description=CTHULHU SIEM Engine
Documentation=https://jts.gg/cthulhu
After=network.target systemd-journald.service auditd.service
Wants=systemd-journald.service

[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=$ROOT/src
Environment=CTHULHU_ROOT=$ROOT
ExecStartPre=/usr/bin/env python3 -m cthulhu.engine --check
ExecStart=/usr/bin/env python3 -m cthulhu.engine
ExecReload=/bin/kill -HUP \$MAINPID
WorkingDirectory=$ROOT
User=root
Group=root

Restart=on-failure
RestartSec=5
TimeoutStopSec=15

# Hardening. The engine needs to read audit logs and /proc, and to write
# only inside its own directory.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$ROOT
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes

StandardOutput=journal
StandardError=journal
SyslogIdentifier=cthulhu

[Install]
WantedBy=multi-user.target
EOF
ok "unit written"

# ── cth command ──────────────────────────────────────────────────────────
step "installing cth command"
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
# CTHULHU SIEM console
export PYTHONPATH="$ROOT/src\${PYTHONPATH:+:\$PYTHONPATH}"
export CTHULHU_ROOT="${ROOT}"
exec python3 -m cthulhu "\$@"
EOF
chmod 755 "$WRAPPER"
ok "cth installed"

# ── validate then start ──────────────────────────────────────────────────
step "validating ruleset"
if PYTHONPATH="$ROOT/src" CTHULHU_ROOT="$ROOT" python3 -m cthulhu.engine --check; then
    ok "ruleset valid"
else
    die "ruleset failed validation — not starting the service"
fi

step "enabling service"
systemctl daemon-reload
systemctl enable cthulhu.service >/dev/null 2>&1 || true
systemctl restart cthulhu.service || warn "service failed to start; check: journalctl -u cthulhu -n 50"

sleep 1
if systemctl is-active --quiet cthulhu.service; then
    ok "cthulhu.service running"
else
    warn "cthulhu.service is not active"
fi

printf '\n  %s^(;,;)^%s  %sinstalled%s\n\n' "$C_ACC" "$C_OFF" "$C_OK" "$C_OFF"
cat <<EOF
    console      cth
    live feed    cth live
    open alerts  cth list --status open
    triage       cth triage <id> tp|bp|fp -m "note"
    statistics   cth stats
    validate     cth check

    service      systemctl status cthulhu
    reload rules systemctl reload cthulhu
    logs         journalctl -u cthulhu -f

    ruleset      $ROOT/alerts.jrl
    alerts       $ROOT/alerts.jsonl
    verdicts     $ROOT/triage.jsonl
    feeds        $ROOT/feeds.d/

EOF
