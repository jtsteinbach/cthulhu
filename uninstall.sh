#!/usr/bin/env bash
#  ^(;,;)^  CTHULHU SIEM — uninstaller
#
#  Usage:
#    sudo bash uninstall.sh              remove CTHULHU, keep alerts and rules
#    sudo bash uninstall.sh --purge      remove everything, including data
#    sudo bash uninstall.sh --keep-audit leave the auditd policy in place
#    sudo bash uninstall.sh --dry-run    show what would happen, change nothing
#
#  Detects and removes a v1 install (flat /cthulhu/src/*.py, alert.rules) as
#  well as v2. Data is preserved unless --purge is given.

set -euo pipefail

ROOT="${CTHULHU_ROOT:-/cthulhu}"
SERVICE="/etc/systemd/system/cthulhu.service"
WRAPPER="/usr/local/bin/cth"
AUDIT_RULES="/etc/audit/rules.d/50-cthulhu.rules"

PURGE=0
KEEP_AUDIT=0
DRY=0
for arg in "$@"; do
    case "$arg" in
        --purge)      PURGE=1 ;;
        --keep-audit) KEEP_AUDIT=1 ;;
        --dry-run|-n) DRY=1 ;;
        -h|--help)    sed -n '2,12p' "$0" | sed 's/^#\s\?//'; exit 0 ;;
        *)            echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

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

run() {
    if [[ "$DRY" -eq 1 ]]; then
        printf '  %swould run:%s %s\n' "$C_DIM" "$C_OFF" "$*"
    else
        "$@" 2>/dev/null || true
    fi
}

remove_path() {
    local target="$1"
    [[ -e "$target" ]] || return 0
    if [[ "$DRY" -eq 1 ]]; then
        printf '  %swould remove:%s %s\n' "$C_DIM" "$C_OFF" "$target"
    else
        rm -rf "$target"
    fi
}

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "must run as root (try: sudo bash uninstall.sh)"

printf '\n  %s^(;,;)^%s  %sCTHULHU%s %suninstaller%s\n\n' \
    "$C_ACC" "$C_OFF" "$C_ACC" "$C_OFF" "$C_DIM" "$C_OFF"

[[ "$DRY" -eq 1 ]] && warn "dry run — nothing will be changed"

# ── what is installed? ───────────────────────────────────────────────────
FOUND=0
V1=0
[[ -f "$SERVICE" ]] && FOUND=1
[[ -f "$WRAPPER" ]] && FOUND=1
[[ -d "$ROOT" ]] && FOUND=1
for m in engine.py cli.py rule_handler.py ingest_events.py alert_handler.py; do
    [[ -f "$ROOT/src/$m" ]] && { V1=1; FOUND=1; }
done
[[ -f "$ROOT/alert.rules" ]] && { V1=1; FOUND=1; }

if [[ "$FOUND" -eq 0 ]]; then
    warn "no CTHULHU install found at $ROOT"
    printf '\n'
    exit 0
fi
[[ "$V1" -eq 1 ]] && step "earlier install layout detected"

# ── stop the service ─────────────────────────────────────────────────────
step "stopping service"
run systemctl stop cthulhu.service
run systemctl disable cthulhu.service
remove_path "$SERVICE"
run systemctl daemon-reload
run systemctl reset-failed cthulhu.service
ok "service removed"

# ── command wrapper ──────────────────────────────────────────────────────
remove_path "$WRAPPER"
ok "cth command removed"

# ── audit policy ─────────────────────────────────────────────────────────
if [[ "$KEEP_AUDIT" -eq 1 ]]; then
    warn "auditd policy left in place at $AUDIT_RULES"
elif [[ -f "$AUDIT_RULES" ]]; then
    step "removing auditd policy"
    remove_path "$AUDIT_RULES"
    if [[ "$DRY" -eq 0 ]] && command -v augenrules >/dev/null 2>&1; then
        if augenrules --load >/dev/null 2>&1; then
            ok "audit policy removed and reloaded"
        else
            warn "audit policy file removed; rules stay active until reboot"
            warn "(auditd may be in immutable mode — check: auditctl -s)"
        fi
    else
        ok "audit policy removed"
    fi
fi

# ── program files ────────────────────────────────────────────────────────
step "removing program files"
remove_path "$ROOT/src"
remove_path "$ROOT/feeds.d"
ok "engine removed"

# ── data ─────────────────────────────────────────────────────────────────
if [[ "$PURGE" -eq 1 ]]; then
    step "purging data"
    for f in alerts.jrl alerts.jrl.new alert.rules alerts.jsonl triage.jsonl state; do
        remove_path "$ROOT/$f"
    done
    if [[ "$DRY" -eq 0 ]]; then
        rm -f "$ROOT"/alerts.jsonl.* "$ROOT"/alerts.jrl.backup-* 2>/dev/null || true
        rm -rf "$ROOT"/backup-* 2>/dev/null || true
        rmdir "$ROOT" 2>/dev/null || true
    fi
    if [[ -d "$ROOT" ]]; then
        warn "$ROOT not empty — inspect and remove manually"
    else
        ok "all data removed"
    fi
else
    KEPT=()
    for f in alerts.jrl alert.rules alerts.jsonl triage.jsonl; do
        [[ -e "$ROOT/$f" ]] && KEPT+=("$f")
    done
    if [[ "${#KEPT[@]}" -gt 0 ]]; then
        ok "data kept at $ROOT: ${KEPT[*]}"
        warn "re-run with --purge to delete alerts, verdicts and rules"
    fi
fi

printf '\n  %s^(;,;)^%s  %suninstalled%s\n\n' "$C_ACC" "$C_OFF" "$C_OK" "$C_OFF"
