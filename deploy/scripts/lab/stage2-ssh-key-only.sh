#!/usr/bin/env bash
# IPAT lab stage 2. A temporary systemd timer reverts the only SSH file changed.
# Do NOT modify SSH port, firewall, host keys, user keys or other accounts here.
set -Eeuo pipefail
umask 077

managed=/etc/ssh/sshd_config.d/00-ipat-lab-hardening.conf
script=/root/ipat-bootstrap/stage2-ssh.sh
marker=/run/ipat-ssh-stage2.active
backup_root=/var/backups/ipat-lab

fatal() { echo "ABORT: $*" >&2; exit 1; }
root_only() { (( EUID == 0 )) || fatal "root required"; }
effective() {
    /usr/sbin/sshd -T -C "user=$1,host=hub.example.invalid,addr=127.0.0.1" |
        awk -v key="$2" '$1==key {print $2;exit}'
}
verify_policy() {
    [[ "$(effective openai passwordauthentication)" == no ]] &&
    [[ "$(effective openai pubkeyauthentication)" == yes ]] &&
    [[ "$(effective root permitrootlogin)" == no ]] &&
    [[ "$(effective root passwordauthentication)" == no ]]
}
verify_host() {
    # shellcheck source=/dev/null
    . /etc/os-release
    [[ "$ID" == ubuntu && "$VERSION_ID" == 26.04 ]] || fatal "unexpected OS"
    [[ -s /home/openai/.ssh/authorized_keys ]] || fatal "openai SSH key absent"
    command -v systemd-run >/dev/null || fatal "systemd-run unavailable"
    systemctl is-active --quiet ssh || fatal "SSH daemon inactive"
}
rollback() {
    root_only
    local dir="$1"
    [[ "$dir" == /var/backups/ipat-lab/stage2-* && -s "$dir/ssh-before.tar.gz" ]] ||
        fatal "invalid rollback directory"
    if [[ -f "$managed" ]]; then
        grep -Fqx '# IPAT LAB STAGE 2 MANAGED (TIMED ROLLBACK)' "$managed" ||
            fatal "unexpected snippet; use provider console for manual recovery"
        rm -f "$managed"
    fi
    /usr/sbin/sshd -t || fatal "rollback config invalid; use console"
    systemctl reload ssh || fatal "rollback reload failed; use console"
    rm -f "$marker"
    echo STAGE2_AUTO_ROLLBACK_COMPLETE
}
preflight() {
    verify_host
    [[ ! -e "$managed" && ! -e "$marker" ]] || fatal "pending or existing stage2 change"
    echo STAGE2_READ_ONLY_PREFLIGHT_PASS
}
apply() {
    root_only
    [[ "${IPAT_STAGE2_APPROVED:-}" == yes ]] || fatal "missing owner consent"
    [[ "${IPAT_STAGE2_CONSOLE_READY:-}" == yes ]] || fatal "console must be verified"
    preflight
    /usr/sbin/sshd -t || fatal "baseline SSH config invalid"
    install -d -o root -g root -m 0700 "$backup_root"
    local backup unit armed
    backup="$(mktemp -d "$backup_root/stage2-XXXXXXXX")"
    chmod 0700 "$backup"
    tar -C / -czf "$backup/ssh-before.tar.gz" etc/ssh/sshd_config etc/ssh/sshd_config.d
    chmod 0600 "$backup/ssh-before.tar.gz"
    sha256sum "$backup/ssh-before.tar.gz" > "$backup/archive.sha256"
    {
        echo "before_openai_password=$(effective openai passwordauthentication)"
        echo "before_openai_pubkey=$(effective openai pubkeyauthentication)"
        echo "before_root_login=$(effective root permitrootlogin)"
    } > "$backup/policy-before.txt"
    chmod 0600 "$backup/policy-before.txt"
    unit="ipat-ssh-revert-$(date -u +%Y%m%d%H%M%S)"
    # Arm fallback BEFORE writing a policy file; no snapshot is available.
    systemd-run --quiet --collect --unit="$unit" --on-active=6m \
        --timer-property=AccuracySec=1s /bin/bash "$script" --rollback "$backup" ||
        fatal "could not arm rollback; no SSH changes"
    systemctl is-active --quiet "$unit.timer" ||
        fatal "rollback timer not active; no SSH changes"
    printf '%s\n%s\n' "$backup" "$unit" > "$marker"
    chmod 0600 "$marker"
    armed=yes
    trap 'if [[ "$armed" == yes ]]; then /bin/bash "$script" --rollback "$backup" || true; fi' ERR
    local temp
    temp="$(mktemp /etc/ssh/sshd_config.d/.ipat-config.XXXXXXXX)"
    cat > "$temp" <<'CONF'
# IPAT LAB STAGE 2 MANAGED (TIMED ROLLBACK)
# Ubuntu OpenSSH: early Include directive wins over later cloud-init/main file.
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
CONF
    install -o root -g root -m 0644 "$temp" "$managed"
    rm -f "$temp"
    /usr/sbin/sshd -t
    verify_policy || { rollback "$backup"; fatal "effective SSH policy not as expected"; }
    systemctl reload ssh
    systemctl is-active --quiet ssh
    armed=no
    trap - ERR
    echo STAGE2_SSH_KEY_ONLY_APPLIED_WITH_ROLLBACK_TIMER
    echo SIX_MINUTES_TO_TEST_AND_CONFIRM_FROM_NEW_CONNECTION
}
confirm() {
    root_only
    [[ -s "$marker" && -f "$managed" ]] || fatal "no pending SSH hardening"
    local backup unit
    backup="$(sed -n '1p' "$marker")"
    unit="$(sed -n '2p' "$marker")"
    [[ "$backup" == /var/backups/ipat-lab/stage2-* &&
       "$unit" == ipat-ssh-revert-* ]] || fatal "invalid rollback marker"
    /usr/sbin/sshd -t
    verify_policy || fatal "SSH policy changed or timed rollback already executed"
    systemctl is-active --quiet ssh || fatal "SSH inactive"
    systemctl is-active --quiet "$unit.timer" || fatal "rollback timer not armed"
    systemctl stop "$unit.timer" || fatal "unable to disarm rollback"
    systemctl is-active --quiet "$unit.timer" && fatal "timer still running"
    verify_policy || fatal "effective policy changed during confirmation"
    rm -f "$marker"
    echo STAGE2_SSH_HARDENING_CONFIRMED_TIMER_DISARMED
    echo FIREWALL_AND_SSH_PORT_UNCHANGED
}

case "${1:-}" in
    --check) [[ "$#" == 1 ]] || fatal "unexpected arguments"; preflight ;;
    --apply) [[ "$#" == 1 ]] || fatal "unexpected arguments"; apply ;;
    --rollback) [[ "$#" == 2 ]] || fatal "rollback path required"; rollback "$2" ;;
    --confirm) [[ "$#" == 1 ]] || fatal "unexpected arguments"; confirm ;;
    *) fatal "usage: --check|--apply|--confirm|--rollback PATH" ;;
esac
