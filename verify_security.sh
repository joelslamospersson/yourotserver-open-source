#!/usr/bin/env bash
set -euo pipefail

# Manual verifier for security features configured by this yourotserver.
# It performs read-only checks and reports PASS/FAIL/WARN for each area.

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
RC=0

is_root(){ [[ $EUID -eq 0 ]]; }

SUDO=""
if ! is_root; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    SUDO="sudo -n"
  else
    echo "WARN: not running as root and sudo not available without password; some checks may be skipped." >&2
  fi
fi

log(){ printf "\n=== %s ===\n" "$*"; }
ok(){ echo "✔ PASS: $*"; PASS_COUNT=$((PASS_COUNT+1)); }
warn(){ echo "⚠ WARN: $*"; WARN_COUNT=$((WARN_COUNT+1)); }
fail(){ echo "✖ FAIL: $*"; FAIL_COUNT=$((FAIL_COUNT+1)); RC=1; }

have(){ command -v "$1" >/dev/null 2>&1; }

check_ufw(){
  log "UFW firewall"
  if have ufw; then
    local s
    if s=$(ufw status 2>/dev/null | head -n1 | awk '{print $2}'); then
      if [[ "$s" == "active" ]]; then
        ok "ufw is active"
        # Verify expected ports are allowed
        local ports=(80 443 7171 7172)
        local missing=0
        for p in "${ports[@]}"; do
          if ufw status | grep -Eq "\b${p}/(tcp|Anywhere)\b"; then
            ok "ufw rule present for port $p"
          else
            warn "ufw rule missing for port $p"
            missing=1
          fi
        done
        # SSH port (detect from sshd_config)
        local ssh_port
        ssh_port=$(awk 'BEGIN{p=22}/^\s*Port\s+[0-9]+/{p=$2;exit}END{print p}' /etc/ssh/sshd_config 2>/dev/null || echo 22)
        if ufw status | grep -Eq "\b${ssh_port}/(tcp|Anywhere)\b|\bOpenSSH\b"; then
          ok "ufw rule present for SSH port ${ssh_port}"
        else
          warn "ufw rule missing for SSH port ${ssh_port}"
        fi
      else
        warn "ufw installed but not active"
      fi
    else
      warn "ufw present but could not read status"
    fi
  else
    warn "ufw not installed (expected if iptables-only hardening is used)"
  fi
}

ipt_rule_exists(){
  # Usage: ipt_rule_exists <args...> for iptables -C INPUT <args>
  $SUDO iptables -C INPUT "$@" >/dev/null 2>&1
}

check_iptables(){
  log "iptables/netfilter rules"
  if ! have iptables; then
    warn "iptables not installed"
    return 0
  fi

  # Default policies
  if $SUDO iptables -S | grep -q "^-P INPUT DROP$"; then
    ok "INPUT default policy is DROP"
  else
    warn "INPUT default policy is not DROP"
  fi
  if $SUDO iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
    ok "RELATED,ESTABLISHED accepted early"
  else
    warn "No RELATED,ESTABLISHED accept rule detected"
  fi
  if ipt_rule_exists -i lo -j ACCEPT; then
    ok "Loopback accepted"
  else
    warn "Loopback accept rule missing"
  fi
  if ipt_rule_exists -m conntrack --ctstate INVALID -j DROP; then
    ok "Invalid packets dropped"
  else
    warn "No explicit DROP for INVALID state"
  fi

  # Check for our chains or direct hashlimit rules
  local has_rate_chain=0 has_tibia_chain=0 has_hashlimit=0
  if $SUDO iptables -L RATE_LIMIT >/dev/null 2>&1; then has_rate_chain=1; fi
  if $SUDO iptables -L TIBIA_LIMIT >/dev/null 2>&1; then has_tibia_chain=1; fi
  if $SUDO iptables -S INPUT | grep -q -- "--hashlimit-name"; then has_hashlimit=1; fi

  if (( has_rate_chain==1 )); then ok "RATE_LIMIT chain present"; else warn "RATE_LIMIT chain not present"; fi
  if (( has_tibia_chain==1 )); then ok "TIBIA_LIMIT chain present"; else warn "TIBIA_LIMIT chain not present"; fi
  if (( has_hashlimit==1 )); then ok "Direct hashlimit rules present in INPUT"; else warn "No direct hashlimit rules detected"; fi

  # Verify ports are protected (either via chains or hashlimit)
  local ports=(80 443 7171 7172)
  for p in "${ports[@]}"; do
    if ipt_rule_exists -p tcp --dport "$p" -j RATE_LIMIT || \
       ipt_rule_exists -p tcp --dport "$p" -j TIBIA_LIMIT || \
       $SUDO iptables -S INPUT | grep -q -- "-p tcp -m tcp --dport ${p} .*--hashlimit-name"; then
      ok "Port $p is rate-limited (chain or hashlimit rule found)"
    else
      warn "No rate-limit detected for port $p"
    fi
  done

  # SSH port allowed via chain
  local ssh_port
  ssh_port=$(awk 'BEGIN{p=22}/^\s*Port\s+[0-9]+/{p=$2;exit}END{print p}' /etc/ssh/sshd_config 2>/dev/null || echo 22)
  if ipt_rule_exists -p tcp --dport "$ssh_port" -j RATE_LIMIT || ipt_rule_exists -p tcp --dport "$ssh_port" -j ACCEPT || \
     $SUDO iptables -S INPUT | grep -q -- "--dport ${ssh_port} "; then
    ok "SSH port ${ssh_port} explicitly allowed/limited"
  else
    warn "SSH port ${ssh_port} rule not found"
  fi

  # Persistence
  if [[ -f /etc/iptables/rules.v4 ]]; then
    ok "/etc/iptables/rules.v4 exists (persistence)"
  else
    warn "iptables persistence file /etc/iptables/rules.v4 not found"
  fi
}

check_fail2ban(){
  log "Fail2ban"
  if have systemctl && systemctl list-unit-files | grep -q fail2ban; then
    if systemctl is-active --quiet fail2ban; then
      ok "fail2ban service is active"
    else
      fail "fail2ban service is not active"
    fi
  else
    warn "fail2ban service not installed"
    return 0
  fi

  if have fail2ban-client; then
    local status
    if status=$(fail2ban-client status 2>/dev/null); then
      echo "$status" | sed -n '1,20p' >/dev/null
      # Check for common jails
      echo "$status" | grep -q "sshd" && ok "sshd jail present" || warn "sshd jail missing"
      echo "$status" | grep -q "recidive" && ok "recidive jail present" || warn "recidive jail missing"
    else
      warn "fail2ban-client status failed"
    fi
  else
    warn "fail2ban-client not available"
  fi

  # Filters we install
  local fd="/etc/fail2ban/filter.d"
  for f in sshd-ddos.conf http-get-dos.conf otserver.conf game-login.conf; do
    if [[ -f "$fd/$f" ]]; then ok "filter present: $f"; else warn "filter missing: $f"; fi
  done
}

check_ssh(){
  log "SSH hardening"
  local conf=/etc/ssh/sshd_config
  if [[ -f "$conf" ]]; then
    if grep -Eq '^[[:space:]]*PermitRootLogin[[:space:]]+no' "$conf"; then
      ok "PermitRootLogin no"
    else
      fail "PermitRootLogin is not set to no"
    fi
    local p
    p=$(awk 'BEGIN{p=22}/^\s*Port\s+[0-9]+/{p=$2;exit}END{print p}' "$conf")
    if [[ "$p" != "22" ]]; then
      ok "SSH Port is $p (non-default)"
    else
      warn "SSH Port is default 22"
    fi
    # Check socket listening
    if have ss; then
      if ss -tln | awk '{print $4}' | grep -q ":$p$"; then ok "sshd listening on :$p"; else warn "sshd not listening on :$p"; fi
    fi
  else
    warn "sshd_config not found"
  fi
}

check_nginx(){
  log "Nginx security headers"
  local site=/etc/nginx/sites-available/default
  if [[ -f "$site" ]]; then
    grep -q 'add_header[[:space:]]\+X-Frame-Options[[:space:]]\+"SAMEORIGIN"' "$site" && ok "X-Frame-Options SAMEORIGIN" || fail "X-Frame-Options header missing"
    grep -q 'add_header[[:space:]]\+X-Content-Type-Options[[:space:]]\+"nosniff"' "$site" && ok "X-Content-Type-Options nosniff" || fail "X-Content-Type-Options header missing"
    grep -q 'add_header[[:space:]]\+X-XSS-Protection[[:space:]]\+"1; mode=block"' "$site" && ok "X-XSS-Protection 1; mode=block" || warn "X-XSS-Protection header missing"
  else
    warn "$site not found"
  fi

  if have nginx; then
    if $SUDO nginx -t >/dev/null 2>&1; then ok "nginx config test OK"; else fail "nginx config test failed"; fi
    if have systemctl && systemctl is-active --quiet nginx; then ok "nginx service active"; else warn "nginx service not active"; fi
  else
    warn "nginx not installed"
  fi
}

check_kernel_sysctl(){
  log "Kernel/LSM/sysctl hardening"
  local grub=/etc/default/grub
  if [[ -f "$grub" ]]; then
    grep -q 'lockdown=integrity' "$grub" && ok "GRUB lockdown=integrity set" || warn "GRUB lockdown flag missing"
    grep -q 'module.sig_enforce=1' "$grub" && ok "GRUB module.sig_enforce=1 set" || warn "GRUB module.sig_enforce flag missing"
    grep -q 'kaslr' "$grub" && ok "GRUB kaslr set" || warn "GRUB kaslr flag missing"
    grep -q 'kptr_restrict=2' "$grub" && ok "GRUB kptr_restrict=2 set" || warn "GRUB kptr_restrict flag missing"
  else
    warn "/etc/default/grub not found"
  fi
  # Live kernel cmdline (post-reboot)
  if [[ -r /proc/cmdline ]]; then
    grep -q 'lockdown=integrity' /proc/cmdline && ok "runtime lockdown=integrity" || warn "runtime lockdown not set"
    grep -q 'kaslr' /proc/cmdline && ok "runtime kaslr" || warn "runtime kaslr not set"
  fi

  # Sysctl expected values
  check_sysctl(){ local k="$1" v="$2"; local cur; cur=$(sysctl -n "$k" 2>/dev/null || echo ""); if [[ "$cur" == "$v" ]]; then ok "sysctl $k=$v"; else warn "sysctl $k expected $v, got '$cur'"; fi; }
  check_sysctl kernel.yama.ptrace_scope 1
  check_sysctl kernel.dmesg_restrict 1
  check_sysctl fs.suid_dumpable 0
  check_sysctl kernel.randomize_va_space 2
  check_sysctl vm.mmap_min_addr 65536
  check_sysctl net.ipv4.tcp_syncookies 1
}

check_mounts(){
  log "/tmp and /var/tmp mount hardening"
  have findmnt || { warn "findmnt not available"; return 0; }
  local opt
  for d in /tmp /var/tmp; do
    if mountpoint -q "$d"; then
      opt=$(findmnt -no OPTIONS "$d" 2>/dev/null || echo "")
      [[ "$opt" == *noexec* ]] && [[ "$opt" == *nosuid* ]] && [[ "$opt" == *nodev* ]] \
        && ok "$d has noexec,nosuid,nodev" \
        || warn "$d missing one of noexec,nosuid,nodev (opts: $opt)"
    else
      warn "$d is not a mountpoint"
    fi
  done
}

check_apparmor(){
  log "AppArmor"
  if have aa-status; then
    if aa-status --enforced >/dev/null 2>&1; then ok "AppArmor profiles enforced"; else warn "AppArmor not fully enforced"; fi
  else
    if [[ -r /sys/module/apparmor/parameters/enabled ]] && grep -qi enforce /sys/module/apparmor/parameters/enabled; then
      ok "AppArmor kernel enabled"
    else
      warn "AppArmor status unknown (tools not installed)"
    fi
  fi
}

check_letsencrypt(){
  log "Let's Encrypt (optional)"
  if [[ -d /etc/letsencrypt/live ]]; then
    local any
    any=$(find /etc/letsencrypt/live -maxdepth 1 -type d -not -name live -print -quit 2>/dev/null || true)
    if [[ -n "$any" ]]; then
      ok "Certs present under /etc/letsencrypt/live"
    else
      warn "No live certs found"
    fi
  else
    warn "/etc/letsencrypt/live not found"
  fi
}

main(){
  log "Security verification started"
  check_ufw
  check_iptables
  check_fail2ban
  check_ssh
  check_nginx
  check_kernel_sysctl
  check_mounts
  check_apparmor
  check_letsencrypt

  printf "\n=== Summary ===\n"
  printf "PASS: %d\nFAIL: %d\nWARN: %d\n" "$PASS_COUNT" "$FAIL_COUNT" "$WARN_COUNT"
  if (( FAIL_COUNT > 0 )); then
    echo "Overall: FAIL"
  else
    echo "Overall: OK"
  fi
  exit $RC
}

main "$@"

