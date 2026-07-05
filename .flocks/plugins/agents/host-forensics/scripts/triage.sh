#!/usr/bin/env bash
# Host Compromise Triage Script
# -----------------------------------------------------------------------
# Quick read-only forensic data collection for a remote Linux host.
# Collects ~20 categories of security indicators in ~30 seconds via
# a single SSH connection.
#
# Output uses ### SECTION_NAME ### markers for structured parsing.
# Safe to modify: add/remove sections as needed for your environment.
# DO NOT add write operations (>, rm, chmod, etc.) — the ssh_run_script
# tool will reject scripts containing destructive commands.
# -----------------------------------------------------------------------

LANG=C; export LANG
_s() { printf '\n### %s ###\n' "$1"; }

_s "TRIAGE_START"
date -u; hostname; uname -a; uptime

_s "CPU_TOP_PROCESSES"
ps aux --sort=-%cpu 2>/dev/null | head -25 || ps aux 2>/dev/null | head -25

_s "ALL_PROCESSES_TREE"
ps auxf 2>/dev/null | head -60

_s "NETWORK_ESTABLISHED"
ss -tunap 2>/dev/null | grep -v "127\.0\.0\.1\|::1" | grep ESTAB | head -40 || \
  netstat -tunap 2>/dev/null | grep -v "127\.0\.0\.1\|::1" | grep ESTABLISHED | head -40

_s "LISTENING_PORTS"
ss -tlnup 2>/dev/null | head -30 || netstat -tlnup 2>/dev/null | head -30

_s "TEMP_DIRECTORIES"
ls -la /tmp /dev/shm /var/tmp 2>/dev/null

_s "HIDDEN_EXECUTABLE_IN_TMP"
find /tmp /dev/shm /var/tmp -name ".*" 2>/dev/null
find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null | head -20

_s "CRON_JOBS"
crontab -l 2>/dev/null; echo '---'
cat /etc/crontab 2>/dev/null; echo '---'
ls -la /etc/cron.d/ 2>/dev/null
cat /etc/cron.d/* 2>/dev/null | head -60

_s "SYSTEMD_RUNNING_SERVICES"
systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -40

_s "PERSISTENCE_MISC"
cat /etc/rc.local 2>/dev/null; echo '---'
cat /root/.bashrc 2>/dev/null | grep -v '^#' | grep -v '^$' | head -30

_s "LD_SO_PRELOAD"
cat /etc/ld.so.preload 2>/dev/null

_s "SSH_AUTHORIZED_KEYS"
cat /root/.ssh/authorized_keys 2>/dev/null
find /home -name "authorized_keys" 2>/dev/null | head -5 | xargs cat 2>/dev/null

_s "USER_ACCOUNTS_INTERACTIVE"
grep -v -E '/nologin|/false|/sync|/halt|/shutdown' /etc/passwd 2>/dev/null

_s "SUDO_RIGHTS"
cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'; echo '---'
ls /etc/sudoers.d/ 2>/dev/null

_s "KNOWN_MINER_PROCESSES"
ps aux 2>/dev/null | grep -iE 'xmrig|minerd|cpuminer|cgminer|bfgminer|ethminer|nbminer|phoenixminer|t-rex|gminer|kinsing|masscan' | grep -v grep
ls -la /proc/*/exe 2>/dev/null | grep -iE 'xmrig|miner|crypt' | head -10

_s "SUSPICIOUS_NETWORK_TO_KNOWN_PORTS"
ss -tunap 2>/dev/null | grep -E ':3333|:4444|:5555|:14444|:45700|:8899|:9999' | grep ESTAB | head -20

_s "RECENTLY_MODIFIED_FILES"
find / -maxdepth 5 -newer /etc/passwd -type f 2>/dev/null \
  | grep -vE '^/proc|^/sys|^/run|^/dev|^/tmp/.X' | head -40

_s "SUID_BINARIES_UNEXPECTED"
find / -perm -4000 -type f 2>/dev/null \
  | grep -vE '^/usr/bin|^/usr/sbin|^/bin|^/sbin|^/usr/lib|^/usr/local' | head -15

_s "RECENT_AUTH_EVENTS"
grep -E 'Failed password|Accepted password|Accepted publickey|ROOT|Invalid user' \
  /var/log/auth.log 2>/dev/null | tail -80 || \
grep -E 'Failed password|Accepted password|Accepted publickey|ROOT|Invalid user' \
  /var/log/secure 2>/dev/null | tail -80

_s "RECENT_LOGINS"
last -n 25 2>/dev/null; echo '---'; lastb -n 15 2>/dev/null

_s "SHELL_HISTORY_ROOT"
tail -60 /root/.bash_history 2>/dev/null
tail -30 /root/.zsh_history 2>/dev/null

_s "DMESG_RECENT"
dmesg 2>/dev/null | tail -30

_s "ENVIRONMENT"
env 2>/dev/null | grep -vE '^LS_COLORS|^TERM=|^LESS=' | head -40

_s "KERNEL_MODULES_UNUSUAL"
lsmod 2>/dev/null | grep -vE '^Module|^nf_|^ip_|^xt_|^bridge|^bonding|^8021q|^veth|^overlay|^br_' | head -20

_s "OPEN_FILES_DELETED"
lsof 2>/dev/null | grep '(deleted)' | head -20

_s "HOSTS_FILE"
cat /etc/hosts 2>/dev/null

_s "TRIAGE_COMPLETE"
date -u
