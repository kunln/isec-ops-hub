#!/usr/bin/env bash
# Host Compromise Deep Scan Script
# -----------------------------------------------------------------------
# Targeted deep forensic data collection. Run ONLY when triage.sh output
# shows suspicious indicators. Covers 6 investigation areas:
#
#   1. Process Investigation
#   2. Persistence Mechanisms
#   3. File System Anomalies
#   4. User & Authentication
#   5. Network & Communication
#   6. Cryptomining Indicators
#
# Expected runtime: 2-5 minutes depending on filesystem size.
# Recommended timeout: 300s when calling ssh_run_script.
#
# Output uses ### SECTION_NAME ### markers for structured parsing.
# Safe to customize: add site-specific checks as needed.
# DO NOT add write operations — the ssh_run_script tool will reject them.
# -----------------------------------------------------------------------

LANG=C; export LANG
_s() { printf '\n### %s ###\n' "$1"; }

_s "DEEP_SCAN_START"
date -u; hostname; uname -a

# -----------------------------------------------------------------------
# 1. Process Investigation
# -----------------------------------------------------------------------

_s "PROC_EXE_LINKS"
ls -la /proc/*/exe 2>/dev/null | grep -v ' -> $' | head -60

_s "PROC_CMDLINES_ALL"
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | head -500); do
  cmd=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' | head -c 200)
  if [ -n "$cmd" ]; then
    echo "$pid: $cmd"
  fi
done

_s "PROC_MAPS_SUSPICIOUS"
for pid in $(ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3>50 {print $2}' | head -5); do
  echo "=== PID $pid maps ==="
  cat /proc/$pid/maps 2>/dev/null | grep -v '\.so' | head -20
done

_s "OPEN_FILES_BY_PROCESS"
lsof -n 2>/dev/null | grep -vE '^COMMAND|\.so|/usr/lib|/lib' | head -80

_s "PROC_NET_BY_PROCESS"
ss -tunap 2>/dev/null | grep -v "127\.0\.0\.1\|::1" | head -50

# -----------------------------------------------------------------------
# 2. Persistence Mechanisms
# -----------------------------------------------------------------------

_s "SYSTEMD_ALL_SERVICES"
systemctl list-units --type=service --all --no-pager 2>/dev/null | head -80

_s "SYSTEMD_UNIT_FILES_NEW"
find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" -newer /etc/passwd 2>/dev/null | head -20

_s "SYSTEMD_UNIT_CONTENTS_NEW"
find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" -newer /etc/passwd 2>/dev/null \
  | head -10 | xargs cat 2>/dev/null

_s "CRON_ALL_USERS"
find /var/spool/cron /var/spool/cron/crontabs /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly \
  -type f 2>/dev/null | xargs cat 2>/dev/null | head -100

_s "INIT_SCRIPTS"
cat /etc/rc.local 2>/dev/null; echo '---'
ls -la /etc/init.d/ 2>/dev/null

_s "SHELL_PROFILES_ALL"
cat /root/.bashrc 2>/dev/null; echo '---'
cat /root/.bash_profile 2>/dev/null; echo '---'
cat /root/.profile 2>/dev/null; echo '---'
find /home -maxdepth 2 \( -name ".bashrc" -o -name ".profile" \) 2>/dev/null | xargs cat 2>/dev/null | head -80

_s "SSH_AUTHORIZED_KEYS_ALL"
cat /root/.ssh/authorized_keys 2>/dev/null; echo '---'
find /home -name "authorized_keys" 2>/dev/null | xargs cat 2>/dev/null

_s "LD_PRELOAD_INJECTION"
cat /etc/ld.so.preload 2>/dev/null; echo '---'
env 2>/dev/null | grep LD_

_s "AT_JOBS"
atq 2>/dev/null

# -----------------------------------------------------------------------
# 3. File System Anomalies
# -----------------------------------------------------------------------

_s "RECENTLY_MODIFIED_DEEP"
find / -maxdepth 6 -newer /etc/passwd -type f 2>/dev/null \
  | grep -vE '^/proc|^/sys|^/run|^/dev|^/tmp/.X' | head -80

_s "HIDDEN_FILES_SYSTEM_DIRS"
find /tmp /dev/shm /var/tmp -name ".*" 2>/dev/null
find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null

_s "SUID_BINARIES_ALL"
find / -perm -4000 -type f 2>/dev/null | head -40

_s "WORLD_WRITABLE_EXECUTABLES"
find /tmp /dev/shm /var/tmp /run -type f -executable 2>/dev/null | head -30

_s "EXECUTABLE_FILES_IN_TMP"
find /tmp /dev/shm /var/tmp -type f 2>/dev/null | xargs file 2>/dev/null | grep -iE 'ELF|executable|script' | head -20

# -----------------------------------------------------------------------
# 4. User & Authentication
# -----------------------------------------------------------------------

_s "PASSWD_INTERACTIVE_USERS"
cat /etc/passwd 2>/dev/null | grep -v -E '/nologin|/false|/sync|/halt|/shutdown'

_s "SHADOW_RECENT_CHANGES"
ls -la /etc/shadow /etc/passwd /etc/group 2>/dev/null

_s "SUDO_CONFIGURATION"
cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'; echo '---'
find /etc/sudoers.d -type f 2>/dev/null | xargs cat 2>/dev/null

_s "SSH_CONFIG"
cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'

_s "AUTH_LOG_FULL"
grep -E 'Failed password|Accepted password|Accepted publickey|ROOT|Invalid user|session opened|session closed' \
  /var/log/auth.log 2>/dev/null | tail -150 || \
grep -E 'Failed password|Accepted password|Accepted publickey|ROOT|Invalid user|session opened|session closed' \
  /var/log/secure 2>/dev/null | tail -150

_s "LAST_LOGINS_FULL"
last -n 50 2>/dev/null; echo '---'; lastb -n 30 2>/dev/null

# -----------------------------------------------------------------------
# 5. Network & Communication
# -----------------------------------------------------------------------

_s "LISTENING_SERVICES_FULL"
ss -tlnup 2>/dev/null

_s "ESTABLISHED_CONNECTIONS_FULL"
ss -tunap 2>/dev/null | grep ESTAB | head -60

_s "HOSTS_FILE"
cat /etc/hosts 2>/dev/null

_s "DNS_RESOLVER"
cat /etc/resolv.conf 2>/dev/null

_s "FIREWALL_RULES"
iptables -L -n 2>/dev/null | head -60; echo '---'
nft list ruleset 2>/dev/null | head -60

_s "NETWORK_INTERFACES"
ip addr 2>/dev/null || ifconfig 2>/dev/null

_s "ROUTING_TABLE"
ip route 2>/dev/null || route -n 2>/dev/null

# -----------------------------------------------------------------------
# 6. Cryptomining Indicators
# -----------------------------------------------------------------------

_s "MINER_PROCESSES_DETAILED"
ps aux 2>/dev/null | grep -iE 'xmrig|minerd|cpuminer|cgminer|bfgminer|ethminer|nbminer|phoenixminer|t-rex|gminer|kinsing|masscan|stratum'
ps aux --sort=-%cpu 2>/dev/null | head -15

_s "MINING_POOL_CONNECTIONS"
ss -tunap 2>/dev/null | grep -E ':443|:3333|:4444|:5555|:8080|:14444|:45700' | head -30

_s "MINER_CONFIG_FILES"
find / -maxdepth 6 \( -name "config.json" -o -name "*.conf" -o -name "*.cfg" \) 2>/dev/null \
  | xargs grep -l 'pool\|wallet\|mining\|stratum' 2>/dev/null | head -10

_s "HIGH_CPU_PROCESSES"
ps aux --sort=-%cpu 2>/dev/null | head -20

_s "PROC_EXE_HASHES_TOP_CPU"
for pid in $(ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3>30 {print $2}' | head -5); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  if [ -n "$exe" ] && [ -f "$exe" ]; then
    echo "$pid $exe $(sha256sum "$exe" 2>/dev/null | awk '{print $1}')"
  fi
done

_s "DEEP_SCAN_COMPLETE"
date -u
