#!/usr/bin/env python3
"""
Lightweight Linux Endpoint Monitor
===================================
Captures: process execution, network connections (TCP/UDP), DNS,
          file access, privilege escalation, reverse shells, malware behavior,
          plus full auditd syscall trail (when auditd is installed).
Outputs:  JSON logs → Wazuh-compatible.

Usage:  sudo python3 endpoint_monitor.py
        sudo python3 endpoint_monitor.py --config /etc/endpoint_monitor.json
        sudo python3 endpoint_monitor.py --install-audit-rules   # one-shot

Requires: root, Linux 2.6.15+, Python 3.6+ (stdlib only — no pip packages).
Optional: auditd installed for the AuditdMonitor component.
"""

import os
import re
import sys
import json
import time
import struct
import socket
import signal
import select
import ctypes
import ctypes.util
import threading
import pwd
from collections import defaultdict
from pathlib import Path

# Reduce per-thread virtual stack from 8 MB → 64 KB (saves committed pages).
# Must be set BEFORE any thread is created.
threading.stack_size(64 * 1024)

# Lazy-loaded heavy imports (only when actually needed):
#   ipaddress  → only for IPv6 parsing in /proc/net/{tcp,udp}6
#   subprocess → only for one-shot audit rule install
#   shutil     → only for one-shot audit rule install

# ── Netlink / Proc Connector constants ────────────────────────────────────
NETLINK_CONNECTOR     = 11
CN_IDX_PROC           = 1
CN_VAL_PROC           = 1
PROC_CN_MCAST_LISTEN  = 1
NLMSG_DONE            = 0x3

PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_UID  = 0x00000004
PROC_EVENT_GID  = 0x00000040
PROC_EVENT_EXIT = 0x80000000

# ── Inotify constants ────────────────────────────────────────────────────
IN_MODIFY      = 0x00000002
IN_ATTRIB      = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM  = 0x00000040
IN_MOVED_TO    = 0x00000080
IN_CREATE      = 0x00000100
IN_DELETE      = 0x00000200
IN_ISDIR       = 0x40000000

INOTIFY_EVENT_SIZE = struct.calcsize("iIII")  # 16 bytes

INOTIFY_MASK_NAMES = {
    IN_MODIFY: "modify", IN_ATTRIB: "attrib", IN_CLOSE_WRITE: "close_write",
    IN_MOVED_FROM: "moved_from", IN_MOVED_TO: "moved_to",
    IN_CREATE: "create", IN_DELETE: "delete",
}

# ── BSD Process Accounting (acct_v3) ─────────────────────────────────────
# Kernel writes a fixed 64-byte record for every process exit.
# See: <sys/acct.h> in glibc; same on Linux ≥ 2.6.
ACCT_V3_RECORD_SIZE = 64
ACCT_V3_FMT = "=ccHIIIIIIfHHHHHHHH16s"

# ac_flag bits
ACCT_AFORK = 0x01    # process was forked but did not exec
ACCT_ASU   = 0x02    # process used super-user privileges
ACCT_ACORE = 0x08    # process dumped core
ACCT_AXSIG = 0x10    # process was killed by a signal

# ── TCP state mapping (/proc/net/tcp) ────────────────────────────────────
TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}

# ── Audit key → (severity, tags) mapping ─────────────────────────────────
AUDIT_KEY_MAP = {
    "proc_exec":       ("info",     ["audit", "process_exec"]),
    "net_conn":        ("info",     ["audit", "network"]),
    "priv_esc":        ("warning",  ["audit", "priv_esc"]),
    "file_tamper":     ("high",     ["audit", "file", "critical_file"]),
    "malware_staging": ("warning",  ["audit", "file", "staging_area"]),
    "shell_exec":      ("info",     ["audit", "process_exec", "shell_exec"]),
    "dns_change":      ("warning",  ["audit", "dns_change"]),
    "kmod_load":       ("high",     ["audit", "kernel_module"]),
    "time_change":     ("warning",  ["audit", "time_change"]),
    "identity":        ("warning",  ["audit", "identity_change"]),
}

# ── Default configuration ────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "log_file":           "/var/log/endpoint_monitor/events.json.log",
    "log_max_bytes":      52_428_800,   # 50 MB
    "log_backup_count":   5,
    "network_poll_sec":   1,
    "correlator_poll_sec": 10,

    # Auditd integration
    "audit_enabled":         True,
    "audit_log_path":        "/var/log/audit/audit.log",
    "audit_install_rules":   True,
    "audit_rules_src":       "/opt/endpoint-monitor/endpoint_monitor.rules",
    "audit_rules_dst":       "/etc/audit/rules.d/endpoint_monitor.rules",
    "audit_flush_ms":        500,   # buffer same-msgid records this long

    # BSD process accounting — guarantees capture of EVERY process exit,
    # including microsecond-lived ones that proc connector can drop on overload.
    "process_accounting_enabled":     True,
    "process_accounting_file":        "/var/log/endpoint_monitor/pacct",
    "process_accounting_max_bytes":   52_428_800,   # rotate at 50 MB

    "watch_files": [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
        "/etc/sudoers", "/etc/crontab", "/etc/ssh/sshd_config",
        "/etc/ld.so.preload", "/etc/resolv.conf", "/etc/hosts",
    ],
    "watch_dirs": [
        "/tmp", "/dev/shm", "/var/tmp", "/var/spool/cron",
        "/etc/cron.d", "/etc/sudoers.d", "/etc/systemd/system", "/etc/pam.d",
    ],
    "critical_files": {
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/ld.so.preload", "/etc/ssh/sshd_config",
    },
    "staging_dirs": {"/tmp", "/dev/shm", "/var/tmp"},
    "shell_bins":       {"bash", "sh", "dash", "zsh", "csh", "fish", "ksh"},
    "suspicious_bins":  {
        "nc", "ncat", "nmap", "curl", "wget", "python", "python3",
        "perl", "ruby", "php", "socat", "telnet", "base64", "xxd",
        "openssl", "nohup", "screen", "tmux",
    },
    "privesc_bins":     {"sudo", "su", "pkexec", "doas", "newgrp", "chroot"},
    "suspicious_ports": {4444, 5555, 6666, 1337, 9001},
}


# ═══════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _uid_to_user(uid):
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError):
        return str(uid)


def get_process_info(pid):
    """Read process details from /proc/<pid>/."""
    info = {"pid": pid}
    proc = f"/proc/{pid}"
    try:
        with open(f"{proc}/cmdline", "rb") as fh:
            info["cmdline"] = fh.read().decode("utf-8", errors="replace") \
                                       .replace("\0", " ").strip()
        try:
            info["exe"] = os.readlink(f"{proc}/exe")
        except OSError:
            info["exe"] = ""

        with open(f"{proc}/status") as fh:
            for line in fh:
                k, _, v = line.partition(":\t")
                v = v.strip()
                if k == "Name":
                    info["comm"] = v
                elif k == "PPid":
                    info["ppid"] = int(v)
                elif k == "Uid":
                    uids = v.split()
                    info["uid"]  = int(uids[0])
                    info["euid"] = int(uids[1]) if len(uids) > 1 else info["uid"]
                elif k == "Gid":
                    info["gid"] = int(v.split()[0])

        try:
            info["cwd"] = os.readlink(f"{proc}/cwd")
        except OSError:
            info["cwd"] = ""

        info["user"] = _uid_to_user(info.get("uid", 0))
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
    return info


def _hex_to_ipv4(h):
    n = int(h, 16)
    return f"{n & 0xFF}.{(n >> 8) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 24) & 0xFF}"


_ipaddress = None  # lazy module reference

def _hex_to_ipv6(h):
    global _ipaddress
    if _ipaddress is None:
        import ipaddress as _ipaddress  # only loaded on first IPv6 conn
    words = [h[i:i+8] for i in range(0, 32, 8)]
    raw = b"".join(struct.pack("<I", int(w, 16)) for w in words)
    return str(_ipaddress.IPv6Address(raw))


def build_inode_to_pid_map():
    """Walk /proc once and build inode → PID for all socket FDs."""
    inode_map = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        fd_dir = f"/proc/{entry}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if link.startswith("socket:["):
                    inode = link[8:-1]
                    inode_map[inode] = pid
        except (PermissionError, FileNotFoundError):
            continue
    return inode_map


# ═══════════════════════════════════════════════════════════════════════════
#  Event Logger  →  JSON lines to file (Wazuh reads this)
#  ----------------------------------------------------------------------------
#  Implemented with raw os.write + manual rotation instead of the stdlib
#  `logging` module. Saves ~1 MB RSS by not loading logging/handlers/Formatter.
# ═══════════════════════════════════════════════════════════════════════════

class EventLogger:
    _ISO_FMT = "%Y-%m-%dT%H:%M:%S"

    def __init__(self, cfg):
        self._path        = cfg["log_file"]
        self._max_bytes   = cfg["log_max_bytes"]
        self._backups     = cfg["log_backup_count"]
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)

        self._fd          = self._open()
        self._size        = os.fstat(self._fd).st_size
        self._hostname    = socket.gethostname()
        self._lock        = threading.Lock()

    def _open(self):
        return os.open(self._path,
                       os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)

    def _rotate(self):
        try:
            os.close(self._fd)
        except OSError:
            pass
        for i in range(self._backups - 1, 0, -1):
            src = f"{self._path}.{i}"
            dst = f"{self._path}.{i + 1}"
            if os.path.exists(src):
                try:
                    os.replace(src, dst)
                except OSError:
                    pass
        try:
            os.replace(self._path, f"{self._path}.1")
        except OSError:
            pass
        self._fd   = self._open()
        self._size = 0

    def emit(self, event_type, severity, details, tags=None):
        # Pre-format timestamp as UTC ISO-8601 without allocating datetime obj.
        t = time.time()
        ts = time.strftime(self._ISO_FMT, time.gmtime(t)) + \
             f".{int((t - int(t)) * 1_000_000):06d}Z"

        record = {
            "timestamp":  ts,
            "hostname":   self._hostname,
            "event_type": event_type,
            "severity":   severity,
            "tags":       tags or [],
            "source":     "endpoint_monitor",
            "details":    details,
        }
        # Compact JSON: ~25% smaller logs, faster serialization, less GC pressure.
        msg = (json.dumps(record, separators=(",", ":"), default=str)
               + "\n").encode("utf-8")

        with self._lock:
            try:
                n = os.write(self._fd, msg)
            except OSError:
                return
            self._size += n
            if self._size >= self._max_bytes:
                self._rotate()


# ═══════════════════════════════════════════════════════════════════════════
#  1. Process Monitor  (netlink proc connector — real-time exec/fork/uid)
# ═══════════════════════════════════════════════════════════════════════════

class ProcessMonitor(threading.Thread):

    _PE = 36   # nlmsghdr(16) + cn_msg(20) → proc_event.what
    _ED = 52   # proc_event header(16)      → event_data

    def __init__(self, logger, cfg):
        super().__init__(daemon=True, name="ProcessMonitor")
        self.logger = logger
        self.cfg    = cfg
        self.running = True
        self.active_shells = {}

    @staticmethod
    def _subscribe(sock):
        msg = struct.pack(
            "=IHHII IIIIHH I",
            40, NLMSG_DONE, 0, 0, os.getpid(),
            CN_IDX_PROC, CN_VAL_PROC, 0, 0, 4, 0,
            PROC_CN_MCAST_LISTEN,
        )
        sock.send(msg)

    def run(self):
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM,
                                 NETLINK_CONNECTOR)
            sock.bind((os.getpid(), CN_IDX_PROC))
            self._subscribe(sock)
            sock.settimeout(1.0)
        except (OSError, PermissionError) as exc:
            print(f"[!] proc connector unavailable ({exc}), "
                  "falling back to /proc polling", file=sys.stderr)
            self._poll_fallback()
            return

        while self.running:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) >= self._ED:
                self._dispatch(data)
        sock.close()

    def _dispatch(self, data):
        what = struct.unpack_from("=I", data, self._PE)[0]

        if what == PROC_EVENT_EXEC:
            pid = struct.unpack_from("=I", data, self._ED)[0]
            self._on_exec(pid)

        elif what == PROC_EVENT_FORK:
            ppid = struct.unpack_from("=I", data, self._ED)[0]
            cpid = struct.unpack_from("=I", data, self._ED + 8)[0]
            if ppid in self.active_shells:
                info = get_process_info(cpid)
                info["parent_pid"] = ppid
                self.logger.emit("process_fork", "info", info,
                                 ["process_exec", "fork_from_shell"])

        elif what == PROC_EVENT_UID:
            pid, _, ruid, euid = struct.unpack_from("=IIII", data, self._ED)
            if ruid != euid:
                info = get_process_info(pid)
                info.update(ruid=ruid, euid=euid,
                            ruser=_uid_to_user(ruid),
                            euser=_uid_to_user(euid))
                self.logger.emit("uid_change", "warning", info,
                                 ["priv_esc", "uid_change"])

        elif what == PROC_EVENT_EXIT:
            pid = struct.unpack_from("=I", data, self._ED)[0]
            self.active_shells.pop(pid, None)

    def _on_exec(self, pid):
        info = get_process_info(pid)
        comm = info.get("comm", "")
        if not comm:
            return

        tags = ["process_exec"]
        severity = "info"

        if comm in self.cfg["privesc_bins"]:
            tags.append("priv_esc");  severity = "warning"
        if comm in self.cfg["shell_bins"]:
            tags.append("shell_exec")
            self.active_shells[pid] = info
        if comm in self.cfg["suspicious_bins"]:
            tags.append("suspicious_binary");  severity = "warning"

        cwd = info.get("cwd", "")
        if any(cwd == d or cwd.startswith(d + "/")
               for d in self.cfg["staging_dirs"]):
            tags.append("exec_from_staging");  severity = "high"

        self.logger.emit("process_exec", severity, info, tags)

    def _poll_fallback(self):
        known = {int(e) for e in os.listdir("/proc") if e.isdigit()}
        while self.running:
            time.sleep(1)
            current = {int(e) for e in os.listdir("/proc") if e.isdigit()}
            for pid in current - known:
                self._on_exec(pid)
            known = current

    def stop(self):
        self.running = False


# ═══════════════════════════════════════════════════════════════════════════
#  2. Network Monitor  (polls /proc/net/{tcp,udp,tcp6,udp6})
# ═══════════════════════════════════════════════════════════════════════════

class NetworkMonitor(threading.Thread):

    _PROTOS = ("tcp", "udp", "tcp6", "udp6")
    _SKIP_REMOTE = {"0.0.0.0", "127.0.0.1", "::1", "::"}

    def __init__(self, logger, cfg):
        super().__init__(daemon=True, name="NetworkMonitor")
        self.logger    = logger
        self.cfg       = cfg
        self.running   = True
        self._known    = set()
        self._interval = cfg["network_poll_sec"]

    def _parse(self, proto):
        path  = f"/proc/net/{proto}"
        conns = []
        try:
            with open(path) as fh:
                lines = fh.readlines()[1:]
        except FileNotFoundError:
            return conns

        v6      = proto.endswith("6")
        convert = _hex_to_ipv6 if v6 else _hex_to_ipv4

        for line in lines:
            p = line.split()
            if len(p) < 10:
                continue
            try:
                lip, lport = p[1].rsplit(":", 1)
                rip, rport = p[2].rsplit(":", 1)
                conns.append({
                    "proto":       proto.upper(),
                    "local_addr":  convert(lip),
                    "local_port":  int(lport, 16),
                    "remote_addr": convert(rip),
                    "remote_port": int(rport, 16),
                    "state":       TCP_STATES.get(p[3], p[3]) if "tcp" in proto else "STATELESS",
                    "uid":         int(p[7]),
                    "user":        _uid_to_user(int(p[7])),
                    "inode":       p[9],
                })
            except (ValueError, IndexError):
                continue
        return conns

    def _conn_key(self, c):
        return (c["proto"], c["local_addr"], c["local_port"],
                c["remote_addr"], c["remote_port"])

    def run(self):
        for proto in self._PROTOS:
            for c in self._parse(proto):
                self._known.add(self._conn_key(c))

        while self.running:
            time.sleep(self._interval)

            current_keys = set()
            by_key       = {}
            for proto in self._PROTOS:
                for c in self._parse(proto):
                    k = self._conn_key(c)
                    current_keys.add(k)
                    by_key[k] = c

            new_keys = current_keys - self._known
            if new_keys:
                inode_map = build_inode_to_pid_map()
                for k in new_keys:
                    c = by_key[k]
                    if c["remote_addr"] in self._SKIP_REMOTE and c["state"] != "ESTABLISHED":
                        continue

                    tags     = ["network"]
                    severity = "info"

                    if c["remote_port"] == 53:
                        tags.append("dns_query")
                    if c["remote_port"] in self.cfg["suspicious_ports"]:
                        tags.append("suspicious_port"); severity = "warning"
                    if c["state"] == "ESTABLISHED" and c["remote_port"] not in (80, 443, 53, 22):
                        tags.append("outbound")

                    pid = inode_map.get(c["inode"])
                    if pid:
                        c["process"] = get_process_info(pid)

                    self.logger.emit("network_connection", severity, c, tags)

            self._known = current_keys

    def stop(self):
        self.running = False


# ═══════════════════════════════════════════════════════════════════════════
#  3. File Monitor  (inotify via ctypes — real-time)
# ═══════════════════════════════════════════════════════════════════════════

class FileMonitor(threading.Thread):

    def __init__(self, logger, cfg):
        super().__init__(daemon=True, name="FileMonitor")
        self.logger  = logger
        self.cfg     = cfg
        self.running = True
        self._libc   = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self._wd_map = {}

    def run(self):
        fd = self._libc.inotify_init()
        if fd < 0:
            print("[!] inotify_init failed", file=sys.stderr)
            return

        mask = (IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB |
                IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO)

        for path in self.cfg["watch_files"] + self.cfg["watch_dirs"]:
            if os.path.exists(path):
                wd = self._libc.inotify_add_watch(fd, path.encode(), mask)
                if wd >= 0:
                    self._wd_map[wd] = path

        while self.running:
            try:
                rlist, _, _ = select.select([fd], [], [], 1.0)
            except (OSError, InterruptedError):
                continue
            if not rlist:
                continue
            try:
                buf = os.read(fd, 8192)
            except OSError:
                break
            self._process_buf(buf)

        os.close(fd)

    def _process_buf(self, buf):
        off = 0
        while off < len(buf):
            wd, emask, _, name_len = struct.unpack_from("iIII", buf, off)
            off += INOTIFY_EVENT_SIZE
            name = buf[off:off + name_len].rstrip(b"\x00") \
                                          .decode("utf-8", errors="replace")
            off += name_len

            watch_path = self._wd_map.get(wd, "?")
            full_path  = os.path.join(watch_path, name) if name else watch_path

            events   = [v for k, v in INOTIFY_MASK_NAMES.items() if emask & k]
            tags     = ["file_event"]
            severity = "info"

            if full_path in self.cfg["critical_files"]:
                severity = "high";  tags.append("critical_file")

            if watch_path in self.cfg["staging_dirs"]:
                tags.append("staging_area")
                if {"create", "close_write"} & set(events):
                    try:
                        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                            tags.append("executable_drop"); severity = "high"
                    except OSError:
                        pass

            if "cron" in watch_path:
                tags.append("cron_modification"); severity = "warning"

            self.logger.emit("file_event", severity, {
                "path": full_path, "watch_path": watch_path,
                "events": events, "is_dir": bool(emask & IN_ISDIR),
            }, tags)

    def stop(self):
        self.running = False


# ═══════════════════════════════════════════════════════════════════════════
#  4. Auditd Monitor  (tails /var/log/audit/audit.log, parses records)
# ═══════════════════════════════════════════════════════════════════════════

class AuditdMonitor(threading.Thread):
    """
    Tails the auditd log, groups multi-line records by msgid, parses fields,
    and emits one structured JSON event per audit record.

    Provides full syscall-level coverage when auditd is installed — the lightest
    way to get kernel-grade visibility (execve args, file paths, syscall args).
    """

    # field=value tokenizer:
    #   bareword:    key=value     (no spaces)
    #   quoted:      key="value"   (with spaces, escapes)
    #   hex-encoded: key=68657800  (for fields containing special chars)
    _FIELD_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
    _MSG_RE   = re.compile(r'msg=audit\(([\d.]+):(\d+)\)')

    def __init__(self, logger, cfg):
        super().__init__(daemon=True, name="AuditdMonitor")
        self.logger    = logger
        self.cfg       = cfg
        self.running   = True
        self._buffer   = defaultdict(list)
        self._buf_time = {}
        self._flush_delay = cfg["audit_flush_ms"] / 1000.0

    def run(self):
        if not self.cfg.get("audit_enabled", True):
            return

        if self.cfg.get("audit_install_rules"):
            self._install_rules()

        path = self.cfg["audit_log_path"]
        while self.running and not os.path.exists(path):
            print(f"[!] audit log not found at {path}; "
                  "is auditd installed and running?", file=sys.stderr)
            time.sleep(30)

        self._tail(path)

    # ── auto-install rules ─────────────────────────────────────────────
    def _install_rules(self):
        # Lazy-import heavy modules only on this one-shot path.
        import shutil
        import subprocess

        src = self.cfg["audit_rules_src"]
        dst = self.cfg["audit_rules_dst"]
        if not os.path.exists(src):
            print(f"[!] audit rules source missing: {src}", file=sys.stderr)
            return
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            print(f"[*] installed audit rules → {dst}")
        except OSError as exc:
            print(f"[!] failed to install audit rules: {exc}", file=sys.stderr)
            return

        last_err = None
        for cmd in (["augenrules", "--load"],
                    ["service", "auditd", "restart"]):
            try:
                subprocess.run(cmd, check=True, capture_output=True,
                               timeout=15)
                print(f"[*] {' '.join(cmd)} OK")
                return
            except (subprocess.CalledProcessError, FileNotFoundError,
                    subprocess.TimeoutExpired) as exc:
                last_err = exc
        print(f"[!] could not reload audit rules: {last_err}", file=sys.stderr)

    # ── tail with rotation handling ────────────────────────────────────
    def _tail(self, path):
        fh, inode = None, None
        try:
            fh = open(path, "r", errors="replace")
            fh.seek(0, os.SEEK_END)
            inode = os.fstat(fh.fileno()).st_ino
        except OSError as exc:
            print(f"[!] cannot open audit log: {exc}", file=sys.stderr)
            return

        while self.running:
            line = fh.readline()
            if line:
                self._on_line(line.rstrip("\n"))
                continue

            self._flush_old()

            try:
                cur_inode = os.stat(path).st_ino
                if cur_inode != inode:
                    fh.close()
                    fh = open(path, "r", errors="replace")
                    inode = cur_inode
                    print("[*] audit log rotated, reopened", file=sys.stderr)
                    continue
            except OSError:
                pass

            time.sleep(0.5)

        try:
            fh.close()
        except OSError:
            pass

    # ── per-line ingestion (buffers by msgid) ──────────────────────────
    def _on_line(self, line):
        if not line.startswith("type="):
            return
        msg_match = self._MSG_RE.search(line)
        if not msg_match:
            return

        ts_str, msgid = msg_match.group(1), msg_match.group(2)
        rec_type     = line.split(" ", 1)[0][5:]

        # Preserve quote info — needed to distinguish a literal "abcd"
        # from hex-encoded bytes 0xab,0xcd in EXECVE args.
        fields = {}
        for m in self._FIELD_RE.finditer(line):
            k = m.group(1)
            if m.group(2) is not None:
                fields[k] = ('q', m.group(2))   # quoted literal
            else:
                fields[k] = ('u', m.group(3))   # unquoted bareword

        self._buffer[msgid].append({"type": rec_type, **fields})
        self._buf_time[msgid] = (time.monotonic(), float(ts_str))

    @staticmethod
    def _v(field):
        """Unwrap (kind, value) tuple → bare string."""
        if isinstance(field, tuple):
            return field[1]
        return field

    @staticmethod
    def _vq(field):
        """Return (was_quoted, value) for fields that need it."""
        if isinstance(field, tuple):
            return field[0] == 'q', field[1]
        return False, field

    # ── flush records that have aged past the buffer window ───────────
    def _flush_old(self):
        now = time.monotonic()
        ready = [mid for mid, (t, _) in self._buf_time.items()
                 if now - t > self._flush_delay]
        for mid in ready:
            records   = self._buffer.pop(mid)
            audit_ts  = self._buf_time.pop(mid)[1]
            self._emit_record(mid, audit_ts, records)

    # ── merge a record group into a single event ──────────────────────
    def _emit_record(self, msgid, audit_ts, records):
        v = self._v
        merged = {"msgid": msgid, "audit_time": audit_ts,
                  "records": [r["type"] for r in records]}
        paths, execve_args = [], []

        for r in records:
            rtype = r.get("type", "")

            if rtype == "SYSCALL":
                for f in ("syscall", "success", "exit", "pid", "ppid",
                          "uid", "euid", "auid", "gid", "comm", "exe",
                          "tty", "key"):
                    if f in r:
                        merged[f] = v(r[f])
                if "uid" in r:
                    merged["user"] = _uid_to_user(v(r["uid"]))

            elif rtype == "EXECVE":
                args = []
                for k in sorted(r.keys()):
                    if not re.fullmatch(r"a\d+", k):
                        continue
                    quoted, val = self._vq(r[k])
                    if quoted:
                        args.append(val)
                    elif (re.fullmatch(r"[0-9A-Fa-f]+", val)
                          and len(val) % 2 == 0):
                        args.append(_maybe_hex_decode(val))
                    else:
                        args.append(val)
                if args:
                    execve_args = args
                    merged["cmdline"] = " ".join(args)

            elif rtype == "PATH":
                paths.append({
                    "name":     v(r.get("name", "")),
                    "nametype": v(r.get("nametype", "")),
                    "mode":     v(r.get("mode", "")),
                    "ouid":     v(r.get("ouid", "")),
                    "ogid":     v(r.get("ogid", "")),
                })

            elif rtype == "CWD":
                merged["cwd"] = v(r.get("cwd", ""))

            elif rtype == "PROCTITLE":
                _, pt = self._vq(r.get("proctitle", ('u', '')))
                if (re.fullmatch(r"[0-9A-Fa-f]+", pt)
                        and len(pt) % 2 == 0):
                    try:
                        merged["proctitle"] = bytes.fromhex(pt) \
                                              .replace(b"\x00", b" ") \
                                              .decode("utf-8", errors="replace") \
                                              .strip()
                    except ValueError:
                        merged["proctitle"] = pt
                else:
                    merged["proctitle"] = pt

            elif rtype in ("USER_CMD", "USER_AUTH", "USER_LOGIN",
                           "ADD_USER", "DEL_USER", "USER_CHAUTHTOK"):
                merged["user_event"] = rtype
                for f in ("acct", "addr", "hostname", "res", "msg"):
                    if f in r:
                        merged[f] = v(r[f])

        if paths:
            merged["paths"] = paths

        key = merged.get("key", "")
        severity, tags = AUDIT_KEY_MAP.get(key, ("info", ["audit"]))
        tags = list(tags)

        if any(r.get("type", "").startswith(("USER_", "ADD_USER",
                                              "DEL_USER")) for r in records):
            if "identity" not in tags:
                tags.append("identity")
            if severity == "info":
                severity = "warning"

        cwd = merged.get("cwd", "")
        if execve_args and any(cwd == d or cwd.startswith(d + "/")
                               for d in self.cfg["staging_dirs"]):
            tags.append("exec_from_staging")
            severity = "high"

        self.logger.emit("audit_event", severity, merged, tags)

    def stop(self):
        self.running = False


def _maybe_hex_decode(s):
    """Decode audit hex-encoded values (used for args with spaces)."""
    try:
        return bytes.fromhex(s).decode("utf-8", errors="replace")
    except ValueError:
        return s


# ═══════════════════════════════════════════════════════════════════════════
#  5. Process Accounting Monitor  (kernel BSD pacct — guaranteed capture)
# ═══════════════════════════════════════════════════════════════════════════

class ProcessAccountingMonitor(threading.Thread):
    """
    Enables the kernel's BSD process accounting via the acct() syscall and
    tails the resulting binary record file. Every process exit produces a
    64-byte acct_v3 record — guaranteed by the kernel, never dropped, no
    matter how short-lived the process.

    This closes the gap where netlink proc connector silently drops events
    under heavy load (it has bounded queues and overrun semantics).
    """

    def __init__(self, logger, cfg):
        super().__init__(daemon=True, name="ProcessAccountingMonitor")
        self.logger     = logger
        self.cfg        = cfg
        self.running    = True
        self._libc      = ctypes.CDLL(ctypes.util.find_library("c"),
                                       use_errno=True)
        self._path      = cfg["process_accounting_file"]
        self._max_bytes = cfg["process_accounting_max_bytes"]

    @staticmethod
    def _decode_comp_t(c):
        """Decode a 16-bit comp_t (3-bit exponent base-8, 13-bit mantissa)."""
        return (c & 0x1FFF) * (8 ** ((c >> 13) & 0x7))

    def _enable(self):
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        if not os.path.exists(self._path):
            open(self._path, "ab").close()
        os.chmod(self._path, 0o640)
        rc = self._libc.acct(self._path.encode())
        if rc < 0:
            errno = ctypes.get_errno()
            print(f"[!] acct({self._path}) failed: errno={errno} — is the "
                  "kernel configured with CONFIG_BSD_PROCESS_ACCT=y?",
                  file=sys.stderr)
            return False
        print(f"[*] BSD process accounting → {self._path}")
        return True

    def _disable(self):
        try:
            self._libc.acct(None)
        except OSError:
            pass

    def _rotate_if_needed(self):
        try:
            sz = os.path.getsize(self._path)
        except OSError:
            return False
        if sz < self._max_bytes:
            return False
        self._disable()
        try:
            os.replace(self._path, self._path + ".1")
            open(self._path, "ab").close()
            os.chmod(self._path, 0o640)
        except OSError as exc:
            print(f"[!] pacct rotate failed: {exc}", file=sys.stderr)
        self._enable()
        return True

    def run(self):
        if not self.cfg.get("process_accounting_enabled", True):
            return
        if not self._enable():
            return

        try:
            fh = open(self._path, "rb")
            fh.seek(0, os.SEEK_END)
        except OSError as exc:
            print(f"[!] open pacct failed: {exc}", file=sys.stderr)
            self._disable()
            return

        leftover = b""
        last_rotate_check = time.monotonic()
        try:
            while self.running:
                chunk = fh.read(ACCT_V3_RECORD_SIZE * 64)
                if chunk:
                    buf = leftover + chunk
                    n = len(buf) // ACCT_V3_RECORD_SIZE
                    for i in range(n):
                        off = i * ACCT_V3_RECORD_SIZE
                        self._on_record(buf[off:off + ACCT_V3_RECORD_SIZE])
                    leftover = buf[n * ACCT_V3_RECORD_SIZE:]
                    continue

                if time.monotonic() - last_rotate_check > 30:
                    if self._rotate_if_needed():
                        fh.close()
                        fh = open(self._path, "rb")
                        leftover = b""
                    last_rotate_check = time.monotonic()

                time.sleep(0.2)
        finally:
            try:
                fh.close()
            except OSError:
                pass
            self._disable()

    def _on_record(self, data):
        try:
            (ac_flag, ac_version, ac_tty, ac_exitcode, ac_uid, ac_gid,
             ac_pid, ac_ppid, ac_btime, ac_etime,
             ac_utime, ac_stime, ac_mem, ac_io, ac_rw,
             ac_minflt, ac_majflt, ac_swaps,
             ac_comm) = struct.unpack(ACCT_V3_FMT, data)
        except struct.error:
            return

        if ac_version != b"\x03":
            return

        comm = ac_comm.rstrip(b"\x00").decode("utf-8", errors="replace")
        if not comm:
            return

        flag_byte = ord(ac_flag)
        flags = []
        if flag_byte & ACCT_AFORK: flags.append("fork_no_exec")
        if flag_byte & ACCT_ASU:   flags.append("used_superuser")
        if flag_byte & ACCT_ACORE: flags.append("core_dumped")
        if flag_byte & ACCT_AXSIG: flags.append("killed_by_signal")

        details = {
            "pid":          ac_pid,
            "ppid":         ac_ppid,
            "uid":          ac_uid,
            "gid":          ac_gid,
            "user":         _uid_to_user(ac_uid),
            "comm":         comm,
            "exit_code":    ac_exitcode,
            "start_time":   ac_btime,
            "elapsed_sec":  round(ac_etime, 3),
            "user_jiffies": self._decode_comp_t(ac_utime),
            "sys_jiffies":  self._decode_comp_t(ac_stime),
            "mem_avg_kb":   self._decode_comp_t(ac_mem),
            "io_chars":     self._decode_comp_t(ac_io),
            "tty":          ac_tty,
        }
        if flags:
            details["flags"] = flags

        tags     = ["process_exit", "process_accounting"]
        severity = "info"

        # Short-lived process (the gap we're fixing — these get missed by
        # /proc polling and can drop from proc connector under load).
        if ac_etime < 1.0:
            tags.append("short_lived")
        if comm in self.cfg["suspicious_bins"]:
            tags.append("suspicious_binary"); severity = "warning"
        if comm in self.cfg["privesc_bins"]:
            tags.append("priv_esc")
        if comm in self.cfg["shell_bins"]:
            tags.append("shell_exec")
        if flag_byte & ACCT_ACORE:
            tags.append("crash"); severity = "warning"
        if flag_byte & ACCT_AXSIG:
            tags.append("killed");
            if severity == "info":
                severity = "warning"
        if flag_byte & ACCT_ASU and ac_uid != 0:
            tags.append("setuid_used"); severity = "warning"

        self.logger.emit("process_exit", severity, details, tags)

    def stop(self):
        self.running = False


# ═══════════════════════════════════════════════════════════════════════════
#  6. Threat Correlator  (reverse shell detection, malware heuristics)
# ═══════════════════════════════════════════════════════════════════════════

class ThreatCorrelator(threading.Thread):

    def __init__(self, logger, proc_mon_ref, cfg):
        super().__init__(daemon=True, name="ThreatCorrelator")
        self.logger        = logger
        self.proc_mon_ref  = proc_mon_ref   # callable returning current ProcessMonitor
        self.cfg           = cfg
        self.running       = True
        self._alerted      = set()

    def run(self):
        while self.running:
            time.sleep(self.cfg["correlator_poll_sec"])
            self._detect_reverse_shells()

    def _detect_reverse_shells(self):
        proc_mon = self.proc_mon_ref()
        if proc_mon is None:
            return
        for pid in list(proc_mon.active_shells):
            if pid in self._alerted:
                continue
            fd_dir = f"/proc/{pid}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        link = os.readlink(f"{fd_dir}/{fd}")
                    except OSError:
                        continue
                    if "socket:" not in link:
                        continue

                    details = get_process_info(pid)
                    details["socket_fd"]    = fd
                    details["socket_inode"] = link
                    self.logger.emit(
                        "reverse_shell_suspect", "critical", details,
                        ["reverse_shell", "threat"],
                    )
                    self._alerted.add(pid)
                    break
            except (FileNotFoundError, PermissionError):
                continue

    def stop(self):
        self.running = False


# ═══════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════

def _load_config():
    cfg = {}
    for k, v in DEFAULT_CONFIG.items():
        if isinstance(v, set):
            cfg[k] = set(v)
        elif isinstance(v, list):
            cfg[k] = list(v)
        else:
            cfg[k] = v

    if len(sys.argv) > 2 and sys.argv[1] == "--config":
        with open(sys.argv[2]) as fh:
            override = json.load(fh)
        for k, v in override.items():
            if k in cfg and isinstance(cfg[k], set):
                cfg[k] = set(v)
            else:
                cfg[k] = v
    return cfg


def _install_audit_rules_once(cfg):
    """Standalone invocation: just install rules and exit."""
    print("[*] Installing audit rules…")
    tmp_logger = EventLogger(cfg)
    mon = AuditdMonitor(tmp_logger, cfg)
    mon._install_rules()
    print("[*] Done. Verify with: auditctl -l")


def main():
    if os.geteuid() != 0:
        sys.exit("[!] Must run as root:  sudo python3 endpoint_monitor.py")

    cfg = _load_config()

    if "--install-audit-rules" in sys.argv:
        _install_audit_rules_once(cfg)
        return

    logger = EventLogger(cfg)

    print(f"[*] Endpoint Monitor starting — {socket.gethostname()}")
    print(f"[*] Log file: {cfg['log_file']}")

    logger.emit("monitor_start", "info", {
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "audit_enabled": cfg.get("audit_enabled", True),
        "pacct_enabled": cfg.get("process_accounting_enabled", True),
    }, ["system"])

    proc_mon  = ProcessMonitor(logger, cfg)
    net_mon   = NetworkMonitor(logger, cfg)
    file_mon  = FileMonitor(logger, cfg)
    audit_mon = AuditdMonitor(logger, cfg) if cfg.get("audit_enabled") else None
    pacct_mon = ProcessAccountingMonitor(logger, cfg) \
                if cfg.get("process_accounting_enabled") else None

    state = {"proc_mon": proc_mon}
    correlator = ThreatCorrelator(logger, lambda: state["proc_mon"], cfg)

    monitors = [proc_mon, net_mon, file_mon, correlator]
    if audit_mon is not None:
        monitors.insert(3, audit_mon)
    if pacct_mon is not None:
        monitors.append(pacct_mon)

    def _shutdown(signum, _frame):
        print("\n[*] Shutting down…")
        for m in monitors:
            m.stop()
        logger.emit("monitor_stop", "info",
                    {"reason": "signal", "signal": signum}, ["system"])
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    for m in monitors:
        m.start()
    print(f"[*] Active monitors: {', '.join(m.name for m in monitors)}")
    print("[*] Press Ctrl-C to stop\n")

    while True:
        time.sleep(5)
        for i, m in enumerate(monitors):
            if m.is_alive() or not m.running:
                continue
            print(f"[!] {m.name} died — restarting", file=sys.stderr)
            if isinstance(m, ThreatCorrelator):
                replacement = ThreatCorrelator(logger,
                                               lambda: state["proc_mon"], cfg)
            else:
                replacement = m.__class__(logger, cfg)
            replacement.start()
            monitors[i] = replacement
            if isinstance(replacement, ProcessMonitor):
                state["proc_mon"] = replacement


if __name__ == "__main__":
    main()
