import json
import os
import platform
import re
import shutil
import signal
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, UTC
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = BASE_DIR / "config.json"
LOG_PATH = DATA_DIR / "guard-events.jsonl"
ALERTS_PATH = DATA_DIR / "alerts.json"
EVENTS_PATH = DATA_DIR / "toast-events.jsonl"

DEFAULT_CONFIG = {
    "scan_interval_seconds": 20,
    "downloads_dir": str(Path.home() / "Downloads"),
    "suspicious_extensions": [".exe", ".scr", ".bat", ".cmd", ".ps1", ".jar", ".apk", ".msi", ".zip"],
    "suspicious_process_keywords": ["nc", "ncat", "netcat", "hydra", "john", "sqlmap", "msfconsole"],
    "suspicious_connection_ports": [23, 4444, 5555, 6667, 1337],
    "user_protection": {
        "download_guard": True,
        "process_guard": True,
        "connection_guard": True,
        "desktop_notifications": True,
        "max_toasts": 3,
        "toast_duration_ms": 5200,
        "group_toasts_window_seconds": 8
    },
    "clamav": {
        "enabled": True,
        "auto_update_signatures": False,
        "prefer_clamdscan": True,
        "auto_block_processes": True,
        "auto_block_connections": True,
        "scan_process_executables": True,
        "process_scan_cooldown_seconds": 900,
        "fallback_to_clamscan": True
    }
}


class LocalProtectionAgent:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._ensure_files()
        self.config = self._load_config()
        self.status = "IDLE"
        self.thread = None
        self.scan_thread = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.scan_lock = threading.Lock()
        self.scan_running = False
        self.pending_scan = False
        self.alerts = deque(maxlen=200)
        self.seen_files = set()
        self.seen_alert_keys = set()
        self.seen_pids = set()
        self.toast_memory = {}
        self.last_scan = "--:--"
        self.stats = {
            "alerts_total": 0,
            "downloads_checked": 0,
            "suspicious_files": 0,
            "process_hits": 0,
            "network_hits": 0,
            "signature_hits": 0,
            "blocks_total": 0,
        }
        self._load_alerts()
        self._seed_logs()
        self.clamd_available = self._detect_clamd_socket()
        self.clamav_ready = self._clam_tools_ready()
        self.last_clamd_error_ts = 0.0
        self.process_scan_blocked_until = 0.0
        self.last_process_scan_notice_ts = 0.0
        if self.config.get("clamav", {}).get("auto_update_signatures", False):
            self.update_signatures()

    def _ensure_files(self):
        if not CONFIG_PATH.exists():
            CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2), encoding="utf-8")
        if not LOG_PATH.exists():
            LOG_PATH.write_text("", encoding="utf-8")
        if not ALERTS_PATH.exists():
            ALERTS_PATH.write_text("[]", encoding="utf-8")
        if not EVENTS_PATH.exists():
            EVENTS_PATH.write_text("", encoding="utf-8")

    def _load_config(self):
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        merged = json.loads(json.dumps(DEFAULT_CONFIG))
        for key, value in raw.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key].update(value)
            else:
                merged[key] = value
        return merged

    def save_config(self, config):
        with self.lock:
            self.config = config
            CONFIG_PATH.write_text(json.dumps(self.config, ensure_ascii=False, indent=2), encoding="utf-8")
        self.clamd_available = self._detect_clamd_socket()
        self.clamav_ready = self._clam_tools_ready()
        self.log("CFG", "Configuration saved from settings panel.", "ok")

    def _seed_logs(self):
        if LOG_PATH.stat().st_size == 0:
            self.log("UI", "Musg Guard initialized.", "accent")
            self.log("CFG", "Download guard, process guard and connection guard are available.", "ok")
            self.log("AV", "ClamAV integration can scan files and use fallback from clamdscan to clamscan.", "ok")

    def _load_alerts(self):
        try:
            data = json.loads(ALERTS_PATH.read_text(encoding="utf-8"))
            for item in data[-100:]:
                self.alerts.append(item)
                key = f"{item.get('title')}|{item.get('details')}"
                self.seen_alert_keys.add(key)
            self.stats["alerts_total"] = len(self.alerts)
        except Exception:
            self.alerts.clear()

    def _save_alerts(self):
        ALERTS_PATH.write_text(json.dumps(list(self.alerts), ensure_ascii=False, indent=2), encoding="utf-8")

    def _now_iso(self):
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")

    def _now_hm(self):
        return datetime.now().strftime("%H:%M")

    def log(self, tag, message, level="ok"):
        row = {"ts": self._now_iso(), "tag": tag, "level": level, "message": message}
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _toast_window_seconds(self):
        return int(self.config.get("user_protection", {}).get("group_toasts_window_seconds", 8))

    def _max_toasts(self):
        return int(self.config.get("user_protection", {}).get("max_toasts", 3))

    def _toast_duration_ms(self):
        return int(self.config.get("user_protection", {}).get("toast_duration_ms", 5200))

    def enqueue_toast(self, title, message, severity="warn", group_key=None):
        if not self.config.get("user_protection", {}).get("desktop_notifications", True):
            return
        now = time.time()
        if group_key:
            prev = self.toast_memory.get(group_key)
            window = self._toast_window_seconds()
            if prev and now - prev["ts"] <= window:
                count = prev["count"] + 1
                event = {
                    "ts": self._now_iso(),
                    "title": title,
                    "message": f"{message} (x{count})",
                    "severity": severity,
                    "group_key": group_key,
                    "replace": True,
                    "count": count,
                    "duration_ms": self._toast_duration_ms(),
                    "max_toasts": self._max_toasts(),
                }
                self.toast_memory[group_key] = {"ts": now, "count": count}
            else:
                event = {
                    "ts": self._now_iso(),
                    "title": title,
                    "message": message,
                    "severity": severity,
                    "group_key": group_key,
                    "replace": False,
                    "count": 1,
                    "duration_ms": self._toast_duration_ms(),
                    "max_toasts": self._max_toasts(),
                }
                self.toast_memory[group_key] = {"ts": now, "count": 1}
        else:
            event = {
                "ts": self._now_iso(),
                "title": title,
                "message": message,
                "severity": severity,
                "group_key": None,
                "replace": False,
                "count": 1,
                "duration_ms": self._toast_duration_ms(),
                "max_toasts": self._max_toasts(),
            }
        with EVENTS_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    def add_alert(self, title, details, severity="warn", toast=True, group_key=None):
        key = f"{title}|{details}"
        if key not in self.seen_alert_keys:
            self.seen_alert_keys.add(key)
            item = {"ts": self._now_iso(), "title": title, "details": details, "severity": severity}
            self.alerts.appendleft(item)
            self.stats["alerts_total"] += 1
            self._save_alerts()
            self.log("ALERT", f"{title}: {details}", severity)
        if toast:
            self.enqueue_toast(title, details, severity, group_key=group_key)

    def _clam_cfg(self):
        return self.config.get("clamav", {})

    def _detect_clamd_socket(self):
        for path in ("/var/run/clamav/clamd.ctl", "/run/clamav/clamd.ctl"):
            if Path(path).exists():
                return True
        return False

    def _clam_tools_ready(self):
        clam_cfg = self._clam_cfg()
        if not clam_cfg.get("enabled", True):
            return False
        if clam_cfg.get("prefer_clamdscan", True) and self.clamd_available and shutil.which("clamdscan"):
            return True
        if shutil.which("clamscan"):
            return True
        if shutil.which("clamdscan") and self.clamd_available:
            return True
        return False

    def _log_clamd_once(self, message):
        now = time.time()
        if now - self.last_clamd_error_ts >= 120:
            self.last_clamd_error_ts = now
            self.log("AV", message, "warn")
            self.enqueue_toast("ClamAV", message, "warn", group_key="clamd-offline")

    def _choose_scanner(self):
        clam_cfg = self._clam_cfg()
        prefer_clamd = clam_cfg.get("prefer_clamdscan", True)
        fallback = clam_cfg.get("fallback_to_clamscan", True)
        self.clamd_available = self._detect_clamd_socket()
        if prefer_clamd and shutil.which("clamdscan") and self.clamd_available:
            return "clamdscan"
        if prefer_clamd and shutil.which("clamdscan") and not self.clamd_available:
            self._log_clamd_once("clamd jest offline; przełączono skanowanie na clamscan.")
            if fallback and shutil.which("clamscan"):
                return "clamscan"
            return None
        if shutil.which("clamscan"):
            return "clamscan"
        if shutil.which("clamdscan") and self.clamd_available:
            return "clamdscan"
        return None

    def update_signatures(self):
        if shutil.which("freshclam") is None:
            self.log("AV", "freshclam not found.", "warn")
            return False
        try:
            proc = subprocess.run(["freshclam"], capture_output=True, text=True, timeout=600)
            if proc.returncode == 0:
                self.log("AV", "ClamAV signatures updated successfully.", "ok")
                self.enqueue_toast("Musg Guard", "Sygnatury ClamAV zostały zaktualizowane.", "ok", group_key="clamav-update")
                self.clamd_available = self._detect_clamd_socket()
                self.clamav_ready = self._clam_tools_ready()
                return True
            self.log("AV", (proc.stderr or proc.stdout or "freshclam failed").strip(), "warn")
            return False
        except Exception as exc:
            self.log("AV", f"Signature update failed: {exc}", "warn")
            return False

    def _parse_clam_signature(self, raw: str, file_path: Path):
        for line in raw.splitlines():
            if "FOUND" in line:
                cleaned = line.replace(str(file_path), "", 1).strip()
                cleaned = cleaned.lstrip(":").strip().replace("FOUND", "").strip()
                return cleaned or "ClamAV signature match"
        return "ClamAV signature match"

    def _scan_path_with_clamav(self, file_path: Path):
        if not file_path.exists() or not file_path.is_file():
            return None, None
        scanner = self._choose_scanner()
        self.clamav_ready = scanner is not None
        if scanner is None:
            return None, None
        cmd = ["clamdscan", "--fdpass", "--no-summary", str(file_path)] if scanner == "clamdscan" else ["clamscan", "--no-summary", str(file_path)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            raw = (proc.stdout or proc.stderr or "").strip()
            if proc.returncode == 1:
                signature = self._parse_clam_signature(raw, file_path)
                return True, signature
            if proc.returncode == 0:
                return False, None
            if scanner == "clamdscan" and "Could not connect to clamd" in raw:
                self.clamd_available = False
                self._log_clamd_once("clamd przestał odpowiadać; używam clamscan zamiast clamdscan.")
                if self._clam_cfg().get("fallback_to_clamscan", True) and shutil.which("clamscan"):
                    return self._scan_path_with_clamav(file_path)
                return None, None
            self.log("AV", f"ClamAV scan error for {file_path.name}: {raw[:220]}", "warn")
            return None, None
        except Exception as exc:
            self.log("AV", f"ClamAV scan failed for {file_path.name}: {exc}", "warn")
            return None, None

    def _resolve_process_exe(self, pid: int):
        exe_link = Path(f"/proc/{pid}/exe")
        try:
            return exe_link.resolve(strict=True)
        except Exception:
            return None

    def _kill_pid(self, pid: int, reason: str, source: str):
        try:
            os.kill(pid, signal.SIGTERM)
            self.stats["blocks_total"] += 1
            title = "Zablokowano proces" if source == "process" else "Zablokowano połączenie"
            details = f"PID {pid} | {reason}"
            group = "blocked-process" if source == "process" else "blocked-connection"
            self.add_alert(title, details, "drop", toast=True, group_key=group)
            self.log("BLOCK", f"PID {pid} terminated: {reason}", "drop")
            return True
        except ProcessLookupError:
            self.log("BLOCK", f"PID {pid} already exited.", "warn")
            return False
        except PermissionError:
            self.log("BLOCK", f"No permission to terminate PID {pid}.", "warn")
            return False
        except Exception as exc:
            self.log("BLOCK", f"Failed to terminate PID {pid}: {exc}", "warn")
            return False

    def _launch_scan(self, reason="scheduled"):
        with self.scan_lock:
            if self.scan_running:
                self.pending_scan = True
                return False
            self.scan_running = True
            self.pending_scan = False
            self.scan_thread = threading.Thread(target=self._scan_worker, args=(reason,), daemon=True)
            self.scan_thread.start()
            return True

    def _scan_worker(self, reason):
        try:
            self.log("SCAN", f"Background scan started ({reason}).", "accent")
            self._scan_all()
        finally:
            rerun = False
            with self.scan_lock:
                self.scan_running = False
                rerun = self.pending_scan and not self.stop_event.is_set() and self.status == "ACTIVE"
                self.pending_scan = False
            if rerun:
                self._launch_scan("queued")

    def start(self):
        if self.thread and self.thread.is_alive():
            self.status = "ACTIVE"
            return
        self.stop_event.clear()
        self.status = "ACTIVE"
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.log("BOOT", "Local protection agent started.", "ok")
        self.enqueue_toast("Musg Guard", "Ochrona została aktywowana.", "ok", group_key="guard-start")
        self._launch_scan("startup")

    def stop(self):
        self.stop_event.set()
        self.status = "IDLE"
        self.log("STOP", "Local protection agent stopped.", "warn")
        self.enqueue_toast("Musg Guard", "Ochrona została zatrzymana.", "warn", group_key="guard-stop")

    def _loop(self):
        while not self.stop_event.is_set():
            interval = int(self.config.get("scan_interval_seconds", 20))
            self.stop_event.wait(max(5, interval))
            if self.stop_event.is_set() or self.status != "ACTIVE":
                break
            self._launch_scan("interval")

    def manual_scan(self):
        self._launch_scan("manual")

    def _scan_all(self):
        self.last_scan = self._now_hm()
        guards = self.config.get("user_protection", {})
        if guards.get("download_guard", True):
            self._scan_downloads()
        if guards.get("process_guard", True):
            self._scan_processes()
        if guards.get("connection_guard", True):
            self._scan_connections()
        self.log("STAT", f"Scan completed at {self.last_scan}.", "ok")

    def _scan_downloads(self):
        downloads = Path(self.config.get("downloads_dir", str(Path.home() / "Downloads")))
        exts = {x.lower() for x in self.config.get("suspicious_extensions", [])}
        if not downloads.exists():
            self.log("DL", f"Downloads directory not found: {downloads}", "warn")
            return
        for file in downloads.iterdir():
            if not file.is_file():
                continue
            self.stats["downloads_checked"] += 1
            suffix = file.suffix.lower()
            key = str(file.resolve())
            if suffix in exts and key not in self.seen_files:
                self.seen_files.add(key)
                self.stats["suspicious_files"] += 1
                infected, signature = self._scan_path_with_clamav(file)
                if infected:
                    self.stats["signature_hits"] += 1
                    self.add_alert("Wykryto plik z sygnaturą", f"{file.name} | sygnatura: {signature}", "drop", toast=True, group_key="signature-file")
                else:
                    self.add_alert("Podejrzany plik w Downloads", f"{file.name} ma rozszerzenie {suffix}", "warn", toast=True, group_key="downloads-warning")

    def _process_scanning_enabled(self):
        return self._clam_cfg().get("scan_process_executables", True)

    def _process_scan_blocked(self):
        return time.time() < self.process_scan_blocked_until

    def _block_process_scanning_temporarily(self):
        cool = int(self._clam_cfg().get("process_scan_cooldown_seconds", 900))
        self.process_scan_blocked_until = time.time() + max(60, cool)
        now = time.time()
        if now - self.last_process_scan_notice_ts >= 120:
            self.last_process_scan_notice_ts = now
            self.log("AV", "Skanowanie plików procesów zostało chwilowo wyłączone; ClamAV daemon jest offline.", "warn")
            self.enqueue_toast("ClamAV", "Skan procesów chwilowo wyłączony; daemon offline.", "warn", group_key="process-scan-paused")

    def _scan_processes(self):
        keywords = [k.lower() for k in self.config.get("suspicious_process_keywords", [])]
        clam_cfg = self._clam_cfg()
        try:
            output = subprocess.check_output(["ps", "-eo", "pid=,comm=,args="], text=True, stderr=subprocess.DEVNULL)
        except Exception as exc:
            self.log("PROC", f"Process scan failed: {exc}", "warn")
            return
        do_exe_scan = self._process_scanning_enabled() and not self._process_scan_blocked()
        if do_exe_scan and clam_cfg.get("prefer_clamdscan", True) and not self._detect_clamd_socket() and not shutil.which("clamscan"):
            self._block_process_scanning_temporarily()
            do_exe_scan = False
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            low = line.lower()
            keyword_hit = any(key and key in low for key in keywords)
            infected = False
            signature = None
            if do_exe_scan:
                exe_path = self._resolve_process_exe(pid)
                if exe_path:
                    infected_raw, signature = self._scan_path_with_clamav(exe_path)
                    infected = infected_raw is True
                    if infected_raw is None and self._clam_cfg().get("prefer_clamdscan", True) and not self.clamd_available and not shutil.which("clamscan"):
                        self._block_process_scanning_temporarily()
                        do_exe_scan = False
            if keyword_hit or infected:
                self.stats["process_hits"] += 1
                details = f"PID {pid} | {line}"
                if signature:
                    details += f" | sygnatura: {signature}"
                if infected:
                    self.stats["signature_hits"] += 1
                if infected and clam_cfg.get("auto_block_processes", True) and pid not in self.seen_pids:
                    self.seen_pids.add(pid)
                    self._kill_pid(pid, signature or "ClamAV signature", "process")
                else:
                    severity = "drop" if infected else "warn"
                    group = "process-signature" if infected else "process-warning"
                    self.add_alert("Podejrzany proces", details, severity, toast=True, group_key=group)

    def _extract_pid_from_ss(self, line: str):
        match = re.search(r"pid=(\d+)", line)
        if match:
            return int(match.group(1))
        return None

    def _scan_connections(self):
        ports = {str(p) for p in self.config.get("suspicious_connection_ports", [])}
        clam_cfg = self._clam_cfg()
        cmd = ["ss", "-tunp"] if platform.system().lower() == "linux" else ["netstat", "-an"]
        try:
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        except Exception as exc:
            self.log("NET", f"Connection scan failed: {exc}", "warn")
            return
        for line in output.splitlines():
            if not any(f":{p}" in line for p in ports):
                continue
            self.stats["network_hits"] += 1
            pid = self._extract_pid_from_ss(line)
            if pid and clam_cfg.get("auto_block_connections", True) and pid not in self.seen_pids:
                self.seen_pids.add(pid)
                self._kill_pid(pid, f"suspicious connection | {line.strip()}", "connection")
            else:
                self.add_alert("Podejrzane połączenie", line.strip(), "drop", toast=True, group_key="network-warning")

    def pop_toast_events(self):
        with self.lock:
            if not EVENTS_PATH.exists():
                return []
            lines = EVENTS_PATH.read_text(encoding="utf-8").splitlines()
            EVENTS_PATH.write_text("", encoding="utf-8")
        events = []
        for line in lines:
            try:
                events.append(json.loads(line))
            except Exception:
                continue
        return events

    def get_state(self):
        scanner = self._choose_scanner()
        self.clamav_ready = scanner is not None
        return {
            "status": self.status,
            "last_scan": self.last_scan,
            "alerts_total": self.stats["alerts_total"],
            "downloads_checked": self.stats["downloads_checked"],
            "suspicious_files": self.stats["suspicious_files"],
            "process_hits": self.stats["process_hits"],
            "network_hits": self.stats["network_hits"],
            "signature_hits": self.stats["signature_hits"],
            "blocks_total": self.stats["blocks_total"],
            "clamav_ready": self.clamav_ready,
            "clamav_mode": scanner or "OFFLINE",
            "scan_running": self.scan_running,
        }

    def read_logs(self, limit=300):
        rows = []
        for line in LOG_PATH.read_text(encoding="utf-8").splitlines()[-limit:]:
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
        return rows

    def get_alerts(self):
        return list(self.alerts)
