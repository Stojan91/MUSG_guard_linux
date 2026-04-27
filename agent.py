import json
import platform
import subprocess
import threading
from collections import deque
from datetime import datetime, UTC
from pathlib import Path

from ml_model import ONNXThreatScorer

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
CONFIG_PATH = BASE_DIR / "config.json"
LOG_PATH = DATA_DIR / "guard-events.jsonl"
ALERTS_PATH = DATA_DIR / "alerts.json"

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
        "clipboard_secret_warning": True
    },
    "ml_enabled": True,
    "ml_model_dir": "models/gte-small-onnx",
    "ml_similarity_threshold": 0.62,
    "threat_patterns": [
        "reverse shell payload",
        "encoded powershell downloader",
        "credential dumping activity",
        "bruteforce login attempt with hydra",
        "suspicious remote access beacon",
        "mass scanning of many open ports",
        "malicious executable dropped in downloads",
        "network tunnel or exfiltration channel",
        "sql injection automation with sqlmap",
        "netcat listener waiting for shell"
    ]
}


class LocalProtectionAgent:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        MODELS_DIR.mkdir(parents=True, exist_ok=True)

        self._ensure_files()
        self.config = self._load_config()

        self.status = "IDLE"
        self.thread = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.alerts = deque(maxlen=200)
        self.seen_files = set()
        self.seen_alert_keys = set()
        self.last_scan = "--:--"

        self.stats = {
            "alerts_total": 0,
            "downloads_checked": 0,
            "suspicious_files": 0,
            "process_hits": 0,
            "network_hits": 0,
        }

        self.ml_scorer = None
        self.model_ready = False
        self.model_name = "none"
        self.last_ml_score = None
        self.last_ml_pattern = None

        self._load_alerts()
        self._seed_logs()
        self.reload_ml()

    def _ensure_files(self):
        if not CONFIG_PATH.exists():
            CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2), encoding="utf-8")
        if not LOG_PATH.exists():
            LOG_PATH.write_text("", encoding="utf-8")
        if not ALERTS_PATH.exists():
            ALERTS_PATH.write_text("[]", encoding="utf-8")

    def _load_config(self):
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    def save_config(self, config):
        with self.lock:
            self.config = config
            CONFIG_PATH.write_text(json.dumps(self.config, ensure_ascii=False, indent=2), encoding="utf-8")
        self.log("CFG", "Configuration saved from settings panel.", "ok")
        self.reload_ml()

    def _seed_logs(self):
        if LOG_PATH.stat().st_size == 0:
            self.log("UI", "Musg Guard local project initialized.", "accent")
            self.log("CFG", "Download guard, process guard and connection guard are available.", "ok")
            self.log("SYS", "Use Run to start periodic local protection scans.", "ok")

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

    def add_alert(self, title, details, severity="warn"):
        key = f"{title}|{details}"
        if key in self.seen_alert_keys:
            return
        self.seen_alert_keys.add(key)
        item = {"ts": self._now_iso(), "title": title, "details": details, "severity": severity}
        self.alerts.appendleft(item)
        self.stats["alerts_total"] += 1
        self._save_alerts()
        self.log("ALERT", f"{title}: {details}", severity)

    def reload_ml(self):
        self.ml_scorer = None
        self.model_ready = False
        self.model_name = "none"
        self.last_ml_score = None
        self.last_ml_pattern = None

        if not self.config.get("ml_enabled", False):
            self.log("ML", "ML layer disabled in configuration.", "warn")
            return

        model_dir = self.config.get("ml_model_dir", "models/gte-small-onnx")
        abs_model_dir = BASE_DIR / model_dir

        try:
            self.ml_scorer = ONNXThreatScorer(abs_model_dir)
            self.model_ready = self.ml_scorer.ready
            self.model_name = self.ml_scorer.model_name
            if self.model_ready:
                self.log("ML", f"Loaded ONNX model from {abs_model_dir}", "ok")
            else:
                self.log("ML", f"Model directory found but ONNX runtime is not ready: {abs_model_dir}", "warn")
        except Exception as exc:
            self.model_ready = False
            self.model_name = "load-error"
            self.log("ML", f"Model load failed: {exc}", "warn")

    def start(self):
        if self.thread and self.thread.is_alive():
            self.status = "ACTIVE"
            return

        self.stop_event.clear()
        self.status = "ACTIVE"
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.log("BOOT", "Local protection agent started.", "ok")
        self.manual_scan()

    def stop(self):
        self.stop_event.set()
        self.status = "IDLE"
        self.log("STOP", "Local protection agent stopped.", "warn")

    def _loop(self):
        while not self.stop_event.is_set():
            self._scan_all()
            interval = int(self.config.get("scan_interval_seconds", 20))
            self.stop_event.wait(max(5, interval))

    def manual_scan(self):
        self.log("SCAN", "Manual scan requested from GUI.", "accent")
        self._scan_all()

    def _score_text(self, text: str):
        self.last_ml_score = None
        self.last_ml_pattern = None

        if not self.config.get("ml_enabled", False):
            return None, None

        if not self.ml_scorer or not self.model_ready:
            return None, None

        patterns = self.config.get("threat_patterns", [])
        if not patterns:
            return None, None

        try:
            score, pattern = self.ml_scorer.score_text(text, patterns)
            self.last_ml_score = score
            self.last_ml_pattern = pattern
            self.log("ML", f"score={score:.3f} pattern={pattern or '-'} text={text[:160]}", "ok")
            return score, pattern
        except Exception as exc:
            self.log("ML", f"Scoring failed: {exc}", "warn")
            return None, None

    def _threshold(self):
        return float(self.config.get("ml_similarity_threshold", 0.62))

    def _scan_all(self):
        self.last_scan = self._now_hm()
        guards = self.config.get("user_protection", {})

        if guards.get("download_guard", True):
            self._scan_downloads()

        if guards.get("process_guard", True):
            self._scan_processes()

        if guards.get("connection_guard", True):
            self._scan_connections()

        if guards.get("clipboard_secret_warning", True):
            self.log("USER", "Clipboard safety reminder is enabled for this session.", "ok")

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

                text = f"downloaded file named {file.name} with extension {suffix}"
                score, pattern = self._score_text(text)

                details = f"{file.name} ma rozszerzenie {suffix}"
                if score is not None:
                    details += f" | ml_score={score:.3f}"
                if pattern:
                    details += f" | pattern={pattern}"

                severity = "warn"
                if score is not None and score >= self._threshold():
                    severity = "drop"

                self.add_alert("Podejrzany plik w Downloads", details, severity)

    def _scan_processes(self):
        keywords = [k.lower() for k in self.config.get("suspicious_process_keywords", [])]

        try:
            output = subprocess.check_output(
                ["ps", "-eo", "pid,comm,args"],
                text=True,
                stderr=subprocess.DEVNULL
            )
        except Exception as exc:
            self.log("PROC", f"Process scan failed: {exc}", "warn")
            return

        for line in output.splitlines()[1:]:
            low = line.lower()
            for key in keywords:
                if key and key in low:
                    self.stats["process_hits"] += 1

                    score, pattern = self._score_text(line.strip())
                    details = line.strip()

                    if score is not None:
                        details += f" | ml_score={score:.3f}"
                    if pattern:
                        details += f" | pattern={pattern}"

                    severity = "warn"
                    if score is not None and score >= self._threshold():
                        severity = "drop"

                    self.add_alert("Podejrzany proces", details, severity)
                    break

    def _scan_connections(self):
        ports = {str(p) for p in self.config.get("suspicious_connection_ports", [])}
        cmd = ["ss", "-tunp"] if platform.system().lower() == "linux" else ["netstat", "-an"]

        try:
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        except Exception as exc:
            self.log("NET", f"Connection scan failed: {exc}", "warn")
            return

        for line in output.splitlines():
            matched_port = next((p for p in ports if f":{p}" in line), None)
            if matched_port:
                self.stats["network_hits"] += 1

                score, pattern = self._score_text(f"network connection on port {matched_port}: {line.strip()}")
                details = line.strip()

                if score is not None:
                    details += f" | ml_score={score:.3f}"
                if pattern:
                    details += f" | pattern={pattern}"

                severity = "warn"
                if score is not None and score >= self._threshold():
                    severity = "drop"

                self.add_alert("Podejrzane połączenie", details, severity)

    def get_state(self):
        return {
            "status": self.status,
            "last_scan": self.last_scan,
            "alerts_total": self.stats["alerts_total"],
            "downloads_checked": self.stats["downloads_checked"],
            "suspicious_files": self.stats["suspicious_files"],
            "process_hits": self.stats["process_hits"],
            "network_hits": self.stats["network_hits"],
            "model_ready": self.model_ready,
            "model_name": self.model_name,
            "last_ml_score": self.last_ml_score,
            "last_ml_pattern": self.last_ml_pattern,
            "ml_threshold": self._threshold(),
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
import platform
import subprocess
import threading
from collections import deque
from datetime import datetime, UTC
from pathlib import Path

from ml_model import ONNXThreatScorer

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
CONFIG_PATH = BASE_DIR / "config.json"
LOG_PATH = DATA_DIR / "guard-events.jsonl"
ALERTS_PATH = DATA_DIR / "alerts.json"

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
        "clipboard_secret_warning": True
    },
    "ml_enabled": True,
    "ml_model_dir": "models/gte-small-onnx",
    "ml_similarity_threshold": 0.62,
    "threat_patterns": [
        "reverse shell payload",
        "encoded powershell downloader",
        "credential dumping activity",
        "bruteforce login attempt with hydra",
        "suspicious remote access beacon",
        "mass scanning of many open ports",
        "malicious executable dropped in downloads",
        "network tunnel or exfiltration channel",
        "sql injection automation with sqlmap",
        "netcat listener waiting for shell"
    ]
}


class LocalProtectionAgent:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        MODELS_DIR.mkdir(parents=True, exist_ok=True)

        self._ensure_files()
        self.config = self._load_config()

        self.status = "IDLE"
        self.thread = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.alerts = deque(maxlen=200)
        self.seen_files = set()
        self.seen_alert_keys = set()
        self.last_scan = "--:--"

        self.stats = {
            "alerts_total": 0,
            "downloads_checked": 0,
            "suspicious_files": 0,
            "process_hits": 0,
            "network_hits": 0,
        }

        self.ml_scorer = None
        self.model_ready = False
        self.model_name = "none"
        self.last_ml_score = None
        self.last_ml_pattern = None

        self._load_alerts()
        self._seed_logs()
        self.reload_ml()

    def _ensure_files(self):
        if not CONFIG_PATH.exists():
            CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2), encoding="utf-8")
        if not LOG_PATH.exists():
            LOG_PATH.write_text("", encoding="utf-8")
        if not ALERTS_PATH.exists():
            ALERTS_PATH.write_text("[]", encoding="utf-8")

    def _load_config(self):
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    def save_config(self, config):
        with self.lock:
            self.config = config
            CONFIG_PATH.write_text(json.dumps(self.config, ensure_ascii=False, indent=2), encoding="utf-8")
        self.log("CFG", "Configuration saved from settings panel.", "ok")
        self.reload_ml()

    def _seed_logs(self):
        if LOG_PATH.stat().st_size == 0:
            self.log("UI", "Musg Guard local project initialized.", "accent")
            self.log("CFG", "Download guard, process guard and connection guard are available.", "ok")
            self.log("SYS", "Use Run to start periodic local protection scans.", "ok")

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

    def add_alert(self, title, details, severity="warn"):
        key = f"{title}|{details}"
        if key in self.seen_alert_keys:
            return
        self.seen_alert_keys.add(key)
        item = {"ts": self._now_iso(), "title": title, "details": details, "severity": severity}
        self.alerts.appendleft(item)
        self.stats["alerts_total"] += 1
        self._save_alerts()
        self.log("ALERT", f"{title}: {details}", severity)

    def reload_ml(self):
        self.ml_scorer = None
        self.model_ready = False
        self.model_name = "none"
        self.last_ml_score = None
        self.last_ml_pattern = None

        if not self.config.get("ml_enabled", False):
            self.log("ML", "ML layer disabled in configuration.", "warn")
            return

        model_dir = self.config.get("ml_model_dir", "models/gte-small-onnx")
        abs_model_dir = BASE_DIR / model_dir

        try:
            self.ml_scorer = ONNXThreatScorer(abs_model_dir)
            self.model_ready = self.ml_scorer.ready
            self.model_name = self.ml_scorer.model_name
            if self.model_ready:
                self.log("ML", f"Loaded ONNX model from {abs_model_dir}", "ok")
            else:
                self.log("ML", f"Model directory found but ONNX runtime is not ready: {abs_model_dir}", "warn")
        except Exception as exc:
            self.model_ready = False
            self.model_name = "load-error"
            self.log("ML", f"Model load failed: {exc}", "warn")

    def start(self):
        if self.thread and self.thread.is_alive():
            self.status = "ACTIVE"
            return

        self.stop_event.clear()
        self.status = "ACTIVE"
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.log("BOOT", "Local protection agent started.", "ok")
        self.manual_scan()

    def stop(self):
        self.stop_event.set()
        self.status = "IDLE"
        self.log("STOP", "Local protection agent stopped.", "warn")

    def _loop(self):
        while not self.stop_event.is_set():
            self._scan_all()
            interval = int(self.config.get("scan_interval_seconds", 20))
            self.stop_event.wait(max(5, interval))

    def manual_scan(self):
        self.log("SCAN", "Manual scan requested from GUI.", "accent")
        self._scan_all()

    def _score_text(self, text: str):
        self.last_ml_score = None
        self.last_ml_pattern = None

        if not self.config.get("ml_enabled", False):
            return None, None

        if not self.ml_scorer or not self.model_ready:
            return None, None

        patterns = self.config.get("threat_patterns", [])
        if not patterns:
            return None, None

        try:
            score, pattern = self.ml_scorer.score_text(text, patterns)
            self.last_ml_score = score
            self.last_ml_pattern = pattern
            self.log("ML", f"score={score:.3f} pattern={pattern or '-'} text={text[:160]}", "ok")
            return score, pattern
        except Exception as exc:
            self.log("ML", f"Scoring failed: {exc}", "warn")
            return None, None

    def _threshold(self):
        return float(self.config.get("ml_similarity_threshold", 0.62))

    def _scan_all(self):
        self.last_scan = self._now_hm()
        guards = self.config.get("user_protection", {})

        if guards.get("download_guard", True):
            self._scan_downloads()

        if guards.get("process_guard", True):
            self._scan_processes()

        if guards.get("connection_guard", True):
            self._scan_connections()

        if guards.get("clipboard_secret_warning", True):
            self.log("USER", "Clipboard safety reminder is enabled for this session.", "ok")

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

                text = f"downloaded file named {file.name} with extension {suffix}"
                score, pattern = self._score_text(text)

                details = f"{file.name} ma rozszerzenie {suffix}"
                if score is not None:
                    details += f" | ml_score={score:.3f}"
                if pattern:
                    details += f" | pattern={pattern}"

                severity = "warn"
                if score is not None and score >= self._threshold():
                    severity = "drop"

                self.add_alert("Podejrzany plik w Downloads", details, severity)

    def _scan_processes(self):
        keywords = [k.lower() for k in self.config.get("suspicious_process_keywords", [])]

        try:
            output = subprocess.check_output(
                ["ps", "-eo", "pid,comm,args"],
                text=True,
                stderr=subprocess.DEVNULL
            )
        except Exception as exc:
            self.log("PROC", f"Process scan failed: {exc}", "warn")
            return

        for line in output.splitlines()[1:]:
            low = line.lower()
            for key in keywords:
                if key and key in low:
                    self.stats["process_hits"] += 1

                    score, pattern = self._score_text(line.strip())
                    details = line.strip()

                    if score is not None:
                        details += f" | ml_score={score:.3f}"
                    if pattern:
                        details += f" | pattern={pattern}"

                    severity = "warn"
                    if score is not None and score >= self._threshold():
                        severity = "drop"

                    self.add_alert("Podejrzany proces", details, severity)
                    break

    def _scan_connections(self):
        ports = {str(p) for p in self.config.get("suspicious_connection_ports", [])}
        cmd = ["ss", "-tunp"] if platform.system().lower() == "linux" else ["netstat", "-an"]

        try:
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        except Exception as exc:
            self.log("NET", f"Connection scan failed: {exc}", "warn")
            return

        for line in output.splitlines():
            matched_port = next((p for p in ports if f":{p}" in line), None)
            if matched_port:
                self.stats["network_hits"] += 1

                score, pattern = self._score_text(f"network connection on port {matched_port}: {line.strip()}")
                details = line.strip()

                if score is not None:
                    details += f" | ml_score={score:.3f}"
                if pattern:
                    details += f" | pattern={pattern}"

                severity = "warn"
                if score is not None and score >= self._threshold():
                    severity = "drop"

                self.add_alert("Podejrzane połączenie", details, severity)

    def get_state(self):
        return {
            "status": self.status,
            "last_scan": self.last_scan,
            "alerts_total": self.stats["alerts_total"],
            "downloads_checked": self.stats["downloads_checked"],
            "suspicious_files": self.stats["suspicious_files"],
            "process_hits": self.stats["process_hits"],
            "network_hits": self.stats["network_hits"],
            "model_ready": self.model_ready,
            "model_name": self.model_name,
            "last_ml_score": self.last_ml_score,
            "last_ml_pattern": self.last_ml_pattern,
            "ml_threshold": self._threshold(),
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
