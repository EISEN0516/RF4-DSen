from __future__ import annotations

import json
import math
import os
import platform
import queue
import re
import subprocess
import sys
import threading
import time
import traceback
import ctypes
import webbrowser
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, quote_plus

import tkinter as tk
from tkinter import messagebox

from rf4_direct_source import DirectMemorySource, find_rf4_process
from rf4_thresholds import FISH_THRESHOLDS, classify_fish_level, compact_badge, resolve_fish_id

try:
    import winsound
except Exception:  # pragma: no cover
    winsound = None


APP_NAME = "RF4 \u4e0a\u9c7c\u63d0\u9192\u5668"
APP_VERSION = "1.08"

LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
APP_DATA_DIR = LOCALAPPDATA / "RF4-Reminder"
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = APP_DATA_DIR / "config.json"
DIAGNOSTIC_DIR = APP_DATA_DIR / "diagnostics"
INSTANCE_MUTEX_NAME = "Local\\RF4BiteReminder_v107"
_INSTANCE_MUTEX = None

BG = "#0d1420"
PANEL = "#121b2c"
CARD = "#172338"
CARD_ACTIVE = "#2a2140"
CARD_PROBE = "#291c34"
CARD_OK = "#153225"
LINE = "#253854"
LINE_ACTIVE = "#8b61ff"
TEXT = "#e2ecff"
MUTED = "#8c9db6"
ACCENT = "#58d2c6"
GOOD = "#7cdf86"
WARN = "#ffb15e"
ALERT = "#ff8f71"

HUD_TRANSPARENT = "#010203"
HUD_BG = "#0b0f19"
HUD_BORDER = "#334155"
HUD_SHADOW = "#05070d"
HUD_WIDTH = 850
HUD_HEIGHT = 46
HUD_ROD_WIDTH = 190
MEMORY_MISSING_GRACE_SECONDS = 1.5

STATE_IDLE = "\u7b49\u9c7c"
STATE_PROBE = "\u8bd5\u63a2\u4e2d"
STATE_BITE = "\u6709\u9c7c\u54ac\u94a9"
STATE_SUGGEST = "\u5efa\u8bae\u63d0\u6746"
STATE_SUCCESS = "\u4e0a\u9c7c\u6210\u529f"
STATE_REEL = "\u6536\u6746"
STATE_WAIT = "\u6682\u65e0\u9c7c\u8baf"

EARLY_HINTS = {STATE_PROBE, STATE_BITE, STATE_SUGGEST, "\u53ef\u523a\u9c7c\u53e3", "\u6d3b\u8dc3\u9c7c\u53e3"}
GOOD_HINTS = {STATE_SUCCESS, "\u4e2d\u9c7c", "\u5df2\u4e2d\u9c7c"}
IDLE_HINTS = {STATE_IDLE, "\u7b49\u5f85\u9c7c\u53e3"}
MAX_RECENT_LINES = 100
GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def fish_reference_matches(query: object = "", limit: int = 80) -> list[tuple[str, dict]]:
    needle = safe_text(query).casefold().replace(" ", "")
    matches: list[tuple[int, str, dict]] = []
    for fish_id, row in FISH_THRESHOLDS.items():
        name = safe_text(row.get("name_zh"))
        compact_id = fish_id.casefold().replace(" ", "")
        compact_name = name.casefold().replace(" ", "")
        haystack = f"{compact_id}{compact_name}"
        if needle and needle not in haystack:
            continue
        exact_rank = 0 if needle and needle in {compact_id, compact_name} else 1
        matches.append((exact_rank, fish_id, row))
    matches.sort(key=lambda item: (item[0], safe_text(item[2].get("name_zh")), item[1]))
    return [(fish_id, row) for _rank, fish_id, row in matches[: max(1, limit)]]


def fish_reference_urls(query: object) -> tuple[str, str]:
    text = safe_text(query)
    fish_id = resolve_fish_id(text)
    if fish_id:
        rf4db = f"https://cn.rf4db.com/zh/fishes/{quote(fish_id, safe='.') }"
    else:
        rf4db = "https://cn.rf4db.com/zh/fishes"
    rf4stat = "https://cn.rf4-stat.ru/fishing/"
    if text:
        rf4stat += f"?fish={quote_plus(text)}"
    return rf4db, rf4stat


def reference_weight(value: object) -> str:
    if not isinstance(value, (int, float)):
        return "-"
    if value >= 1000:
        return f"{value / 1000:g} kg"
    return f"{value:g} g"


def now_text() -> str:
    return datetime.now().strftime("%H:%M:%S")


def ts_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_text(value: object, default: str = "") -> str:
    text = str(value).strip() if value is not None else ""
    return text or default


def short_text(text: str, limit: int = 18) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 1)] + "..."


def format_age(updated_at: float) -> str:
    if not updated_at:
        return "--"
    delta = max(0, int(time.time() - updated_at))
    if delta < 60:
        return f"{delta}s"
    return f"{delta // 60}m"


def normalize_status(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return STATE_IDLE
    if any(hint in text for hint in GOOD_HINTS):
        return STATE_SUCCESS
    if STATE_PROBE in text:
        return STATE_PROBE
    if STATE_BITE in text or "\u54ac\u94a9" in text:
        return STATE_BITE
    if "\u53ef\u523a\u9c7c\u53e3" in text or "\u6d3b\u8dc3\u9c7c\u53e3" in text or STATE_SUGGEST in text:
        return STATE_SUGGEST
    if any(hint in text for hint in IDLE_HINTS):
        return STATE_IDLE
    return text


def palette_for_status(status: str) -> tuple[str, str, str]:
    if status == STATE_SUGGEST:
        return CARD_ACTIVE, LINE_ACTIVE, WARN
    if status in {STATE_PROBE, STATE_BITE}:
        return CARD_PROBE, "#f08c58", ACCENT
    if status == STATE_SUCCESS:
        return CARD_OK, GOOD, GOOD
    return CARD, LINE, TEXT


def pretty_weight(value: object) -> str:
    text = safe_text(value)
    if not text:
        return "0 g"
    if text.lower().endswith("g"):
        return text
    try:
        num = float(text)
        return f"{int(num)} g" if num.is_integer() else f"{num:.1f} g"
    except Exception:
        return text


def pretty_distance(value: object) -> str:
    text = safe_text(value)
    if not text:
        return ""
    if text.endswith("m") or text.endswith("\u7c73"):
        return text
    try:
        num = float(text)
        return f"{int(num)}m" if num.is_integer() else f"{num:.1f}m"
    except Exception:
        return text


def pretty_weight_grams(value: float) -> str:
    if not math.isfinite(value):
        return "0 g"
    if value >= 1000:
        text = f"{value / 1000:.3f}".rstrip("0").rstrip(".")
        return f"{text} kg"
    return f"{int(value)} g" if value.is_integer() else f"{value:.1f} g"


def compact_weight(value: object) -> str:
    text = pretty_weight(value).lower().replace(" ", "")
    try:
        if text.endswith("kg"):
            kg = float(text[:-2])
            return f"{kg:.3f}".rstrip("0").rstrip(".") + "kg"
        if text.endswith("g"):
            grams = float(text[:-1])
            if grams >= 1000:
                return f"{grams / 1000:.3f}".rstrip("0").rstrip(".") + "kg"
            return f"{grams:g}g"
    except Exception:
        pass
    return short_text(text or "0g", 8)


def catch_badge(
    fish: object = "",
    weight_g: object = None,
    rarity: object = "",
    grade: object = "",
    flags: object = "",
) -> str:
    level = classify_fish_level(fish, weight_g, rarity, grade, flags)
    return compact_badge(level)


def live_fish_details(rod: "RodState") -> str:
    parts: list[str] = []
    if rod.fish and rod.fish not in {STATE_WAIT, STATE_IDLE, STATE_SUCCESS, STATE_REEL}:
        parts.append(rod.fish)
    if rod.weight_g is not None:
        parts.append(pretty_weight_grams(rod.weight_g))
    elif rod.weight and rod.weight != "0 g":
        parts.append(rod.weight)
    if rod.catch_badge:
        parts.append(rod.catch_badge)
    return " · ".join(parts)


def parse_jsonl_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        for line in f:
            obj = parse_jsonl_line(line)
            if obj is not None:
                rows.append(obj)
    return rows


def tail_jsonl(path: Path, state: dict) -> list[dict]:
    if not path.exists():
        state["offset"] = 0
        state["buffer"] = ""
        return []
    try:
        stat = path.stat()
    except Exception:
        return []
    if stat.st_size < state.get("offset", 0):
        state["offset"] = 0
        state["buffer"] = ""
    try:
        with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
            f.seek(state.get("offset", 0))
            chunk = f.read()
            state["offset"] = f.tell()
    except Exception:
        return []
    text = (state.get("buffer", "") or "") + chunk
    if not text:
        state["buffer"] = ""
        return []
    lines = text.splitlines()
    if text.endswith("\n") or text.endswith("\r"):
        state["buffer"] = ""
    else:
        state["buffer"] = lines.pop() if lines else text
    out: list[dict] = []
    for line in lines:
        obj = parse_jsonl_line(line)
        if obj is not None:
            out.append(obj)
    return out


def latest_file(root: Path, filename: str) -> Path | None:
    if not root.exists():
        return None
    best: Path | None = None
    best_sig = (-1, -1)
    try:
        for path in root.rglob(filename):
            if not path.is_file():
                continue
            try:
                stat = path.stat()
            except Exception:
                continue
            sig = (stat.st_mtime_ns, stat.st_size)
            if sig > best_sig:
                best_sig = sig
                best = path
    except Exception:
        return None
    return best


def detect_mode(path: Path) -> str:
    name = path.name.lower()
    if name == "timeline.jsonl":
        return "timeline"
    if name == "catch-protocol-trace.jsonl":
        return "trace"
    if name.endswith(".tsv"):
        return "tsv"
    if name.endswith(".jsonl"):
        return "trace"
    return "file"


@dataclass
class AppConfig:
    schema_version: int = 5
    process_name: str = "rf4_x64.exe"
    monitor_process: bool = True
    sound_enabled: bool = True
    popup_enabled: bool = True
    topmost: bool = True
    auto_start_monitoring: bool = True
    poll_ms: int = 80
    window_x: int = -1
    window_y: int = 16


@dataclass
class RodState:
    index: int
    key: str = ""
    slot: str = ""
    status: str = STATE_IDLE
    fish: str = STATE_WAIT
    weight: str = "0 g"
    hook: str = "\u65e0"
    bait: str = "\u65e0"
    groundbait: str = ""
    rig_type: str = ""
    distance: str = ""
    player_state: str = ""
    backend_state: str = ""
    last_event: str = ""
    updated_at: float = 0.0
    in_water: bool = False
    session: bool = False
    memory_valid: bool = False
    memory_root: str = ""
    action_type: str = ""
    graph_types: str = ""
    live_phase: str = ""
    live_instance: str = ""
    weight_g: float | None = None
    rarity: str = ""
    grade: str = ""
    flags: str = ""
    fight_initialized: bool = False
    fight_factor: float = 0.0
    fight_deadline: float | None = None
    meta_status: str = ""
    owner_live: bool = False
    fish_graph_live: bool = False
    strike_ready: bool = False
    catch_badge: str = ""
    bell_code: int | None = None
    bell_baseline: int | None = None
    bell_state_address: str = ""


@dataclass
class EnvState:
    map_id: str = ""
    coordinate: str = ""
    time: str = ""
    weather: str = ""
    temperature: str = ""
    wind: str = ""
    clip: str = ""


def load_config() -> AppConfig:
    if CONFIG_FILE.exists():
        try:
            raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if int(raw.get("schema_version", 1)) < 2:
                raw["topmost"] = True
            base = asdict(AppConfig())
            for key in base:
                if key in raw:
                    base[key] = raw[key]
            base["schema_version"] = 5
            return AppConfig(**base)
        except Exception:
            pass
    return AppConfig()


def save_config(cfg: AppConfig) -> None:
    CONFIG_FILE.write_text(json.dumps(asdict(cfg), ensure_ascii=False, indent=2), encoding="utf-8")


def diagnostic_json_default(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, tuple)):
        return list(value)
    try:
        return asdict(value)  # type: ignore[arg-type]
    except Exception:
        return str(value)


def write_diagnostic_bundle(
    output_dir: Path,
    base_name: str,
    diagnostics_text: str,
    payload: dict[str, object],
    *,
    extra_text_files: dict[str, str] | None = None,
) -> Path:
    """Write a sendable diagnostic zip and keep the unpacked folder beside it."""
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", base_name).strip("-") or "RF4-DSen-diagnostic"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    bundle_dir = output_dir / f"{safe_name}-{stamp}"
    suffix = 1
    while bundle_dir.exists():
        suffix += 1
        bundle_dir = output_dir / f"{safe_name}-{stamp}-{suffix}"
    bundle_dir.mkdir(parents=True, exist_ok=False)

    files: list[Path] = []
    diagnostics_path = bundle_dir / "diagnostics.txt"
    diagnostics_path.write_text(diagnostics_text, encoding="utf-8", errors="replace")
    files.append(diagnostics_path)

    payload_path = bundle_dir / "state.json"
    payload_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=diagnostic_json_default),
        encoding="utf-8",
        errors="replace",
    )
    files.append(payload_path)

    for name, text in (extra_text_files or {}).items():
        clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._") or "extra.txt"
        path = bundle_dir / clean
        path.write_text(str(text), encoding="utf-8", errors="replace")
        files.append(path)

    zip_path = bundle_dir.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, arcname=path.name)
    return zip_path


def acquire_single_instance() -> bool:
    global _INSTANCE_MUTEX
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateMutexW(None, False, INSTANCE_MUTEX_NAME)
        if not handle or kernel32.GetLastError() == 183:
            if handle:
                kernel32.CloseHandle(handle)
            return False
        _INSTANCE_MUTEX = handle
        return True
    except Exception:
        return True


def focus_existing_instance() -> bool:
    """Bring an already-running RF4-DSen window to the front when possible."""
    if os.name != "nt":
        return False
    try:
        user32 = ctypes.windll.user32
        handles: list[int] = []

        enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        @enum_proc
        def callback(hwnd, _lparam):
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            title = buffer.value or ""
            if f"{APP_NAME} V{APP_VERSION}" in title:
                handles.append(int(hwnd))
                return False
            return True

        user32.EnumWindows(callback, None)
        if not handles:
            return False
        hwnd = handles[0]
        user32.ShowWindow(ctypes.c_void_p(hwnd), 9)  # SW_RESTORE
        user32.SetForegroundWindow(ctypes.c_void_p(hwnd))
        return True
    except Exception:
        return False


def is_process_running(process_name: str) -> bool:
    if process_name.lower() == "rf4_x64.exe":
        return find_rf4_process(process_name) is not None
    try:
        cp = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH", "/FI", f"IMAGENAME eq {process_name}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=3,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = (cp.stdout or "") + (cp.stderr or "")
        if "No tasks are running" in out or "INFO:" in out:
            return False
        return process_name.lower() in out.lower()
    except Exception:
        return False


def current_rf4_pid() -> int | None:
    """Return the live RF4 PID from the Windows process table."""
    found = find_rf4_process("rf4_x64.exe")
    return found[0] if found else None


def find_official_backend(_configured: str = "") -> Path | None:
    """Compatibility stub: RF4-DSen never launches or reads rf4db."""
    return None


def parse_bool(value: object) -> bool:
    return safe_text(value).lower() in {"1", "true", "yes", "on", "active", "requested"}


def parse_number(value: object, default: float | None = None) -> float | None:
    text = safe_text(value).replace(",", ".")
    if not text:
        return default
    match = re.search(r"[-+]?\d+(?:\.\d+)?", text)
    if not match:
        return default
    try:
        number = float(match.group(0))
    except ValueError:
        return default
    return number if math.isfinite(number) else default


def parse_weight_g(value: object, *, explicit_grams: bool = False) -> float | None:
    """Normalize backend weight fields without mistaking kilograms for grams."""
    text = safe_text(value).replace(",", ".")
    if not text:
        return None
    number = parse_number(text)
    if number is None:
        return None
    lowered = text.lower()
    if explicit_grams or " g" in lowered or lowered.endswith("g") or "克" in lowered:
        return number
    if "kg" in lowered or "千克" in lowered or "公斤" in lowered:
        return number * 1000.0
    # The backend's ``weight`` field is serialized in grams in current builds.
    return number


def backend_status_text(text: object) -> str:
    raw = safe_text(text)
    lower = raw.lower()
    if any(token in lower for token in ("result_dialog", "terminal", "harvest", "success", "caught", "鱼口结束", "上鱼成功")):
        return STATE_SUCCESS
    if any(token in lower for token in ("strike", "可刺", "刺鱼", "提杆", "hooked", "中鱼", "打口")):
        return STATE_SUGGEST
    if any(token in lower for token in ("bite", "probe", "试探", "活跃鱼口", "鱼口")):
        return STATE_BITE
    if any(token in lower for token in ("等待鱼口", "waiting", "idle")):
        return STATE_IDLE
    return ""


class Toast:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.win: tk.Toplevel | None = None

    def show(self, title: str, body: str, ms: int = 1600) -> None:
        if self.win and self.win.winfo_exists():
            try:
                self.win.destroy()
            except Exception:
                pass
        win = tk.Toplevel(self.root)
        self.win = win
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=PANEL)
        width, height = 286, 92
        x = self.root.winfo_screenwidth() - width - 16
        y = self.root.winfo_screenheight() - height - 56
        win.geometry(f"{width}x{height}+{x}+{y}")
        frame = tk.Frame(win, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text=title, fg=ACCENT, bg=PANEL, font=("Segoe UI", 11, "bold")).pack(
            anchor="w", padx=12, pady=(10, 0)
        )
        tk.Label(
            frame,
            text=body,
            fg=TEXT,
            bg=PANEL,
            justify="left",
            anchor="w",
            wraplength=260,
            font=("Segoe UI", 10),
        ).pack(fill="both", expand=True, padx=12, pady=(4, 0))
        win.after(ms, lambda: win.winfo_exists() and win.destroy())


def discover_source(cfg: AppConfig) -> tuple[str, Path] | tuple[str, None]:
    # Retained only for compatibility with old imports. File sources are disabled.
    return "none", None
    manual = Path(cfg.source_path).expanduser() if cfg.source_path else None
    if manual and manual.exists():
        return detect_mode(manual), manual

    roots: list[Path] = []
    for raw in (cfg.trace_root, str(DEFAULT_TRACE_ROOT)):
        root = Path(raw).expanduser()
        if root.exists() and root not in roots:
            roots.append(root)

    candidates: list[tuple[int, int, int, str, Path]] = []
    for mode, filename in (("timeline", "timeline.jsonl"), ("trace", "catch-protocol-trace.jsonl")):
        for root in roots:
            candidate = latest_file(root, filename)
            if candidate is None:
                continue
            try:
                stat = candidate.stat()
            except Exception:
                continue
            priority = 0 if mode == "timeline" else 1 if mode == "trace" else 2
            candidates.append((priority, -stat.st_mtime_ns, -stat.st_size, mode, candidate))

    if not candidates:
        return "none", None
    candidates.sort()
    _, _, _, mode, path = candidates[0]
    return mode, path


class LegacyRF4Monitor(threading.Thread):
    def __init__(self, ui_queue: queue.Queue, stop_event: threading.Event, cfg: AppConfig):
        super().__init__(daemon=True)
        self.ui_queue = ui_queue
        self.stop_event = stop_event
        self.cfg = cfg
        self.file_state: dict[str, dict[str, object]] = {}
        self.current_mode = "none"
        self.current_path: Path | None = None
        self.process_running: bool | None = None
        self.rods = [RodState(index=i) for i in range(3)]
        self.env = EnvState()
        self.key_to_index: dict[str, int] = {}
        self.slot_to_index: dict[str, int] = {}
        self.alerted: set[str] = set()
        self.recent_lines: list[str] = []
        self.alert_count = 0
        self.probe_count = 0
        self.strike_count = 0
        self._bootstrapped = False

    def emit(self, event_kind: str, **payload) -> None:
        if "kind" in payload:
            payload = dict(payload)
            payload["alert_kind"] = payload.pop("kind")
        self.ui_queue.put({"kind": event_kind, **payload})

    def log(self, text: str) -> None:
        line = f"[{ts_text()}] {text}"
        self.recent_lines.append(line)
        if len(self.recent_lines) > MAX_RECENT_LINES:
            self.recent_lines = self.recent_lines[-MAX_RECENT_LINES:]
        self.emit("log", line=line)

    def state_for_path(self, path: Path) -> dict[str, object]:
        state = self.file_state.get(str(path))
        if state is None:
            state = {"offset": 0, "buffer": "", "sig": None}
            self.file_state[str(path)] = state
        return state

    @staticmethod
    def file_signature(path: Path) -> tuple[int, int] | None:
        try:
            stat = path.stat()
            return (stat.st_mtime_ns, stat.st_size)
        except Exception:
            return None

    def reset_capture_state(self) -> None:
        self.rods = [RodState(index=i) for i in range(3)]
        self.env = EnvState()
        self.key_to_index.clear()
        self.slot_to_index.clear()
        self.alerted.clear()
        self.probe_count = 0
        self.strike_count = 0

    def bootstrap_tsv(self, path: Path) -> None:
        seen = set()
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    for cell in line.split("\t"):
                        cell = cell.strip()
                        if cell:
                            seen.add(cell)
        except Exception:
            pass
        state = self.state_for_path(path)
        try:
            state["offset"] = path.stat().st_size
        except Exception:
            state["offset"] = 0
        state["buffer"] = ""
        state["sig"] = self.file_signature(path)
        self.log(f"TSV \u57fa\u7ebf {len(seen)} \u6761")

    def load_baseline(self, path: Path, mode: str) -> None:
        self.reset_capture_state()
        state = self.state_for_path(path)
        if mode in {"timeline", "trace"}:
            for obj in read_jsonl(path):
                self.process_event(obj, notify=False)
            try:
                state["offset"] = path.stat().st_size
            except Exception:
                state["offset"] = 0
            state["buffer"] = ""
        else:
            self.bootstrap_tsv(path)
        state["sig"] = self.file_signature(path)
        self.current_mode = mode
        self.current_path = path
        self.emit("snapshot", rods=[asdict(r) for r in self.rods], env=asdict(self.env))
        self.emit("source", mode=mode, path=str(path), ready=True, bootstrap=True)

    def resolve_index(self, fields: dict) -> int | None:
        key = safe_text(fields.get("gear") or fields.get("instance") or fields.get("capture_id"))
        slot = safe_text(fields.get("slot") or fields.get("bait_slot"))
        if key and key in self.key_to_index:
            idx = self.key_to_index[key]
        elif slot and slot in self.slot_to_index:
            idx = self.slot_to_index[slot]
        else:
            idx = None
            for i, rod in enumerate(self.rods):
                if not rod.key:
                    idx = i
                    break
            if idx is None:
                idx = 0
        if key:
            self.key_to_index[key] = idx
        if slot:
            self.slot_to_index[slot] = idx
        return idx

    def update_environment(self, fields: dict) -> None:
        for attr in ("map_id", "coordinate", "time", "weather", "temperature", "wind", "clip"):
            value = safe_text(fields.get(attr))
            if value:
                setattr(self.env, attr, value)
        self.emit("environment", env=asdict(self.env))

    def set_rod(self, idx: int, fields: dict, status: str, event_type: str) -> None:
        rod = self.rods[idx]
        key = safe_text(fields.get("gear") or fields.get("instance") or fields.get("capture_id"))
        slot = safe_text(fields.get("slot") or fields.get("bait_slot"))
        if key:
            rod.key = key
        if slot:
            rod.slot = slot
        rod.status = normalize_status(status)
        fish = safe_text(fields.get("fish") or fields.get("species"))
        if fish:
            rod.fish = fish
        elif rod.status != STATE_SUCCESS:
            rod.fish = STATE_WAIT
        raw_weight = fields.get("weight") or fields.get("weight_g")
        if raw_weight not in (None, ""):
            rod.weight = pretty_weight(raw_weight)
        elif rod.status != STATE_SUCCESS:
            rod.weight = "0 g"
        bait = safe_text(fields.get("bait_names") or fields.get("bait_products") or fields.get("bait") or rod.bait or "\u65e0")
        if bait:
            rod.bait = bait
        hook = safe_text(fields.get("hook_name") or fields.get("hook") or rod.hook or "\u65e0")
        if hook:
            rod.hook = hook
        distance = pretty_distance(fields.get("line_distance") or fields.get("distance") or rod.distance)
        if distance:
            rod.distance = distance
        rig_type = safe_text(fields.get("rig_type") or fields.get("rig_id") or rod.rig_type)
        if rig_type:
            rod.rig_type = rig_type
        rod.player_state = safe_text(fields.get("player_state") or fields.get("state") or rod.player_state)
        rod.backend_state = safe_text(fields.get("backend_state") or rod.backend_state)
        rod.last_event = event_type
        rod.updated_at = time.time()
        self.emit("rod", index=idx, rod=asdict(rod))

    def alert_signature(self, event_type: str, idx: int, fields: dict, status: str) -> str:
        key = safe_text(fields.get("gear") or fields.get("instance") or fields.get("capture_id") or fields.get("slot") or idx)
        return f"{event_type}:{key}:{status}"

    def should_alert(self, event_type: str, fields: dict, status: str) -> bool:
        status = normalize_status(status)
        player = normalize_status(safe_text(fields.get("player_state") or fields.get("state")))
        backend = normalize_status(safe_text(fields.get("backend_state")))
        phase = safe_text(fields.get("phase")).lower()
        source = safe_text(fields.get("source")).lower()
        hint = " ".join(filter(None, [status, player, backend, phase, source]))
        if event_type == "bite_probe":
            return any(x in hint for x in EARLY_HINTS) or ("sample" in phase and player == STATE_PROBE)
        if event_type == "bite":
            if source == "result_dialog" and self.current_mode != "timeline":
                return True
            return any(x in hint for x in EARLY_HINTS)
        return False

    def process_event(self, obj: dict, notify: bool = True) -> None:
        if not isinstance(obj, dict):
            return
        event_type = safe_text(obj.get("type") or obj.get("event"))
        fields = obj.get("fields") if isinstance(obj.get("fields"), dict) else {}

        if event_type == "environment":
            self.update_environment(fields)
            return

        if event_type == "rod_telemetry":
            idx = self.resolve_index(fields)
            if idx is not None:
                self.set_rod(idx, fields, safe_text(obj.get("player_state") or fields.get("player_state") or STATE_IDLE), event_type)
            return

        if event_type == "gear_component":
            idx = self.resolve_index(fields)
            if idx is None:
                return
            kind = safe_text(fields.get("kind")).lower()
            if kind == "hook":
                self.rods[idx].hook = safe_text(fields.get("name") or fields.get("id") or self.rods[idx].hook)
            elif kind == "bait":
                self.rods[idx].bait = safe_text(fields.get("name") or fields.get("id") or self.rods[idx].bait)
            elif kind == "rig":
                self.rods[idx].rig_type = safe_text(fields.get("name") or fields.get("id") or self.rods[idx].rig_type)
            elif kind == "line" and fields.get("capacity_kg"):
                self.rods[idx].distance = safe_text(fields.get("capacity_kg"))
            self.rods[idx].updated_at = time.time()
            self.emit("rod", index=idx, rod=asdict(self.rods[idx]))
            return

        if event_type in {"catch_context_rod", "catch_context_begin", "gear_begin"}:
            idx = self.resolve_index(fields)
            if idx is None:
                return
            if fields.get("bait_names"):
                self.rods[idx].bait = safe_text(fields.get("bait_names"))
            elif fields.get("bait_products") and not self.rods[idx].bait:
                self.rods[idx].bait = safe_text(fields.get("bait_products"))
            if fields.get("line_distance"):
                self.rods[idx].distance = pretty_distance(fields.get("line_distance"))
            if fields.get("rig_type"):
                self.rods[idx].rig_type = safe_text(fields.get("rig_type"))
            self.rods[idx].updated_at = time.time()
            self.emit("rod", index=idx, rod=asdict(self.rods[idx]))
            return

        if event_type in {"bite_probe", "bite"}:
            idx = self.resolve_index(fields)
            if idx is None:
                return
            player_state = safe_text(obj.get("player_state") or fields.get("player_state") or fields.get("state"))
            backend_state = safe_text(obj.get("backend_state") or fields.get("backend_state"))
            status = normalize_status(player_state or backend_state or (STATE_PROBE if event_type == "bite_probe" else STATE_SUGGEST))
            fish = safe_text(fields.get("fish") or fields.get("species") or "")
            if fish and fish != STATE_WAIT:
                self.rods[idx].fish = fish
            self.set_rod(idx, fields, status, event_type)
            self.rods[idx].player_state = player_state or self.rods[idx].player_state
            self.rods[idx].backend_state = backend_state or self.rods[idx].backend_state
            self.rods[idx].fish = fish or (self.rods[idx].fish if status == STATE_SUCCESS else STATE_WAIT)
            self.rods[idx].updated_at = time.time()
            if event_type == "bite_probe":
                self.probe_count += 1
            else:
                self.strike_count += 1
            self.emit("rod", index=idx, rod=asdict(self.rods[idx]))
            if notify and self.should_alert(event_type, fields, status):
                sig = self.alert_signature(event_type, idx, fields, status)
                if sig not in self.alerted:
                    self.alerted.add(sig)
                    self.alert_count += 1
                    summary = f"U{idx + 1} {status}"
                    if fish and fish != STATE_WAIT:
                        summary += f" \u00b7 {fish}"
                    self.emit(
                        "alert",
                        index=idx,
                        kind="probe" if event_type == "bite_probe" else "bite",
                        status=status,
                        fish=fish,
                        summary=summary,
                        source=safe_text(fields.get("source") or obj.get("source") or event_type),
                    )
            return

        if event_type == "load_indicator":
            self.emit("status", text="\u52a0\u8f7d\u4e2d" if safe_text(fields.get("active")).lower() == "true" else "\u7a7a\u95f2")
            return

        if event_type == "diagnostic":
            msg = safe_text(fields.get("message") or obj.get("message"))
            if msg:
                self.log(msg)

    def attach_source(self, mode: str, path: Path) -> None:
        if self.current_path != path:
            self.reset_capture_state()
            self.alerted.clear()
        self.load_baseline(path, mode)
        self.log(f"\u5df2\u8fde\u63a5 {mode}: {path.name}")

    def scan_process(self) -> None:
        if not self.cfg.monitor_process:
            return
        running = is_process_running(self.cfg.process_name)
        if self.process_running is None or self.process_running != running:
            self.process_running = running
            self.emit("process", running=running, process_name=self.cfg.process_name)

    def scan_source(self) -> None:
        mode, path = discover_source(self.cfg)
        if path is None or mode == "none":
            self.emit("source", mode="none", path="", ready=False)
            return
        if self.current_path != path or self.current_mode != mode or not self._bootstrapped:
            self.attach_source(mode, path)
            self._bootstrapped = True
            return
        state = self.state_for_path(path)
        sig = self.file_signature(path)
        if mode != "tsv" and sig is not None and state.get("sig") == sig:
            return
        state["sig"] = sig
        if mode in {"timeline", "trace"}:
            for obj in tail_jsonl(path, state):
                self.process_event(obj, notify=True)
            return
        # No other file format is a live bite source.
        return

    def build_snapshot(self) -> None:
        self.emit("snapshot", rods=[asdict(r) for r in self.rods], env=asdict(self.env))

    def run(self) -> None:
        self.emit("status", text="\u542f\u52a8\u4e2d")
        try:
            self.scan_process()
            self.scan_source()
            self.build_snapshot()
            self.emit("status", text="\u76d1\u542c\u4e2d")
            while not self.stop_event.is_set():
                try:
                    self.scan_process()
                    self.scan_source()
                except Exception as exc:
                    self.emit("error", message=str(exc), trace=traceback.format_exc())
                self.stop_event.wait(max(0.25, self.cfg.poll_ms / 1000.0))
        except Exception as exc:
            self.emit("error", message=str(exc), trace=traceback.format_exc())


class RF4Monitor(threading.Thread):
    def __init__(self, ui_queue: queue.Queue, stop_event: threading.Event, cfg: AppConfig):
        super().__init__(daemon=True)
        self.ui_queue = ui_queue
        self.stop_event = stop_event
        self.cfg = cfg
        self.memory = DirectMemorySource(cfg.process_name)
        self.rods = [RodState(index=i) for i in range(3)]
        self.env = EnvState()
        self.recent_lines: list[str] = []
        self.alert_count = 0
        self.probe_count = 0
        self.strike_count = 0
        self.process_running: bool | None = None
        self.memory_pid = 0
        self.session_token = ""
        self.mapping_source = ""
        self.runtime_diagnostics: dict[str, object] = {}
        self.current_mode = "memory"
        self.current_path: Path | None = None
        self.file_state: dict[str, dict[str, object]] = {}
        self.bite_active: dict[str, bool] = {}
        self.suggest_active: dict[str, bool] = {}
        self.result_suppressed: set[str] = set()
        self.live_bite_path = None
        self.live_bite_guids: set[str] = set()
        self.live_bite_baselined = False
        self.live_bite_signature: tuple[int, int] | None = None
        self.live_bite_alerted: set[str] = set()
        self.final_until: dict[int, float] = {}
        self.trace_until: dict[int, float] = {}
        self.trace_alerted: set[str] = set()
        self._rod_signatures: dict[int, tuple] = {}
        self._last_trace_discovery = 0.0
        self._last_memory_error = ""
        self._last_source_path = ""
        self._source_data_ready = False
        self._source_signature: tuple[bool, str, str, bool] | None = None
        self._memory_missing_since: dict[int, float] = {}

    def emit(self, event_kind: str, **payload) -> None:
        # ``kind`` is also the alert subtype (probe/bite); keep it available
        # in the payload without colliding with the event envelope field.
        if "kind" in payload:
            payload = dict(payload)
            payload["alert_kind"] = payload.pop("kind")
        self.ui_queue.put({"kind": event_kind, **payload})

    def _emit_memory_source(
        self,
        connected: bool,
        *,
        pid: int = 0,
        error: str = "",
        data_ready: bool | None = None,
        bootstrap: bool = False,
    ) -> None:
        """Report source health without discarding the last usable source path."""
        if connected and pid:
            self._last_source_path = f"rf4_x64.exe PID {pid}"
        if data_ready is not None:
            self._source_data_ready = data_ready
        path = self._last_source_path
        signature = (connected, path, error, self._source_data_ready)
        if not bootstrap and signature == self._source_signature:
            return
        self._source_signature = signature
        self.emit(
            "source",
            mode="direct-runtime",
            path=path,
            ready=connected,
            connected=connected,
            data_ready=self._source_data_ready,
            state=(
                "connected"
                if connected and self._source_data_ready
                else "waiting_mapping"
                if connected
                else "retrying"
                if path
                else "disconnected"
            ),
            error=error,
            bootstrap=bootstrap,
        )

    def log(self, text: str) -> None:
        line = f"[{ts_text()}] {text}"
        self.recent_lines.append(line)
        if len(self.recent_lines) > MAX_RECENT_LINES:
            self.recent_lines = self.recent_lines[-MAX_RECENT_LINES:]
        self.emit("log", line=line)

    def state_for_path(self, path: Path) -> dict[str, object]:
        key = str(path)
        state = self.file_state.get(key)
        if state is None:
            state = {"offset": 0, "buffer": "", "sig": None}
            self.file_state[key] = state
        return state

    @staticmethod
    def _state_signature(rod: RodState) -> tuple:
        return (
            rod.key,
            rod.status,
            rod.fish,
            rod.weight,
            rod.rig_type,
            rod.distance,
            rod.in_water,
            rod.session,
            rod.memory_valid,
            rod.memory_root,
            rod.action_type,
            rod.graph_types,
            rod.live_phase,
            rod.live_instance,
            rod.weight_g,
            rod.rarity,
            rod.grade,
            rod.flags,
            rod.fight_initialized,
            rod.fight_factor,
            rod.fight_deadline,
            rod.meta_status,
            rod.owner_live,
            rod.fish_graph_live,
            rod.strike_ready,
            rod.catch_badge,
        )

    def _emit_process(self, running: bool) -> None:
        if self.process_running is None or self.process_running != running:
            self.process_running = running
            self.emit(
                "process",
                running=running,
                process_name=self.cfg.process_name,
                pid=self.memory_pid,
            )

    def _reset_session(self, pid: int, token: str, mapping_source: str) -> None:
        self.memory_pid = pid
        self.session_token = token
        self.mapping_source = mapping_source
        self.rods = [RodState(index=i) for i in range(3)]
        self.bite_active.clear()
        self.suggest_active.clear()
        self.result_suppressed.clear()
        self.live_bite_guids.clear()
        self.live_bite_alerted.clear()
        self.live_bite_baselined = False
        self.live_bite_signature = None
        self.final_until.clear()
        self.trace_until.clear()
        self.trace_alerted.clear()
        self._rod_signatures.clear()
        self._memory_missing_since.clear()
        self.emit("snapshot", rods=[asdict(rod) for rod in self.rods], env=asdict(self.env))
        source = f"rf4_x64.exe PID {pid}"
        self._last_source_path = source
        self._emit_memory_source(True, pid=pid, data_ready=False, bootstrap=True)
        self.log(f"实时内存会话 PID {pid}，数据源 {mapping_source}")

    def _emit_rod_if_changed(self, idx: int) -> None:
        if not (0 <= idx < len(self.rods)):
            return
        rod = self.rods[idx]
        signature = self._state_signature(rod)
        if self._rod_signatures.get(idx) != signature:
            self._rod_signatures[idx] = signature
            self.emit("rod", index=idx, rod=asdict(rod))

    def _clear_memory_rod(
        self,
        idx: int,
        now: float,
        *,
        drop_mapping: bool = False,
        reason: str = "memory_out",
    ) -> None:
        """Clear live fish data when a rig leaves the water or disappears."""
        if not (0 <= idx < len(self.rods)):
            return
        rod = self.rods[idx]
        old_key = rod.key
        if old_key:
            self.bite_active.pop(old_key, None)
            self.suggest_active.pop(old_key, None)
            self.result_suppressed.discard(old_key)
        rod.status = STATE_REEL
        rod.fish = STATE_WAIT
        rod.weight = "0 g"
        rod.in_water = False
        rod.session = False
        # A rig that is out of water/session is not a live display source.
        # Clear the validity bit as well, otherwise the HUD can resurrect the
        # previous fish when only a partial runtime snapshot is received.
        rod.memory_valid = False
        rod.live_phase = ""
        rod.live_instance = ""
        rod.weight_g = None
        rod.rarity = ""
        rod.grade = ""
        rod.flags = ""
        rod.fight_initialized = False
        rod.fight_factor = 0.0
        rod.fight_deadline = None
        rod.meta_status = ""
        rod.owner_live = False
        rod.fish_graph_live = False
        rod.strike_ready = False
        rod.catch_badge = ""
        rod.bell_code = None
        rod.bell_baseline = None
        rod.bell_state_address = ""
        rod.last_event = reason
        rod.updated_at = now
        if drop_mapping:
            rod.key = ""
            rod.slot = ""
            rod.rig_type = ""
            rod.distance = ""
            rod.memory_root = ""
            rod.action_type = ""
            rod.graph_types = ""
        self._emit_rod_if_changed(idx)

    def _apply_memory_rod(self, item: MemoryRodState, now: float) -> None:
        idx = item.slot - 1
        if not (0 <= idx < len(self.rods)):
            return
        rod = self.rods[idx]
        previous_memory_valid = rod.memory_valid
        previous_memory_root = rod.memory_root
        unmapped_bobber = (
            item.rig_type.startswith("RigBobber")
            and getattr(item, "reason", "") == "浮钓未映射"
        )
        incoming_bite = bool(item.valid and item.bite_active)
        if (
            not item.valid
            and not unmapped_bobber
            and not incoming_bite
            and previous_memory_valid
            and previous_memory_root == f"0x{item.root:X}"
        ):
            since = self._memory_missing_since.setdefault(idx, now)
            if now - since < MEMORY_MISSING_GRACE_SECONDS:
                return
        rod.key = item.guid
        rod.slot = str(item.slot)
        rod.rig_type = item.rig_type
        rod.memory_valid = item.valid
        rod.memory_root = f"0x{item.root:X}"
        rod.in_water = item.in_water
        rod.session = item.session
        rod.action_type = item.action_type
        rod.graph_types = " | ".join(item.graph_types[:12])
        if item.distance_m is not None:
            rod.distance = f"{int(item.distance_m + 0.5)}m"

        # All of these fields are from the current memory snapshot. They must
        # be cleared on the first non-live snapshot so a previous catch cannot
        # remain visible as the next fish.
        rod.live_phase = item.live_phase
        rod.live_instance = item.live_instance
        rod.weight_g = item.weight_g
        rod.rarity = item.rarity
        rod.grade = item.grade
        rod.flags = item.flags
        rod.fight_initialized = item.fight_initialized
        rod.fight_factor = item.fight_factor
        rod.fight_deadline = item.fight_deadline
        rod.meta_status = item.meta_status
        rod.owner_live = item.owner_live
        rod.fish_graph_live = item.fish_graph_live
        rod.strike_ready = item.strike_ready
        rod.bell_code = getattr(item, "bell_code", None)
        rod.bell_baseline = getattr(item, "bell_baseline", None)
        bell_state = getattr(item, "bell_state_address", 0)
        rod.bell_state_address = f"0x{bell_state:X}" if bell_state else ""

        key = item.guid or f"slot-{idx}"
        raw_bite_active = bool(item.valid and item.in_water and item.session and item.bite_active)
        if not raw_bite_active:
            self.result_suppressed.discard(key)
        live = raw_bite_active and key not in self.result_suppressed
        bite_active = live
        suggest_active = live and (
            item.strike_ready
            or item.live_phase.lower() == "suggest"
            or normalize_status(item.meta_status) == STATE_SUGGEST
        )
        was_bite = self.bite_active.get(key, False)
        was_suggest = self.suggest_active.get(key, False)
        self.bite_active[key] = bite_active
        self.suggest_active[key] = suggest_active

        if live:
            self._memory_missing_since.pop(idx, None)
            has_fish_info = bool(
                item.fish_name
                or item.weight_g is not None
                or item.rarity
                or item.grade
                or item.flags
            )
            rod.fish = item.fish_name or STATE_BITE
            rod.weight = pretty_weight_grams(item.weight_g) if item.weight_g is not None else "--"
            rod.catch_badge = catch_badge(
                item.fish_name,
                item.weight_g,
                item.rarity,
                item.grade,
                item.flags,
            ) if has_fish_info else ("待确认" if item.fish_name else "")
            rod.status = STATE_SUGGEST if suggest_active else STATE_BITE
            rod.last_event = "live_strike" if suggest_active else "live_bite"
        elif item.valid and item.in_water and item.session:
            self._memory_missing_since.pop(idx, None)
            probe_active = bool(item.bell_active and item.live_phase == "probe")
            rod.status = STATE_PROBE if probe_active else STATE_IDLE
            rod.fish = STATE_WAIT
            rod.weight = "0 g"
            rod.live_phase = "probe" if probe_active else ""
            rod.live_instance = ""
            rod.weight_g = None
            rod.rarity = ""
            rod.grade = ""
            rod.flags = ""
            rod.fight_initialized = False
            rod.fight_factor = 0.0
            rod.fight_deadline = None
            rod.meta_status = ""
            rod.owner_live = False
            rod.fish_graph_live = False
            rod.strike_ready = False
            rod.catch_badge = ""
            rod.last_event = "memory_probe" if probe_active else "memory_idle"
        else:
            # A rescan can briefly return an invalid copy while Unity is
            # rebuilding its managed object graph.  Keep the last verified
            # rod for a short grace period instead of turning it into "无竿".
            self._clear_memory_rod(
                idx,
                now,
                drop_mapping=not unmapped_bobber,
                reason="浮钓未映射" if unmapped_bobber else "memory_out",
            )
            if unmapped_bobber:
                rod.key = item.guid
                rod.slot = str(item.slot)
                rod.rig_type = item.rig_type
                rod.memory_root = f"0x{item.root:X}"
                self._emit_rod_if_changed(idx)
            return
        rod.updated_at = now

        if bite_active and not was_bite:
            self.alert_count += 1
            self.strike_count += 1
            self.emit(
                "alert",
                index=idx,
                kind="bite",
                status=STATE_SUGGEST if suggest_active else STATE_BITE,
                fish=rod.fish,
                summary=f"U{idx + 1} {rod.status}"
                + (f" · {live_fish_details(rod)}" if live_fish_details(rod) else ""),
                source="rf4_x64 实时内存",
            )
            graph = rod.graph_types or item.action_type or "live fight state"
            self.log(f"U{idx + 1} 实时鱼口: {short_text(graph, 100)}")
        elif suggest_active and not was_suggest:
            self.alert_count += 1
            self.probe_count += 1
            self.emit(
                "alert",
                index=idx,
                kind="probe",
                status=STATE_SUGGEST,
                fish=rod.fish,
                summary=f"U{idx + 1} {STATE_SUGGEST}"
                + (f" · {live_fish_details(rod)}" if live_fish_details(rod) else ""),
                source="rf4_x64 实时内存",
            )
            self.log(f"U{idx + 1} 进入提杆阶段")

        self._emit_rod_if_changed(idx)

    @staticmethod
    def _read_guid_set(path: Path) -> set[str]:
        values: set[str] = set()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return values
        for line in text.splitlines():
            for cell in line.split("\t"):
                value = cell.strip().lower()
                if GUID_RE.fullmatch(value):
                    values.add(value)
        return values

    def scan_live_bites(self) -> None:
        """Disabled: terminal-bite-instances.tsv is a post-catch result list."""
        return

    def scan_memory(self) -> None:
        try:
            snapshot = self.memory.snapshot()
        except Exception as exc:
            message = safe_text(exc)
            self.runtime_diagnostics = dict(getattr(self.memory, "diagnostics", {}) or {})
            process_alive = is_process_running(self.cfg.process_name)
            self._emit_process(process_alive)
            self._emit_memory_source(False, error=message)
            if message != self._last_memory_error:
                self._last_memory_error = message
                self.log(f"等待实时内存: {message}")
            return

        self._last_memory_error = ""
        self.runtime_diagnostics = dict(getattr(snapshot, "diagnostics", {}) or {})
        if snapshot.pid != self.memory_pid:
            self._reset_session(
                snapshot.pid,
                snapshot.session_token,
                snapshot.mapping_source,
            )
        else:
            self.session_token = snapshot.session_token
            self.mapping_source = snapshot.mapping_source
        self._emit_process(True)
        now = time.time()
        present_slots = {item.slot - 1 for item in snapshot.rods if 1 <= item.slot <= 3}
        for idx in range(len(self.rods)):
            if idx not in present_slots:
                rod = self.rods[idx]
                if rod.memory_valid or rod.key:
                    since = self._memory_missing_since.setdefault(idx, now)
                    if now - since >= MEMORY_MISSING_GRACE_SECONDS:
                        self._clear_memory_rod(idx, now, drop_mapping=True, reason="memory_missing")
                        self._memory_missing_since.pop(idx, None)
                else:
                    self._memory_missing_since.pop(idx, None)
            else:
                self._memory_missing_since.pop(idx, None)
        for item in snapshot.rods:
            self._apply_memory_rod(item, now)
        self._emit_memory_source(
            True,
            pid=snapshot.pid,
            data_ready=any(item.valid for item in snapshot.rods),
        )
        if not any(item.valid for item in snapshot.rods):
            self.emit("status", text="等待鱼竿数据")

    def _discover_trace(self) -> Path | None:
        return None
        manual = Path(self.cfg.source_path) if self.cfg.source_path else None
        if manual and manual.is_file() and manual.name.lower() == "catch-protocol-trace.jsonl":
            return manual
        candidates: list[Path] = []
        for root in (Path(self.cfg.trace_root), DEFAULT_TRACE_ROOT):
            path = latest_file(root, "catch-protocol-trace.jsonl")
            if path and path not in candidates:
                candidates.append(path)
        if not candidates:
            return None
        return max(candidates, key=lambda path: path.stat().st_mtime_ns)

    def _attach_trace(self, path: Path) -> None:
        self.current_path = path
        state = self.state_for_path(path)
        try:
            state["offset"] = path.stat().st_size
        except OSError:
            state["offset"] = 0
        state["buffer"] = ""
        state["sig"] = None
        self.log(f"结算补充文件: {path.name}（仅鱼名/重量，不触发报警）")

    def _resolve_final_index(self, fields: dict, *, zero_based_slot: bool = False) -> int | None:
        gear = safe_text(fields.get("gear")).lower()
        for idx, rod in enumerate(self.rods):
            if gear and rod.key.lower() == gear:
                return idx
        slot = safe_text(fields.get("slot"))
        if slot.isdigit():
            value = int(slot)
            # The trace uses zero only for its first slot; values 1-3 are
            # kept one-based when no gear UUID is available. Gear matching
            # above remains the authoritative path for all other slots.
            if zero_based_slot and value == 0:
                return 0
            if 1 <= value <= 3:
                return value - 1
        return None

    def _process_final_event(self, obj: dict) -> None:
        event_type = safe_text(obj.get("event") or obj.get("type")).lower()
        fields = obj.get("fields") if isinstance(obj.get("fields"), dict) else {}
        if event_type != "bite":
            return
        source = safe_text(fields.get("source")).lower()
        idx = self._resolve_final_index(fields, zero_based_slot=source == "result_dialog")
        if idx is None:
            return
        instance = safe_text(fields.get("instance") or fields.get("capture_id"), "unknown")
        if source != "result_dialog":
            # Only a validated fight_state is early enough to alert. Action
            # graph names and result UUIDs are not events by themselves.
            if source != "fight_state":
                return
            initialized = safe_text(fields.get("fight_initialized")).lower() in {"1", "true", "yes"}
            try:
                factor = float(safe_text(fields.get("fight_factor"), "0"))
                deadline = float(safe_text(fields.get("fight_deadline"), "nan"))
            except (TypeError, ValueError):
                return
            if not initialized or factor <= 0 or not (deadline == deadline) or deadline >= 3.0e38:
                return
            status_text = safe_text(
                fields.get("state")
                or fields.get("player_state")
                or obj.get("player_state")
                or obj.get("backend_state")
            )
            strike_ready = safe_text(
                fields.get("bobber_strike_ready") or fields.get("strike_ready")
            ).lower() in {"1", "true", "yes"}
            normalized = normalize_status(status_text)
            if normalized == STATE_SUCCESS:
                return
            status = STATE_SUGGEST if strike_ready or normalized == STATE_SUGGEST else STATE_BITE
            identity = instance if instance != "unknown" else safe_text(fields.get("fight"), "unknown")
            event_key = f"{identity}:{status}"
            if event_key in self.trace_alerted:
                return
            self.trace_alerted.add(event_key)
            rod = self.rods[idx]
            fish = safe_text(fields.get("fish") or fields.get("species"))
            weight_value = fields.get("weight") or fields.get("weight_g")
            rod.fish = fish or STATE_WAIT
            rod.weight = pretty_weight(weight_value) if safe_text(weight_value) else "0 g"
            try:
                rod.weight_g = float(weight_value) if safe_text(weight_value) else None
            except (TypeError, ValueError):
                rod.weight_g = None
            rod.rarity = safe_text(fields.get("rarity"))
            rod.grade = safe_text(fields.get("grade"))
            rod.flags = safe_text(fields.get("flags"))
            rod.catch_badge = catch_badge(rod.fish, rod.weight_g, rod.rarity, rod.grade, rod.flags) if (
                rod.fish != STATE_WAIT or rod.weight_g is not None or rod.rarity or rod.grade or rod.flags
            ) else ""
            rod.status = status
            rod.live_phase = "suggest" if status == STATE_SUGGEST else "fight"
            rod.live_instance = identity
            rod.fight_initialized = True
            rod.fight_factor = factor
            rod.fight_deadline = deadline
            rod.strike_ready = strike_ready
            rod.meta_status = status_text
            rod.last_event = "fight_state"
            rod.updated_at = time.time()
            self._emit_rod_if_changed(idx)
            self.alert_count += 1
            self.probe_count += 1
            details = live_fish_details(rod)
            self.emit(
                "alert",
                index=idx,
                kind="probe",
                status=status,
                fish=rod.fish,
                summary=f"U{idx + 1} {status}" + (f" · {details}" if details else ""),
                source=f"rf4_x64 实时内存 · {source}",
            )
            self.log(f"U{idx + 1} 早期鱼口: {short_text(status_text or status, 80)}")
            return
        rod = self.rods[idx]
        fish = safe_text(fields.get("fish") or fields.get("species"), STATE_WAIT)
        rod.fish = fish
        rod.weight = pretty_weight(fields.get("weight") or fields.get("weight_g"))
        try:
            rod.weight_g = float(fields.get("weight") or fields.get("weight_g"))
        except (TypeError, ValueError):
            rod.weight_g = None
        rod.rarity = safe_text(fields.get("rarity"))
        rod.grade = safe_text(fields.get("grade"))
        rod.flags = safe_text(fields.get("flags"))
        rod.catch_badge = catch_badge(rod.fish, rod.weight_g, rod.rarity, rod.grade, rod.flags)
        rod.status = STATE_SUCCESS
        rod.last_event = "result_dialog"
        rod.updated_at = time.time()
        self.final_until[idx] = time.time() + 6.0
        self.bite_active[rod.key] = False
        self.suggest_active[rod.key] = False
        if rod.key:
            self.result_suppressed.add(rod.key)
        self.strike_count += 1
        self._emit_rod_if_changed(idx)
        self.log(f"U{idx + 1} 结算补充: {fish} {rod.weight}")

    def scan_trace(self) -> None:
        # V1.08 is runtime-only.  Catch/protocol trace files are deliberately
        # excluded so a post-catch record can never generate a live alert.
        return

    def run(self) -> None:
        self.emit("status", text="连接实时内存")
        try:
            while not self.stop_event.is_set():
                try:
                    self.scan_memory()
                except Exception as exc:
                    self.emit("error", message=str(exc), trace=traceback.format_exc())
                self.stop_event.wait(max(0.03, min(0.15, self.cfg.poll_ms / 1000.0)))
        finally:
            self.memory.close()


# V1.02 independent build: removed the historical rf4db/backend monitor.
# Runtime data path is DirectMemorySource -> rf4_x64.exe only.

class App:
    def __init__(self):
        self.cfg = load_config()
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} V{APP_VERSION}")
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        default_x = max(0, (screen_width - HUD_WIDTH) // 2)
        x = self.cfg.window_x if self.cfg.window_x >= 0 else default_x
        x = min(max(0, x), max(0, screen_width - HUD_WIDTH))
        y = min(max(0, self.cfg.window_y), max(0, screen_height - HUD_HEIGHT))
        self.root.geometry(f"{HUD_WIDTH}x{HUD_HEIGHT}+{x}+{y}")
        self.root.minsize(HUD_WIDTH, HUD_HEIGHT)
        self.root.maxsize(HUD_WIDTH, HUD_HEIGHT)
        self.root.configure(bg=HUD_TRANSPARENT)
        self.root.overrideredirect(True)
        try:
            self.root.attributes("-transparentcolor", HUD_TRANSPARENT)
        except tk.TclError:
            self.root.configure(bg=HUD_BG)
        self.root.attributes("-topmost", self.cfg.topmost)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.monitor: threading.Thread | None = None
        self.toast = Toast(self.root)
        self.extra_windows: dict[str, tk.Toplevel] = {}

        self.total_alerts = 0
        self.last_alert = "-"
        self.last_source = "-"
        self.last_valid_source = "-"
        self.last_diagnostic_bundle = ""
        self.source_connected = False
        self.source_retrying = False
        self.source_data_ready = False
        self.source_waiting_mapping = False
        self.source_error = ""
        self.source_mode = "none"
        self.process_running = False
        self.rods = [RodState(index=i) for i in range(3)]
        self.env = EnvState()
        self.recent_lines: list[str] = []
        self._drag = {"x": 0, "y": 0, "active": False, "moved": False}

        self.clock_var = tk.StringVar(value=now_text())
        self.title_status_var = tk.StringVar(value="\u521d\u59cb\u5316\u4e2d")
        self.source_status_var = tk.StringVar(value="\u672a\u8fde\u63a5")
        self.footer_var = tk.StringVar(value="")
        self.header_source_var = tk.StringVar(value="")
        self.alert_var = tk.StringVar(value="\u63d0\u9192 0")

        self.card_views: list[dict[str, int]] = []
        self.hud_items: dict[str, int] = {}
        self.control_bounds: dict[str, tuple[int, int]] = {}
        self.status_color = GOOD
        self._build_ui()
        self.apply_config()

        self.root.bind("<Escape>", lambda e: self.on_close())
        self.root.after(120, self._pump_queue)
        self.root.after(1000, self._tick_clock)
        if self.cfg.auto_start_monitoring:
            self.start_monitoring()

    def _begin_drag(self, event):
        self._drag["x"] = event.x_root - self.root.winfo_x()
        self._drag["y"] = event.y_root - self.root.winfo_y()
        self._drag["active"] = True
        self._drag["moved"] = False

    def _drag_move(self, event):
        if not self.root.overrideredirect() or not self._drag.get("active"):
            return
        x = event.x_root - self._drag["x"]
        y = event.y_root - self._drag["y"]
        if abs(x - self.root.winfo_x()) > 1 or abs(y - self.root.winfo_y()) > 1:
            self._drag["moved"] = True
        self.root.geometry(f"+{x}+{y}")

    @staticmethod
    def _rounded_rect(canvas: tk.Canvas, x1: int, y1: int, x2: int, y2: int, radius: int, **kwargs) -> int:
        radius = min(radius, (x2 - x1) // 2, (y2 - y1) // 2)
        points = (
            x1 + radius, y1,
            x2 - radius, y1,
            x2, y1,
            x2, y1 + radius,
            x2, y2 - radius,
            x2, y2,
            x2 - radius, y2,
            x1 + radius, y2,
            x1, y2,
            x1, y2 - radius,
            x1, y1 + radius,
            x1, y1,
        )
        return canvas.create_polygon(points, smooth=True, splinesteps=24, **kwargs)

    def _build_ui(self) -> None:
        canvas = tk.Canvas(
            self.root,
            width=HUD_WIDTH,
            height=HUD_HEIGHT,
            bg=HUD_TRANSPARENT,
            highlightthickness=0,
            bd=0,
        )
        canvas.pack(fill="both", expand=True)
        self.hud_canvas = canvas

        self._rounded_rect(canvas, 4, 5, HUD_WIDTH - 2, HUD_HEIGHT - 1, 20, fill=HUD_SHADOW, outline="")
        self._rounded_rect(
            canvas,
            2,
            2,
            HUD_WIDTH - 4,
            HUD_HEIGHT - 4,
            20,
            fill=HUD_BG,
            outline=HUD_BORDER,
            width=1,
        )

        self.hud_items["dot"] = canvas.create_oval(15, 19, 23, 27, fill=MUTED, outline="")
        self.hud_items["brand"] = canvas.create_text(
            31,
            23,
            text="RF4-DSen",
            anchor="w",
            fill="#cbd5e1",
            font=("Consolas", 9, "bold"),
        )
        canvas.create_line(88, 12, 88, 34, fill="#1e293b")

        rod_start = 98
        for idx in range(3):
            x1 = rod_start + idx * (HUD_ROD_WIDTH + 6)
            x2 = x1 + HUD_ROD_WIDTH
            bg_id = self._rounded_rect(
                canvas,
                x1,
                8,
                x2,
                38,
                14,
                fill="#101725",
                outline="#1e293b",
                width=1,
            )
            unit_bg = self._rounded_rect(canvas, x1 + 7, 13, x1 + 34, 33, 6, fill="#1e293b", outline="")
            unit = canvas.create_text(x1 + 20, 23, text=f"U{idx + 1}", fill="#94a3b8", font=("Consolas", 8, "bold"))
            distance = canvas.create_text(x1 + 42, 23, text="--", anchor="w", fill="#94a3b8", font=("Consolas", 8, "bold"))
            primary = canvas.create_text(x1 + 78, 23, text=STATE_IDLE, anchor="w", fill="#64748b", font=("Microsoft YaHei UI", 8, "bold"))
            badge = canvas.create_text(x2 - 50, 23, text="", anchor="e", fill="#94a3b8", font=("Microsoft YaHei UI", 7, "bold"))
            weight = canvas.create_text(x2 - 8, 23, text="0g", anchor="e", fill="#475569", font=("Consolas", 8, "bold"))
            self.card_views.append(
                {
                    "bg": bg_id,
                    "unit_bg": unit_bg,
                    "unit": unit,
                    "distance": distance,
                    "primary": primary,
                    "badge": badge,
                    "weight": weight,
                }
            )

        control_start = rod_start + 3 * HUD_ROD_WIDTH + 2 * 6 + 10
        canvas.create_line(control_start, 12, control_start, 34, fill="#1e293b")
        self.hud_items["count"] = canvas.create_text(
            control_start + 26,
            23,
            text="0",
            fill="#94a3b8",
            font=("Consolas", 8, "bold"),
        )
        self.hud_items["menu"] = canvas.create_text(control_start + 61, 21, text="···", fill="#94a3b8", font=("Segoe UI", 11, "bold"))
        self.hud_items["settings"] = canvas.create_text(control_start + 91, 23, text="⚙", fill="#94a3b8", font=("Segoe UI Symbol", 10))
        self.hud_items["close"] = canvas.create_text(control_start + 121, 22, text="×", fill="#94a3b8", font=("Segoe UI", 12, "bold"))
        self.control_bounds = {
            "count": (control_start + 4, control_start + 47),
            "menu": (control_start + 48, control_start + 76),
            "settings": (control_start + 77, control_start + 106),
            "close": (control_start + 107, HUD_WIDTH - 5),
        }

        self.hud_menu = tk.Menu(
            self.root,
            tearoff=0,
            bg="#111827",
            fg=TEXT,
            activebackground="#26354d",
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            font=("Microsoft YaHei UI", 9),
        )
        self.hud_menu.add_command(label="采集诊断", command=self.collect_diagnostics)
        self.hud_menu.add_command(label="诊断", command=self.open_diagnostics)
        self.hud_menu.add_command(label="统计", command=self.open_stats)
        self.hud_menu.add_command(label="雷达", command=self.open_radar)
        self.hud_menu.add_command(label="RF4资料", command=self.open_reference)
        self.hud_menu.add_separator()
        self.hud_menu.add_command(label="测试提醒", command=self.test_alert)
        self.hud_menu.add_command(label="停止监听", command=self.toggle_monitoring)
        self._monitor_menu_index = self.hud_menu.index("end")

        canvas.bind("<ButtonPress-1>", self._hud_press)
        canvas.bind("<B1-Motion>", self._drag_move)
        canvas.bind("<ButtonRelease-1>", self._hud_release)
        canvas.bind("<Motion>", self._hud_motion)
        canvas.bind("<Leave>", lambda _event: self._set_control_hover(None))
        canvas.bind("<Button-3>", self._show_hud_menu)

    def _control_at(self, x: int) -> str | None:
        for name, (left, right) in self.control_bounds.items():
            if left <= x <= right:
                return name
        return None

    def _hud_press(self, event) -> None:
        if self._control_at(event.x) is None:
            self._begin_drag(event)
        else:
            self._drag["active"] = False
            self._drag["moved"] = False

    def _hud_release(self, event) -> None:
        was_dragging = bool(self._drag.get("active"))
        moved = bool(self._drag.get("moved"))
        self._drag["active"] = False
        if was_dragging:
            if moved:
                self.cfg.window_x = self.root.winfo_x()
                self.cfg.window_y = self.root.winfo_y()
                save_config(self.cfg)
            return
        action = self._control_at(event.x)
        if action == "count":
            self.open_stats()
        elif action == "menu":
            self._show_hud_menu(event)
        elif action == "settings":
            self.open_settings()
        elif action == "close":
            self.on_close()

    def _hud_motion(self, event) -> None:
        self._set_control_hover(self._control_at(event.x))

    def _set_control_hover(self, active: str | None) -> None:
        if not hasattr(self, "hud_canvas"):
            return
        for name in ("count", "menu", "settings", "close"):
            color = "#fb7185" if name == "close" and active == name else "#e2e8f0" if active == name else "#94a3b8"
            self.hud_canvas.itemconfigure(self.hud_items[name], fill=color)

    def _set_status_dot(self, color: str | None = None) -> None:
        if not hasattr(self, "hud_canvas") or "dot" not in self.hud_items:
            return
        self.hud_canvas.itemconfigure(self.hud_items["dot"], fill=color or self.status_color)

    def _show_hud_menu(self, event) -> None:
        label = "停止监听" if self.monitor and self.monitor.is_alive() else "开始监听"
        self.hud_menu.entryconfigure(self._monitor_menu_index, label=label)
        try:
            self.hud_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.hud_menu.grab_release()

    def toggle_monitoring(self) -> None:
        if self.monitor and self.monitor.is_alive():
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def apply_config(self) -> None:
        self.root.attributes("-topmost", bool(self.cfg.topmost))
        save_config(self.cfg)
        self.refresh_footer()

    def refresh_footer(self) -> None:
        source_text = self.last_source if self.last_source != "-" else "\u672a\u8fde\u63a5"
        self.footer_var.set(f"v{APP_VERSION}  |  \u6e90: {short_text(source_text, 54)}")
        if self.source_connected:
            source_state = "\u5df2\u8fde\u63a5" if self.source_data_ready else "\u7b49\u5f85\u7aff\u4f4d\u6620\u5c04"
        elif self.source_retrying:
            source_state = "\u77ed\u6682\u91cd\u8bd5"
        else:
            source_state = "\u672a\u8fde\u63a5"
        process_state = "\u8fd0\u884c\u4e2d" if self.process_running else "\u672a\u8fd0\u884c"
        self.source_status_var.set(f"{self.cfg.process_name} \u00b7 {process_state} · {source_state}")

    def set_status(self, text: str, color: str) -> None:
        self.title_status_var.set(text)
        self.status_color = color
        self._set_status_dot(color)

    def start_monitoring(self) -> None:
        self.apply_config()
        if self.monitor and self.monitor.is_alive():
            return
        self.stop_event = threading.Event()
        self.monitor = RF4Monitor(self.queue, self.stop_event, self.cfg)
        self.monitor.start()
        self.push_recent("\u7cfb\u7edf", "\u5f00\u59cb\u76d1\u542c")
        self.set_status("\u76d1\u542c\u4e2d", GOOD)

    def stop_monitoring(self) -> None:
        monitor = self.monitor
        if monitor:
            self.stop_event.set()
            try:
                monitor.join(timeout=2.5)
            except RuntimeError:
                pass
        self.monitor = None
        self.push_recent("\u7cfb\u7edf", "\u5df2\u505c\u6b62\u76d1\u542c")
        self.set_status("\u5df2\u505c\u6b62", MUTED)

    def push_recent(self, tag: str, text: str) -> None:
        self.recent_lines.append(f"[{ts_text()}] [{tag}] {text}")
        if len(self.recent_lines) > MAX_RECENT_LINES:
            self.recent_lines = self.recent_lines[-MAX_RECENT_LINES:]

    @staticmethod
    def _sanitize_display_rod(rod: RodState) -> bool:
        """Make the HUD state reflect only a currently inserted, cast rig."""
        live_rod = bool(rod.memory_valid and rod.in_water and rod.session)
        if live_rod:
            return True
        rod.status = STATE_REEL
        rod.fish = STATE_WAIT
        rod.weight = "0 g"
        rod.weight_g = None
        rod.rarity = ""
        rod.grade = ""
        rod.flags = ""
        rod.catch_badge = ""
        rod.live_phase = ""
        rod.live_instance = ""
        rod.fight_initialized = False
        rod.fight_factor = 0.0
        rod.fight_deadline = None
        rod.meta_status = ""
        rod.owner_live = False
        rod.fish_graph_live = False
        rod.strike_ready = False
        rod.memory_valid = False
        rod.in_water = False
        rod.session = False
        rod.distance = ""
        rod.memory_root = ""
        rod.key = ""
        rod.slot = ""
        return False

    def render_cards(self) -> None:
        for idx, rod in enumerate(self.rods):
            view = self.card_views[idx]
            live_rod = self._sanitize_display_rod(rod)
            status = rod.status or STATE_IDLE
            bg, border, status_fg = palette_for_status(status)
            self.hud_canvas.itemconfigure(view["bg"], fill=bg, outline=border)
            unit_fill = "#4c2f79" if status in {STATE_PROBE, STATE_BITE, STATE_SUGGEST} else "#20553d" if status == STATE_SUCCESS else "#1e293b"
            unit_fg = "#e9d5ff" if status in {STATE_PROBE, STATE_BITE, STATE_SUGGEST} else GOOD if status == STATE_SUCCESS else "#94a3b8"
            self.hud_canvas.itemconfigure(view["unit_bg"], fill=unit_fill)
            self.hud_canvas.itemconfigure(view["unit"], fill=unit_fg)

            # A timestamp is not a fishing distance. Only memory/trace distance is valid here.
            distance = rod.distance or "--"
            self.hud_canvas.itemconfigure(
                view["distance"],
                text=short_text(distance, 6),
                fill=status_fg if status != STATE_IDLE else "#94a3b8",
            )

            fish = safe_text(rod.fish) if live_rod else ""
            has_real_fish = bool(
                live_rod and fish and fish not in {STATE_WAIT, STATE_IDLE, STATE_SUCCESS, STATE_REEL}
            )
            if status in {STATE_BITE, STATE_SUGGEST, STATE_SUCCESS} and has_real_fish:
                primary_text = short_text(fish, 5)
                primary_fg = GOOD if status == STATE_SUCCESS else status_fg
            elif live_rod and status == STATE_IDLE:
                primary_text = "等鱼"
                primary_fg = "#64748b"
            elif not live_rod and rod.last_event == "浮钓未映射":
                primary_text = "浮钓未映射"
                primary_fg = WARN
            elif not live_rod:
                primary_text = "无竿"
                primary_fg = "#475569"
            else:
                primary_text = short_text(status, 7)
                primary_fg = status_fg
            self.hud_canvas.itemconfigure(view["primary"], text=primary_text, fill=primary_fg)

            weight_text = compact_weight(rod.weight) if live_rod and status in {STATE_BITE, STATE_SUGGEST, STATE_SUCCESS} and has_real_fish and rod.weight_g is not None else ("--" if live_rod and status in {STATE_BITE, STATE_SUGGEST, STATE_SUCCESS} and has_real_fish else "0g")
            weight_fg = GOOD if status == STATE_SUCCESS else status_fg if has_real_fish else "#475569"
            self.hud_canvas.itemconfigure(view["weight"], text=weight_text, fill=weight_fg)
            badge = compact_badge(rod.catch_badge) if live_rod and has_real_fish else ""
            badge_color = {
                "达标": GOOD,
                "稀有": "#c084fc",
                "星鱼": "#facc15",
                "超稀有": "#f0abfc",
                "待确认": WARN,
            }.get(badge, "#94a3b8")
            self.hud_canvas.itemconfigure(view["badge"], text=badge, fill=badge_color)

        self.hud_canvas.itemconfigure(self.hud_items["count"], text=str(self.total_alerts))
        self._set_status_dot()

    def record_alert(
        self,
        idx: int,
        kind: str,
        status: str,
        fish: str,
        source: str,
        summary: str = "",
    ) -> None:
        self.total_alerts += 1
        line = summary or (f"U{idx + 1} {status}" if 0 <= idx < len(self.rods) else f"{status}")
        if not summary and fish and fish != STATE_WAIT:
            line += f" \u00b7 {fish}"
        line += f" ({source})"
        self.last_alert = line
        self.alert_var.set(f"\u63d0\u9192 {self.total_alerts}")
        self.push_recent("\u63d0\u9192", line)
        self.set_status(status, WARN if kind == "probe" else GOOD)
        if self.cfg.sound_enabled:
            self.beep()
        if self.cfg.popup_enabled:
            self.toast.show(f"RF4 {status}", line)
        self.root.lift()
        self.render_cards()

    def beep(self) -> None:
        if winsound is None:
            try:
                self.root.bell()
            except Exception:
                pass
            return
        try:
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            winsound.Beep(980, 100)
        except Exception:
            try:
                winsound.MessageBeep()
            except Exception:
                pass

    def handle_snapshot(self, event: dict) -> None:
        rods = event.get("rods") if isinstance(event.get("rods"), list) else []
        env = event.get("env") if isinstance(event.get("env"), dict) else {}
        # A snapshot is authoritative. Rebuild all slots so a missing rod can
        # never inherit the previous snapshot's fish, weight, or badge.
        new_rods = [RodState(index=i) for i in range(3)]
        for idx, item in enumerate(rods[:3]):
            try:
                new_rods[idx] = RodState(**item)
            except Exception:
                pass
        for rod in new_rods:
            self._sanitize_display_rod(rod)
        self.rods = new_rods
        if env:
            try:
                self.env = EnvState(**env)
            except Exception:
                pass
        self.render_cards()
        self.refresh_footer()

    def handle_rod(self, event: dict) -> None:
        idx = int(event.get("index") or 0)
        rod = event.get("rod") if isinstance(event.get("rod"), dict) else None
        if rod is None or not (0 <= idx < len(self.rods)):
            return
        try:
            new_rod = RodState(**rod)
        except Exception:
            return
        self._sanitize_display_rod(new_rod)
        self.rods[idx] = new_rod
        self.render_cards()
        self.refresh_footer()

    def handle_environment(self, event: dict) -> None:
        env = event.get("env") if isinstance(event.get("env"), dict) else None
        if env is None:
            return
        try:
            self.env = EnvState(**env)
        except Exception:
            return
        self.refresh_footer()

    def handle_alert(self, event: dict) -> None:
        try:
            idx = int(event.get("index", -1))
        except (TypeError, ValueError):
            idx = -1
        kind = safe_text(event.get("alert_kind"), "bite")
        status = safe_text(event.get("status"), STATE_SUGGEST)
        fish = safe_text(event.get("fish"))
        source = safe_text(event.get("source"), self.last_source or "timeline")
        summary = safe_text(event.get("summary"))
        self.record_alert(idx, kind, status, fish, source, summary)

    def handle_process(self, event: dict) -> None:
        running = bool(event.get("running"))
        pname = safe_text(event.get("process_name"), self.cfg.process_name)
        self.process_running = running
        self.push_recent("\u8fdb\u7a0b", f"{pname} {'\u8fd0\u884c\u4e2d' if running else '\u672a\u8fd0\u884c'}")
        self.refresh_footer()
        self.set_status(self.title_status_var.get(), GOOD if running else WARN)

    def handle_source(self, event: dict) -> None:
        mode = safe_text(event.get("mode"), "none")
        path = safe_text(event.get("path"))
        ready = bool(event.get("ready"))
        connected = bool(event.get("connected", ready))
        data_ready = bool(event.get("data_ready", connected))
        error = safe_text(event.get("error"))
        self.source_mode = mode
        if path:
            self.last_valid_source = short_text(path, 60)
        self.source_connected = connected
        self.source_data_ready = data_ready
        self.source_retrying = (not connected) and bool(self.process_running and self.last_valid_source != "-")
        self.source_waiting_mapping = connected and not data_ready
        self.source_error = error
        self.last_source = self.last_valid_source if self.last_valid_source != "-" else "\u672a\u8fde\u63a5"
        if connected and ready and data_ready:
            self.push_recent("\u6570\u636e\u6e90", f"{mode} · {self.last_source}")
            self.set_status("\u76d1\u542c\u4e2d", GOOD)
        elif self.source_waiting_mapping:
            self.set_status("\u7b49\u5f85\u7aff\u4f4d\u6620\u5c04", WARN)
        elif error:
            self.set_status(short_text(error, 24), WARN)
        elif self.source_retrying:
            self.set_status("\u91cd\u8bd5\u5b9e\u65f6\u5185\u5b58", WARN)
        else:
            self.set_status("\u672a\u627e\u5230\u6570\u636e", WARN)
        self.refresh_footer()

    def handle_status(self, event: dict) -> None:
        text = safe_text(event.get("text"))
        if text:
            self.set_status(text, self.status_color)

    def handle_log(self, event: dict) -> None:
        line = safe_text(event.get("line"))
        if line:
            self.recent_lines.append(line)
            if len(self.recent_lines) > MAX_RECENT_LINES:
                self.recent_lines = self.recent_lines[-MAX_RECENT_LINES:]

    def handle_error(self, event: dict) -> None:
        message = safe_text(event.get("message"), "unknown")
        trace = safe_text(event.get("trace"))
        self.push_recent("\u9519\u8bef", message)
        self.set_status("\u5f02\u5e38", ALERT)
        if trace:
            self.recent_lines.append(trace)

    def build_diagnostic_payload(self) -> dict[str, object]:
        runtime = dict(getattr(self.monitor, "runtime_diagnostics", {}) or {}) if self.monitor else {}
        memory_debug: dict[str, object] = {}
        if self.monitor and getattr(self.monitor, "memory", None):
            try:
                debug_state = getattr(self.monitor.memory, "debug_state", None)
                if callable(debug_state):
                    memory_debug = dict(debug_state() or {})
            except Exception as exc:
                memory_debug = {"error": safe_text(exc), "trace": traceback.format_exc()}
        process_lookup: dict[str, object] = {}
        try:
            found = find_rf4_process(self.cfg.process_name)
            if found:
                process_lookup = {"pid": found[0], "path": found[1]}
            else:
                process_lookup = {"pid": 0, "path": ""}
        except Exception as exc:
            process_lookup = {"error": safe_text(exc)}
        return {
            "app": {
                "name": APP_NAME,
                "version": APP_VERSION,
                "time": ts_text(),
                "executable": sys.executable,
                "argv": sys.argv,
                "cwd": os.getcwd(),
                "python": sys.version,
                "platform": platform.platform(),
                "app_data_dir": str(APP_DATA_DIR),
            },
            "process": {
                "configured_name": self.cfg.process_name,
                "running": self.process_running,
                "lookup": process_lookup,
            },
            "source": {
                "mode": self.source_mode,
                "last_source": self.last_source,
                "last_valid_source": self.last_valid_source,
                "connected": self.source_connected,
                "data_ready": self.source_data_ready,
                "waiting_mapping": self.source_waiting_mapping,
                "retrying": self.source_retrying,
                "error": self.source_error,
            },
            "config": asdict(self.cfg),
            "hud": {
                "title_status": self.title_status_var.get(),
                "source_status": self.source_status_var.get(),
                "footer": self.footer_var.get(),
                "window": {
                    "x": self.root.winfo_x(),
                    "y": self.root.winfo_y(),
                    "width": self.root.winfo_width(),
                    "height": self.root.winfo_height(),
                    "topmost": self.cfg.topmost,
                },
            },
            "alerts": {
                "total": self.total_alerts,
                "last": self.last_alert,
                "probe_count": getattr(self.monitor, "probe_count", 0) if self.monitor else 0,
                "strike_count": getattr(self.monitor, "strike_count", 0) if self.monitor else 0,
            },
            "environment": asdict(self.env),
            "rods": [asdict(rod) for rod in self.rods],
            "recent_lines": list(self.recent_lines[-MAX_RECENT_LINES:]),
            "runtime_diagnostics": runtime,
            "direct_memory_state": memory_debug,
        }

    def build_diagnostics_text(self) -> str:
        runtime = getattr(self.monitor, "runtime_diagnostics", {}) if self.monitor else {}
        sha256 = safe_text(runtime.get("game_assembly_sha256"))
        base = runtime.get("game_assembly_base")
        cache_rva = runtime.get("class_cache_rva")

        def hex_value(value: object) -> str:
            return f"0x{value:X}" if isinstance(value, int) and value else "-"

        def mib(value: object) -> str:
            return f"{value / 1048576:.0f} MiB" if isinstance(value, int) else "-"

        lines = [
            f"{APP_NAME} {APP_VERSION}",
            f"\u65f6\u95f4: {ts_text()}",
            f"\u8fdb\u7a0b: {self.cfg.process_name} \u00b7 {'\u8fd0\u884c\u4e2d' if self.process_running else '\u672a\u8fd0\u884c'}",
            f"\u6570\u636e\u6e90: {self.source_mode}",
            f"\u5b9e\u65f6\u6765\u6e90: {self.last_source}",
            f"\u63d0\u9192\u6570: {self.total_alerts}",
            "",
            "[RF4 / Build / Layout]",
            f"RF4 build: {runtime.get('game_build', '-')}",
            f"GameAssembly SHA-256: {sha256 or '-'}",
            f"GameAssembly: base={hex_value(base)} · image={mib(runtime.get('game_assembly_image_size'))} · file={mib(runtime.get('game_assembly_file_size'))}",
            f"class cache: status={runtime.get('class_cache_status', '-')} · rva={hex_value(cache_rva)} · valid={runtime.get('class_cache_valid', '-')} · classes={runtime.get('class_cache_classes', '-')}",
            f"runtime: regions={runtime.get('runtime_regions', '-')} · size={mib(runtime.get('runtime_bytes'))} · discovered={runtime.get('discovered_classes', '-')}",
            f"hotbar: status={runtime.get('hotbar_status', '-')} · candidates={runtime.get('hotbar_array_candidates', '-')} · mapped={runtime.get('hotbar_mapped_sets', '-')}",
            f"rigs: {runtime.get('rigs', '-')} · discovery={runtime.get('discovery_ms', '-')} ms",
            f"discovery: status={runtime.get('discovery_status', '-')} · thread={runtime.get('discovery_thread_alive', False)} · attempts={runtime.get('discovery_attempts', '-')}",
            f"discovery error: {runtime.get('discovery_error', '-')}",
            "",
            "[\u73af\u5883]",
            f"\u5730\u56fe: {self.env.map_id or '-'}",
            f"\u5750\u6807: {self.env.coordinate or '-'}",
            f"\u65f6\u95f4: {self.env.time or '-'}",
            f"\u5929\u6c14: {self.env.weather or '-'}",
            f"\u6e29\u5ea6: {self.env.temperature or '-'}",
            f"\u98ce: {self.env.wind or '-'}",
            f"clip: {self.env.clip or '-'}",
            "",
            "[\u9c7c\u7aff]",
        ]
        for i, rod in enumerate(self.rods, start=1):
            lines.append(f"U{i}: {rod.status} / {rod.fish} / {rod.weight} / {rod.hook} / {rod.bait} / {rod.groundbait or '-'} / {rod.rig_type or '-'}")
        lines.extend(
            [
                "",
                "[\u8bca\u65ad\u6536\u96c6]",
                f"\u6700\u8fd1\u8bca\u65ad\u5305: {self.last_diagnostic_bundle or '-'}",
                f"\u8bca\u65ad\u76ee\u5f55: {DIAGNOSTIC_DIR}",
                "\u70b9\u51fb\u83dc\u5355\u300c\u91c7\u96c6\u8bca\u65ad\u300d\u540e\uff0c\u628a\u751f\u6210\u7684 zip \u53d1\u7ed9 Codex\u3002",
                "",
                "[runtime raw]",
            ]
        )
        if runtime:
            for key in sorted(runtime):
                value = runtime.get(key)
                lines.append(f"{key}: {value}")
        else:
            lines.append("(none)")
        lines.extend(["", "[\u6700\u8fd1\u4e8b\u4ef6]"])
        lines.extend(self.recent_lines[-20:] or ["(\u65e0)"])
        return "\n".join(lines)

    def build_stats_text(self) -> str:
        lines = [
            f"\u603b\u63d0\u9192: {self.total_alerts}",
            f"\u8bd5\u63a2\u63d0\u9192: {self.monitor.probe_count if self.monitor else 0}",
            f"\u4e2d\u9c7c\u63d0\u9192: {self.monitor.strike_count if self.monitor else 0}",
            f"\u6570\u636e\u6e90: {self.source_mode}",
            f"\u76d1\u542c\u72b6\u6001: {'\u5df2\u8fde\u63a5' if self.source_connected and self.source_data_ready else '\u7b49\u5f85\u7aff\u4f4d\u6620\u5c04' if self.source_waiting_mapping else '\u77ed\u6682\u91cd\u8bd5' if self.source_retrying else '\u672a\u8fde\u63a5'}",
            f"\u5b9e\u65f6\u6e90: {self.last_source}",
            f"\u6700\u8fd1\u8bfb\u53d6\u9519\u8bef: {self.source_error or '-'}",
            "",
        ]
        for i, rod in enumerate(self.rods, start=1):
            lines.append(f"U{i}: {rod.status} / {rod.fish} / {rod.weight}")
        return "\n".join(lines)

    def build_radar_text(self) -> str:
        lines = [f"\u5f53\u524d\u72b6\u6001  {self.title_status_var.get()}", ""]
        for i, rod in enumerate(self.rods, start=1):
            lines.append(f"U{i}  {rod.status}")
            lines.append(f"  {rod.fish}")
            lines.append(f"  {rod.hook}  {rod.bait}")
        return "\n".join(lines)

    def open_text_window(self, key: str, title: str, builder, actions=None) -> None:
        win = self.extra_windows.get(key)
        if win and win.winfo_exists():
            win.lift()
            win.focus_force()
            return
        win = tk.Toplevel(self.root)
        self.extra_windows[key] = win
        win.title(title)
        win.geometry("520x420")
        win.configure(bg=BG)

        head = tk.Frame(win, bg=BG)
        head.pack(fill="x", padx=10, pady=(10, 6))
        tk.Label(head, text=title, fg=ACCENT, bg=BG, font=("Segoe UI", 12, "bold")).pack(side="left")
        tk.Button(
            head,
            text="\u5173\u95ed",
            command=win.destroy,
            bg="#1a2740",
            fg=TEXT,
            activebackground="#2b3d5d",
            relief="flat",
            bd=0,
            padx=10,
            pady=2,
            font=("Segoe UI", 9),
        ).pack(side="right")
        for label, command in actions or []:
            tk.Button(
                head,
                text=label,
                command=command,
                bg="#1c6f63",
                fg=TEXT,
                activebackground="#248476",
                relief="flat",
                bd=0,
                padx=10,
                pady=2,
                font=("Segoe UI", 9),
            ).pack(side="right", padx=(0, 6))

        text = tk.Text(
            win,
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=LINE,
            font=("Consolas", 9),
            wrap="word",
        )
        text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        def refresh() -> None:
            if not win.winfo_exists():
                return
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.insert("end", builder())
            text.configure(state="disabled")
            win.after(650, refresh)

        refresh()
        win.protocol("WM_DELETE_WINDOW", win.destroy)

    def collect_diagnostics(self) -> None:
        try:
            payload = self.build_diagnostic_payload()
            extra: dict[str, str] = {}
            try:
                if CONFIG_FILE.exists():
                    extra["config.json"] = CONFIG_FILE.read_text(encoding="utf-8", errors="ignore")
            except Exception as exc:
                extra["config-read-error.txt"] = safe_text(exc)
            zip_path = write_diagnostic_bundle(
                DIAGNOSTIC_DIR,
                f"RF4-DSen-V{APP_VERSION}-diagnostic",
                self.build_diagnostics_text(),
                payload,
                extra_text_files=extra,
            )
            self.last_diagnostic_bundle = str(zip_path)
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(str(zip_path))
            except Exception:
                pass
            self.push_recent("\u8bca\u65ad", f"\u5df2\u751f\u6210 {zip_path}")
            self.set_status("\u8bca\u65ad\u5df2\u91c7\u96c6", GOOD)
            messagebox.showinfo(
                "\u8bca\u65ad\u6536\u96c6",
                f"\u5df2\u751f\u6210\u8bca\u65ad\u5305\uff0c\u8def\u5f84\u5df2\u590d\u5236\u5230\u526a\u8d34\u677f\uff1a\n{zip_path}",
            )
            try:
                os.startfile(str(zip_path.parent))  # type: ignore[attr-defined]
            except Exception:
                pass
        except Exception as exc:
            self.push_recent("\u8bca\u65ad", f"\u91c7\u96c6\u5931\u8d25: {exc}")
            messagebox.showerror("\u8bca\u65ad\u6536\u96c6", f"\u91c7\u96c6\u5931\u8d25\uff1a{exc}")

    def open_diagnostics(self) -> None:
        self.open_text_window(
            "diagnostics",
            "\u8bca\u65ad",
            self.build_diagnostics_text,
            actions=[("\u91c7\u96c6\u8bca\u65ad", self.collect_diagnostics)],
        )

    def open_stats(self) -> None:
        self.open_text_window("stats", "\u7edf\u8ba1", self.build_stats_text)

    def open_radar(self) -> None:
        self.open_text_window("radar", "\u96f7\u8fbe", self.build_radar_text)

    def open_reference(self) -> None:
        win = self.extra_windows.get("reference")
        if win and win.winfo_exists():
            win.lift()
            win.focus_force()
            return

        win = tk.Toplevel(self.root)
        self.extra_windows["reference"] = win
        win.title("RF4资料")
        win.geometry("680x520")
        win.minsize(560, 420)
        win.configure(bg=BG)

        current_fish = next(
            (rod.fish for rod in self.rods if rod.fish and rod.fish != STATE_WAIT),
            "",
        )
        query_var = tk.StringVar(value=current_fish)
        status_var = tk.StringVar(value=f"本地鱼种索引 {len(FISH_THRESHOLDS)} 条")

        toolbar = tk.Frame(win, bg=BG)
        toolbar.pack(fill="x", padx=12, pady=(12, 8))
        entry = tk.Entry(
            toolbar,
            textvariable=query_var,
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Microsoft YaHei UI", 10),
        )
        entry.pack(side="left", fill="x", expand=True, ipady=6)

        body = tk.Frame(win, bg=BG)
        body.pack(fill="both", expand=True, padx=12)
        results = tk.Listbox(
            body,
            width=31,
            bg=PANEL,
            fg=TEXT,
            selectbackground="#26354d",
            selectforeground=TEXT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=LINE,
            exportselection=False,
            font=("Microsoft YaHei UI", 9),
        )
        results.pack(side="left", fill="both")
        details = tk.Text(
            body,
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=LINE,
            wrap="word",
            font=("Microsoft YaHei UI", 10),
            state="disabled",
        )
        details.pack(side="left", fill="both", expand=True, padx=(8, 0))
        matched: list[tuple[str, dict]] = []

        def selected_query() -> str:
            selection = results.curselection()
            if selection and selection[0] < len(matched):
                fish_id, row = matched[selection[0]]
                return safe_text(row.get("name_zh")) or fish_id
            return query_var.get().strip()

        def show_details(_event=None) -> None:
            selection = results.curselection()
            details.configure(state="normal")
            details.delete("1.0", "end")
            if selection and selection[0] < len(matched):
                fish_id, row = matched[selection[0]]
                name = safe_text(row.get("name_zh"), fish_id)
                details.insert(
                    "end",
                    f"{name}\n\n"
                    f"内部 ID: {fish_id}\n"
                    f"达标线: {reference_weight(row.get('qualified_weight_g'))}\n"
                    f"奖杯线: {reference_weight(row.get('star_weight_g'))}\n"
                    f"蓝冠线: {reference_weight(row.get('blue_crown_weight_g'))}\n\n"
                    "RF4DB：鱼种、地图、点位和饵料资料\n"
                    "RF4-STAT：玩家渔获与活跃点位资料",
                )
            else:
                details.insert("end", "没有匹配的本地鱼种。仍可用下方按钮打开网站查询。")
            details.configure(state="disabled")

        def refresh_results(_event=None) -> None:
            nonlocal matched
            matched = fish_reference_matches(query_var.get())
            results.delete(0, "end")
            for fish_id, row in matched:
                results.insert("end", f"{safe_text(row.get('name_zh'), fish_id)}  [{fish_id}]")
            status_var.set(f"匹配 {len(matched)} 条 · 本地索引共 {len(FISH_THRESHOLDS)} 条")
            if matched:
                results.selection_set(0)
                results.activate(0)
            show_details()

        def open_site(site: str) -> None:
            rf4db_url, rf4stat_url = fish_reference_urls(selected_query())
            webbrowser.open(rf4db_url if site == "rf4db" else rf4stat_url)

        tk.Button(
            toolbar,
            text="搜索",
            command=refresh_results,
            bg="#1c6f63",
            fg=TEXT,
            activebackground="#248476",
            relief="flat",
            bd=0,
            padx=14,
            pady=6,
        ).pack(side="left", padx=(8, 0))

        footer = tk.Frame(win, bg=BG)
        footer.pack(fill="x", padx=12, pady=(8, 12))
        tk.Label(footer, textvariable=status_var, fg=MUTED, bg=BG, anchor="w").pack(side="left")
        for label, site in (("RF4-STAT", "rf4stat"), ("RF4DB", "rf4db")):
            tk.Button(
                footer,
                text=label,
                command=lambda value=site: open_site(value),
                bg="#1a2740",
                fg=TEXT,
                activebackground="#2b3d5d",
                relief="flat",
                bd=0,
                padx=12,
                pady=5,
            ).pack(side="right", padx=(8, 0))

        entry.bind("<Return>", refresh_results)
        results.bind("<<ListboxSelect>>", show_details)
        results.bind("<Double-Button-1>", lambda _event: open_site("rf4db"))
        refresh_results()
        entry.focus_set()
        win.protocol("WM_DELETE_WINDOW", win.destroy)

    def open_settings(self) -> None:
        win = self.extra_windows.get("settings")
        if win and win.winfo_exists():
            win.lift()
            win.focus_force()
            return

        win = tk.Toplevel(self.root)
        self.extra_windows["settings"] = win
        win.title("\u8bbe\u7f6e")
        win.geometry("520x280")
        win.configure(bg=BG)

        body = tk.Frame(win, bg=BG)
        body.pack(fill="both", expand=True, padx=10, pady=10)

        def row(label_text: str, value_var: tk.StringVar, browse=None) -> None:
            container = tk.Frame(body, bg=BG)
            container.pack(fill="x", pady=4)
            tk.Label(container, text=label_text, fg=TEXT, bg=BG, width=12, anchor="w").pack(side="left")
            tk.Entry(container, textvariable=value_var, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat").pack(
                side="left", fill="x", expand=True, padx=(0, 6)
            )
            if browse:
                tk.Button(
                    container,
                    text="\u9009\u62e9",
                    command=browse,
                    bg="#1a2740",
                    fg=TEXT,
                    activebackground="#2b3d5d",
                    relief="flat",
                    bd=0,
                    padx=10,
                    pady=2,
                ).pack(side="left")

        process_var = tk.StringVar(value=self.cfg.process_name)
        poll_var = tk.StringVar(value=str(self.cfg.poll_ms))
        process_on = tk.BooleanVar(value=self.cfg.monitor_process)
        sound_on = tk.BooleanVar(value=self.cfg.sound_enabled)
        popup_on = tk.BooleanVar(value=self.cfg.popup_enabled)
        topmost_on = tk.BooleanVar(value=self.cfg.topmost)
        autostart_on = tk.BooleanVar(value=self.cfg.auto_start_monitoring)

        row("\u8fdb\u7a0b\u540d", process_var)
        row("\u8f6e\u8be2(ms)", poll_var)

        checks = tk.Frame(body, bg=BG)
        checks.pack(fill="x", pady=(8, 4))
        for text, var in (
            ("\u76d1\u63a7\u8fdb\u7a0b", process_on),
            ("\u58f0\u97f3\u63d0\u9192", sound_on),
            ("\u5f39\u7a97\u63d0\u9192", popup_on),
            ("\u7a97\u53e3\u7f6e\u9876", topmost_on),
            ("\u542f\u52a8\u5373\u76d1\u542c", autostart_on),
        ):
            tk.Checkbutton(checks, text=text, variable=var, bg=BG, fg=TEXT, activebackground=BG, activeforeground=TEXT, selectcolor=PANEL, anchor="w").pack(side="left", padx=(0, 12))

        buttons = tk.Frame(body, bg=BG)
        buttons.pack(fill="x", pady=(12, 0))

        def save() -> None:
            try:
                poll_ms = max(50, int(poll_var.get().strip() or "80"))
            except Exception:
                messagebox.showerror("\u8bbe\u7f6e", "\u8f6e\u8be2\u95f4\u9694\u5fc5\u987b\u662f\u6570\u5b57")
                return
            self.cfg.process_name = process_var.get().strip() or "rf4_x64.exe"
            self.cfg.poll_ms = poll_ms
            self.cfg.monitor_process = bool(process_on.get())
            self.cfg.sound_enabled = bool(sound_on.get())
            self.cfg.popup_enabled = bool(popup_on.get())
            self.cfg.topmost = bool(topmost_on.get())
            self.cfg.auto_start_monitoring = bool(autostart_on.get())
            self.root.attributes("-topmost", self.cfg.topmost)
            save_config(self.cfg)
            self.refresh_footer()
            win.destroy()

        tk.Button(buttons, text="\u4fdd\u5b58", command=save, bg="#1c6f63", fg=TEXT, activebackground="#248476", relief="flat", bd=0, padx=14, pady=4).pack(side="right", padx=(6, 0))
        tk.Button(buttons, text="\u53d6\u6d88", command=win.destroy, bg="#1a2740", fg=TEXT, activebackground="#2b3d5d", relief="flat", bd=0, padx=14, pady=4).pack(side="right")

        win.protocol("WM_DELETE_WINDOW", win.destroy)

    def test_alert(self) -> None:
        self.record_alert(0, "probe", STATE_SUGGEST, "TEST-ALERT", "\u672c\u5730\u6d4b\u8bd5")

    def minimize_window(self) -> None:
        try:
            self.root.iconify()
        except Exception:
            self.root.withdraw()
            self.root.after(250, self.root.deiconify)

    def _pump_queue(self) -> None:
        try:
            while True:
                event = self.queue.get_nowait()
                kind = event.get("kind")
                if kind == "snapshot":
                    self.handle_snapshot(event)
                elif kind == "rod":
                    self.handle_rod(event)
                elif kind == "environment":
                    self.handle_environment(event)
                elif kind == "alert":
                    self.handle_alert(event)
                elif kind == "process":
                    self.handle_process(event)
                elif kind == "source":
                    self.handle_source(event)
                elif kind == "status":
                    self.handle_status(event)
                elif kind == "log":
                    self.handle_log(event)
                elif kind == "error":
                    self.handle_error(event)
        except queue.Empty:
            pass
        self.render_cards()
        self.clock_var.set(now_text())
        self.refresh_footer()
        if hasattr(self, "status_color"):
            self.title_status_var.set(self.title_status_var.get())
        self.root.after(120, self._pump_queue)

    def _tick_clock(self) -> None:
        self.clock_var.set(now_text())
        self.root.after(1000, self._tick_clock)

    def on_close(self) -> None:
        try:
            self.stop_monitoring()
        finally:
            save_config(self.cfg)
            self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    if not acquire_single_instance():
        if not focus_existing_instance():
            try:
                messagebox.showinfo(APP_NAME, "RF4-DSen 已经在运行，但没有找到可聚焦窗口。请在任务管理器里结束旧进程后再打开。")
            except Exception:
                pass
        return
    App().run()


if __name__ == "__main__":
    main()


