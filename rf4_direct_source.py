from __future__ import annotations

"""Independent RF4 runtime reader.

The module talks to ``rf4_x64.exe`` directly.  Runtime discovery is based on
the current IL2CPP class metadata and live object graph, so addresses are
never carried across game launches.  Normal polling only reads the discovered
rig graph and its live bite state.
"""

import ctypes
import ctypes.wintypes as wintypes
import hashlib
import json
import math
import os
import re
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    from rf4_thresholds import FISH_THRESHOLDS
except Exception:  # pragma: no cover - diagnostics tool can run standalone
    FISH_THRESHOLDS = {}

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
READABLE_PROTECTIONS = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

CLASS_NAME_OFFSET = 0x10
CLASS_NAMESPACE_OFFSET = 0x18
CLASS_PARENT_OFFSET = 0x58
CLASS_FIELDS_OFFSET = 0x80
CLASS_INSTANCE_SIZE_OFFSET = 0xF8
CLASS_FIELD_COUNT_OFFSET = 0x124
FIELD_INFO_SIZE = 0x20

RIG_SET_FIRST_OFFSET = 0x50
RIG_DISTANCE_OFFSET = 0x58
RIG_IN_WATER_OFFSET = 0x74
RIG_SET_SECOND_OFFSET = 0x80
RIG_SESSION_OFFSET = 0xA8
RIG_HOOK_OFFSET = 0xD8
RIG_FEEDER_OFFSET = 0x108

SET_ROOT_OFFSET = 0x38
SET_ROD_REST_OFFSET = 0x30
SET_BELL_OFFSET = 0x58
SET_INTERACTIVE_ROD_OFFSET = 0x100

ROD_REST_SET_OFFSET = 0x48
ROD_REST_DIRECTION_X_OFFSET = 0x38
ROD_REST_DIRECTION_Z_OFFSET = 0x40
ROD_REST_POSITION_X_OFFSET = 0x5C
ROD_REST_POSITION_Y_OFFSET = 0x60
ROD_REST_POSITION_Z_OFFSET = 0x64

BELL_STATE_OFFSET = 0x20
BELL_CODE_OFFSET = 0x20

# The current IL2CPP build keeps a pointer to the generated class table at
# GameAssembly.dll + 0x42620A0.  The reader validates the table contents before
# using it and falls back to the slower string-reference discovery on builds
# where this RVA changes.
GAME_ASSEMBLY_CLASS_CACHE_RVAS = (0x42620A0,)
MAX_CLASS_CACHE_ENTRIES = 20000
HOOK_FISH_OFFSET = 0x140

KNOWN_GAME_ASSEMBLY_BUILDS = {
    "7c38bc13": "4.0.24799",
    "8acb9100": "4.0.25017",
    "c63b8ea4": "4.0.25026",
    "900ae4ac": "4.0.25029",
}

# Unity reserves a very large sparse address range for its private heaps.  The
# class cache and live objects are several gigabytes apart in current builds;
# this is a virtual-address span, not an amount of memory we read at once.
DISCOVERY_WINDOW = 0x600000000
READ_CHUNK = 0x800000
MAX_CLASS_SIZE = 0x10000
RIG_RESCAN_INTERVAL = 1.0
PARTIAL_RIG_RESCAN_INTERVAL = 1.0
LIVE_SCAN_INTERVAL = 0.45
FISHINGSET_TINY_REGION_LIMIT = 0x20000
FISHINGSET_SMALL_REGION_LIMIT = 0x40000
INITIAL_DISCOVERY_ATTEMPTS = 3
INITIAL_DISCOVERY_DELAY = 0.35
INITIAL_DISCOVERY_SYNC_WAIT = 7.0
RIG_FAST_REGION_LIMIT = 0x100000
RIG_MEDIUM_REGION_LIMIT = 0x800000
RIG_EXPECTED_MAX = 3
FISHER_LIVE_REGION_DELTA = 0x200000000
HOTKEY_CALIBRATION_DELAY = 0.32
SET_REDISCOVERY_WINDOW = 0x18000000

SESSION_CACHE_FORMAT = 2
SESSION_CACHE_PATH = (
    Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    / "RF4-Reminder"
    / "direct-session-v1.json"
)

HIGH_RUNTIME_ADDRESS = 0x10000000000
SET_CLASS_NAMES = {"RodReelRigFishingSet", "RodRigFishingSet"}

# These are fields that have remained structurally stable in the current RF4
# IL2CPP layout.  Their names are obfuscated at runtime, so the offsets are
# used only after the owning object has passed class and graph validation.
SET_ACTION_OFFSETS = (0x120, 0xE8, 0xF0)
RIG_GRAPH_OFFSETS = (0xD8, 0x108, 0xE8, 0xF0, 0x120)
SET_GRAPH_OFFSETS = (0x38, 0x58, 0x100, 0x120, 0xE8, 0xF0)

FISH_META_OFFSET = 0x30
FISH_META_SPECIES_OFFSET = 0x38
FISH_SPECIES_ID_OFFSET = 0x80
FISH_SET_BACKREF_OFFSETS = (0xD8, 0xE0)


class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MemoryBasicInformation),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.GetProcessTimes.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
]
kernel32.GetProcessTimes.restype = wintypes.BOOL

psapi = ctypes.WinDLL("psapi", use_last_error=True)
psapi.EnumProcessModulesEx.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.HMODULE),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD,
]
psapi.EnumProcessModulesEx.restype = wintypes.BOOL
psapi.GetModuleBaseNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.HMODULE,
    wintypes.LPWSTR,
    wintypes.DWORD,
]
psapi.GetModuleBaseNameW.restype = wintypes.DWORD

LIST_MODULES_ALL = 0x03

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

try:
    import numpy as _np
except Exception:  # pragma: no cover - the bundled build may omit numpy
    _np = None


@dataclass(frozen=True)
class MemoryRegion:
    base: int
    size: int
    protection: int
    region_type: int


@dataclass(frozen=True)
class DirectRig:
    slot: int
    root: int
    set_address: int
    class_address: int
    rig_type: str
    order_address: int = 0
    order_confidence: float = 0.0
    slot_source: str = ""


@dataclass
class BellTracker:
    baseline: int | None = None
    last_code: int | None = None
    candidate_code: int | None = None
    candidate_since: float = 0.0
    idle_since: float = 0.0
    active: bool = False
    last_state_address: int = 0
    armed: bool = False
    stable_since: float = 0.0


@dataclass
class DirectRodState:
    slot: int
    guid: str
    root: int
    rig_type: str = ""
    set_address: int = 0
    distance_m: float | None = None
    in_water: bool = False
    session: bool = False
    bite_active: bool = False
    action_address: int = 0
    action_type: str = ""
    graph_types: list[str] = field(default_factory=list)
    bell_active: bool = False
    bell_code: int | None = None
    bell_baseline: int | None = None
    bell_state_address: int = 0
    live_phase: str = ""
    live_instance: str = ""
    fish_name: str = ""
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
    valid: bool = False
    reason: str = ""


@dataclass
class DirectSnapshot:
    pid: int
    session_token: str
    mapping_source: str
    rods: list[DirectRodState]
    diagnostics: dict[str, object] = field(default_factory=dict)


def _set_diagnostic(reader: object, key: str, value: object) -> None:
    diagnostics = getattr(reader, "diagnostics", None)
    if isinstance(diagnostics, dict):
        diagnostics[key] = value


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest().upper()


def _pe_image_size(path: str) -> int:
    try:
        with open(path, "rb") as stream:
            head = stream.read(0x1000)
    except OSError:
        return 0
    if len(head) < 0x40 or head[:2] != b"MZ":
        return 0
    pe_offset = struct.unpack_from("<I", head, 0x3C)[0]
    size_offset = pe_offset + 24 + 56
    if pe_offset + 4 > len(head) or head[pe_offset:pe_offset + 4] != b"PE\0\0":
        return 0
    if size_offset + 4 > len(head):
        return 0
    return struct.unpack_from("<I", head, size_offset)[0]


def _known_build(sha256: str) -> str:
    lowered = sha256.casefold()
    return next(
        (build for prefix, build in KNOWN_GAME_ASSEMBLY_BUILDS.items() if lowered.startswith(prefix)),
        "unknown",
    )


def _process_creation_ticks(handle: int) -> int:
    created = wintypes.FILETIME()
    exited = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    if not kernel32.GetProcessTimes(
        handle,
        ctypes.byref(created),
        ctypes.byref(exited),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        return 0
    return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)


def find_rf4_process(process_name: str = "rf4_x64.exe") -> tuple[int, str] | None:
    """Find RF4 without invoking tasklist/cmd or reading helper files."""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == INVALID_HANDLE_VALUE:
        return None
    entry = ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(ProcessEntry32W)
    try:
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == process_name.lower():
                pid = int(entry.th32ProcessID)
                path = ""
                handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if handle:
                    try:
                        buffer = ctypes.create_unicode_buffer(1024)
                        length = wintypes.DWORD(len(buffer))
                        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
                            path = buffer.value
                    finally:
                        kernel32.CloseHandle(handle)
                return pid, path
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return None


class ProcessReader:
    def __init__(self, pid: int):
        self.pid = pid
        self.handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
        )
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        self._class_cache: dict[int, tuple[str, str, int] | None] = {}
        self._field_cache: dict[int, dict[str, int]] = {}
        self._module_cache: dict[str, int] = {}
        self.diagnostics: dict[str, object] = {}

    def close(self) -> None:
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def read(self, address: int, size: int) -> bytes | None:
        if not self.handle or not address or size <= 0:
            return None
        buffer = ctypes.create_string_buffer(size)
        received = ctypes.c_size_t()
        ok = kernel32.ReadProcessMemory(
            self.handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(received),
        )
        if not ok or received.value != size:
            return None
        return buffer.raw

    def u8(self, address: int) -> int | None:
        raw = self.read(address, 1)
        return raw[0] if raw else None

    def u16(self, address: int) -> int | None:
        raw = self.read(address, 2)
        return struct.unpack("<H", raw)[0] if raw else None

    def u32(self, address: int) -> int | None:
        raw = self.read(address, 4)
        return struct.unpack("<I", raw)[0] if raw else None

    def i32(self, address: int) -> int | None:
        raw = self.read(address, 4)
        return struct.unpack("<i", raw)[0] if raw else None

    def u64(self, address: int) -> int | None:
        raw = self.read(address, 8)
        return struct.unpack("<Q", raw)[0] if raw else None

    def f32(self, address: int) -> float | None:
        raw = self.read(address, 4)
        return struct.unpack("<f", raw)[0] if raw else None

    def f64(self, address: int) -> float | None:
        raw = self.read(address, 8)
        return struct.unpack("<d", raw)[0] if raw else None

    def c_string(self, address: int, limit: int = 160) -> str | None:
        raw = self.read(address, limit)
        if not raw:
            return None
        raw = raw.split(b"\0", 1)[0]
        if not raw:
            return ""
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if any(ord(ch) < 0x20 and ch not in "\t\r\n" for ch in value):
            return None
        return value

    def module_base(self, module_name: str) -> int:
        """Return a remote module base without invoking tasklist or a shell."""
        key = module_name.lower()
        if key in self._module_cache:
            return self._module_cache[key]
        if not self.handle:
            return 0
        modules = (wintypes.HMODULE * 1024)()
        needed = wintypes.DWORD()
        if not psapi.EnumProcessModulesEx(
            self.handle,
            modules,
            ctypes.sizeof(modules),
            ctypes.byref(needed),
            LIST_MODULES_ALL,
        ):
            return 0
        count = min(len(modules), int(needed.value // ctypes.sizeof(wintypes.HMODULE)))
        for module in modules[:count]:
            name = ctypes.create_unicode_buffer(260)
            if not psapi.GetModuleBaseNameW(self.handle, module, name, len(name)):
                continue
            if name.value.lower() != key:
                continue
            address = ctypes.cast(module, ctypes.c_void_p).value or 0
            self._module_cache[key] = address
            return address
        return 0

    def class_info(self, class_address: int) -> tuple[str, str, int] | None:
        if class_address in self._class_cache:
            return self._class_cache[class_address]
        if not class_address or class_address & 7:
            self._class_cache[class_address] = None
            return None
        name_ptr = self.u64(class_address + CLASS_NAME_OFFSET) or 0
        namespace_ptr = self.u64(class_address + CLASS_NAMESPACE_OFFSET) or 0
        size = self.u32(class_address + CLASS_INSTANCE_SIZE_OFFSET)
        if not name_ptr or size is None or not (0x10 <= size <= MAX_CLASS_SIZE):
            self._class_cache[class_address] = None
            return None
        name = self.c_string(name_ptr, 128)
        namespace = self.c_string(namespace_ptr, 160) if namespace_ptr else ""
        if not name or len(name) > 120:
            self._class_cache[class_address] = None
            return None
        result = (name, namespace or "", size)
        self._class_cache[class_address] = result
        return result

    def object_info(self, address: int) -> tuple[str, str, int] | None:
        if not address or address & 7:
            return None
        class_address = self.u64(address) or 0
        return self.class_info(class_address)

    def field_offsets(self, class_address: int) -> dict[str, int]:
        cached = self._field_cache.get(class_address)
        if cached is not None:
            return cached
        fields: dict[str, int] = {}
        seen: set[int] = set()
        current = class_address
        while current and current not in seen and len(seen) < 32:
            seen.add(current)
            info = self.class_info(current)
            if not info:
                break
            fields_ptr = self.u64(current + CLASS_FIELDS_OFFSET) or 0
            count = self.u16(current + CLASS_FIELD_COUNT_OFFSET) or 0
            if fields_ptr and count <= 512:
                for index in range(count):
                    field = fields_ptr + index * FIELD_INFO_SIZE
                    name_ptr = self.u64(field) or 0
                    offset = self.i32(field + 0x18)
                    name = self.c_string(name_ptr, 128) if name_ptr else None
                    if name and offset is not None and offset >= 0:
                        fields.setdefault(name, offset)
            current = self.u64(current + CLASS_PARENT_OFFSET) or 0
        self._field_cache[class_address] = fields
        return fields

    def class_cache_map(self) -> dict[str, int]:
        """Read the live IL2CPP class table and return validated class pointers."""
        base = self.module_base("GameAssembly.dll")
        self.diagnostics["game_assembly_base"] = base
        if not base:
            self.diagnostics["class_cache_status"] = "module_missing"
            return {}
        for rva in GAME_ASSEMBLY_CLASS_CACHE_RVAS:
            self.diagnostics["class_cache_rva"] = rva
            table = self.u64(base + rva) or 0
            if table < HIGH_RUNTIME_ADDRESS or table & 7:
                self.diagnostics["class_cache_status"] = "invalid_table"
                continue
            classes: dict[str, int] = {}
            valid_count = 0
            invalid_run = 0
            for index in range(MAX_CLASS_CACHE_ENTRIES):
                class_address = self.u64(table + index * 8) or 0
                info = self.class_info(class_address)
                if not info:
                    invalid_run += 1
                    if valid_count > 512 and invalid_run >= 512:
                        break
                    continue
                valid_count += 1
                invalid_run = 0
                name, namespace, _size = info
                previous = classes.get(name)
                if previous is None:
                    classes[name] = class_address
                else:
                    previous_info = self.class_info(previous)
                    if previous_info and not previous_info[1].startswith("RF4.Client") and namespace.startswith("RF4.Client"):
                        classes[name] = class_address
            if valid_count >= 1000:
                self.diagnostics["class_cache_status"] = "ok"
                self.diagnostics["class_cache_valid"] = valid_count
                self.diagnostics["class_cache_classes"] = len(classes)
                return classes
            self.diagnostics["class_cache_status"] = "insufficient_classes"
            self.diagnostics["class_cache_valid"] = valid_count
        return {}


def readable_regions(
    reader: ProcessReader,
    start_address: int = 0,
    end_address: int = 0x7FFF_FFFF_FFFF,
) -> list[MemoryRegion]:
    rows: list[MemoryRegion] = []
    address = max(0, start_address)
    limit = max(address, end_address)
    mbi_size = ctypes.sizeof(MemoryBasicInformation)
    high_private_anchor = 0
    while address < limit:
        mbi = MemoryBasicInformation()
        if not kernel32.VirtualQueryEx(
            reader.handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size
        ):
            address += 0x1000
            continue
        base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0
        size = int(mbi.RegionSize)
        protection = int(mbi.Protect)
        if (
            size
            and int(mbi.State) == MEM_COMMIT
            and (protection & 0xFF) in READABLE_PROTECTIONS
            and not (protection & PAGE_GUARD)
        ):
            region_type = int(mbi.Type)
            rows.append(MemoryRegion(base, size, protection, region_type))
            if (
                not high_private_anchor
                and region_type == MEM_PRIVATE
                and base >= HIGH_RUNTIME_ADDRESS
            ):
                high_private_anchor = base
        address = max(address + 0x1000, base + max(size, 0x1000))
        if high_private_anchor and address > high_private_anchor + DISCOVERY_WINDOW:
            break
    return rows


def choose_runtime_regions(regions: list[MemoryRegion]) -> list[MemoryRegion]:
    """Return the high Unity private window containing class and live objects.

    The active FishingScene objects are often in a small allocation below the
    large IL2CPP heap. Selecting only large regions silently drops those rigs.
    """
    high_private = [
        item
        for item in regions
        if item.region_type == MEM_PRIVATE and item.base >= HIGH_RUNTIME_ADDRESS
    ]
    if not high_private:
        return [item for item in regions if item.region_type == MEM_PRIVATE]
    anchor = min(high_private, key=lambda item: item.base)
    end = anchor.base + DISCOVERY_WINDOW
    selected = [
        item
        for item in regions
        if item.region_type == MEM_PRIVATE
        and item.base < end
        and item.base + item.size > anchor.base
    ]
    return sorted(selected, key=lambda item: item.base)


def regions_in_span(
    regions: list[MemoryRegion],
    start: int,
    end: int,
) -> list[MemoryRegion]:
    return [
        item
        for item in regions
        if item.base < end and item.base + item.size > start
    ]


def _unique_regions(regions: list[MemoryRegion]) -> list[MemoryRegion]:
    seen: set[tuple[int, int]] = set()
    result: list[MemoryRegion] = []
    for region in regions:
        key = (region.base, region.size)
        if key in seen:
            continue
        seen.add(key)
        result.append(region)
    return result


def _sorted_small_first(regions: list[MemoryRegion]) -> list[MemoryRegion]:
    return sorted(regions, key=lambda item: (item.size, item.base))


def _read_region_chunks(reader: ProcessReader, region: MemoryRegion):
    offset = 0
    tail = b""
    while offset < region.size:
        length = min(READ_CHUNK, region.size - offset)
        raw = reader.read(region.base + offset, length)
        if raw is None:
            offset += length
            tail = b""
            continue
        yield region.base + offset, raw, tail
        tail = raw[-256:]
        offset += length


def find_named_strings(
    reader: ProcessReader,
    regions: list[MemoryRegion],
    names: set[str],
    stop_when: set[str] | None = None,
) -> dict[str, list[int]]:
    wanted = {name.encode("ascii"): name for name in names}
    hits: dict[str, list[int]] = {name: [] for name in names}
    required = set(stop_when) if stop_when else set()
    for region in regions:
        for base, raw, tail in _read_region_chunks(reader, region):
            data = tail + raw
            data_base = base - len(tail)
            for needle, name in wanted.items():
                start = 0
                while True:
                    hit = data.find(needle, start)
                    if hit < 0:
                        break
                    end = hit + len(needle)
                    if end >= len(data) or data[end] == 0:
                        hits[name].append(data_base + hit)
                    start = hit + 1
            if required and all(hits.get(name) for name in required):
                return hits
    return hits


def scan_qword_targets(
    reader: ProcessReader,
    regions: list[MemoryRegion],
    targets: set[int],
    limit_per_target: int = 10000,
) -> dict[int, list[int]]:
    if not targets:
        return {}
    result: dict[int, list[int]] = {target: [] for target in targets}
    if _np is not None:
        target_array = _np.asarray(list(targets), dtype="<u8")
        target_set = set(targets)
    else:
        target_array = None
        target_set = set(targets)
    for region in regions:
        offset = 0
        while offset < region.size:
            length = min(READ_CHUNK, region.size - offset)
            length -= length % 8
            if length <= 0:
                break
            raw = reader.read(region.base + offset, length)
            if raw is not None:
                if target_array is not None:
                    values = _np.frombuffer(raw, dtype="<u8")
                    for index in _np.flatnonzero(_np.isin(values, target_array)):
                        value = int(values[int(index)])
                        bucket = result.get(value)
                        if bucket is not None and len(bucket) < limit_per_target:
                            bucket.append(region.base + offset + int(index) * 8)
                else:
                    for index in range(0, len(raw), 8):
                        value = struct.unpack_from("<Q", raw, index)[0]
                        if value in target_set and len(result[value]) < limit_per_target:
                            result[value].append(region.base + offset + index)
            offset += length
    return result


def _candidate_class_names(reader: ProcessReader, regions: list[MemoryRegion]) -> set[str]:
    """Collect likely fishing class names from the IL2CPP string pool."""
    pattern = re.compile(rb"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]{2,80})\x00")
    names: set[str] = set()
    for region in regions:
        for base, raw, tail in _read_region_chunks(reader, region):
            data = tail + raw
            data_base = base - len(tail)
            for match in pattern.finditer(data):
                try:
                    value = match.group(1).decode("ascii")
                except UnicodeDecodeError:
                    continue
                if (
                    value.startswith("Rig")
                    or "FishingSet" in value
                    or "Fishing" in value
                    or "Fish" in value
                    or "Fight" in value
                    or "Bite" in value
                    or value.startswith("RHUD")
                    or value.startswith("RUI")
                ):
                    names.add(value)
    return names


def discover_class_map(reader: ProcessReader, regions: list[MemoryRegion]) -> dict[str, int]:
    exact = {
        "BiteAlarmSimpleBell",
        "RodReelRigFishingSet",
        "RodRigFishingSet",
        "RigBottomSimple",
        "RigBottomCarpMethod",
        "RigBottomLiveFish",
        "Hook",
        "Fish",
        "FishBehaviour",
        "FightFishBiteMeta",
        "Fisher",
        "Bobber",
        "RodRestController",
        "RodPodRodRestController",
        "RigBobberBase",
        "RigBobberClassic",
        "RUIHotSwapSlotCell",
        "RHUDActiveItemSlot",
        "RHUDActiveRigComponent",
        "RHUDActiveRigWidget",
        "RHUDFishingSetWidget",
        "RHUDActivatedFishingSets",
        "RHUDFishingSetStateWidget",
        "FishAsset",
    }
    # The four classes below are enough to locate and poll active rigs.  The
    # optional fish classes are searched opportunistically after the core
    # names, so a missing class in a particular scene cannot delay startup.
    core = {
        "BiteAlarmSimpleBell",
        "RodReelRigFishingSet",
        "RodRigFishingSet",
    }

    # The IL2CPP class table is the authoritative source for runtime classes.
    # Keep concrete bottom/bobber rig classes so the object scan remains
    # bounded; scanning every class in the table would turn startup into a
    # multi-minute operation on the large Unity heap.
    cached = reader.class_cache_map()
    if cached:
        classes = {
            name: address
            for name, address in cached.items()
            if name in exact
            or name.startswith("RigBottom")
            or name.startswith("RigBobber")
        }
        has_set = any(name in classes for name in SET_CLASS_NAMES)
        has_rig = any(
            name.startswith("RigBottom") or name.startswith("RigBobber")
            for name in classes
        )
        if has_set and has_rig:
            return classes

    anchor = min(
        (item.base for item in regions if item.base >= HIGH_RUNTIME_ADDRESS),
        default=min((item.base for item in regions), default=0),
    )
    # Class-name literals for the current builds are in the first 8 GiB of
    # the runtime window. Keep discovery bounded and fall back only when the
    # required classes are not present there.
    string_regions = regions_in_span(regions, anchor, anchor + 0x200000000)
    string_hits = find_named_strings(reader, string_regions or regions, exact)
    if not any(string_hits.get(name) for name in core):
        string_hits = find_named_strings(reader, regions, exact)
    name_ptrs = {
        address
        for values in string_hits.values()
        for address in values
    }
    # Class structures live in the low Unity heap next to the class cache,
    # while their name literals live in a later string-pool region.
    class_regions = regions_in_span(regions, anchor, anchor + 0x100000000)
    refs = scan_qword_targets(reader, class_regions or regions, name_ptrs, limit_per_target=200)
    if not any(refs.values()) and class_regions:
        class_regions = regions_in_span(regions, anchor, anchor + 0x200000000)
        refs = scan_qword_targets(reader, class_regions or regions, name_ptrs, limit_per_target=200)
    classes: dict[str, int] = {}
    for name, addresses in string_hits.items():
        for name_address in addresses:
            for pointer_location in refs.get(name_address, []):
                class_address = pointer_location - CLASS_NAME_OFFSET
                info = reader.class_info(class_address)
                if info and info[0] == name:
                    # Prefer the runtime class in the expected RF4 namespace.
                    old = classes.get(name)
                    if old is None or info[1].startswith("RF4.Client"):
                        classes[name] = class_address
    return classes


def _is_fishing_set(reader: ProcessReader, address: int) -> bool:
    info = reader.object_info(address)
    return bool(
        info
        and info[0].endswith("FishingSet")
        and (info[1].startswith("RF4.Client") or not info[1])
    )


def _valid_rig(reader: ProcessReader, address: int, rig_classes: set[int]) -> tuple[str, int] | None:
    if not address or address & 7 or not rig_classes:
        return None
    class_address = reader.u64(address) or 0
    if class_address not in rig_classes:
        return None
    info = reader.class_info(class_address)
    if not info or not info[0].startswith("Rig"):
        return None
    set_address = 0
    for offset in (RIG_SET_FIRST_OFFSET, RIG_SET_SECOND_OFFSET):
        candidate = reader.u64(address + offset) or 0
        if _is_fishing_set(reader, candidate):
            if reader.u64(candidate + SET_ROOT_OFFSET) != address:
                continue
            set_address = candidate
            break
    if not set_address:
        return None
    # Bobber rigs do not share the verified bottom-rig telemetry layout.  Their
    # class and FishingSet relationship are enough to retain the hotbar slot;
    # snapshot() exposes them as unmapped instead of reading bottom offsets.
    if info[0].startswith("RigBobber"):
        return info[0], set_address
    distance = reader.f64(address + RIG_DISTANCE_OFFSET)
    if distance is None or not math.isfinite(distance) or not (0 <= distance <= 2000):
        return None
    in_water = reader.u8(address + RIG_IN_WATER_OFFSET)
    session = reader.u8(address + RIG_SESSION_OFFSET)
    if in_water not in (0, 1) or session not in (0, 1):
        return None
    return info[0], set_address


def _component_score(reader: ProcessReader, address: int) -> float:
    expected = {
        -0x20: "BodyEnvironment",
        -0x18: "BodyStatisticsGrabberStub",
        -0x10: "Hook",
        -0x08: "Rigidbody",
        0x08: "RigHitchController",
        0x10: "BodyChain",
        0x18: "JointConnector",
    }
    score = 0.0
    for offset, name in expected.items():
        target = reader.u64(address + offset) or 0
        info = reader.object_info(target)
        if info and info[0] == name:
            score += 1.0
    # Component arrays are allocated well after the class cache.  This avoids
    # selecting class metadata references that happen to contain a rig pointer.
    if address > 0x22800000000 + 0x18000000:
        score += 0.25
    return score


def _finite_float(value: float | None, *, limit: float = 1_000_000.0) -> float | None:
    if value is None or not math.isfinite(value) or abs(value) > limit:
        return None
    return float(value)


def _rodrest_metrics(reader: ProcessReader, set_address: int) -> dict[str, float | int] | None:
    """Return verified rod-rest position evidence for a FishingSet.

    V1.03 assigned U slots from allocator/root address order.  The captured
    live process showed the opposite mapping for U1/U3.  The RodRestController
    is owned by the FishingSet and carries the physical rod-pod slot position,
    so it is the closest independent in-process slot evidence currently
    available when the hotbar UI binding object is not reachable.
    """
    controller = reader.u64(set_address + SET_ROD_REST_OFFSET) or 0
    info = reader.object_info(controller)
    if not info or "RodRestController" not in info[0]:
        return None
    if (reader.u64(controller + ROD_REST_SET_OFFSET) or 0) != set_address:
        return None
    values = {
        "controller": controller,
        "dir_x": _finite_float(reader.f32(controller + ROD_REST_DIRECTION_X_OFFSET), limit=10.0),
        "dir_z": _finite_float(reader.f32(controller + ROD_REST_DIRECTION_Z_OFFSET), limit=10.0),
        "pos_x": _finite_float(reader.f32(controller + ROD_REST_POSITION_X_OFFSET)),
        "pos_y": _finite_float(reader.f32(controller + ROD_REST_POSITION_Y_OFFSET)),
        "pos_z": _finite_float(reader.f32(controller + ROD_REST_POSITION_Z_OFFSET)),
    }
    if sum(value is not None for key, value in values.items() if key != "controller") < 2:
        return None
    return values  # type: ignore[return-value]


def _consensus_slot_order(
    reader: ProcessReader,
    selected: list[tuple[int, int, tuple[str, int, int]]],
) -> dict[int, tuple[int, int, float]]:
    """Map FishingSet address to (slot, evidence address, confidence).

    The order is accepted only when several independent RodRestController
    fields agree.  This keeps V1.04 from falling back to the allocator-address
    guess that put the real U3 rod into U1.
    """
    if not selected:
        return {}
    evidence: dict[int, dict[str, float | int]] = {}
    for _root, set_address, _payload in selected:
        metrics = _rodrest_metrics(reader, set_address)
        if metrics:
            evidence[set_address] = metrics
    _set_diagnostic(reader, "rodrest_evidence_sets", len(evidence))
    if evidence:
        _set_diagnostic(
            reader,
            "rodrest_evidence_detail",
            ";".join(
                "set=0x{set_address:X},controller=0x{controller:X},pos=({pos_x},{pos_y},{pos_z}),dir=({dir_x},{dir_z})".format(
                    set_address=set_address,
                    controller=int(metrics.get("controller", 0) or 0),
                    pos_x=metrics.get("pos_x"),
                    pos_y=metrics.get("pos_y"),
                    pos_z=metrics.get("pos_z"),
                    dir_x=metrics.get("dir_x"),
                    dir_z=metrics.get("dir_z"),
                )
                for set_address, metrics in sorted(evidence.items())
            ),
        )
    if len(evidence) < 2:
        _set_diagnostic(reader, "slot_mapping_status", "single_set_no_slot_anchor")
        return {}

    axes: list[tuple[str, bool]] = [
        # Verified against the user's RF4 4.0.25029 diagnostics: the previous
        # direction-based vote reversed U1/U3 after recast. Hotbar slots follow
        # the RodRest physical positions on the pod, not the rod facing vector.
        ("pos_x", False),
        ("pos_z", False),
        ("pos_y", True),
    ]
    orders: dict[tuple[int, ...], int] = {}
    order_evidence: dict[tuple[int, ...], tuple[str, int]] = {}
    for key, reverse in axes:
        values: list[tuple[float, int]] = []
        for set_address, metrics in evidence.items():
            value = metrics.get(key)
            if isinstance(value, (int, float)) and math.isfinite(float(value)):
                values.append((float(value), set_address))
        if len(values) != len(evidence):
            continue
        spread = max(value for value, _ in values) - min(value for value, _ in values)
        if spread < 0.0001:
            continue
        ordered = tuple(
            set_address
            for _value, set_address in sorted(values, key=lambda item: item[0], reverse=reverse)
        )
        orders[ordered] = orders.get(ordered, 0) + 1
        order_evidence.setdefault(
            ordered,
            (key, int(evidence[ordered[0]].get("controller", 0) or 0)),
        )
    if not orders:
        _set_diagnostic(reader, "slot_mapping_status", "rodrest_no_order")
        return {}
    best_order, votes = max(orders.items(), key=lambda item: (item[1], len(item[0])))
    _set_diagnostic(reader, "slot_mapping_order_votes", votes)
    _set_diagnostic(reader, "slot_mapping_order_sets", ",".join(f"0x{item:X}" for item in best_order))
    if votes < 2:
        _set_diagnostic(reader, "slot_mapping_status", "rodrest_conflict")
        return {}
    evidence_key, evidence_address = order_evidence[best_order]
    confidence = min(1.0, votes / max(1, len(axes)))
    completed_order = best_order
    missing_sets = [
        set_address
        for _root, set_address, _payload in selected
        if set_address not in evidence
    ]
    if missing_sets:
        _set_diagnostic(reader, "rodrest_missing_sets", ",".join(f"0x{item:X}" for item in missing_sets))
        selected_sets = [set_address for _root, set_address, _payload in selected]
        if len(missing_sets) != 1 or len(selected_sets) != RIG_EXPECTED_MAX:
            _set_diagnostic(reader, "slot_mapping_status", "rodrest_incomplete")
            return {}
        # If exactly one RodRestController is temporarily absent, keep the third
        # rod visible only when the two measured rests agree with the monotonic
        # live FishingSet allocation in this process.  This covers the observed
        # "active/hovered rod has rest=0" transition without accepting arbitrary
        # object-address order as a primary slot source.
        by_address = sorted(selected_sets)
        known_by_address = [item for item in by_address if item in evidence]
        if list(best_order) == known_by_address:
            completed_order = tuple(by_address)
        elif list(best_order) == list(reversed(known_by_address)):
            completed_order = tuple(reversed(by_address))
        else:
            _set_diagnostic(reader, "slot_mapping_status", "rodrest_partial_unanchored")
            return {}
        confidence = min(confidence, 0.50)
        _set_diagnostic(reader, "slot_mapping_status", "rodrest_partial_bridge")
        _set_diagnostic(reader, "slot_mapping_partial", True)
    else:
        _set_diagnostic(reader, "slot_mapping_status", "rodrest_consensus")
    _set_diagnostic(reader, "slot_mapping_axis", evidence_key)
    return {
        set_address: (index + 1, evidence_address, confidence)
        for index, set_address in enumerate(completed_order[:RIG_EXPECTED_MAX])
    }


def _direct_rigs_from_selected(
    reader: ProcessReader,
    selected: list[tuple[int, int, tuple[str, int, int]]],
) -> list[DirectRig]:
    if selected:
        _set_diagnostic(
            reader,
            "selected_rig_candidates",
            ";".join(
                f"root=0x{root:X},set=0x{set_address:X},type={payload[0]},class=0x{payload[2]:X}"
                for root, set_address, payload in selected
            ),
        )
    slot_map = _consensus_slot_order(reader, selected)
    result: list[DirectRig] = []
    if not slot_map:
        # V1.04 deliberately refuses allocator/root order as slot evidence.
        _set_diagnostic(reader, "hotbar_status", "authoritative_mapping_unavailable")
        return []
    for root, set_address, payload in selected:
        mapped = slot_map.get(set_address)
        if not mapped:
            continue
        slot, evidence_address, confidence = mapped
        if slot < 1 or slot > RIG_EXPECTED_MAX:
            continue
        rig_type, _set_address, class_address = payload
        slot_source = (
            "rodrest_partial"
            if getattr(reader, "diagnostics", {}).get("slot_mapping_status") == "rodrest_partial_bridge"
            else "rodrest_consensus"
        )
        result.append(
            DirectRig(
                slot=slot,
                root=root,
                set_address=set_address,
                class_address=class_address,
                rig_type=rig_type,
                order_address=evidence_address,
                order_confidence=confidence,
                slot_source=slot_source,
            )
        )
    result.sort(key=lambda item: item.slot)
    if result:
        _set_diagnostic(
            reader,
            "rig_mapping_detail",
            ";".join(
                f"U{item.slot}=set:0x{item.set_address:X},root:0x{item.root:X},source:{item.slot_source},confidence:{item.order_confidence:.2f}"
                for item in result
            ),
        )
    return result


def _discover_rigs_from_fishing_sets(
    reader: ProcessReader,
    regions: list[MemoryRegion],
    class_map: dict[str, int],
    *,
    preferred_sets: set[int] | None = None,
) -> list[DirectRig]:
    """Rediscover rods from live ``FishingSet -> Rig`` links.

    Recasting rebuilds the ``Rig`` root objects while the old root addresses
    can remain readable for a short time.  The previous Fisher-offset path can
    then return no valid sets and the legacy rig-class full scan can spend more
    than a minute walking the Unity heap.  The FishingSet objects themselves are
    compact, typed, and still point directly at the current Rig root, so scan
    those class instances first and validate the back-reference graph.
    """
    set_classes = {
        address
        for name, address in class_map.items()
        if name in SET_CLASS_NAMES or name.endswith("FishingSet")
    }
    set_classes = {address for address in set_classes if address}
    if not set_classes:
        _set_diagnostic(reader, "fishingset_scan_status", "class_missing")
        return []

    preferred = {address for address in (preferred_sets or set()) if address}
    class_anchor = min((address for address in class_map.values() if address), default=0)
    live_tiny = _sorted_small_first(
        [
            item
            for item in regions
            if item.size <= FISHINGSET_TINY_REGION_LIMIT
            and (not class_anchor or item.base >= class_anchor + FISHER_LIVE_REGION_DELTA)
        ]
    )
    all_tiny = _sorted_small_first(
        [item for item in regions if item.size <= FISHINGSET_TINY_REGION_LIMIT]
    )
    live_small = _sorted_small_first(
        [
            item
            for item in regions
            if item.size <= FISHINGSET_SMALL_REGION_LIMIT
            and (not class_anchor or item.base >= class_anchor + FISHER_LIVE_REGION_DELTA)
        ]
    )
    all_small = _sorted_small_first(
        [item for item in regions if item.size <= FISHINGSET_SMALL_REGION_LIMIT]
    )
    live_medium = _sorted_small_first(
        [
            item
            for item in regions
            if item.size <= RIG_MEDIUM_REGION_LIMIT
            and (not class_anchor or item.base >= class_anchor + FISHER_LIVE_REGION_DELTA)
        ]
    )
    medium = _sorted_small_first(
        [item for item in regions if item.size <= RIG_MEDIUM_REGION_LIMIT]
    )
    previous_regions: list[MemoryRegion] = []
    if preferred:
        previous_regions = _sorted_small_first(
            regions_in_span(
                regions,
                max(0, min(preferred) - SET_REDISCOVERY_WINDOW),
                max(preferred) + SET_REDISCOVERY_WINDOW,
            )
        )

    tiers: list[tuple[str, list[MemoryRegion], int]] = []
    if previous_regions:
        tiers.append(("near_previous_sets", previous_regions, 3000))
    tiers.extend(
        [
            ("live_tiny_sets", live_tiny, 1000),
            ("all_tiny_sets", all_tiny, 1500),
            ("live_small_sets", live_small, 2500),
            ("all_small_sets", all_small, 3000),
            ("live_medium_sets", live_medium, 3000),
            ("medium_sets", medium, 5000),
        ]
    )

    candidates: dict[int, tuple[int, int, tuple[str, int, int]]] = {}
    scanned: set[tuple[int, int]] = set()
    scanned_regions = 0
    scanned_bytes = 0
    tiers_used: list[str] = []
    for label, tier_regions, limit in tiers:
        fresh = [
            item
            for item in _unique_regions(tier_regions)
            if (item.base, item.size) not in scanned
        ]
        if not fresh:
            continue
        scanned.update((item.base, item.size) for item in fresh)
        scanned_regions += len(fresh)
        scanned_bytes += sum(item.size for item in fresh)
        tiers_used.append(label)
        hits = scan_qword_targets(reader, fresh, set_classes, limit_per_target=limit)
        raw_hits = sum(len(values) for values in hits.values())
        for _class_address, locations in hits.items():
            for set_address in sorted(set(locations)):
                if set_address in candidates:
                    continue
                valid = _valid_fishing_set(reader, set_address, set_classes)
                if not valid:
                    continue
                rig_type, root, root_class_address = valid
                candidates[set_address] = (
                    root,
                    set_address,
                    (rig_type, set_address, root_class_address),
                )
        _set_diagnostic(reader, f"fishingset_{label}_raw", raw_hits)
        _set_diagnostic(reader, f"fishingset_{label}_valid", len(candidates))
        if len(candidates) >= RIG_EXPECTED_MAX:
            break
        if (
            label in {"all_tiny_sets", "all_small_sets"}
            and not candidates
            and (
                int(getattr(reader, "diagnostics", {}).get("fishingset_live_tiny_sets_raw") or 0)
                + int(getattr(reader, "diagnostics", {}).get("fishingset_all_tiny_sets_raw") or 0)
                + int(getattr(reader, "diagnostics", {}).get("fishingset_live_small_sets_raw") or 0)
                + raw_hits
            ) > 0
        ):
            _set_diagnostic(reader, "fishingset_scan_fast_empty", f"{label}_rootless")
            break

    _set_diagnostic(reader, "fishingset_scan_tiers", ",".join(tiers_used))
    _set_diagnostic(reader, "fishingset_scan_regions", scanned_regions)
    _set_diagnostic(reader, "fishingset_scan_bytes", scanned_bytes)
    _set_diagnostic(reader, "fishingset_scan_candidates", len(candidates))
    if candidates:
        _set_diagnostic(
            reader,
            "fishingset_scan_detail",
            ";".join(
                f"set=0x{set_address:X},root=0x{root:X},type={payload[0]},class=0x{payload[2]:X}"
                for set_address, (root, _set_address, payload) in sorted(candidates.items())
            ),
        )
    if len(candidates) < RIG_EXPECTED_MAX:
        _set_diagnostic(reader, "fishingset_scan_status", "partial" if candidates else "no_valid_sets")
        return []

    selected = list(candidates.values())[:RIG_EXPECTED_MAX]
    result = _direct_rigs_from_selected(reader, selected)
    if result:
        _set_diagnostic(reader, "rig_discovery_method", "fishingset_scan")
        _set_diagnostic(reader, "hotbar_status", "fishingset_rodrest")
        _set_diagnostic(reader, "fishingset_scan_status", "ok")
    else:
        _set_diagnostic(reader, "fishingset_scan_status", "slot_unmapped")
    return result


def _discover_hotbar_set_order(
    reader: ProcessReader,
    regions: list[MemoryRegion],
    set_addresses: set[int],
) -> list[tuple[int, int]]:
    """Read RF4's own active fishing-set array in hotbar order.

    The allocator address of a rig is unrelated to its number on the fishing
    hotbar.  Current builds keep the active ``FishingSet`` objects in a typed
    managed array.  We locate that array through its live set references and
    return ``(array_index, set_address)`` pairs.  No ordering is returned when
    the relationship cannot be verified.
    """
    targets = {address for address in set_addresses if address}
    _set_diagnostic(reader, "hotbar_target_sets", len(targets))
    if not targets:
        return []

    low = min(targets) - 0x40000000
    high = max(targets) + 0x40000000
    search_regions = regions_in_span(regions, low, high) or regions
    references = scan_qword_targets(
        reader,
        search_regions,
        targets,
        limit_per_target=10000,
    )
    candidates: dict[int, tuple[float, list[tuple[int, int]], str, int]] = {}
    for target, locations in references.items():
        for location in locations:
            # A one-dimensional IL2CPP managed array starts with its length at
            # +0x18 and its first element at +0x20.
            for index in range(32):
                address = location - 0x20 - index * 8
                info = reader.object_info(address)
                if not info or not info[0].endswith("[]"):
                    continue
                length = reader.u32(address + 0x18)
                if length is None or not 0 <= length <= 64 or index >= length:
                    continue
                if (reader.u64(address + 0x20 + index * 8) or 0) != target:
                    continue
                values = [
                    reader.u64(address + 0x20 + item * 8) or 0
                    for item in range(length)
                ]
                ordered = [
                    (item, value)
                    for item, value in enumerate(values)
                    if value in targets
                ]
                unique_values = {value for _item, value in ordered}
                if not ordered or len(unique_values) < 1:
                    continue
                nonzero = [value for value in values if value]
                all_known = bool(nonzero) and all(value in targets for value in nonzero)
                indices = [item for item, _value in ordered]
                contiguous = indices == list(range(len(indices)))
                # Prefer the array containing the most known active sets.  A
                # short, contiguous array containing only those sets is the
                # strongest proof of a hotbar relationship.
                score = float(len(unique_values) * 1000)
                if all_known:
                    score += 500.0
                if contiguous:
                    score += 400.0
                if 1 <= length <= 6:
                    score += 300.0
                score -= min(length, 64) * 2.0
                previous = candidates.get(address)
                if previous is None or score > previous[0]:
                    candidates[address] = (score, ordered, info[0], length)

    _set_diagnostic(reader, "hotbar_array_candidates", len(candidates))
    if not candidates:
        _set_diagnostic(reader, "hotbar_status", "no_candidates")
        return []
    ranked_arrays = sorted(candidates.values(), key=lambda item: item[0], reverse=True)
    picked = None
    for score, ordered, array_type, length in ranked_arrays:
        indices = [index for index, _address in ordered]
        if not indices or length > 8 or max(indices) >= 6:
            continue
        picked = (score, ordered, array_type, length)
        break
    if picked is None:
        _set_diagnostic(reader, "hotbar_status", "no_valid_candidate")
        return []
    _score, ordered, _array_type, _length = picked
    _set_diagnostic(reader, "hotbar_array_type", _array_type)
    _set_diagnostic(reader, "hotbar_array_length", _length)
    _set_diagnostic(reader, "hotbar_mapped_sets", len(ordered))
    # A duplicated pointer in a stale array is not a valid slot mapping.
    values = [value for _index, value in ordered]
    if len(values) != len(set(values)):
        _set_diagnostic(reader, "hotbar_status", "duplicate_set")
        return []
    _set_diagnostic(reader, "hotbar_status", "ok")
    return ordered


def _discover_rigs_legacy(
    reader: ProcessReader,
    regions: list[MemoryRegion],
    class_map: dict[str, int],
) -> list[DirectRig]:
    rig_classes = {
        address
        for name, address in class_map.items()
        if (
            (name.startswith("RigBottom") or name.startswith("RigBobber"))
            and "LiveFish" not in name
        )
    }
    # Current RF4 builds expose the active bottom rig class reliably even when
    # the generic class-name pass misses an obfuscated sibling.
    if not rig_classes and class_map.get("RigBottomCarpMethod"):
        rig_classes.add(class_map["RigBottomCarpMethod"])
    if not rig_classes:
        raise RuntimeError("未找到 RF4 运行时竿类")
    candidates: dict[int, tuple[str, int, int]] = {}

    def collect_valid_hits(hits: dict[int, list[int]]) -> None:
        for class_address, locations in hits.items():
            for location in locations:
                valid = _valid_rig(reader, location, rig_classes)
                if valid:
                    candidates[location] = (valid[0], valid[1], class_address)

    anchor = min((item.base for item in regions), default=0)
    object_regions = regions_in_span(
        regions,
        anchor + 0x200000000,
        anchor + 0x280000000,
    )
    small_regions = _sorted_small_first(
        [item for item in regions if item.size <= RIG_FAST_REGION_LIMIT]
    )
    medium_regions = _sorted_small_first(
        [
            item
            for item in regions
            if RIG_FAST_REGION_LIMIT < item.size <= RIG_MEDIUM_REGION_LIMIT
        ]
    )
    tiers: list[tuple[str, list[MemoryRegion], int]] = [
        ("small", small_regions, 4000),
        ("medium", medium_regions, 4000),
        ("object_span", object_regions, 4000),
    ]
    scanned: set[tuple[int, int]] = set()
    scanned_bytes = 0
    scanned_regions = 0
    discovery_tiers: list[str] = []
    for label, tier_regions, limit in tiers:
        fresh = [
            item
            for item in _unique_regions(tier_regions)
            if (item.base, item.size) not in scanned
        ]
        if not fresh:
            continue
        scanned.update((item.base, item.size) for item in fresh)
        scanned_regions += len(fresh)
        scanned_bytes += sum(item.size for item in fresh)
        discovery_tiers.append(label)
        hits = scan_qword_targets(
            reader,
            fresh,
            rig_classes,
            limit_per_target=limit,
        )
        collect_valid_hits(hits)
        set_count = len({payload[1] for payload in candidates.values()})
        _set_diagnostic(reader, f"rig_{label}_candidates", len(candidates))
        _set_diagnostic(reader, f"rig_{label}_sets", set_count)
        if set_count >= RIG_EXPECTED_MAX:
            break
        # V1.03 stopped as soon as *any* small/medium candidate appeared.
        # That made a partial scan look successful and caused only one rod to
        # be displayed.  Continue through the tier list until all current rods
        # are discovered or the bounded tiers are exhausted.
    _set_diagnostic(reader, "rig_discovery_tiers", ",".join(discovery_tiers))
    _set_diagnostic(reader, "rig_discovery_scanned_regions", scanned_regions)
    _set_diagnostic(reader, "rig_discovery_scanned_bytes", scanned_bytes)
    _set_diagnostic(reader, "rig_candidates", len(candidates))
    _set_diagnostic(
        reader,
        "rig_candidate_sets",
        len({payload[1] for payload in candidates.values()}),
    )
    if not candidates:
        raise RuntimeError("未找到活动鱼竿对象")
    roots = sorted(candidates)
    if roots:
        # The rig component blocks sit roughly 0x300 MiB below the rig
        # instances in the current allocator.
        low = min(roots) - 0x50000000
        high = max(roots) + 0x20000000
        reference_regions = regions_in_span(regions, low, high)
    else:
        reference_regions = regions
    # The managed FishingSet[] relationship is diagnostic only.  It is not the
    # hotbar slot; on RF4 4.0.25029 it can be ordered by cast/rebuild history.
    set_addresses = {payload[1] for payload in candidates.values()}
    _set_diagnostic(reader, "hotbar_target_sets", len(set_addresses))
    hotbar_order: list[tuple[int, int]] = []
    _set_diagnostic(reader, "hotbar_array_order_ignored", bool(hotbar_order))
    _set_diagnostic(reader, "hotbar_status", "ui_binding_slot_pending")

    by_set: dict[int, list[tuple[int, tuple[str, int, int]]]] = {}
    for root, payload in candidates.items():
        by_set.setdefault(payload[1], []).append((root, payload))

    selected: list[tuple[int, int, tuple[str, int, int]]] = []
    for set_address in sorted(by_set):
        payloads = by_set.get(set_address, [])
        if not payloads:
            continue

        def candidate_score(item: tuple[int, tuple[str, int, int]]) -> tuple[int, int, float, int]:
            candidate_root, payload = item
            bottom_layout = not payload[0].startswith("RigBobber")
            distance = reader.f64(candidate_root + RIG_DISTANCE_OFFSET) if bottom_layout else None
            valid_distance = float(distance) if distance is not None and math.isfinite(distance) else -1.0
            return (
                int(bottom_layout and (reader.u8(candidate_root + RIG_IN_WATER_OFFSET) or 0) == 1),
                int(bottom_layout and (reader.u8(candidate_root + RIG_SESSION_OFFSET) or 0) == 1),
                valid_distance,
                candidate_root,
            )

        root, payload = max(payloads, key=candidate_score)
        selected.append((root, set_address, payload))

    result = _direct_rigs_from_selected(reader, selected[:RIG_EXPECTED_MAX])
    if not result:
        raise RuntimeError("RF4 竿位缺少可验证的 RodRest/热键证据，拒绝按地址猜 U 位")
    return result


def _valid_fishing_set(
    reader: ProcessReader,
    address: int,
    set_classes: set[int],
) -> tuple[str, int, int] | None:
    """Validate a live FishingSet and its Rig back-reference."""
    if not address or address & 7:
        return None
    class_address = reader.u64(address) or 0
    if set_classes and class_address not in set_classes:
        return None
    info = reader.class_info(class_address)
    if not info or not _is_fishing_set(reader, address):
        return None
    root = reader.u64(address + SET_ROOT_OFFSET) or 0
    root_class_address = reader.u64(root) or 0
    root_info = reader.object_info(root)
    if not root_info or not root_info[0].startswith("Rig"):
        return None
    distance = reader.f64(root + RIG_DISTANCE_OFFSET)
    in_water = reader.u8(root + RIG_IN_WATER_OFFSET)
    session = reader.u8(root + RIG_SESSION_OFFSET)
    if (
        distance is None
        or not math.isfinite(distance)
        or not 0 <= distance <= 2000
        or in_water not in (0, 1)
        or session not in (0, 1)
    ):
        return None
    if reader.u64(root + RIG_SET_FIRST_OFFSET) != address and reader.u64(root + RIG_SET_SECOND_OFFSET) != address:
        return None
    return root_info[0], root, root_class_address


def _instances_of_class(
    reader: ProcessReader,
    regions: list[MemoryRegion],
    class_address: int,
    class_name: str,
    *,
    limit: int = 100000,
) -> list[int]:
    if not class_address:
        return []
    hits = scan_qword_targets(reader, regions, {class_address}, limit_per_target=limit)
    result: list[int] = []
    for address in sorted(set(hits.get(class_address, []))):
        info = reader.object_info(address)
        if info and info[0] == class_name:
            result.append(address)
    return result


def _read_managed_list_items(reader: ProcessReader, list_address: int, *, limit: int = 16) -> list[int]:
    info = reader.object_info(list_address)
    if not info or info[0] != "List`1":
        return []
    array = reader.u64(list_address + 0x10) or 0
    size = reader.u32(list_address + 0x18)
    length = reader.u32(array + 0x18) if array else None
    if size is None or length is None or size < 0 or length < 0:
        return []
    count = min(int(size), int(length), limit)
    values: list[int] = []
    for index in range(count):
        value = reader.u64(array + 0x20 + index * 8) or 0
        if value:
            values.append(value)
    return values


def _fisher_set_sequence(
    reader: ProcessReader,
    fisher: int,
    set_addresses: set[int],
) -> list[int]:
    """Return Fisher's live current set followed by its hotkey-ring list."""
    values: list[int] = []
    current = reader.u64(fisher + 0xF0) or 0
    if current in set_addresses:
        values.append(current)
    for list_offset in (0x140, 0xC8):
        for set_address in _read_managed_list_items(
            reader,
            reader.u64(fisher + list_offset) or 0,
            limit=RIG_EXPECTED_MAX + 3,
        ):
            if set_address in set_addresses and set_address not in values:
                values.append(set_address)
    return values


def _rf4_window_handles(pid: int) -> list[int]:
    if not pid:
        return []
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
    except Exception:
        return []
    enum_windows = user32.EnumWindows
    get_window_thread_process_id = user32.GetWindowThreadProcessId
    is_window_visible = user32.IsWindowVisible
    get_window_text = user32.GetWindowTextW
    enum_windows.argtypes = [
        ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM),
        wintypes.LPARAM,
    ]
    get_window_thread_process_id.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    ]
    is_window_visible.argtypes = [wintypes.HWND]
    is_window_visible.restype = wintypes.BOOL
    get_window_text.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    result: list[int] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def callback(hwnd: int, _lparam: int) -> bool:
        process_id = wintypes.DWORD()
        get_window_thread_process_id(hwnd, ctypes.byref(process_id))
        if int(process_id.value) == int(pid) and is_window_visible(hwnd):
            title = ctypes.create_unicode_buffer(512)
            get_window_text(hwnd, title, len(title))
            if title.value:
                result.append(int(hwnd))
        return True

    enum_windows(callback, 0)
    return result


def _focus_window(hwnd: int) -> bool:
    if not hwnd:
        return False
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_window_thread_process_id = user32.GetWindowThreadProcessId
        get_window_thread_process_id.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(wintypes.DWORD),
        ]
        get_window_thread_process_id.restype = wintypes.DWORD
        attach_thread_input = user32.AttachThreadInput
        attach_thread_input.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
        show_window = user32.ShowWindow
        set_foreground_window = user32.SetForegroundWindow
        set_foreground_window.argtypes = [wintypes.HWND]
        set_foreground_window.restype = wintypes.BOOL
        current_thread = kernel.GetCurrentThreadId()
        process_id = wintypes.DWORD()
        target_thread = get_window_thread_process_id(hwnd, ctypes.byref(process_id))
        attach_thread_input(current_thread, target_thread, True)
        try:
            show_window(hwnd, 9)
            return bool(set_foreground_window(hwnd))
        finally:
            attach_thread_input(current_thread, target_thread, False)
    except Exception:
        return False


def _send_digit_key(slot: int) -> bool:
    if slot < 1 or slot > RIG_EXPECTED_MAX:
        return False
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
    except Exception:
        return False

    input_keyboard = 1
    keyeventf_keyup = 0x0002
    ulong_ptr = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong

    class MouseInput(ctypes.Structure):
        _fields_ = [
            ("dx", wintypes.LONG),
            ("dy", wintypes.LONG),
            ("mouseData", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ulong_ptr),
        ]

    class KeyboardInput(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ulong_ptr),
        ]

    class HardwareInput(ctypes.Structure):
        _fields_ = [
            ("uMsg", wintypes.DWORD),
            ("wParamL", wintypes.WORD),
            ("wParamH", wintypes.WORD),
        ]

    class InputUnion(ctypes.Union):
        _fields_ = [("mi", MouseInput), ("ki", KeyboardInput), ("hi", HardwareInput)]

    class Input(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("u", InputUnion)]

    send_input = user32.SendInput
    send_input.argtypes = [wintypes.UINT, ctypes.POINTER(Input), ctypes.c_int]
    send_input.restype = wintypes.UINT
    vk = 0x30 + int(slot)
    inputs = (Input * 2)()
    inputs[0].type = input_keyboard
    inputs[0].u.ki = KeyboardInput(vk, 0, 0, 0, 0)
    inputs[1].type = input_keyboard
    inputs[1].u.ki = KeyboardInput(vk, 0, keyeventf_keyup, 0, 0)
    return int(send_input(2, inputs, ctypes.sizeof(Input))) == 2


def _calibrate_fisher_hotkeys(
    reader: ProcessReader,
    fisher: int,
    set_addresses: set[int],
    *,
    pid: int = 0,
) -> dict[int, int]:
    """Build authoritative ``FishingSet -> U slot`` mapping by reading RF4 after key 1/2/3.

    The active Fisher object is the source of truth: after pressing a numeric
    hotkey, ``Fisher+0xF0`` becomes the set bound to that hotkey and
    ``Fisher+0x140`` contains the remaining sets in hotkey-ring order.  This
    avoids the RodRest/allocator ordering that put the real U3 rod into U1.
    """
    targets = {address for address in set_addresses if address}
    if not fisher or not targets:
        _set_diagnostic(reader, "hotkey_calibration_status", "no_fisher_or_sets")
        return {}
    # Do not send 1/2/3 during normal polling/startup.  On the live 4.0.25029
    # process those keys can pick up or rotate rods and temporarily clear the
    # RodRest link, which is exactly what made U2/U3 disappear after a restart.
    # The active Fisher object is still read-only useful as a fast FishingSet
    # collector; hotkey calibration remains an explicit lab-only probe.
    if os.environ.get("RF4_DSEN_ENABLE_HOTKEY_CALIBRATION") != "1":
        _set_diagnostic(reader, "hotkey_calibration_status", "disabled_default")
        return {}

    initial_current = reader.u64(fisher + 0xF0) or 0
    window_handles = _rf4_window_handles(pid)
    _set_diagnostic(reader, "hotkey_calibration_windows", len(window_handles))
    if window_handles:
        _set_diagnostic(reader, "hotkey_calibration_focus", _focus_window(window_handles[0]))
        time.sleep(0.08)

    direct_map: dict[int, int] = {}
    sequences: dict[int, list[int]] = {}
    for slot in range(1, RIG_EXPECTED_MAX + 1):
        sent = _send_digit_key(slot)
        _set_diagnostic(reader, f"hotkey_{slot}_sent", sent)
        time.sleep(HOTKEY_CALIBRATION_DELAY)
        sequence = _fisher_set_sequence(reader, fisher, targets)
        sequences[slot] = sequence
        current = reader.u64(fisher + 0xF0) or 0
        _set_diagnostic(reader, f"hotkey_{slot}_current", f"0x{current:X}" if current else "")
        if current in targets:
            direct_map[current] = slot

    slot_map = dict(direct_map)
    if len(slot_map) < len(targets):
        _set_diagnostic(
            reader,
            "hotkey_calibration_sequences",
            ";".join(
                f"{slot}:{','.join(f'0x{set_address:X}' for set_address in sequence)}"
                for slot, sequence in sorted(sequences.items())
            ),
        )

    # Restore the previously active set when it was known; otherwise leave U1
    # selected so the game ends calibration in a deterministic state.
    restore_slot = slot_map.get(initial_current) or 1
    if restore_slot in range(1, RIG_EXPECTED_MAX + 1):
        _send_digit_key(restore_slot)
        time.sleep(0.05)

    if len(slot_map) == len(targets):
        _set_diagnostic(reader, "hotkey_calibration_status", "ok")
    else:
        _set_diagnostic(reader, "hotkey_calibration_status", "partial")
    _set_diagnostic(
        reader,
        "hotkey_calibration_map",
        ",".join(
            f"U{slot}=0x{set_address:X}"
            for set_address, slot in sorted(slot_map.items(), key=lambda item: item[1])
        ),
    )
    return slot_map


def _direct_rigs_from_slot_map(
    selected_by_set: dict[int, tuple[int, int, tuple[str, int, int]]],
    slot_map: dict[int, int],
    *,
    evidence_address: int,
    source: str,
    confidence: float = 1.0,
) -> list[DirectRig]:
    result: list[DirectRig] = []
    for set_address, (root, _set_address, payload) in selected_by_set.items():
        slot = slot_map.get(set_address)
        if slot is None or slot < 1 or slot > RIG_EXPECTED_MAX:
            continue
        rig_type, _payload_set, class_address = payload
        result.append(
            DirectRig(
                slot=slot,
                root=root,
                set_address=set_address,
                class_address=class_address,
                rig_type=rig_type,
                order_address=evidence_address,
                order_confidence=confidence,
                slot_source=source,
            )
        )
    result.sort(key=lambda item: item.slot)
    return result


def _discover_rigs_from_fisher(
    reader: ProcessReader,
    regions: list[MemoryRegion],
    class_map: dict[str, int],
) -> list[DirectRig]:
    """Fast path: read Fisher's live FishingSet references, then slot by RodRest evidence.

    This is still an independent rf4_x64.exe memory reader.  It does not use
    rf4db helper files/backend.  The Fisher object is a live RF4 object and its
    set list avoids the slow full-heap rig-class scan that made startup appear
    one minute late.  Slot assignment is read-only: the returned FishingSet
    objects are ordered by their verified RodRestController metrics.  Sending
    RF4 hotkeys is intentionally opt-in only because it changes game state.
    """
    fisher_class = class_map.get("Fisher") or 0
    if not fisher_class:
        _set_diagnostic(reader, "fisher_status", "class_missing")
        return []
    set_classes = {
        address
        for name, address in class_map.items()
        if name in SET_CLASS_NAMES or name.endswith("FishingSet")
    }
    class_anchor = min((address for address in class_map.values() if address), default=0)
    live_regions = _sorted_small_first(
        [
            item
            for item in regions
            if item.size <= RIG_MEDIUM_REGION_LIMIT
            and (not class_anchor or item.base >= class_anchor + FISHER_LIVE_REGION_DELTA)
        ]
    )
    medium_regions = _sorted_small_first(
        [item for item in regions if item.size <= RIG_MEDIUM_REGION_LIMIT]
    )
    tiers: list[tuple[str, list[MemoryRegion], int]] = [
        ("live_medium", live_regions, 30000),
        ("medium", medium_regions, 50000),
    ]

    def collect_sets_for_fisher(
        fisher: int,
    ) -> dict[int, tuple[int, int, tuple[str, int, int]]]:
        selected_by_set: dict[int, tuple[int, int, tuple[str, int, int]]] = {}
        set_values: list[int] = []
        current = reader.u64(fisher + 0xF0) or 0
        if current:
            set_values.append(current)
        for list_offset in (0x140, 0xC8):
            set_values.extend(_read_managed_list_items(reader, reader.u64(fisher + list_offset) or 0, limit=RIG_EXPECTED_MAX + 3))
        for set_address in set_values:
            if set_address in selected_by_set:
                continue
            valid = _valid_fishing_set(reader, set_address, set_classes)
            if not valid:
                continue
            rig_type, root, class_address = valid
            selected_by_set[set_address] = (
                root,
                set_address,
                (rig_type, set_address, class_address),
            )
        return selected_by_set

    scanned: set[tuple[int, int]] = set()
    seen_fishers: set[int] = set()
    total_fishers = 0
    discovery_tiers: list[str] = []
    best_fisher = 0
    best_selected: dict[int, tuple[int, int, tuple[str, int, int]]] = {}
    for label, tier_regions, limit in tiers:
        fresh = [
            item
            for item in _unique_regions(tier_regions)
            if (item.base, item.size) not in scanned
        ]
        if not fresh:
            continue
        scanned.update((item.base, item.size) for item in fresh)
        discovery_tiers.append(label)
        fishers = _instances_of_class(reader, fresh, fisher_class, "Fisher", limit=limit)
        total_fishers += len(fishers)
        for fisher in fishers:
            if fisher in seen_fishers:
                continue
            seen_fishers.add(fisher)
            selected_by_set = collect_sets_for_fisher(fisher)
            if len(selected_by_set) > len(best_selected):
                best_fisher = fisher
                best_selected = selected_by_set
            if len(best_selected) >= RIG_EXPECTED_MAX:
                break
        if len(best_selected) >= RIG_EXPECTED_MAX:
            break

    selected = list(best_selected.values())
    _set_diagnostic(reader, "fisher_scan_tiers", ",".join(discovery_tiers))
    _set_diagnostic(reader, "fisher_instances", total_fishers)
    _set_diagnostic(reader, "fisher_best", f"0x{best_fisher:X}" if best_fisher else "")
    _set_diagnostic(reader, "fisher_sets", len(selected))
    if selected:
        _set_diagnostic(
            reader,
            "fisher_selected_detail",
            ";".join(
                f"set=0x{set_address:X},root=0x{root:X},type={payload[0]},class=0x{payload[2]:X}"
                for root, set_address, payload in selected
            ),
        )
    if not selected or not best_fisher:
        _set_diagnostic(reader, "fisher_status", "no_valid_sets")
        return []

    selected_order = selected[:RIG_EXPECTED_MAX]
    result = _direct_rigs_from_selected(reader, selected_order)
    if result:
        _set_diagnostic(reader, "rig_discovery_method", "fisher_rodrest")
        _set_diagnostic(reader, "hotbar_status", "read_only_rodrest")
        _set_diagnostic(reader, "fisher_status", "ok")
        return result

    # Optional diagnostic probe only.  Production builds do not enter this path
    # unless RF4_DSEN_ENABLE_HOTKEY_CALIBRATION=1 is set by the tester.
    set_addresses = set(best_selected)
    slot_map = _calibrate_fisher_hotkeys(
        reader,
        best_fisher,
        set_addresses,
        pid=int(getattr(reader, "pid", 0) or 0),
    )
    result = _direct_rigs_from_slot_map(
        best_selected,
        slot_map,
        evidence_address=best_fisher,
        source="fisher_hotkey",
    )
    if result:
        _set_diagnostic(reader, "rig_discovery_method", "fisher_hotkey")
        _set_diagnostic(reader, "slot_mapping_status", "fisher_hotkey")
        _set_diagnostic(reader, "hotbar_status", "fisher_hotkey")
        _set_diagnostic(reader, "fisher_status", "ok")
    else:
        _set_diagnostic(reader, "fisher_status", "rodrest_mapping_unverified")
    return result


def discover_rigs(
    reader: ProcessReader,
    regions: list[MemoryRegion],
    class_map: dict[str, int],
    *,
    preferred_sets: set[int] | None = None,
) -> list[DirectRig]:
    """Discover active rods from the game's own FishingSet -> Rig links."""
    set_scan = _discover_rigs_from_fishing_sets(
        reader,
        regions,
        class_map,
        preferred_sets=preferred_sets,
    )
    if set_scan:
        return set_scan
    # FishingSet class scanning is the current-build source of truth.  When the
    # class exists and the bounded scan completed with no active validated sets
    # (or with unmappable partial evidence), falling through to the old Fisher /
    # Rig heap walkers only recreates the observed ~70s "等待竿位映射" state.
    if getattr(reader, "diagnostics", {}).get("fishingset_scan_status") in {
        "no_valid_sets",
        "partial",
        "slot_unmapped",
    }:
        return []
    fast = _discover_rigs_from_fisher(reader, regions, class_map)
    if fast:
        return fast
    # The object address is an allocator detail and is not the hotbar slot.
    # Legacy class scanning is retained only as a candidate collector; V1.04
    # still requires RodRest/slot evidence before returning a U number.
    return _discover_rigs_legacy(reader, regions, class_map)


def _managed_string(reader: ProcessReader, address: int) -> str:
    if not address or not reader.object_info(address):
        return ""
    length = reader.u32(address + 0x10)
    if length is None or length > 512:
        return ""
    raw = reader.read(address + 0x14, length * 2)
    if not raw:
        return ""
    try:
        return raw.decode("utf-16-le", errors="ignore").strip()
    except UnicodeError:
        return ""


def _object_edges(reader: ProcessReader, address: int, size: int) -> list[tuple[int, str]]:
    raw = reader.read(address, min(size, 0x500))
    if not raw:
        return []
    edges: list[tuple[int, str]] = []
    for offset in range(0x10, len(raw) - 7, 8):
        target = struct.unpack_from("<Q", raw, offset)[0]
        info = reader.object_info(target)
        if not info:
            continue
        name, namespace, _ = info
        if namespace.startswith("System") or name in {"String", "Byte[]"}:
            continue
        edges.append((target, f"{namespace}.{name}".lstrip(".")))
    return edges


def _read_named_signal(reader: ProcessReader, address: int) -> dict[str, object]:
    info = reader.object_info(address)
    if not info:
        return {}
    fields = reader.field_offsets(reader.u64(address) or 0)
    if not fields:
        return {}
    aliases = {
        "fight_initialized": {"fight_initialized", "is_fight_initialized"},
        "fight_factor": {"fight_factor", "factor"},
        "fight_deadline": {"fight_deadline", "deadline"},
        "meta_status": {"meta_status", "status"},
        "owner_live": {"owner_live", "owner_is_live"},
        "fish_graph_live": {"fish_graph_live", "graph_live"},
        "strike_ready": {"bobber_strike_ready", "strike_ready"},
        "fish_name": {"fish", "species", "meta_species"},
        "weight_g": {"weight", "meta_weight", "weight_g"},
        "rarity": {"rarity", "meta_rarity"},
        "grade": {"grade", "meta_grade"},
        "flags": {"flags", "meta_flags"},
        "live_instance": {"instance", "meta_instance"},
    }
    aliases_by_name = {
        alias: key for key, values in aliases.items() for alias in values
    }
    result: dict[str, object] = {}
    for field_name, offset in fields.items():
        key = aliases_by_name.get(field_name.lower())
        if not key or key in result:
            continue
        location = address + offset
        if key in {"fight_factor", "fight_deadline", "weight_g"}:
            value = reader.f32(location)
            if value is not None and math.isfinite(value):
                result[key] = float(value)
        elif key in {"fight_initialized", "owner_live", "fish_graph_live", "strike_ready"}:
            value = reader.u8(location)
            if value is not None:
                result[key] = bool(value)
        elif key in {"fish_name", "rarity", "grade", "flags", "live_instance"}:
            value = _managed_string(reader, reader.u64(location) or 0)
            if value:
                result[key] = value
        else:
            value = reader.u32(location)
            if value is not None:
                result[key] = str(value)
    return result


def _fish_name_from_id(fish_id: str) -> str:
    key = str(fish_id or "").strip()
    if not key:
        return ""
    row = FISH_THRESHOLDS.get(key)
    name = str(row.get("name_zh") or "").strip() if isinstance(row, dict) else ""
    return name or key


def _read_fish_species_id(reader: ProcessReader, fish: int) -> str:
    # Verified on RF4 4.0.25029 live process:
    # Fish+0x30 -> metadata/controller; +0x38 -> species/meta; +0x80 -> string id.
    meta = reader.u64(fish + FISH_META_OFFSET) or 0
    species = reader.u64(meta + FISH_META_SPECIES_OFFSET) if meta else 0
    species_id = _managed_string(reader, reader.u64(species + FISH_SPECIES_ID_OFFSET) if species else 0)
    if species_id:
        return species_id
    # Conservative fallback: look one level below Fish+0x30 for bundled fish ids
    # such as sh_barbel.  Only strings that resolve to the local fish catalog are
    # accepted, so random UI/debug strings cannot become a fish name.
    if not meta:
        return ""
    meta_info = reader.object_info(meta)
    if not meta_info:
        return ""
    for target, _target_type in _object_edges(reader, meta, min(meta_info[2], 0x180)):
        target_info = reader.object_info(target)
        if not target_info:
            continue
        for offset in range(0x10, min(target_info[2], 0x180), 8):
            value = _managed_string(reader, reader.u64(target + offset) or 0)
            if value and value in FISH_THRESHOLDS:
                return value
    return ""


def _extract_fish_details(
    reader: ProcessReader,
    fish: int,
    *,
    expected_set: int = 0,
) -> dict[str, object]:
    if not fish:
        return {}
    set_backrefs: list[int] = []
    for offset in FISH_SET_BACKREF_OFFSETS:
        candidate = reader.u64(fish + offset) or 0
        if _is_fishing_set(reader, candidate) and candidate not in set_backrefs:
            set_backrefs.append(candidate)
    if expected_set and set_backrefs and expected_set not in set_backrefs:
        return {"owner_mismatch": True}
    result: dict[str, object] = {}
    if set_backrefs:
        result["owner_live"] = True
        result["owner_set"] = f"set:{set_backrefs[0]:X}"
    species_id = _read_fish_species_id(reader, fish)
    if species_id:
        result["fish_id"] = species_id
        result["fish_name"] = _fish_name_from_id(species_id)
    return result


class DirectMemorySource:
    """Read RF4's live rig state without the official helper."""

    def __init__(self, process_name: str = "rf4_x64.exe"):
        self.process_name = process_name
        self.reader: ProcessReader | None = None
        self.pid = 0
        self.process_path = ""
        self.session_token = ""
        self.mapping_source = ""
        self.regions: list[MemoryRegion] = []
        self._all_runtime_regions: list[MemoryRegion] = []
        self.class_map: dict[str, int] = {}
        self.rigs: list[DirectRig] = []
        self.diagnostics: dict[str, object] = {}
        self.bells: dict[int, BellTracker] = {}
        self._live_instances: list[int] = []
        self._last_live_scan = 0.0
        self._last_rig_rescan = 0.0
        self._rig_rescan_lock = threading.Lock()
        self._rig_rescan_thread: threading.Thread | None = None
        self._rig_rescan_result: tuple[
            int, int, list[DirectRig], float, dict[str, object]
        ] | None = None
        self._rig_generation = 0
        self._session_identity: dict[str, object] = {}
        self._cache_path = SESSION_CACHE_PATH

    def close(self) -> None:
        with self._rig_rescan_lock:
            self._rig_generation += 1
            self._rig_rescan_result = None
            self._rig_rescan_thread = None
        if self.reader:
            self.reader.close()
        self.reader = None
        self.pid = 0
        self.process_path = ""
        self.session_token = ""
        self.mapping_source = ""
        self.regions = []
        self._all_runtime_regions = []
        self.class_map = {}
        self.rigs = []
        self.diagnostics = {}
        self.bells.clear()
        self._live_instances = []
        self._last_rig_rescan = 0.0
        self._session_identity = {}

    def debug_state(self) -> dict[str, object]:
        """Return current in-memory reader state for the diagnostic zip."""
        with self._rig_rescan_lock:
            thread_alive = bool(self._rig_rescan_thread and self._rig_rescan_thread.is_alive())
            pending_result = self._rig_rescan_result is not None

        def region_dict(region: MemoryRegion) -> dict[str, object]:
            return {
                "base": f"0x{region.base:X}",
                "size": region.size,
                "protection": f"0x{region.protection:X}",
                "type": f"0x{region.region_type:X}",
            }

        def rig_dict(rig: DirectRig) -> dict[str, object]:
            return {
                "slot": rig.slot,
                "root": f"0x{rig.root:X}",
                "set_address": f"0x{rig.set_address:X}",
                "class_address": f"0x{rig.class_address:X}",
                "rig_type": rig.rig_type,
                "order_address": f"0x{rig.order_address:X}" if rig.order_address else "",
                "order_confidence": rig.order_confidence,
                "slot_source": rig.slot_source,
            }

        relevant_classes = {
            name: f"0x{address:X}"
            for name, address in sorted(self.class_map.items())
            if (
                name in {
                    "Fisher",
                    "RUIHotSwapSlotCell",
                    "RHUDActiveItemSlot",
                    "RHUDActiveRigComponent",
                    "RHUDActiveRigWidget",
                    "RHUDFishingSetWidget",
                    "RHUDActivatedFishingSets",
                    "RodRestController",
                    "RodPodRodRestController",
                    "RodRigFishingSet",
                    "RodReelRigFishingSet",
                    "RigBottomLiveFish",
                    "Hook",
                    "Fish",
                    "FightFishBiteMeta",
                }
                or name.startswith("RigBottom")
                or name.startswith("RigBobber")
            )
        }
        return {
            "process_name": self.process_name,
            "pid": self.pid,
            "process_path": self.process_path,
            "session_token": self.session_token,
            "mapping_source": self.mapping_source,
            "diagnostics": dict(self.diagnostics),
            "session_identity": dict(self._session_identity),
            "rig_generation": self._rig_generation,
            "rig_rescan_thread_alive": thread_alive,
            "rig_rescan_pending_result": pending_result,
            "last_rig_rescan_monotonic": self._last_rig_rescan,
            "rigs": [rig_dict(rig) for rig in self.rigs],
            "bells": {
                f"0x{set_address:X}": {
                    "baseline": tracker.baseline,
                    "last_code": tracker.last_code,
                    "candidate_code": tracker.candidate_code,
                    "active": tracker.active,
                    "armed": tracker.armed,
                    "last_state_address": f"0x{tracker.last_state_address:X}" if tracker.last_state_address else "",
                }
                for set_address, tracker in sorted(self.bells.items())
            },
            "live_instances": [f"0x{value:X}" for value in self._live_instances[:64]],
            "regions": {
                "poll_count": len(self.regions),
                "poll_bytes": sum(item.size for item in self.regions),
                "all_count": len(self._all_runtime_regions),
                "all_bytes": sum(item.size for item in self._all_runtime_regions),
                "poll_first_32": [region_dict(region) for region in self.regions[:32]],
                "all_first_32": [region_dict(region) for region in self._all_runtime_regions[:32]],
            },
            "class_map": relevant_classes,
        }

    @staticmethod
    def _region_from_cache(value: object) -> MemoryRegion | None:
        if not isinstance(value, list) or len(value) != 4:
            return None
        try:
            return MemoryRegion(*(int(item) for item in value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _rig_from_cache(value: object) -> DirectRig | None:
        if not isinstance(value, dict):
            return None
        try:
            return DirectRig(
                slot=int(value["slot"]),
                root=int(value["root"]),
                set_address=int(value["set_address"]),
                class_address=int(value["class_address"]),
                rig_type=str(value["rig_type"]),
                order_address=int(value.get("order_address", 0)),
                order_confidence=float(value.get("order_confidence", 0.0)),
                slot_source=str(value.get("slot_source", "")),
            )
        except (KeyError, TypeError, ValueError):
            return None

    def _load_session_cache(self) -> bool:
        # V1.02 uses process-live evidence only. A previous Unity snapshot is
        # never proof of the current hotbar membership or slot number.
        return False
        # The legacy implementation is intentionally unreachable.
        reader = self.reader
        if not reader or not self._session_identity:
            return False
        try:
            payload = json.loads(self._cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return False
        if payload.get("format") != SESSION_CACHE_FORMAT:
            return False
        if payload.get("identity") != self._session_identity:
            return False
        all_regions = [
            item
            for value in payload.get("runtime_regions", [])
            if (item := self._region_from_cache(value)) is not None
        ]
        poll_regions = [
            item
            for value in payload.get("poll_regions", [])
            if (item := self._region_from_cache(value)) is not None
        ]
        try:
            class_map = {
                str(name): int(address)
                for name, address in payload.get("class_map", {}).items()
            }
        except (AttributeError, TypeError, ValueError):
            return False
        if not all_regions or not class_map:
            return False
        cached_rigs = [
            item
            for value in payload.get("rigs", [])
            if (item := self._rig_from_cache(value)) is not None
        ]
        rig_classes = set(class_map.values())
        valid_rigs = [
            rig for rig in cached_rigs if _valid_rig(reader, rig.root, rig_classes)
        ]
        self._all_runtime_regions = all_regions
        self.regions = poll_regions or all_regions
        self.class_map = class_map
        self.rigs = sorted(valid_rigs, key=lambda item: item.slot)
        self.bells = {item.set_address: BellTracker() for item in self.rigs}
        cached_diagnostics = payload.get("diagnostics", {})
        if isinstance(cached_diagnostics, dict):
            reader.diagnostics.update(cached_diagnostics)
        reader.diagnostics.update(
            {
                "cache_status": "restored",
                "cached_rigs": len(cached_rigs),
                "validated_cached_rigs": len(self.rigs),
            }
        )
        return True

    def _save_session_cache(self) -> None:
        # Do not persist runtime mappings in the clean V1.02 data path.
        return
        # The legacy implementation is intentionally unreachable.
        if not self._session_identity or not self._all_runtime_regions or not self.class_map:
            return
        payload = {
            "format": SESSION_CACHE_FORMAT,
            "identity": self._session_identity,
            "runtime_regions": [
                [item.base, item.size, item.protection, item.region_type]
                for item in self._all_runtime_regions
            ],
            "poll_regions": [
                [item.base, item.size, item.protection, item.region_type]
                for item in self.regions
            ],
            "class_map": self.class_map,
            "rigs": [
                {
                    "slot": item.slot,
                    "root": item.root,
                    "set_address": item.set_address,
                    "class_address": item.class_address,
                    "rig_type": item.rig_type,
                    "order_address": item.order_address,
                    "order_confidence": item.order_confidence,
                    "slot_source": item.slot_source,
                }
                for item in self.rigs
            ],
            "diagnostics": {
                key: self.diagnostics.get(key)
                for key in (
                    "game_build",
                    "game_assembly_sha256",
                    "game_assembly_file_size",
                    "game_assembly_image_size",
                    "class_cache_status",
                    "class_cache_rva",
                    "class_cache_valid",
                    "class_cache_classes",
                )
                if self.diagnostics.get(key) is not None
            },
        }
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._cache_path.with_suffix(self._cache_path.suffix + ".tmp")
            temporary.write_text(
                json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
                encoding="utf-8",
            )
            os.replace(temporary, self._cache_path)
        except OSError:
            pass

    def _open_current_process(self) -> None:
        found = find_rf4_process(self.process_name)
        if not found:
            raise RuntimeError("未找到 rf4_x64.exe")
        pid, path = found
        if self.reader and pid == self.pid:
            return
        self.close()
        self.reader = ProcessReader(pid)
        self.pid = pid
        self.process_path = path
        started_at = time.monotonic()
        try:
            game_directory = os.path.dirname(path)
            self.reader.diagnostics.update(
                {
                    "game_root": game_directory,
                    "game_files_scanned": 0,
                    "game_bytes_scanned": 0,
                    "game_installation_error": "",
                }
            )
            assembly_path = os.path.join(game_directory, "GameAssembly.dll")
            try:
                assembly_stat = os.stat(assembly_path)
                assembly_file_size = int(assembly_stat.st_size)
                assembly_mtime_ns = int(assembly_stat.st_mtime_ns)
            except OSError:
                assembly_file_size = 0
                assembly_mtime_ns = 0
            self._session_identity = {
                "pid": pid,
                "process_created": _process_creation_ticks(self.reader.handle),
                "process_path": os.path.normcase(os.path.abspath(path)),
                "assembly_size": assembly_file_size,
                "assembly_mtime_ns": assembly_mtime_ns,
            }
            assembly_hash = _sha256_file(assembly_path)
            self.reader.diagnostics.update(
                {
                    "game_build": _known_build(assembly_hash),
                    "game_assembly_sha256": assembly_hash,
                    "game_assembly_file_size": assembly_file_size,
                    "game_assembly_image_size": _pe_image_size(assembly_path),
                }
            )
            self.class_map = discover_class_map(self.reader, [])
            class_anchor = min(self.class_map.values(), default=0)
            if class_anchor:
                region_start = max(HIGH_RUNTIME_ADDRESS, class_anchor - 0x40000000)
                region_end = class_anchor + DISCOVERY_WINDOW
                self.regions = readable_regions(self.reader, region_start, region_end)
            else:
                self.regions = readable_regions(self.reader)
            runtime_regions = choose_runtime_regions(self.regions)
            if not runtime_regions:
                raise RuntimeError("未找到 Unity 私有运行时内存")
            if not self.class_map:
                self.class_map = discover_class_map(self.reader, runtime_regions)
            self.reader.diagnostics.update(
                {
                    "readable_regions": len(self.regions),
                    "runtime_regions": len(runtime_regions),
                    "runtime_bytes": sum(item.size for item in runtime_regions),
                    "discovered_classes": len(self.class_map),
                }
            )
            anchor = min((item.base for item in runtime_regions), default=0)
            object_regions = regions_in_span(
                runtime_regions,
                anchor + 0x200000000,
                anchor + 0x280000000,
            )
            self._all_runtime_regions = runtime_regions
            self.regions = object_regions or runtime_regions
            self.session_token = f"direct:{pid}"
            self.mapping_source = "rf4_x64.exe 独立实时内存"
            self.bells = {}
            self._live_instances = []
            self.reader.diagnostics["rigs"] = 0
            self.reader.diagnostics["discovery_status"] = "scanning"
            self.reader.diagnostics["connect_ms"] = int(
                (time.monotonic() - started_at) * 1000
            )
            self.diagnostics = dict(self.reader.diagnostics)
            self._save_session_cache()
            self._last_rig_rescan = 0.0
            self._refresh_rigs_if_needed(force=True)
        except Exception as exc:
            failed_diagnostics = dict(self.reader.diagnostics) if self.reader else {}
            failed_diagnostics["rigs"] = len(self.rigs)
            failed_diagnostics["discovery_error"] = str(exc)
            failed_diagnostics["discovery_ms"] = int(
                (time.monotonic() - started_at) * 1000
            )
            self.close()
            self.diagnostics = failed_diagnostics
            raise

    def _apply_discovered_rigs(self, rigs: list[DirectRig]) -> None:
        if not rigs:
            return
        if len(self.rigs) >= RIG_EXPECTED_MAX and len(rigs) < len(self.rigs):
            self.diagnostics["partial_discovery_ignored"] = len(rigs)
            return
        old_mapping = tuple((item.slot, item.set_address, item.root) for item in self.rigs)
        # Do not merge an older observation into a newer partial Unity graph.
        # Every displayed mapping must be positively rediscovered now.
        self.rigs = sorted(
            (item for item in rigs if 1 <= item.slot <= 3),
            key=lambda item: item.slot,
        )
        new_mapping = tuple((item.slot, item.set_address, item.root) for item in self.rigs)
        if old_mapping != new_mapping:
            self.bells = {
                item.set_address: self.bells.get(item.set_address, BellTracker())
                for item in self.rigs
            }
            self._live_instances = []
            self.diagnostics["rigs"] = len(self.rigs)
            self._save_session_cache()

    def _collect_rig_rescan(self) -> None:
        with self._rig_rescan_lock:
            result = self._rig_rescan_result
            self._rig_rescan_result = None
        if not result:
            return
        generation, pid, rigs, finished_at, diagnostics = result
        self._last_rig_rescan = time.monotonic()
        if generation == self._rig_generation and pid == self.pid:
            self._apply_discovered_rigs(rigs)
            self.diagnostics.update(diagnostics)
            self.diagnostics["rigs"] = len(self.rigs)
            self.diagnostics["last_discovery_at"] = time.time()

    def _discover_rigs_background(
        self,
        generation: int,
        pid: int,
        runtime_regions: list[MemoryRegion],
        class_map: dict[str, int],
        preferred_sets: set[int],
    ) -> None:
        rigs: list[DirectRig] = []
        diagnostics: dict[str, object] = {}
        scan_reader: ProcessReader | None = None
        started_at = time.monotonic()
        try:
            # Keep discovery isolated from the high-frequency polling handle.
            scan_reader = ProcessReader(pid)
            last_error: Exception | None = None
            for attempt in range(INITIAL_DISCOVERY_ATTEMPTS):
                scan_reader.diagnostics["discovery_attempts"] = attempt + 1
                try:
                    rigs = discover_rigs(
                        scan_reader,
                        runtime_regions,
                        class_map,
                        preferred_sets=preferred_sets,
                    )
                    last_error = None
                    break
                except Exception as exc:
                    last_error = exc
                    if attempt + 1 < INITIAL_DISCOVERY_ATTEMPTS:
                        time.sleep(INITIAL_DISCOVERY_DELAY)
            diagnostics = dict(getattr(scan_reader, "diagnostics", {}) or {})
            if last_error is not None:
                diagnostics["discovery_error"] = str(last_error)
                diagnostics["discovery_status"] = "failed"
            else:
                diagnostics.pop("discovery_error", None)
                diagnostics["discovery_status"] = "ready"
        except Exception as exc:
            diagnostics["discovery_error"] = str(exc)
            diagnostics["discovery_status"] = "failed"
        finally:
            if scan_reader:
                scan_reader.close()
        finished_at = time.monotonic()
        diagnostics["discovery_ms"] = int((finished_at - started_at) * 1000)
        diagnostics["discovered_rigs"] = len(rigs)
        with self._rig_rescan_lock:
            if generation == self._rig_generation and pid == self.pid:
                self._rig_rescan_result = (
                    generation, pid, rigs, finished_at, diagnostics
                )

    def _refresh_rigs_if_needed(self, *, force: bool = False) -> None:
        had_rigs = bool(self.rigs)
        self._collect_rig_rescan()
        if force and not had_rigs and self.rigs:
            # A previous startup scan finished while this snapshot was entering
            # refresh.  Use that verified result instead of immediately firing a
            # second full discovery pass.
            force = False
        if not self.reader or not self._all_runtime_regions:
            return
        if not force and len(self.rigs) >= 3:
            return
        now = time.monotonic()
        interval = PARTIAL_RIG_RESCAN_INTERVAL if self.rigs else RIG_RESCAN_INTERVAL
        if not force and now - self._last_rig_rescan < interval:
            return
        with self._rig_rescan_lock:
            if self._rig_rescan_thread and self._rig_rescan_thread.is_alive():
                return
            generation = self._rig_generation
            pid = self.pid
            worker = threading.Thread(
                target=self._discover_rigs_background,
                args=(
                    generation,
                    pid,
                    list(self._all_runtime_regions),
                    dict(self.class_map),
                    {item.set_address for item in self.rigs if item.set_address},
                ),
                name="RF4RigDiscovery",
                daemon=True,
            )
            self._rig_rescan_thread = worker
            self._last_rig_rescan = now
            self.diagnostics["discovery_status"] = "scanning"
            self.diagnostics["discovery_started_at"] = time.time()
            worker.start()
        if force and not self.rigs:
            worker.join(INITIAL_DISCOVERY_SYNC_WAIT)
            self._collect_rig_rescan()

    def _bell_state(self, rig: DirectRig, in_water: bool, session: bool) -> tuple[bool, int | None, int | None, int, str]:
        reader = self.reader
        if not reader:
            return False, None, None, 0, ""
        bell = reader.u64(rig.set_address + SET_BELL_OFFSET) or 0
        state = reader.u64(bell + BELL_STATE_OFFSET) if bell else 0
        code = reader.u32(state + BELL_CODE_OFFSET) if state else None
        tracker = self.bells.setdefault(rig.set_address, BellTracker())
        now = time.monotonic()
        if not in_water or not session or code is None:
            tracker.baseline = code
            tracker.last_code = code
            tracker.candidate_code = None
            tracker.candidate_since = 0.0
            tracker.active = False
            tracker.armed = False
            tracker.stable_since = 0.0
            tracker.idle_since = now
            tracker.last_state_address = state or 0
            return False, code, tracker.baseline, state or 0, ""
        if not tracker.armed:
            if tracker.last_code == code:
                if not tracker.stable_since:
                    tracker.stable_since = now
                elif now - tracker.stable_since >= 0.30:
                    tracker.baseline = code
                    tracker.armed = True
            else:
                tracker.stable_since = now
            tracker.last_code = code
            tracker.last_state_address = state or 0
            return False, code, tracker.baseline, state or 0, "arming"
        if code != tracker.baseline:
            tracker.idle_since = 0.0
            if tracker.candidate_code != code:
                tracker.candidate_code = code
                tracker.candidate_since = now
            if not tracker.active and now - tracker.candidate_since >= 0.04:
                tracker.active = True
            tracker.last_code = code
        else:
            tracker.candidate_code = None
            if tracker.active:
                if not tracker.idle_since:
                    tracker.idle_since = now
                elif now - tracker.idle_since >= 0.15:
                    tracker.active = False
            tracker.last_code = code
        tracker.last_state_address = state or 0
        phase = "active" if tracker.active else "candidate" if code != tracker.baseline else "idle"
        return tracker.active, code, tracker.baseline, state or 0, phase

    def _scan_live_instances(self) -> None:
        reader = self.reader
        class_address = self.class_map.get("RigBottomLiveFish") if self.class_map else None
        if not reader or not class_address:
            return
        hits = scan_qword_targets(reader, self.regions, {class_address}, limit_per_target=200)
        values: list[int] = []
        for address in hits.get(class_address, []):
            if reader.object_info(address) and address not in values:
                values.append(address)
        self._live_instances = values

    def _is_fish_object(self, address: int) -> bool:
        reader = self.reader
        if not reader or not address:
            return False
        info = reader.object_info(address)
        if not info:
            return False
        fish_class = self.class_map.get("Fish")
        class_address = reader.u64(address) or 0
        if fish_class and class_address == fish_class:
            return True
        # Keep derived Fish classes compatible with future builds.
        current = class_address
        seen: set[int] = set()
        while current and current not in seen and len(seen) < 16:
            seen.add(current)
            parent = reader.u64(current + CLASS_PARENT_OFFSET) or 0
            parent_info = reader.class_info(parent)
            if parent_info and parent_info[0] == "Fish":
                return True
            current = parent
        return False

    def _read_hook_fish(self, rig: DirectRig) -> dict[str, object]:
        """Read the fish actually attached to this rig's Hook component.

        In the current build this pointer is the earliest stable per-rod
        indicator of a hooked fish.  It is independent of the bell animation
        and of post-catch/result files.
        """
        reader = self.reader
        if not reader:
            return {}
        hook = reader.u64(rig.root + RIG_HOOK_OFFSET) or 0
        hook_info = reader.object_info(hook)
        if not hook_info or hook_info[0] != "Hook":
            return {}
        fish = reader.u64(hook + HOOK_FISH_OFFSET) or 0
        if not self._is_fish_object(fish):
            return {}
        graph_details = _extract_fish_details(reader, fish, expected_set=rig.set_address)
        if graph_details.get("owner_mismatch"):
            return {}
        signal = {
            "live": True,
            "live_phase": "hooked",
            "live_instance": f"fish:{fish:X}",
            "owner_live": True,
            "fish_graph_live": True,
        }
        for key, value in graph_details.items():
            signal.setdefault(key, value)
        details = _read_named_signal(reader, fish)
        for key, value in details.items():
            signal.setdefault(key, value)
        return signal

    def _read_live_signal(self, rig: DirectRig, active: bool) -> dict[str, object]:
        reader = self.reader
        if not reader or not active:
            return {}
        now = time.monotonic()
        if now - self._last_live_scan > 0.5 or not self._live_instances:
            self._last_live_scan = now
            self._scan_live_instances()
        if not self._live_instances:
            return {}
        # Only a live-fish object reachable from this rig may contribute data.
        starts = [rig.root, rig.set_address]
        for offset in (RIG_HOOK_OFFSET, RIG_FEEDER_OFFSET, SET_INTERACTIVE_ROD_OFFSET):
            owner = rig.root if offset in (RIG_HOOK_OFFSET, RIG_FEEDER_OFFSET) else rig.set_address
            target = reader.u64(owner + offset) or 0
            if target:
                starts.append(target)
        target_set = set(self._live_instances)
        stack = [(address, 0) for address in starts]
        seen: set[int] = set()
        reachable: list[int] = []
        while stack and len(seen) < 500:
            address, depth = stack.pop()
            if address in seen:
                continue
            seen.add(address)
            if address in target_set:
                reachable.append(address)
            if depth >= 4:
                continue
            info = reader.object_info(address)
            if not info:
                continue
            for target, _ in _object_edges(reader, address, info[2]):
                if target not in seen:
                    stack.append((target, depth + 1))
        if not reachable:
            return {}
        for address in reachable:
            signal = _read_named_signal(reader, address)
            if signal:
                signal.setdefault("live", True)
                signal.setdefault("live_phase", "fight")
                return signal
        return {}

    def snapshot(self) -> DirectSnapshot:
        self._open_current_process()
        reader = self.reader
        if not reader:
            raise RuntimeError("未连接 RF4 进程")
        self._refresh_rigs_if_needed(force=not self.rigs)
        if False and not self.rigs:
            raise RuntimeError("未找到快捷栏竿位，请确认已把竿插入 1-3 号位并抛出")
        elif any(
            not _valid_rig(reader, rig.root, {rig.class_address})
            for rig in self.rigs
        ):
            self._refresh_rigs_if_needed(force=True)
        rods: list[DirectRodState] = []
        for rig in self.rigs:
            state = DirectRodState(
                slot=rig.slot,
                guid=f"set-{rig.set_address:X}".lower(),
                root=rig.root,
                rig_type=rig.rig_type,
                set_address=rig.set_address,
            )
            info = _valid_rig(reader, rig.root, {rig.class_address})
            if not info:
                state.reason = "鱼竿对象已变化"
                rods.append(state)
                continue
            if rig.rig_type.startswith("RigBobber"):
                state.reason = "浮钓未映射"
                rods.append(state)
                continue
            distance = reader.f64(rig.root + RIG_DISTANCE_OFFSET)
            state.distance_m = distance if distance is not None and math.isfinite(distance) else None
            state.in_water = reader.u8(rig.root + RIG_IN_WATER_OFFSET) == 1
            state.session = reader.u8(rig.root + RIG_SESSION_OFFSET) == 1
            hook_signal = self._read_hook_fish(rig)
            active, code, baseline, bell_state, phase = self._bell_state(
                rig, state.in_water, state.session
            )
            state.bell_active = active
            state.bite_active = bool(hook_signal.get("live"))
            state.bell_code = code
            state.bell_baseline = baseline
            state.bell_state_address = bell_state
            state.live_phase = "probe" if active and not state.bite_active else ""
            signal = hook_signal if hook_signal.get("live") else {}
            if signal.get("live"):
                state.bite_active = True
                state.bell_active = active
                state.live_phase = str(signal.get("live_phase") or "fight")
                state.live_instance = str(signal.get("live_instance") or "")
                state.fish_name = str(signal.get("fish_name") or "")
                raw_weight = signal.get("weight_g")
                if isinstance(raw_weight, (int, float)) and math.isfinite(raw_weight):
                    state.weight_g = float(raw_weight)
                state.rarity = str(signal.get("rarity") or "")
                state.grade = str(signal.get("grade") or "")
                state.flags = str(signal.get("flags") or "")
                state.fight_initialized = bool(signal.get("fight_initialized"))
                state.fight_factor = float(signal.get("fight_factor") or 0.0)
                deadline = signal.get("fight_deadline")
                if isinstance(deadline, (int, float)) and math.isfinite(deadline):
                    state.fight_deadline = float(deadline)
                state.meta_status = str(signal.get("meta_status") or "")
                state.owner_live = bool(signal.get("owner_live"))
                state.fish_graph_live = bool(signal.get("fish_graph_live"))
                state.strike_ready = bool(signal.get("strike_ready"))
            state.valid = True
            rods.append(state)
        return DirectSnapshot(
            pid=self.pid,
            session_token=self.session_token,
            mapping_source=self.mapping_source,
            rods=rods,
            diagnostics={
                **self.diagnostics,
                "rigs": len(self.rigs),
                "poll_rods": ";".join(
                    f"U{rod.slot}=root:0x{rod.root:X},set:0x{rod.set_address:X},valid:{rod.valid},water:{rod.in_water},session:{rod.session},fish:{rod.fish_name or '-'},phase:{rod.live_phase or '-'},reason:{rod.reason or '-'}"
                    for rod in rods
                ),
                "discovery_thread_alive": bool(
                    self._rig_rescan_thread and self._rig_rescan_thread.is_alive()
                ),
            },
        )


if __name__ == "__main__":  # lightweight development probe, not used by the EXE
    source = DirectMemorySource()
    try:
        snapshot = source.snapshot()
        print(f"pid={snapshot.pid} source={snapshot.mapping_source}")
        for rod in snapshot.rods:
            print(
                f"U{rod.slot} root=0x{rod.root:X} set=0x{rod.set_address:X} "
                f"distance={rod.distance_m!r} water={rod.in_water} session={rod.session} "
                f"bell=0x{rod.bell_code or 0:X} active={rod.bite_active}"
            )
    finally:
        source.close()
