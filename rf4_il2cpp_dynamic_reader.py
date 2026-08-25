from __future__ import annotations

"""Dynamic IL2CPP reader for RF4.

The reader consumes Il2CppDumper output placed beside this file/executable.
It never uses another application's process, files, pipes, or backend.
"""

import argparse
import ctypes
import ctypes.wintypes as wintypes
import json
import re
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
LIST_MODULES_ALL = 0x03

IL2CPP_CLASS_NAME = 0x10
IL2CPP_CLASS_NAMESPACE = 0x18
IL2CPP_CLASS_STATIC_FIELDS = 0xB8
LIST_ITEMS = 0x10
LIST_SIZE = 0x18
ARRAY_LENGTH = 0x18
ARRAY_FIRST_ITEM = 0x20


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
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
kernel32.Process32NextW.restype = wintypes.BOOL

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


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _key(mapping: dict[str, Any], *names: str) -> Any:
    lowered = {str(key).lower(): value for key, value in mapping.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


@dataclass(frozen=True)
class FieldLayout:
    name: str
    type_name: str
    offset: int
    is_static: bool = False


@dataclass
class TypeLayout:
    name: str
    namespace: str = ""
    base_name: str = ""
    address: int | None = None
    fields: dict[str, FieldLayout] = field(default_factory=dict)

    @property
    def full_name(self) -> str:
        return f"{self.namespace}.{self.name}" if self.namespace else self.name


@dataclass(frozen=True)
class ResolvedLayout:
    manager: TypeLayout
    singleton_field: FieldLayout
    rig_list_field: FieldLayout
    rig_type: TypeLayout
    rig_in_water: FieldLayout
    fight_initialized: FieldLayout
    fight_factor: FieldLayout


class LayoutError(RuntimeError):
    pass


class Il2CppLayoutParser:
    """Parse common enhanced JSON exports and stock Il2CppDumper output."""

    TYPE_NAME_KEYS = ("name", "typename", "classname")
    FIELD_LIST_KEYS = ("fields", "fieldlist", "instancefields", "staticfields")
    ADDRESS_KEYS = (
        "typeinfoaddress",
        "classaddress",
        "address",
        "rva",
        "offset",
    )

    def __init__(self) -> None:
        self.types: dict[str, TypeLayout] = {}
        self.metadata_addresses: dict[str, int] = {}
        self.sources: list[str] = []

    @classmethod
    def from_files(cls, script_json: Path, dump_cs: Path | None = None) -> "Il2CppLayoutParser":
        parser = cls()
        if not script_json.is_file():
            raise LayoutError(f"找不到 {script_json}")
        try:
            payload = json.loads(script_json.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise LayoutError(f"script.json 读取失败: {exc}") from exc
        parser._parse_json(payload)
        parser.sources.append(str(script_json))
        fallback = dump_cs or script_json.with_name("dump.cs")
        if fallback.is_file():
            parser._parse_dump_cs(fallback.read_text(encoding="utf-8-sig", errors="replace"))
            parser.sources.append(str(fallback))
        return parser

    def _upsert_type(
        self,
        name: str,
        namespace: str = "",
        base_name: str = "",
        address: int | None = None,
    ) -> TypeLayout:
        name = name.strip().replace("/", ".")
        namespace = namespace.strip()
        if "." in name and not namespace:
            namespace, name = name.rsplit(".", 1)
        key = _norm(f"{namespace}.{name}")
        existing = self.types.get(key)
        if existing is None:
            existing = TypeLayout(name=name, namespace=namespace)
            self.types[key] = existing
        if base_name and not existing.base_name:
            existing.base_name = base_name.strip()
        if address is not None and existing.address is None:
            existing.address = address
        return existing

    @staticmethod
    def _looks_like_field(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        name = _key(value, "name", "fieldname")
        offset = _key(value, "offset", "fieldoffset")
        return isinstance(name, str) and _integer(offset) is not None

    def _parse_field(self, raw: dict[str, Any], force_static: bool = False) -> FieldLayout | None:
        name = _key(raw, "name", "fieldname")
        offset = _integer(_key(raw, "offset", "fieldoffset"))
        if not isinstance(name, str) or offset is None or offset < 0:
            return None
        type_value = _key(raw, "type", "typename", "fieldtype")
        if isinstance(type_value, dict):
            type_value = _key(type_value, "name", "fullname", "type")
        type_name = str(type_value or "")
        static_value = _key(raw, "isstatic", "static")
        attrs = str(_key(raw, "attributes", "attrs", "modifiers") or "")
        is_static = force_static or static_value is True or "static" in attrs.lower()
        return FieldLayout(name=name, type_name=type_name, offset=offset, is_static=is_static)

    def _parse_json(self, payload: Any) -> None:
        if isinstance(payload, dict):
            metadata = _key(payload, "ScriptMetadata")
            if isinstance(metadata, list):
                for item in metadata:
                    if not isinstance(item, dict):
                        continue
                    name = _key(item, "Name")
                    address = _integer(_key(item, "Address"))
                    if isinstance(name, str) and address is not None:
                        cleaned = re.sub(r"(?:\$\$|_)(?:TypeInfo|Il2CppType)$", "", name)
                        self.metadata_addresses[_norm(cleaned)] = address

            self._parse_json_type_node(payload)
            for value in payload.values():
                self._parse_json(value)
        elif isinstance(payload, list):
            for item in payload:
                self._parse_json(item)

    def _parse_json_type_node(self, raw: dict[str, Any]) -> None:
        field_containers: list[tuple[Any, bool]] = []
        for key, value in raw.items():
            if key.lower() in self.FIELD_LIST_KEYS and isinstance(value, (list, dict)):
                field_containers.append((value, "static" in key.lower()))
        if not field_containers:
            return
        name = _key(raw, *self.TYPE_NAME_KEYS)
        if not isinstance(name, str) or not name.strip():
            return
        namespace = str(_key(raw, "namespace") or "")
        base_name = str(_key(raw, "base", "basename", "parent", "basetype") or "")
        address = None
        for key in self.ADDRESS_KEYS:
            address = _integer(_key(raw, key))
            if address is not None:
                break
        layout = self._upsert_type(name, namespace, base_name, address)
        for values, force_static in field_containers:
            if isinstance(values, dict):
                values = values.values()
            for item in values:
                if self._looks_like_field(item):
                    field_layout = self._parse_field(item, force_static)
                    if field_layout:
                        layout.fields[field_layout.name] = field_layout

    def _parse_dump_cs(self, text: str) -> None:
        class_pattern = re.compile(
            r"(?m)^(?:\[[^\n]*\]\s*)*(?:public|private|internal|protected)?\s*"
            r"(?:abstract\s+|sealed\s+|static\s+|partial\s+)*"
            r"(?:class|struct)\s+([^\s:<{]+)(?:<[^\n{]+>)?\s*"
            r"(?::\s*([^\n{]+))?[^\n{]*\s*\{"
        )
        matches = list(class_pattern.finditer(text))
        namespace_matches = list(re.finditer(r"(?m)^// Namespace:\s*(.*)$", text))
        for index, match in enumerate(matches):
            start = match.end()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            body = text[start:end]
            namespace = ""
            for ns_match in namespace_matches:
                if ns_match.start() > match.start():
                    break
                namespace = ns_match.group(1).strip()
            base_name = (match.group(2) or "").split(",", 1)[0].strip()
            layout = self._upsert_type(match.group(1), namespace, base_name)
            fields_part = body.split("// Methods", 1)[0]
            for line in fields_part.splitlines():
                field_match = re.search(
                    r"\b(?:(public|private|protected|internal)\s+)?"
                    r"(?:(static)\s+)?(?:readonly\s+|const\s+|volatile\s+)*"
                    r"([^;=]+?)\s+([A-Za-z_$<>][\w$<>]*)\s*(?:=[^;]*)?;\s*//\s*0x([0-9A-Fa-f]+)",
                    line,
                )
                if not field_match:
                    continue
                type_name = field_match.group(3).strip()
                name = field_match.group(4).strip()
                layout.fields[name] = FieldLayout(
                    name=name,
                    type_name=type_name,
                    offset=int(field_match.group(5), 16),
                    is_static=bool(field_match.group(2)),
                )

        for key, address in self.metadata_addresses.items():
            candidates = [item for item_key, item in self.types.items() if item_key.endswith(key)]
            if len(candidates) == 1 and candidates[0].address is None:
                candidates[0].address = address

    def find_type(self, aliases: Iterable[str], required: bool = True) -> TypeLayout | None:
        alias_norms = [_norm(alias) for alias in aliases if alias]
        exact = [layout for key, layout in self.types.items() if key in alias_norms or _norm(layout.name) in alias_norms]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            raise LayoutError("类名匹配不唯一: " + ", ".join(item.full_name for item in exact))
        suffix = [layout for key, layout in self.types.items() if any(key.endswith(alias) for alias in alias_norms)]
        if len(suffix) == 1:
            return suffix[0]
        if required:
            raise LayoutError("缺少类: " + "/".join(aliases))
        return None

    def inherited_fields(self, layout: TypeLayout) -> dict[str, FieldLayout]:
        result: dict[str, FieldLayout] = {}
        current: TypeLayout | None = layout
        seen: set[str] = set()
        while current is not None and _norm(current.full_name) not in seen:
            seen.add(_norm(current.full_name))
            for name, value in current.fields.items():
                result.setdefault(name, value)
            current = self.find_type([current.base_name], required=False) if current.base_name else None
        return result

    def find_field(
        self,
        layout: TypeLayout,
        aliases: Iterable[str],
        *,
        static: bool | None = None,
        type_contains: Iterable[str] = (),
        label: str,
    ) -> FieldLayout:
        fields = self.inherited_fields(layout)
        alias_norms = {_norm(alias) for alias in aliases}
        exact = [value for value in fields.values() if _norm(value.name) in alias_norms]
        if static is not None:
            exact = [value for value in exact if value.is_static == static]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            raise LayoutError(f"{label} 字段不唯一: " + ", ".join(value.name for value in exact))
        hints = [_norm(value) for value in type_contains]
        structural = [
            value
            for value in fields.values()
            if (static is None or value.is_static == static)
            and hints
            and any(hint in _norm(value.type_name) for hint in hints)
        ]
        if len(structural) == 1:
            return structural[0]
        detail = ", ".join(f"{value.name}:{value.type_name}@0x{value.offset:X}" for value in structural)
        if structural:
            raise LayoutError(f"{label} 的类型特征不唯一: {detail}")
        raise LayoutError(f"{layout.full_name} 缺少 {label} 字段")

    def resolve_rf4_layout(
        self,
        manager_name: str = "FishingManager",
        rig_name: str = "RigBottomSimple",
        singleton_name: str = "",
        list_name: str = "",
    ) -> ResolvedLayout:
        manager_aliases = [manager_name, "FishingManager", "FishingController"]
        manager = self.find_type(manager_aliases, required=False)
        if manager is None:
            manager_candidates: list[TypeLayout] = []
            for candidate in self.types.values():
                fields = list(candidate.fields.values())
                has_self_static = any(
                    value.is_static and _norm(candidate.name) in _norm(value.type_name)
                    for value in fields
                )
                has_rig_list = any(
                    not value.is_static
                    and "list" in _norm(value.type_name)
                    and "rig" in _norm(value.type_name)
                    for value in fields
                )
                if has_self_static and has_rig_list:
                    manager_candidates.append(candidate)
            if len(manager_candidates) != 1:
                names = ", ".join(item.full_name for item in manager_candidates) or "none"
                raise LayoutError(f"FishingManager 结构匹配不唯一: {names}")
            manager = manager_candidates[0]

        rig_aliases = [rig_name, "RigBottomSimple", "RigBottomBase", "Rig"]
        rig_type = self.find_type(rig_aliases, required=False)
        if rig_type is None:
            semantic_names = {
                _norm(value)
                for value in (
                    "rig_in_water", "inWater", "isInWater", "_inWater",
                    "fight_initialized", "fightInitialized", "isFightInitialized", "_fightInitialized",
                    "fight_factor", "fightFactor", "_fightFactor",
                )
            }
            rig_candidates = [
                candidate
                for candidate in self.types.values()
                if len({_norm(name) for name in self.inherited_fields(candidate)} & semantic_names) >= 3
            ]
            if len(rig_candidates) != 1:
                names = ", ".join(item.full_name for item in rig_candidates) or "none"
                raise LayoutError(f"Rig 类型结构匹配不唯一: {names}")
            rig_type = rig_candidates[0]
        singleton = self.find_field(
            manager,
            [singleton_name, "instance", "_instance", "singleton", "s_instance"],
            static=True,
            type_contains=[manager.name],
            label="Singleton",
        )
        rig_list = self.find_field(
            manager,
            [list_name, "rigs", "activeRigs", "fishingRigs", "rigList", "_rigs"],
            static=False,
            type_contains=["List<Rig", "List`1", "IList<Rig"],
            label="Rig List",
        )
        in_water = self.find_field(
            rig_type,
            ["rig_in_water", "inWater", "isInWater", "_inWater"],
            static=False,
            type_contains=[],
            label="rig_in_water",
        )
        fight_initialized = self.find_field(
            rig_type,
            ["fight_initialized", "fightInitialized", "isFightInitialized", "_fightInitialized"],
            static=False,
            type_contains=[],
            label="fight_initialized",
        )
        fight_factor = self.find_field(
            rig_type,
            ["fight_factor", "fightFactor", "_fightFactor"],
            static=False,
            type_contains=[],
            label="fight_factor",
        )
        return ResolvedLayout(manager, singleton, rig_list, rig_type, in_water, fight_initialized, fight_factor)

    def summary(self) -> dict[str, Any]:
        return {
            "sources": self.sources,
            "types": len(self.types),
            "fields": sum(len(item.fields) for item in self.types.values()),
            "metadata_addresses": len(self.metadata_addresses),
        }


def find_process(name: str) -> int:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    entry = ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == name.lower():
                return int(entry.th32ProcessID)
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return 0


class ProcessMemory:
    def __init__(self, pid: int):
        self.pid = pid
        self.handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def read(self, address: int, size: int) -> bytes:
        if not address or size <= 0:
            raise OSError(f"无效读取 0x{address:X}+{size}")
        buffer = ctypes.create_string_buffer(size)
        received = ctypes.c_size_t()
        ok = kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(received)
        )
        if not ok or received.value != size:
            raise OSError(f"ReadProcessMemory 失败: 0x{address:X}+{size}")
        return buffer.raw

    def u8(self, address: int) -> int:
        return self.read(address, 1)[0]

    def i32(self, address: int) -> int:
        return struct.unpack("<i", self.read(address, 4))[0]

    def u64(self, address: int) -> int:
        return struct.unpack("<Q", self.read(address, 8))[0]

    def f32(self, address: int) -> float:
        return struct.unpack("<f", self.read(address, 4))[0]

    def c_string(self, address: int, limit: int = 160) -> str:
        return self.read(address, limit).split(b"\0", 1)[0].decode("utf-8", errors="replace")

    def module_base(self, module_name: str) -> int:
        modules = (wintypes.HMODULE * 2048)()
        needed = wintypes.DWORD()
        if not psapi.EnumProcessModulesEx(
            self.handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), LIST_MODULES_ALL
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        count = min(len(modules), needed.value // ctypes.sizeof(wintypes.HMODULE))
        for module in modules[:count]:
            buffer = ctypes.create_unicode_buffer(260)
            if psapi.GetModuleBaseNameW(self.handle, module, buffer, len(buffer)):
                if buffer.value.lower() == module_name.lower():
                    return ctypes.cast(module, ctypes.c_void_p).value or 0
        return 0

    def class_name(self, class_address: int) -> str:
        name_ptr = self.u64(class_address + IL2CPP_CLASS_NAME)
        return self.c_string(name_ptr, 128) if name_ptr else ""


def read_managed_list(reader: Any, list_address: int, maximum: int = 256) -> list[int]:
    if not list_address:
        return []
    items = reader.u64(list_address + LIST_ITEMS)
    size = reader.i32(list_address + LIST_SIZE)
    if not items or size < 0 or size > maximum:
        raise LayoutError(f"List<T> 无效: list=0x{list_address:X}, size={size}")
    capacity = reader.i32(items + ARRAY_LENGTH)
    if capacity < size or capacity > max(maximum, size):
        raise LayoutError(f"T[] 无效: items=0x{items:X}, length={capacity}, size={size}")
    return [reader.u64(items + ARRAY_FIRST_ITEM + index * 8) for index in range(size)]


def is_bite(rig_in_water: bool, fight_initialized: bool, fight_factor: float) -> bool:
    return bool(rig_in_water and fight_initialized and fight_factor > 0.0)


class DynamicRigMonitor:
    def __init__(self, reader: ProcessMemory, catalog: Il2CppLayoutParser, layout: ResolvedLayout):
        self.reader = reader
        self.catalog = catalog
        self.layout = layout
        self.module_base = reader.module_base("GameAssembly.dll")
        if not self.module_base:
            raise LayoutError("rf4_x64.exe 未加载 GameAssembly.dll")
        self.class_address = self._resolve_class()
        self.manager_instance = self._resolve_singleton()

    def _runtime_address(self, value: int) -> int:
        if value < 0x80000000:
            return self.module_base + value
        # Il2CppDumper commonly emits VA using the PE preferred base.
        if 0x180000000 <= value < 0x200000000:
            return self.module_base + value - 0x180000000
        return value

    def _resolve_class(self) -> int:
        raw = self.layout.manager.address
        if raw is None:
            raw = self.catalog.metadata_addresses.get(_norm(self.layout.manager.full_name))
        if raw is None:
            raw = self.catalog.metadata_addresses.get(_norm(self.layout.manager.name))
        if raw is None:
            raise LayoutError(f"{self.layout.manager.full_name} 缺少 TypeInfo/Il2CppClass Address")
        slot = self._runtime_address(raw)
        candidates: list[int] = []
        try:
            candidates.append(self.reader.u64(slot))
        except OSError:
            pass
        candidates.append(slot)
        expected = _norm(self.layout.manager.name)
        for candidate in candidates:
            if not candidate:
                continue
            try:
                if _norm(self.reader.class_name(candidate)) == expected:
                    return candidate
            except OSError:
                continue
        raise LayoutError(f"TypeInfo 未解析为 {self.layout.manager.name}: source=0x{raw:X}, runtime=0x{slot:X}")

    def _resolve_singleton(self) -> int:
        static_fields = self.reader.u64(self.class_address + IL2CPP_CLASS_STATIC_FIELDS)
        if not static_fields:
            raise LayoutError(f"{self.layout.manager.name}.static_fields 为空")
        instance = self.reader.u64(static_fields + self.layout.singleton_field.offset)
        if not instance:
            raise LayoutError(f"{self.layout.manager.name}.{self.layout.singleton_field.name} 尚未初始化")
        return instance

    def rigs(self) -> list[int]:
        list_address = self.reader.u64(self.manager_instance + self.layout.rig_list_field.offset)
        return [address for address in read_managed_list(self.reader, list_address) if address]

    def sample(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for index, rig in enumerate(self.rigs(), start=1):
            water = self.reader.u8(rig + self.layout.rig_in_water.offset) != 0
            initialized = self.reader.u8(rig + self.layout.fight_initialized.offset) != 0
            factor = self.reader.f32(rig + self.layout.fight_factor.offset)
            rows.append(
                {
                    "index": index,
                    "address": f"0x{rig:X}",
                    "rig_in_water": water,
                    "fight_initialized": initialized,
                    "fight_factor": factor,
                    "bite": is_bite(water, initialized, factor),
                }
            )
        return rows

    def diagnostics(self) -> dict[str, Any]:
        return {
            "game_assembly_base": f"0x{self.module_base:X}",
            "manager_class": f"0x{self.class_address:X}",
            "manager_instance": f"0x{self.manager_instance:X}",
            "manager_type": self.layout.manager.full_name,
            "singleton": f"{self.layout.singleton_field.name}@0x{self.layout.singleton_field.offset:X}",
            "rig_list": f"{self.layout.rig_list_field.name}@0x{self.layout.rig_list_field.offset:X}",
            "rig_type": self.layout.rig_type.full_name,
            "rig_in_water": f"{self.layout.rig_in_water.name}@0x{self.layout.rig_in_water.offset:X}",
            "fight_initialized": f"{self.layout.fight_initialized.name}@0x{self.layout.fight_initialized.offset:X}",
            "fight_factor": f"{self.layout.fight_factor.name}@0x{self.layout.fight_factor.offset:X}",
        }


def application_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RF4 independent dynamic IL2CPP rig reader")
    parser.add_argument("--script", type=Path, default=application_dir() / "script.json")
    parser.add_argument("--dump-cs", type=Path, default=None)
    parser.add_argument("--process", default="rf4_x64.exe")
    parser.add_argument("--manager", default="FishingManager")
    parser.add_argument("--rig", default="RigBottomSimple")
    parser.add_argument("--singleton-field", default="")
    parser.add_argument("--list-field", default="")
    parser.add_argument("--interval", type=float, default=0.20)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--layout-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        catalog = Il2CppLayoutParser.from_files(args.script, args.dump_cs)
        layout = catalog.resolve_rf4_layout(
            manager_name=args.manager,
            rig_name=args.rig,
            singleton_name=args.singleton_field,
            list_name=args.list_field,
        )
        print(json.dumps({"parser": catalog.summary(), "layout": {
            "manager": layout.manager.full_name,
            "singleton": vars(layout.singleton_field),
            "rig_list": vars(layout.rig_list_field),
            "rig_type": layout.rig_type.full_name,
            "rig_in_water": vars(layout.rig_in_water),
            "fight_initialized": vars(layout.fight_initialized),
            "fight_factor": vars(layout.fight_factor),
        }}, ensure_ascii=False, indent=2))
        if args.layout_only:
            return 0
        pid = find_process(args.process)
        if not pid:
            raise LayoutError(f"进程未运行: {args.process}")
        reader = ProcessMemory(pid)
        try:
            monitor = DynamicRigMonitor(reader, catalog, layout)
            print(json.dumps({"pid": pid, **monitor.diagnostics()}, ensure_ascii=False))
            previous: dict[int, bool] = {}
            while True:
                rows = monitor.sample()
                print(json.dumps({"time": time.time(), "rigs": rows}, ensure_ascii=False), flush=True)
                for row in rows:
                    index = int(row["index"])
                    active = bool(row["bite"])
                    if active and not previous.get(index, False):
                        print(f"BITE U{index}: factor={row['fight_factor']}", flush=True)
                    previous[index] = active
                if args.once:
                    return 0
                time.sleep(max(0.05, args.interval))
        finally:
            reader.close()
    except (LayoutError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
