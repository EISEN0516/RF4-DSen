from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from rf4_il2cpp_dynamic_reader import (
    ARRAY_FIRST_ITEM,
    ARRAY_LENGTH,
    LIST_ITEMS,
    LIST_SIZE,
    Il2CppLayoutParser,
    is_bite,
    read_managed_list,
)


class FakeMemory:
    def __init__(self) -> None:
        self.memory: dict[int, bytes] = {}

    def set_u64(self, address: int, value: int) -> None:
        self.memory[address] = struct.pack("<Q", value)

    def set_i32(self, address: int, value: int) -> None:
        self.memory[address] = struct.pack("<i", value)

    def read(self, address: int, size: int) -> bytes:
        value = self.memory[address]
        assert len(value) == size
        return value

    def u64(self, address: int) -> int:
        return struct.unpack("<Q", self.read(address, 8))[0]

    def i32(self, address: int) -> int:
        return struct.unpack("<i", self.read(address, 4))[0]


class DynamicReaderTests(unittest.TestCase):
    def test_enhanced_json_resolves_all_semantic_fields(self) -> None:
        payload = {
            "Types": [
                {
                    "Name": "FishingManager",
                    "Namespace": "RF4.Client",
                    "TypeInfoAddress": "0x123456",
                    "Fields": [
                        {"Name": "instance", "Type": "FishingManager", "Offset": "0x0", "IsStatic": True},
                        {"Name": "rigs", "Type": "List<Rig>", "Offset": "0x28"},
                    ],
                },
                {
                    "Name": "RigBottomSimple",
                    "Namespace": "RF4.Client",
                    "Fields": [
                        {"Name": "rig_in_water", "Type": "System.Boolean", "Offset": "0x74"},
                        {"Name": "fight_initialized", "Type": "System.Boolean", "Offset": "0x120"},
                        {"Name": "fight_factor", "Type": "System.Single", "Offset": "0x124"},
                    ],
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "script.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            parsed = Il2CppLayoutParser.from_files(path)
            layout = parsed.resolve_rf4_layout()
        self.assertEqual(layout.manager.address, 0x123456)
        self.assertEqual(layout.rig_list_field.offset, 0x28)
        self.assertEqual(layout.rig_in_water.offset, 0x74)
        self.assertEqual(layout.fight_initialized.offset, 0x120)
        self.assertEqual(layout.fight_factor.offset, 0x124)

    def test_stock_script_json_uses_dump_cs_for_field_offsets(self) -> None:
        payload = {
            "ScriptMetadata": [
                {"Address": 0x1ABC, "Name": "RF4.Client.FishingManager$$TypeInfo", "Signature": ""}
            ]
        }
        dump = """
// Namespace: RF4.Client
public class FishingManager : System.Object
{
    // Fields
    private static FishingManager instance; // 0x0
    private List<Rig> rigs; // 0x28
    // Methods
}
// Namespace: RF4.Client
public class RigBottomSimple : Rig
{
    // Fields
    private bool rig_in_water; // 0x74
    private bool fight_initialized; // 0x120
    private float fight_factor; // 0x124
    // Methods
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "script.json"
            script.write_text(json.dumps(payload), encoding="utf-8")
            script.with_name("dump.cs").write_text(dump, encoding="utf-8")
            parsed = Il2CppLayoutParser.from_files(script)
            layout = parsed.resolve_rf4_layout()
        self.assertEqual(layout.manager.address, 0x1ABC)
        self.assertTrue(layout.singleton_field.is_static)
        self.assertEqual(layout.rig_list_field.offset, 0x28)

    def test_managed_list_uses_10_18_20_layout(self) -> None:
        memory = FakeMemory()
        managed_list, array = 0x1000, 0x2000
        memory.set_u64(managed_list + LIST_ITEMS, array)
        memory.set_i32(managed_list + LIST_SIZE, 3)
        memory.set_i32(array + ARRAY_LENGTH, 4)
        for index, value in enumerate((0x3000, 0x4000, 0x5000)):
            memory.set_u64(array + ARRAY_FIRST_ITEM + index * 8, value)
        self.assertEqual(read_managed_list(memory, managed_list), [0x3000, 0x4000, 0x5000])

    def test_obfuscated_class_names_resolve_by_field_structure(self) -> None:
        payload = {
            "Types": [
                {
                    "Name": "A1",
                    "Address": 0x5000,
                    "Fields": [
                        {"Name": "x", "Type": "A1", "Offset": 0, "IsStatic": True},
                        {"Name": "y", "Type": "System.Collections.Generic.List<Rig>", "Offset": 0x30},
                    ],
                },
                {
                    "Name": "B2",
                    "Fields": [
                        {"Name": "rig_in_water", "Type": "bool", "Offset": 0x70},
                        {"Name": "fight_initialized", "Type": "bool", "Offset": 0x90},
                        {"Name": "fight_factor", "Type": "float", "Offset": 0x94},
                    ],
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "script.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            parsed = Il2CppLayoutParser.from_files(path)
            layout = parsed.resolve_rf4_layout(manager_name="Missing", rig_name="Missing")
        self.assertEqual(layout.manager.name, "A1")
        self.assertEqual(layout.rig_type.name, "B2")
        self.assertEqual(layout.rig_list_field.name, "y")

    def test_bite_requires_all_three_conditions(self) -> None:
        self.assertTrue(is_bite(True, True, 0.01))
        self.assertFalse(is_bite(False, True, 1.0))
        self.assertFalse(is_bite(True, False, 1.0))
        self.assertFalse(is_bite(True, True, 0.0))
        self.assertFalse(is_bite(True, True, -1.0))


if __name__ == "__main__":
    unittest.main()
