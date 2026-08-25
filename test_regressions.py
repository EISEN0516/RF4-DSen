from __future__ import annotations

import queue
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import app_v104 as app_v101
import rf4_direct_source as direct


class FakeReader:
    def __init__(self) -> None:
        self.diagnostics: dict[str, object] = {}
        self.qwords: dict[int, int] = {}
        self.dwords: dict[int, int] = {}
        self.bytes: dict[int, int] = {}
        self.floats: dict[int, float] = {}
        self.doubles: dict[int, float] = {}
        self.objects: dict[int, tuple[str, str, int]] = {}
        self.classes: dict[int, tuple[str, str, int]] = {}

    def u64(self, address: int) -> int | None:
        return self.qwords.get(address)

    def u32(self, address: int) -> int | None:
        return self.dwords.get(address)

    def u8(self, address: int) -> int | None:
        return self.bytes.get(address)

    def f64(self, address: int) -> float | None:
        return self.doubles.get(address)

    def f32(self, address: int) -> float | None:
        return self.floats.get(address)

    def object_info(self, address: int):
        return self.objects.get(address)

    def class_info(self, address: int):
        return self.classes.get(address)

    def field_offsets(self, _address: int) -> dict[str, int]:
        return {}

    def read(self, _address: int, _size: int) -> bytes | None:
        return None

    def close(self) -> None:
        pass


def make_rig(slot: int = 1, root: int = 0x1000, set_address: int = 0x2000) -> direct.DirectRig:
    return direct.DirectRig(
        slot=slot,
        root=root,
        set_address=set_address,
        class_address=0x3000,
        rig_type="RigBottomCarpMethod",
    )


def make_state(**changes) -> direct.DirectRodState:
    values = {
        "slot": 1,
        "guid": "set-2000",
        "root": 0x1000,
        "rig_type": "RigBottomCarpMethod",
        "set_address": 0x2000,
        "distance_m": 42.0,
        "in_water": True,
        "session": True,
        "valid": True,
    }
    values.update(changes)
    return direct.DirectRodState(**values)


class DirectSourceRegressionTests(unittest.TestCase):
    def test_known_gameassembly_fingerprint_resolves_build(self) -> None:
        fingerprint = "900AE4ACEDE67445129CF56ECF8392940C327843DBB0882EBD2A6887942F530B"
        self.assertEqual(direct._known_build(fingerprint), "4.0.25029")
        self.assertEqual(direct._known_build("0" * 64), "unknown")

    def test_valid_rig_rejects_unbound_set(self) -> None:
        reader = FakeReader()
        root, class_address, set_address, set_class = 0x1000, 0x3000, 0x2000, 0x4000
        reader.qwords[root] = class_address
        reader.classes[class_address] = ("RigBottomCarpMethod", "RF4.Client", 0x200)
        reader.qwords[root + direct.RIG_SET_FIRST_OFFSET] = set_address
        reader.objects[set_address] = ("RodRigFishingSet", "RF4.Client", 0x200)
        reader.qwords[set_address] = set_class
        reader.classes[set_class] = ("RodRigFishingSet", "RF4.Client", 0x200)
        reader.qwords[set_address + direct.SET_ROOT_OFFSET] = 0

        self.assertIsNone(direct._valid_rig(reader, root, {class_address}))

    def test_bobber_validation_does_not_read_bottom_telemetry(self) -> None:
        reader = FakeReader()
        root, class_address, set_address, set_class = 0x1000, 0x3000, 0x2000, 0x4000
        reader.qwords[root] = class_address
        reader.classes[class_address] = ("RigBobberFloat", "RF4.Client", 0x200)
        reader.qwords[root + direct.RIG_SET_FIRST_OFFSET] = set_address
        reader.objects[set_address] = ("RodRigFishingSet", "RF4.Client", 0x200)
        reader.qwords[set_address] = set_class
        reader.classes[set_class] = ("RodRigFishingSet", "RF4.Client", 0x200)
        reader.qwords[set_address + direct.SET_ROOT_OFFSET] = root

        self.assertEqual(
            direct._valid_rig(reader, root, {class_address}),
            ("RigBobberFloat", set_address),
        )

    def test_root_address_order_never_assigns_hotbar_slots(self) -> None:
        reader = FakeReader()
        roots = (0x3000, 0x2000, 0x1000)
        # Captured failure shape: allocator/root order would put set 0x2100
        # into U1, but RodRest evidence says the real order is 0x2300,0x2200,0x2100.
        sets = (0x2100, 0x2200, 0x2300)
        rest = (0x4100, 0x4200, 0x4300)
        class_address, set_class = 0x3000, 0x4000
        reader.classes[class_address] = ("RigBottomCarpMethod", "RF4.Client", 0x200)
        reader.classes[set_class] = ("RodRigFishingSet", "RF4.Client", 0x200)
        for root, set_address, rest_address, pos_x, pos_z, dir_x, dir_z in zip(
            roots,
            sets,
            rest,
            (165.204, 164.519, 164.098),
            (514.389, 513.972, 513.405),
            (0.846, 0.828, 0.816),
            (0.532, 0.560, 0.577),
        ):
            reader.qwords[root] = class_address
            reader.qwords[root + direct.RIG_SET_FIRST_OFFSET] = set_address
            reader.qwords[set_address] = set_class
            reader.qwords[set_address + direct.SET_ROOT_OFFSET] = root
            reader.qwords[set_address + direct.SET_ROD_REST_OFFSET] = rest_address
            reader.objects[rest_address] = ("RodRestController", "RF4.Client", 0x70)
            reader.qwords[rest_address + direct.ROD_REST_SET_OFFSET] = set_address
            reader.floats[rest_address + direct.ROD_REST_POSITION_X_OFFSET] = pos_x
            reader.floats[rest_address + direct.ROD_REST_POSITION_Z_OFFSET] = pos_z
            reader.floats[rest_address + direct.ROD_REST_DIRECTION_X_OFFSET] = dir_x
            reader.floats[rest_address + direct.ROD_REST_DIRECTION_Z_OFFSET] = dir_z
            reader.objects[set_address] = ("RodRigFishingSet", "RF4.Client", 0x200)
            reader.doubles[root + direct.RIG_DISTANCE_OFFSET] = 50.0
            reader.bytes[root + direct.RIG_IN_WATER_OFFSET] = 1
            reader.bytes[root + direct.RIG_SESSION_OFFSET] = 1

        regions = [direct.MemoryRegion(0x100, 0x10000, 0x04, direct.MEM_PRIVATE)]
        scans = [
            {class_address: list(roots)},
        ]
        with (
            mock.patch.object(direct, "scan_qword_targets", side_effect=scans),
        ):
            found = direct._discover_rigs_legacy(
                reader,
                regions,
                {"RigBottomCarpMethod": class_address},
            )

        self.assertEqual([(item.slot, item.set_address) for item in found], [(1, 0x2300), (2, 0x2200), (3, 0x2100)])
        self.assertTrue(all(item.order_confidence > 0.0 for item in found))
        self.assertEqual(reader.diagnostics["slot_mapping_status"], "rodrest_consensus")

    def test_one_missing_rodrest_keeps_third_rod_when_order_is_anchored(self) -> None:
        reader = FakeReader()
        roots = (0x1100, 0x1200, 0x1300)
        sets = (0x2100, 0x2200, 0x2300)
        rests = (0x4100, 0x4200)
        class_address, set_class = 0x3000, 0x4000
        reader.classes[class_address] = ("RigBottomCarpMethod", "RF4.Client", 0x200)
        reader.classes[set_class] = ("RodRigFishingSet", "RF4.Client", 0x200)
        for root, set_address in zip(roots, sets):
            reader.qwords[root] = class_address
            reader.qwords[root + direct.RIG_SET_FIRST_OFFSET] = set_address
            reader.qwords[set_address] = set_class
            reader.qwords[set_address + direct.SET_ROOT_OFFSET] = root
            reader.objects[root] = ("RigBottomCarpMethod", "RF4.Client", 0x200)
            reader.objects[set_address] = ("RodRigFishingSet", "RF4.Client", 0x200)
            reader.doubles[root + direct.RIG_DISTANCE_OFFSET] = 50.0
            reader.bytes[root + direct.RIG_IN_WATER_OFFSET] = 1
            reader.bytes[root + direct.RIG_SESSION_OFFSET] = 1
        for index, (set_address, rest_address) in enumerate(zip(sets[:2], rests), start=1):
            reader.qwords[set_address + direct.SET_ROD_REST_OFFSET] = rest_address
            reader.objects[rest_address] = ("RodRestController", "RF4.Client", 0x70)
            reader.qwords[rest_address + direct.ROD_REST_SET_OFFSET] = set_address
            reader.floats[rest_address + direct.ROD_REST_POSITION_X_OFFSET] = float(index)
            reader.floats[rest_address + direct.ROD_REST_POSITION_Z_OFFSET] = float(index)
            reader.floats[rest_address + direct.ROD_REST_POSITION_Y_OFFSET] = float(10 - index)
            reader.floats[rest_address + direct.ROD_REST_DIRECTION_X_OFFSET] = float(index)
            reader.floats[rest_address + direct.ROD_REST_DIRECTION_Z_OFFSET] = float(10 - index)

        selected = [
            (root, set_address, ("RigBottomCarpMethod", set_address, class_address))
            for root, set_address in zip(roots, sets)
        ]

        found = direct._direct_rigs_from_selected(reader, selected)

        self.assertEqual([(item.slot, item.set_address) for item in found], [(1, 0x2100), (2, 0x2200), (3, 0x2300)])
        self.assertEqual(found[-1].slot_source, "rodrest_partial")
        self.assertEqual(reader.diagnostics["slot_mapping_status"], "rodrest_partial_bridge")

    def test_bell_requires_stable_arming_and_debounce(self) -> None:
        reader = FakeReader()
        rig = make_rig()
        bell, state = 0x4000, 0x5000
        reader.qwords[rig.set_address + direct.SET_BELL_OFFSET] = bell
        reader.qwords[bell + direct.BELL_STATE_OFFSET] = state
        reader.dwords[state + direct.BELL_CODE_OFFSET] = 7
        source = direct.DirectMemorySource()
        source.reader = reader

        with mock.patch.object(direct.time, "monotonic", return_value=10.0):
            self.assertFalse(source._bell_state(rig, True, True)[0])
        with mock.patch.object(direct.time, "monotonic", return_value=10.31):
            self.assertFalse(source._bell_state(rig, True, True)[0])
        self.assertTrue(source.bells[rig.set_address].armed)

        reader.dwords[state + direct.BELL_CODE_OFFSET] = 8
        with mock.patch.object(direct.time, "monotonic", return_value=10.32):
            self.assertFalse(source._bell_state(rig, True, True)[0])
        with mock.patch.object(direct.time, "monotonic", return_value=10.37):
            self.assertTrue(source._bell_state(rig, True, True)[0])

    def test_hook_reads_details_from_its_own_fish(self) -> None:
        reader = FakeReader()
        rig = make_rig()
        hook, fish = 0x4000, 0x5000
        reader.qwords[rig.root + direct.RIG_HOOK_OFFSET] = hook
        reader.objects[hook] = ("Hook", "RF4.Client", 0x200)
        reader.qwords[hook + direct.HOOK_FISH_OFFSET] = fish
        source = direct.DirectMemorySource()
        source.reader = reader
        with (
            mock.patch.object(source, "_is_fish_object", return_value=True),
            mock.patch.object(direct, "_read_named_signal", return_value={"fish_name": "鲤鱼", "weight_g": 1234.0}),
        ):
            signal = source._read_hook_fish(rig)

        self.assertTrue(signal["live"])
        self.assertEqual(signal["live_instance"], "fish:5000")
        self.assertEqual(signal["fish_name"], "鲤鱼")
        self.assertEqual(signal["weight_g"], 1234.0)

    def test_hook_reads_species_id_graph_and_catalog_name(self) -> None:
        reader = FakeReader()
        rig = make_rig()
        hook, fish, meta, species, fish_id_string = 0x4000, 0x5000, 0x6000, 0x7000, 0x8000
        reader.qwords[rig.root + direct.RIG_HOOK_OFFSET] = hook
        reader.objects[hook] = ("Hook", "RF4.Client", 0x200)
        reader.qwords[hook + direct.HOOK_FISH_OFFSET] = fish
        reader.qwords[fish + direct.FISH_SET_BACKREF_OFFSETS[0]] = rig.set_address
        reader.objects[rig.set_address] = ("RodRigFishingSet", "RF4.Client", 0x200)
        reader.qwords[fish + direct.FISH_META_OFFSET] = meta
        reader.qwords[meta + direct.FISH_META_SPECIES_OFFSET] = species
        reader.qwords[species + direct.FISH_SPECIES_ID_OFFSET] = fish_id_string
        source = direct.DirectMemorySource()
        source.reader = reader
        with (
            mock.patch.object(source, "_is_fish_object", return_value=True),
            mock.patch.object(direct, "_managed_string", return_value="sh_barbel"),
            mock.patch.object(direct, "_read_named_signal", return_value={}),
        ):
            signal = source._read_hook_fish(rig)

        self.assertTrue(signal["live"])
        self.assertEqual(signal["fish_id"], "sh_barbel")
        self.assertEqual(signal["fish_name"], "短头梭鲃")

    def test_hook_rejects_fish_backref_from_another_set(self) -> None:
        reader = FakeReader()
        rig = make_rig(set_address=0x2000)
        hook, fish, other_set = 0x4000, 0x5000, 0x9000
        reader.qwords[rig.root + direct.RIG_HOOK_OFFSET] = hook
        reader.objects[hook] = ("Hook", "RF4.Client", 0x200)
        reader.qwords[hook + direct.HOOK_FISH_OFFSET] = fish
        reader.qwords[fish + direct.FISH_SET_BACKREF_OFFSETS[0]] = other_set
        reader.objects[other_set] = ("RodRigFishingSet", "RF4.Client", 0x200)
        source = direct.DirectMemorySource()
        source.reader = reader
        with mock.patch.object(source, "_is_fish_object", return_value=True):
            self.assertEqual(source._read_hook_fish(rig), {})

    def test_live_signal_does_not_fall_back_to_another_rod(self) -> None:
        reader = FakeReader()
        rig = make_rig()
        reader.objects[rig.root] = ("RigBottomCarpMethod", "RF4.Client", 0x20)
        reader.objects[rig.set_address] = ("RodRigFishingSet", "RF4.Client", 0x20)
        source = direct.DirectMemorySource()
        source.reader = reader
        source._live_instances = [0x9000]
        source._last_live_scan = 10.0
        with mock.patch.object(direct.time, "monotonic", return_value=10.1):
            self.assertEqual(source._read_live_signal(rig, True), {})

    def test_tracker_follows_set_when_root_changes(self) -> None:
        source = direct.DirectMemorySource()
        source.reader = FakeReader()
        source.pid = 77
        source.session_token = "direct:77"
        source._all_runtime_regions = [direct.MemoryRegion(0x100, 0x100, 0x04, direct.MEM_PRIVATE)]
        old_rig = make_rig(root=0x1000, set_address=0x2000)
        new_rig = make_rig(root=0x1100, set_address=0x2000)
        tracker = direct.BellTracker(armed=True, baseline=7)
        source.rigs = [old_rig]
        source.bells = {old_rig.set_address: tracker}

        source._apply_discovered_rigs([new_rig])

        self.assertIs(source.bells[new_rig.set_address], tracker)
        self.assertEqual(source.session_token, "direct:77")

    def test_background_refresh_adds_rods_without_blocking_polling(self) -> None:
        source = direct.DirectMemorySource()
        source.reader = FakeReader()
        source.pid = 77
        source._all_runtime_regions = [
            direct.MemoryRegion(0x100, 0x100, 0x04, direct.MEM_PRIVATE)
        ]
        old_rig = make_rig()
        new_rigs = [old_rig, make_rig(2, 0x1100, 0x2100), make_rig(3, 0x1200, 0x2200)]
        tracker = direct.BellTracker(armed=True, baseline=7)
        source.rigs = [old_rig]
        source.bells = {old_rig.set_address: tracker}
        source._last_rig_rescan = 0.0
        started = threading.Event()
        release = threading.Event()

        def slow_discovery(*_args, **_kwargs):
            started.set()
            release.wait(2.0)
            return new_rigs

        with (
            mock.patch.object(direct, "ProcessReader", return_value=FakeReader()),
            mock.patch.object(direct, "discover_rigs", side_effect=slow_discovery),
        ):
            source._refresh_rigs_if_needed()
            self.assertTrue(started.wait(0.5))
            self.assertEqual(source.rigs, [old_rig])
            self.assertTrue(source._rig_rescan_thread.is_alive())
            release.set()
            source._rig_rescan_thread.join(2.0)
            source._collect_rig_rescan()

        self.assertEqual([item.slot for item in source.rigs], [1, 2, 3])
        self.assertIs(source.bells[old_rig.set_address], tracker)

    def test_failed_background_refresh_keeps_last_known_mapping(self) -> None:
        source = direct.DirectMemorySource()
        source.reader = FakeReader()
        source.pid = 77
        source._all_runtime_regions = [
            direct.MemoryRegion(0x100, 0x100, 0x04, direct.MEM_PRIVATE)
        ]
        old_rig = make_rig()
        source.rigs = [old_rig]
        source._last_rig_rescan = 0.0

        with (
            mock.patch.object(direct, "ProcessReader", return_value=FakeReader()),
            mock.patch.object(direct, "discover_rigs", return_value=[]),
        ):
            source._refresh_rigs_if_needed()
            source._rig_rescan_thread.join(2.0)
            source._collect_rig_rescan()

        self.assertEqual(source.rigs, [old_rig])

    def test_partial_refresh_cannot_degrade_complete_mapping(self) -> None:
        source = direct.DirectMemorySource()
        complete = [
            make_rig(1, 0x1000, 0x2000),
            make_rig(2, 0x1100, 0x2100),
            make_rig(3, 0x1200, 0x2200),
        ]
        source.rigs = complete

        replacement = make_rig(3, 0x1300, 0x2300)
        source._apply_discovered_rigs([replacement])

        self.assertEqual([item.slot for item in source.rigs], [1, 2, 3])
        self.assertEqual(source.rigs, complete)
        self.assertEqual(source.diagnostics["partial_discovery_ignored"], 1)

    def test_same_process_cache_is_disabled(self) -> None:
        reader = FakeReader()
        rigs = [
            make_rig(1, 0x1000, 0x2000),
            make_rig(2, 0x1100, 0x2100),
            make_rig(3, 0x1200, 0x2200),
        ]
        set_class = 0x4000
        reader.classes[set_class] = ("RodRigFishingSet", "RF4.Client", 0x200)
        for rig in rigs:
            reader.qwords[rig.root] = rig.class_address
            reader.classes[rig.class_address] = (rig.rig_type, "RF4.Client", 0x200)
            reader.qwords[rig.root + direct.RIG_SET_FIRST_OFFSET] = rig.set_address
            reader.objects[rig.set_address] = (
                "RodRigFishingSet",
                "RF4.Client",
                0x200,
            )
            reader.qwords[rig.set_address] = set_class
            reader.qwords[rig.set_address + direct.SET_ROOT_OFFSET] = rig.root
            reader.doubles[rig.root + direct.RIG_DISTANCE_OFFSET] = 50.0
            reader.bytes[rig.root + direct.RIG_IN_WATER_OFFSET] = 1
            reader.bytes[rig.root + direct.RIG_SESSION_OFFSET] = 1

        identity = {
            "pid": 77,
            "process_created": 123,
            "process_path": "c:\\rf4\\rf4_x64.exe",
            "assembly_size": 456,
            "assembly_mtime_ns": 789,
        }
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "direct-session-v1.json"
            first = direct.DirectMemorySource()
            first.reader = reader
            first.pid = 77
            first._session_identity = identity
            first._cache_path = cache_path
            first._all_runtime_regions = [
                direct.MemoryRegion(0x100, 0x100, 0x04, direct.MEM_PRIVATE)
            ]
            first.regions = list(first._all_runtime_regions)
            first.class_map = {rigs[0].rig_type: rigs[0].class_address}
            first.rigs = rigs
            first._save_session_cache()

            restored = direct.DirectMemorySource()
            restored.reader = reader
            restored.pid = 77
            restored._session_identity = identity
            restored._cache_path = cache_path
            self.assertFalse(restored._load_session_cache())

        self.assertEqual(restored.rigs, [])

    def test_snapshot_reports_connected_while_discovery_is_pending(self) -> None:
        source = direct.DirectMemorySource()
        source.reader = FakeReader()
        source.pid = 77
        source.session_token = "direct:77"
        source.mapping_source = "runtime"
        with (
            mock.patch.object(source, "_open_current_process"),
            mock.patch.object(source, "_refresh_rigs_if_needed"),
        ):
            snapshot = source.snapshot()

        self.assertEqual(snapshot.pid, 77)
        self.assertEqual(snapshot.rods, [])

    def test_snapshot_keeps_bell_probe_separate_from_hooked_bite(self) -> None:
        reader = FakeReader()
        rig = make_rig()
        set_class = 0x4000
        reader.qwords[rig.root] = rig.class_address
        reader.classes[rig.class_address] = (rig.rig_type, "RF4.Client", 0x200)
        reader.qwords[rig.root + direct.RIG_SET_FIRST_OFFSET] = rig.set_address
        reader.objects[rig.set_address] = ("RodRigFishingSet", "RF4.Client", 0x200)
        reader.qwords[rig.set_address] = set_class
        reader.classes[set_class] = ("RodRigFishingSet", "RF4.Client", 0x200)
        reader.qwords[rig.set_address + direct.SET_ROOT_OFFSET] = rig.root
        reader.doubles[rig.root + direct.RIG_DISTANCE_OFFSET] = 50.0
        reader.bytes[rig.root + direct.RIG_IN_WATER_OFFSET] = 1
        reader.bytes[rig.root + direct.RIG_SESSION_OFFSET] = 1
        source = direct.DirectMemorySource()
        source.reader = reader
        source.pid = 77
        source.session_token = "direct:77"
        source.mapping_source = "runtime"
        source.rigs = [rig]

        with (
            mock.patch.object(source, "_open_current_process"),
            mock.patch.object(source, "_read_hook_fish", return_value={}),
            mock.patch.object(source, "_bell_state", return_value=(True, 8, 7, 0x5000, "active")),
        ):
            state = source.snapshot().rods[0]

        self.assertTrue(state.bell_active)
        self.assertFalse(state.bite_active)
        self.assertEqual(state.live_phase, "probe")
        self.assertEqual(state.guid, "set-2000")

    def test_valid_fishing_set_returns_root_rig_class_for_snapshot_validation(self) -> None:
        reader = FakeReader()
        root, root_class, set_address, set_class = 0x1000, 0x3000, 0x2000, 0x4000
        reader.qwords[set_address] = set_class
        reader.classes[set_class] = ("RodRigFishingSet", "RF4.Client", 0x200)
        reader.objects[set_address] = ("RodRigFishingSet", "RF4.Client", 0x200)
        reader.qwords[set_address + direct.SET_ROOT_OFFSET] = root
        reader.qwords[root] = root_class
        reader.classes[root_class] = ("RigBottomCarpMethod", "RF4.Client", 0x200)
        reader.objects[root] = ("RigBottomCarpMethod", "RF4.Client", 0x200)
        reader.qwords[root + direct.RIG_SET_FIRST_OFFSET] = set_address
        reader.doubles[root + direct.RIG_DISTANCE_OFFSET] = 50.0
        reader.bytes[root + direct.RIG_IN_WATER_OFFSET] = 1
        reader.bytes[root + direct.RIG_SESSION_OFFSET] = 1

        self.assertEqual(
            direct._valid_fishing_set(reader, set_address, {set_class}),
            ("RigBottomCarpMethod", root, root_class),
        )

    def test_fishingset_scan_remaps_recast_roots_from_live_sets(self) -> None:
        reader = FakeReader()
        root_class, set_class = 0x3000, 0x4000
        reader.classes[root_class] = ("RigBottomCarpSimple", "RF4.Client", 0x200)
        reader.classes[set_class] = ("RodReelRigFishingSet", "RF4.Client", 0x300)
        sets = (0x2100, 0x2200, 0x2300)
        roots = (0x1100, 0x1200, 0x1300)
        rests = (0x4100, 0x4200, 0x4300)
        # Captured recast shape: old Rig roots are gone, but current FishingSet
        # instances still point to fresh root objects and RodRest position
        # evidence gives the U1/U2/U3 order.
        for index, (set_address, root, rest) in enumerate(zip(sets, roots, rests), start=1):
            reader.qwords[set_address] = set_class
            reader.objects[set_address] = ("RodReelRigFishingSet", "RF4.Client", 0x300)
            reader.qwords[set_address + direct.SET_ROOT_OFFSET] = root
            reader.qwords[set_address + direct.SET_ROD_REST_OFFSET] = rest
            reader.qwords[root] = root_class
            reader.objects[root] = ("RigBottomCarpSimple", "RF4.Client", 0x200)
            reader.qwords[root + direct.RIG_SET_FIRST_OFFSET] = set_address
            reader.doubles[root + direct.RIG_DISTANCE_OFFSET] = 5.0 + index
            reader.bytes[root + direct.RIG_IN_WATER_OFFSET] = 1
            reader.bytes[root + direct.RIG_SESSION_OFFSET] = 1
            reader.objects[rest] = ("RodRestController", "RF4.Client", 0x70)
            reader.qwords[rest + direct.ROD_REST_SET_OFFSET] = set_address
            reader.floats[rest + direct.ROD_REST_POSITION_X_OFFSET] = float(index)
            reader.floats[rest + direct.ROD_REST_POSITION_Z_OFFSET] = float(index)
            reader.floats[rest + direct.ROD_REST_POSITION_Y_OFFSET] = float(10 - index)
            # Direction vectors are rod orientation, not slot identity; make
            # them conflict so the regression locks the V1.07 fix.
            reader.floats[rest + direct.ROD_REST_DIRECTION_X_OFFSET] = float(10 - index)
            reader.floats[rest + direct.ROD_REST_DIRECTION_Z_OFFSET] = float(10 - index)

        with mock.patch.object(direct, "scan_qword_targets", return_value={set_class: [sets[2], sets[0], sets[1]]}):
            found = direct._discover_rigs_from_fishing_sets(
                reader,
                [direct.MemoryRegion(0x1000, 0x20000, 0x04, direct.MEM_PRIVATE)],
                {"RodReelRigFishingSet": set_class},
            )

        self.assertEqual([(item.slot, item.set_address, item.root) for item in found], [
            (1, sets[0], roots[0]),
            (2, sets[1], roots[1]),
            (3, sets[2], roots[2]),
        ])
        self.assertEqual(reader.diagnostics["rig_discovery_method"], "fishingset_scan")
        self.assertEqual(reader.diagnostics["fishingset_scan_status"], "ok")
        self.assertEqual(reader.diagnostics["slot_mapping_status"], "rodrest_consensus")

    def test_discover_rigs_does_not_fall_back_to_slow_heap_when_fishingset_scan_is_definitive(self) -> None:
        reader = FakeReader()
        with (
            mock.patch.object(direct, "_discover_rigs_from_fishing_sets", return_value=[]) as set_scan,
            mock.patch.object(direct, "_discover_rigs_from_fisher", side_effect=AssertionError("slow fisher scan must not run")),
            mock.patch.object(direct, "_discover_rigs_legacy", side_effect=AssertionError("slow rig scan must not run")),
        ):
            reader.diagnostics["fishingset_scan_status"] = "no_valid_sets"
            found = direct.discover_rigs(
                reader,
                [direct.MemoryRegion(0x1000, 0x20000, 0x04, direct.MEM_PRIVATE)],
                {"RodReelRigFishingSet": 0x4000},
            )

        self.assertEqual(found, [])
        set_scan.assert_called_once()

    def test_fisher_default_uses_read_only_rodrest_without_hotkeys(self) -> None:
        reader = FakeReader()
        fisher = 0x5000
        set1, set2, set3 = 0x2100, 0x2200, 0x2300
        roots = {set1: 0x1100, set2: 0x1200, set3: 0x1300}
        rests = {set1: 0x4100, set2: 0x4200, set3: 0x4300}
        reader.qwords[fisher + 0xF0] = set1
        for index, set_address in enumerate((set1, set2, set3), start=1):
            root = roots[set_address]
            rest = rests[set_address]
            reader.qwords[set_address + direct.SET_ROD_REST_OFFSET] = rest
            reader.objects[rest] = ("RodRestController", "RF4.Client", 0x70)
            reader.qwords[rest + direct.ROD_REST_SET_OFFSET] = set_address
            reader.floats[rest + direct.ROD_REST_POSITION_X_OFFSET] = float(index)
            reader.floats[rest + direct.ROD_REST_POSITION_Z_OFFSET] = float(index)
            reader.floats[rest + direct.ROD_REST_POSITION_Y_OFFSET] = float(10 - index)
            reader.floats[rest + direct.ROD_REST_DIRECTION_X_OFFSET] = float(index)
            reader.floats[rest + direct.ROD_REST_DIRECTION_Z_OFFSET] = float(10 - index)

        def valid_set(_reader, address, _set_classes):
            root = roots.get(address)
            return ("RigBottomCarpMethod", root, 0x3000) if root else None

        with (
            mock.patch.object(direct, "_instances_of_class", return_value=[fisher]),
            mock.patch.object(direct, "_read_managed_list_items", return_value=[set2, set3]),
            mock.patch.object(direct, "_valid_fishing_set", side_effect=valid_set),
            mock.patch.object(direct, "_calibrate_fisher_hotkeys", side_effect=AssertionError("hotkey path must stay disabled")),
        ):
            found = direct._discover_rigs_from_fisher(
                reader,
                [direct.MemoryRegion(0x100, 0x1000, 0x04, direct.MEM_PRIVATE)],
                {"Fisher": 0x9000, "RodRigFishingSet": 0x9100},
            )

        self.assertEqual([(item.slot, item.set_address) for item in found], [(1, set1), (2, set2), (3, set3)])
        self.assertEqual([item.slot_source for item in found], ["rodrest_consensus"] * 3)
        self.assertEqual(reader.diagnostics["rig_discovery_method"], "fisher_rodrest")

    def test_fisher_hotkey_mapping_fallback_when_rodrest_unavailable(self) -> None:
        reader = FakeReader()
        reader.pid = 77
        fisher = 0x5000
        set1, set2, set3 = 0x2100, 0x2200, 0x2300
        reader.qwords[fisher + 0xF0] = set3

        def valid_set(_reader, address, _set_classes):
            roots = {set1: 0x1100, set2: 0x1200, set3: 0x1300}
            return ("RigBottomCarpMethod", roots[address], 0x3000) if address in roots else None

        with (
            mock.patch.object(direct, "_instances_of_class", return_value=[fisher]),
            mock.patch.object(direct, "_read_managed_list_items", return_value=[set1, set2]),
            mock.patch.object(direct, "_valid_fishing_set", side_effect=valid_set),
            mock.patch.object(direct, "_calibrate_fisher_hotkeys", return_value={set1: 1, set2: 2, set3: 3}),
        ):
            found = direct._discover_rigs_from_fisher(
                reader,
                [direct.MemoryRegion(0x100, 0x1000, 0x04, direct.MEM_PRIVATE)],
                {"Fisher": 0x9000, "RodRigFishingSet": 0x9100},
            )

        self.assertEqual([(item.slot, item.set_address) for item in found], [(1, set1), (2, set2), (3, set3)])
        self.assertEqual([item.slot_source for item in found], ["fisher_hotkey"] * 3)
        self.assertEqual(reader.diagnostics["rig_discovery_method"], "fisher_hotkey")

    def test_force_refresh_rescans_even_when_previous_mapping_has_three_rods(self) -> None:
        source = direct.DirectMemorySource()
        source.reader = FakeReader()
        source.pid = 77
        source._all_runtime_regions = [direct.MemoryRegion(0x100, 0x100, 0x04, direct.MEM_PRIVATE)]
        source.class_map = {"Fisher": 0x9000}
        source.rigs = [
            make_rig(1, 0x1000, 0x2000),
            make_rig(2, 0x1100, 0x2100),
            make_rig(3, 0x1200, 0x2200),
        ]
        started = threading.Event()

        def mark_started(*_args):
            started.set()

        with mock.patch.object(source, "_discover_rigs_background", side_effect=mark_started):
            source._refresh_rigs_if_needed(force=True)

        self.assertTrue(started.wait(0.5))


class MonitorRegressionTests(unittest.TestCase):
    def test_write_diagnostic_bundle_creates_sendable_zip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = app_v101.write_diagnostic_bundle(
                Path(tmp),
                f"RF4-DSen-V{app_v101.APP_VERSION}-diagnostic",
                "诊断正文",
                {"app": {"version": app_v101.APP_VERSION}, "rods": []},
                extra_text_files={"config.json": "{\"poll_ms\":80}"},
            )

            self.assertTrue(zip_path.is_file())
            with zipfile.ZipFile(zip_path) as archive:
                names = set(archive.namelist())
                self.assertIn("diagnostics.txt", names)
                self.assertIn("state.json", names)
                self.assertIn("config.json", names)
                self.assertIn("诊断正文", archive.read("diagnostics.txt").decode("utf-8"))

    def test_config_has_no_external_file_source_fields(self) -> None:
        keys = set(app_v101.asdict(app_v101.AppConfig()))
        self.assertFalse({"trace_root", "source_path", "backend_path"} & keys)

    def test_reference_catalog_resolves_fish_and_links(self) -> None:
        matches = app_v101.fish_reference_matches("欧鳊")
        self.assertTrue(matches)
        self.assertEqual(matches[0][0], "bream")
        rf4db, rf4stat = app_v101.fish_reference_urls("欧鳊")
        self.assertEqual(rf4db, "https://cn.rf4db.com/zh/fishes/bream")
        self.assertIn("fish=%E6%AC%A7%E9%B3%8A", rf4stat)

    def test_official_helper_backend_is_disabled(self) -> None:
        self.assertIsNone(app_v101.find_official_backend("C:/rf4db小助手_v3.40.exe"))

    def setUp(self) -> None:
        self.monitor = app_v101.RF4Monitor(
            queue.Queue(),
            threading.Event(),
            app_v101.AppConfig(),
        )

    def test_probe_updates_state_without_alert(self) -> None:
        self.monitor._apply_memory_rod(
            make_state(bell_active=True, bite_active=False, live_phase="probe"),
            10.0,
        )
        self.assertEqual(self.monitor.rods[0].status, app_v101.STATE_PROBE)
        self.assertEqual(self.monitor.alert_count, 0)

    def test_invalid_snapshot_keeps_previous_state_during_grace(self) -> None:
        self.monitor._apply_memory_rod(make_state(), 10.0)
        self.monitor.rods[0].status = app_v101.STATE_BITE
        self.monitor._apply_memory_rod(
            make_state(valid=False, in_water=False, session=False, reason="鱼竿对象已变化"),
            10.1,
        )
        self.monitor._apply_memory_rod(
            make_state(valid=False, in_water=False, session=False, reason="鱼竿对象已变化"),
            10.2,
        )
        self.assertTrue(self.monitor.rods[0].memory_valid)
        self.assertEqual(self.monitor.rods[0].status, app_v101.STATE_BITE)

    def test_same_pid_new_token_does_not_reset_session(self) -> None:
        self.monitor.memory_pid = 77
        self.monitor.session_token = "direct:77:old-root"
        snapshot = direct.DirectSnapshot(77, "direct:77", "runtime", [])
        self.monitor.memory = mock.Mock()
        self.monitor.memory.snapshot.return_value = snapshot

        with mock.patch.object(self.monitor, "_reset_session") as reset:
            self.monitor.scan_memory()

        reset.assert_not_called()
        self.assertEqual(self.monitor.session_token, "direct:77")

    def test_memory_bite_with_fish_name_no_weight_displays_name_and_unknown_weight(self) -> None:
        self.monitor._apply_memory_rod(
            make_state(
                bite_active=True,
                fish_name="短头梭鲃",
                weight_g=None,
                live_phase="hooked",
                owner_live=True,
                fish_graph_live=True,
            ),
            10.0,
        )

        rod = self.monitor.rods[0]
        self.assertEqual(rod.fish, "短头梭鲃")
        self.assertEqual(rod.weight, "--")
        self.assertEqual(rod.status, app_v101.STATE_BITE)
        self.assertEqual(rod.catch_badge, "待确认")

    def test_live_hook_without_name_uses_bite_fallback_not_wait(self) -> None:
        self.monitor._apply_memory_rod(
            make_state(bite_active=True, fish_name="", weight_g=None, live_phase="hooked"),
            10.0,
        )

        rod = self.monitor.rods[0]
        self.assertEqual(rod.fish, app_v101.STATE_BITE)
        self.assertEqual(rod.weight, "--")
        self.assertEqual(rod.status, app_v101.STATE_BITE)



if __name__ == "__main__":
    unittest.main()



