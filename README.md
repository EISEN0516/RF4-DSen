# RF4-DSen V1.08

RF4-DSen 独立版 Windows HUD，用于 Russian Fishing 4。

## 实时数据源

- 只查找并读取 `rf4_x64.exe`。
- 通过 `OpenProcess` / `ReadProcessMemory` 只读 RF4 进程内存。
- 使用 `GameAssembly.dll` 指纹和 IL2CPP class cache 识别当前运行布局。
- Fisher 对象只用于只读发现当前 live `FishingSet`；U1/U2/U3 由每个 `FishingSet` 绑定的 `RodRestController` 实测坐标/方向共识决定。
- 默认不发送 1/2/3 热键，避免启动提醒器时拿竿/切竿导致 U2/U3 暂时丢失。
- 某一根竿的 `RodRestController` 在切换/悬停瞬间为 0 时，只在另外两根 RodRest 与当前进程内 FishingSet 顺序同向时补齐第三根，避免直接显示“无竿”。
- 不启动、不连接、不监听、不读取 `rf4db小助手`、`RF4-HELPER`、`rig-session.tsv`、`hotbar-map.tsv` 或其它外部实时源。
- `FishingSet[]`、对象地址顺序都不再作为主路径 U 槽位依据。

## 当前验证目标

- 当前 RF4 进程版本：`4.0.25029`。
- U 槽位以当前游戏进程内 `FishingSet -> Rig -> RodRestController` 的实测关系为准。
- 有鱼时优先显示鱼名；活鱼重量未读到时显示 `--`，级别显示 `待确认`，避免把未知重量显示成 `0g`。

## 文件

- `RF4-DSen-V1.08.exe`：可运行程序。
- `rf4_il2cpp_dynamic_reader.py`：独立 IL2CPP 动态布局读取器。
- `test_il2cpp_dynamic_reader.py`：动态布局、List 和鱼口条件回归测试。
- `%LOCALAPPDATA%\RF4-Reminder\config.json`：本地配置。

## V1.08 动态 IL2CPP 框架

- 从同目录 `script.json` 自动读取 TypeInfo/Il2CppClass 地址。
- 从增强 JSON 的类型字段表读取 Offset；标准 Il2CppDumper `script.json` 配合同目录 `dump.cs` 读取字段 Offset。
- 通过 `Il2CppClass + 0xB8 -> static_fields -> Singleton` 解析管理器实例。
- 通过 `List<T> + 0x10 -> items`、`+0x18 -> size`、数组 `+0x20` 遍历 Rig。
- 严格使用 `rig_in_water && fight_initialized && fight_factor > 0.0` 判定鱼口。
- 类名轻度混淆时，按静态自引用 Singleton、`List<Rig>` 和语义字段组合定位；候选不唯一时输出诊断并停止，绝不按顺序猜字段。

运行布局检查：

```powershell
python -X utf8 rf4_il2cpp_dynamic_reader.py --layout-only
```

单次读取运行中游戏：

```powershell
python -X utf8 rf4_il2cpp_dynamic_reader.py --once
```

标准 Il2CppDumper 的 `script.json` 只含方法、字符串和 metadata 地址，不含实例字段 Offset，因此必须把同一次导出的 `dump.cs` 一并放到程序目录。增强版 JSON 若包含 `Types/Fields/Offset`，可单独使用。

## V1.07 修复

- 重抛后不再抱旧 Rig root：新增 FishingSet 类实例快速重发现，直接从当前 FishingSet -> Rig root 回链恢复 3 根竿。
- 修正 U1/U3 反向问题：槽位用 RodRestController 物理位置共识，移除会随朝向变化的 direction 向量投票。
- 启动/重扫先扫 live tiny memory regions，避免旧版 70 秒全堆扫描导致“等待竿位映射”。
## V1.06 修复

- 新增菜单「采集诊断」：一键生成可发送的 zip，包含 diagnostics.txt、state.json、config.json、当前 U1/U2/U3、runtime raw、DirectMemorySource 内部映射、rig/root/set/rodrest/fisher 证据。
- 诊断窗口增加「采集诊断」按钮，生成路径自动复制到剪贴板并打开诊断目录。
- direct-runtime 诊断增加 selected_rig_candidates、rodrest_evidence_detail、fisher_selected_detail、rig_mapping_detail、poll_rods，便于定位 U 位错位、重抛丢竿、鱼名缺失。

## V1.05 修复

- 修复 U2/U3 启动后丢失的根因：V1.05 默认不再触发 RF4 热键校准，避免读数动作本身改变游戏状态。
- Fisher 只做快速只读集合发现，槽位仍要求 RodRestController 多字段共识，禁止回退到对象地址猜 U 位。
- 增加单根 RodRest 暂缺桥接：两根有坐标实测 + 三根 FishingSet 仍有效时继续显示三根竿。
- 修复 Fisher 路径返回 FishingSet class 导致 snapshot 复验失败的问题。
- 修复已有 3 根竿时强制刷新被提前拦截的问题。
- 修复实时咬钩有鱼名时仍显示“有鱼咬钩 / 0g”的 UI fallback。



