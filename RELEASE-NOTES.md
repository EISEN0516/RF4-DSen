# RF4-DSen V1.08

## 主要变更

- 新增独立 IL2CPP 动态布局读取框架。
- 支持增强版 `script.json` 的类型、字段和偏移解析。
- 支持标准 Il2CppDumper `script.json + dump.cs` 组合解析。
- 实现 `Il2CppClass -> static_fields -> Singleton -> List<Rig>` 遍历。
- 严格使用 `rig_in_water && fight_initialized && fight_factor > 0.0` 判断鱼口。
- 类或字段候选不唯一时输出诊断，不按内存地址或字段顺序猜测。

## 验证

- 37 项自动化测试全部通过。
- Python 语法编译检查通过。
- Windows x64 EXE 构建通过。

## EXE SHA-256

`E1B1D9335A6FF78486101DFB0F85E53338198648EFE3A35EEC6E8B42A739AD62`
