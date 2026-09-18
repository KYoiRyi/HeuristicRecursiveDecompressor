# Heuristic Recursive Decompressor (HRD)

Zig 0.16 实现的启发式递归解压引擎——永不信任文件后缀，始终以 Magic Bytes 为准。

## 架构

```
┌─────────────────────────────────────────────────────┐
│  Module 1: 分卷聚合引擎                              │
│  part1.rar / .001/.002 / .z01/.zip → 锁定首卷       │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│  Module 2: 真实载体嗅探与隐写剥离                     │
│  Magic Bytes + EOCD 尾部定位 + 64MiB 滑动窗口扫描    │
│  → 提取 offset 处真实压缩流 → sliceToFile            │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│  Module 3: 探测校验与分级密码调度                      │
│  Level 1: 密码库快照匹配 (hrd_passwords.txt + 同目录) │
│  Level 2: 人工交互 (callback)                        │
│  Level 3: 免密透传 (未加密则跳过)                     │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│  Module 4: 流水线解压 + 递归展开                      │
│  解压产物 → 重新扫描 → 若仍有压缩包则递归 (max 8层)  │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│  Module 5: 安全熔断与交付                             │
│  解压炸弹检测 (膨胀比 + 总大小限制)                   │
│  清理临时文件 → 交付到目标路径                        │
└─────────────────────────────────────────────────────┘
```

## 构建

```bash
# Windows (需 7-Zip CLI 与 7z.dll 在 PATH / third_party/)
zig build

# 跨平台 (Linux/macOS: apt install p7zip-full 或 brew install p7zip)
zig build -Dbackend=sys

# 测试
zig build test
```

## 使用

```bash
# 解压单个文件
hrd archive.zip -o ./extracted

# 解压目录下所有内容
hrd ./downloads/ -o ./extracted

# 多分卷
hrd part1.rar part2.rar part3.rar -o ./out

# 隐写/伪装文件
hrd photo.png -o ./out
hrd fake_video.mp4 -o ./out
```

## ABI (C 调用接口)

导出 `hrd.dll` / `libhrd.so` / `libhrd.dylib`，头文件 `include/hrd.h`。

```c
#include "hrd.h"

hrd_ctx_t *ctx = hrd_ctx_create(NULL);
const char *inputs[] = {"archive.zip"};
hrd_process(ctx, inputs, 1, "./output", NULL);
hrd_ctx_destroy(ctx);
```

## 测试样本

```bash
python tools/generate_samples.py
```

生成: zip / rar / 7z 分卷、加密包、隐写图种、嵌套压缩包、炸弹包。

## 项目结构

```
src/
  main.zig          CLI 入口
  abi.zig           C ABI 导出
  engine.zig        核心调度引擎
  ffi_bridge.zig    7z.dll COM 桥接层
  sevenzip_com.zig  COM 接口定义
  types.zig         公共类型
  util.zig          工具函数
  ioctx.zig         Zig 0.16 IO 上下文
  sniffer.zig       魔数嗅探 + 隐写剥离
  volumes.zig       分卷识别与聚合
  password.zig      密码库管理
  tests.zig         单元测试
  io_tests.zig      IO 测试
include/
  hrd.h             C ABI 头文件
third_party/
  7zip/7z.dll       预编译 7z.dll (Windows)
tools/
  generate_samples.py   测试样本生成器
```
