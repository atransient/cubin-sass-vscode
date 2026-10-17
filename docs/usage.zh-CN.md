# Cubin SASS Preview 使用手册

安装与快速开始见[中文首页](../README.zh-CN.md)。本手册介绍具体操作、编辑限制和配置。

- [支持的文件与编辑模式](#支持的文件与编辑模式)
- [宿主可执行文件中的 cubin](#宿主可执行文件中的-cubin)
- [预览与源码功能](#预览与源码功能)
- [编辑与保存](#编辑)
- [配置与后台任务](#配置)
- [故障排查](#故障排查)
- [命令行](#命令行)

> 当前编辑与“以 SASS 源码打开/汇编回写”只支持 **sm_90**。非 sm_90 的指令宽度、
> 控制束和字段布局不同；后端会明确报告实际架构，不会套用 sm_90 规则冒险写坏文件。

## 支持的文件与编辑模式

既可以打开独立的 `.cubin`，也可以直接打开 Linux CUDA 可执行文件、共享库 `.so`
和目标文件 `.o`，编辑其中内嵌的 cubin。增删指令的空间限制取决于文件和编辑模式：

| 输入文件 | 预览中的 `+` / `−` | `.nvsass` 源码模式 |
| --- | --- | --- |
| 独立 `.cubin` | 定长增删：插入消耗目标函数尾部 NOP，删除后末尾补 NOP，物理指令槽数量不变。 | 可以增加、减少指令数量，让已有代码 section 扩容或缩容，不受尾部 NOP 数量限制。 |
| 宿主 ELF：可执行文件、`.so`、`.o` | 在选中的内嵌 cubin 中定长增删，规则同上。 | 内嵌 cubin 的总字节数必须保持不变；导致总长度变化的编辑会被拒绝。 |

以上操作都需要通过指令编码、分支重定位及相应的布局检查；有空间也可能因验证
失败而拒绝编辑。目前不支持新增或删除整个代码 section。宿主文件还要求设备 image
未压缩、架构为 sm_90；编辑对象是其 `.nv_fatbin` 内的设备 SASS，宿主 ELF 布局保持不变。

“汇编 cubin”以**现有 cubin 为基底**。从 CUDA C++ / PTX 生成最初的 cubin，使用
`nvcc` / `ptxas` 等工具；插件负责之后的 SASS 编辑和汇编回写。例如：

```bash
# 用 CUDA Toolkit 编译出独立的 sm_90 cubin
nvcc -arch=sm_90 -cubin kernel.cu -o kernel.cubin

# 导出源码，编辑 kernel.nvsass 后，以原 cubin 为基底汇编成新文件
python3 scripts/cubin_sass.py kernel.cubin --emit-source --all-sections --out kernel.nvsass
python3 scripts/cubin_sass.py kernel.cubin --assemble-source kernel.nvsass --out edited.cubin
```

## 宿主可执行文件中的 cubin

命令面板运行 `Cubin: 打开可执行文件中的 sm_90 SASS`，可以直接选择 nvcc 生成的
Linux 可执行文件、`.so` 或 `.o`。后端会解析宿主 ELF 的 `.nv_fatbin`，选出其中
未压缩的 `sm_90` cubin；若有多个包含代码的 `sm_90` image，扩展会列出 image 编号
和 `.text.*` section 让用户选择。页面上的 `file_off` 是**宿主文件真实偏移**，字段、
整条 SASS、原始字节、插入/删除、patch 和保存安全闸都沿用独立 cubin 的编辑链路。

从预览打开的源码会绑定所选 image，标签名包含 `image-N`。即使不同 image 的 kernel
名字相同，也会打开独立源码文档。关闭宿主预览或重载窗口后，源码仍保留 image 绑定；
重新打开宿主并预览另一个 image，也不会改变已有源码的编辑目标。

写回采用等长原位替换：宿主 ELF 的 section、program header、fatbin entry 与 relocation
全部保持不动。因此当前明确拒绝两种情况：fatbin 中压缩的 device ELF，以及让内嵌
cubin 总长度变化的源码重排。普通改单条/字段/字节、定长插入删除，以及不改变 cubin
总长度的 `.nvsass` 保存均可用。

预览中的修改先进入**宿主文件的编辑缓冲区**，保存宿主标签页才写入磁盘。从该预览
打开 `.nvsass` 后，保存源码先汇编到同一个宿主缓冲区；验证失败不更新缓冲区，虚拟
源码仍保持未保存状态。如果基底未在自定义编辑器中打开，保存源码会在验证通过后
直接写回宿主文件。上述流程无需手工提取 cubin 或重新链接宿主程序。

无后缀可执行文件第一次不能靠双击自动识别（VS Code 的 custom editor selector 只看
文件名，不看 ELF 内容）。可右键文件选择 `Open With…` →
`SASS preview (CUDA Host ELF)`，再用 `Configure Default Editor for...` 为该文件名建立
关联；扩展也在资源管理器右键菜单提供 `Cubin: 打开可执行文件中的 sm_90 SASS`。

命令行多 image 时用 `--image N`：

```bash
python3 scripts/cubin_sass.py ./app --image 1
python3 scripts/cubin_sass.py ./app --image 1 \
  --at 0x985a8 --assemble 'IADD3 R5, R0, 0x2, RZ'
```

## 预览与源码功能

- **SASS**：`nvdisasm -c` 的结果，按 `.text.*` 段分组，寄存器/立即数/谓词着色
- **kernel 折叠**：每个 `.text.*` 是一个独立折叠区，默认只展开第一个；摘要显示
  文件偏移、段大小和指令数，长符号名自动省略（悬停可看全名）。收起的 kernel
  不生成指令 DOM，搜索、只看差异和源码滚动定位会按需展开对应 kernel
- **控制段解码**：每条指令的 `stall / yield / wrbar / rdbar / waitmask / reuse`，
  鼠标悬停看含义。默认值（`wrbar=7`、`waitmask=0` 这些"没用上"的）压暗显示，
  真正设了的字段一眼跳出来
- **原始字节**：16 字节按 nvdisasm 的两个 64 位半字分组，配 `+0x…` 文件偏移。
  点左边的 `/*00a0*/` 复制对应的 `xxd -s … -l 16` 命令
- **两个 cubin 对比**：标题栏的 ⇄ 按钮（或命令面板 `Cubin: 与另一个 cubin 对比`）
  选另一个 cubin，字节不同的指令高亮；勾"只看差异"就只剩它们
- **以 SASS 源码打开**（命令面板 `Cubin: 以 SASS 源码打开`）：把全部
  `.text.*` section 导成同一份 `.nvsass` **文本文档**；每个 kernel 是一个原生
  折叠区，默认展开第一个、收起其余，不再先弹框选择 kernel。撤销/重做、
  搜索、多光标、行号、语法高亮全是 VS Code 自己的。这份源码**不落盘**：它是
  cubin 的一个可编辑视图（内存文件系统 `nvsass:`，见 `nvsassfs.js`），唯一的
  真相是**打开着的那份 cubin 字节**；工作区不会多出源码文件。源码里
  `Ctrl+S` 是**缓冲区 -> 缓冲区**的汇编：结果回到同一个 cubin document（可撤销、
  标签页变脏），磁盘要等 cubin 自己 `Ctrl+S`。每条指令行内自带控制码前缀
  `[B------:R-:W-:-:S01]`（该指令 bits 105:121 的解码），段内跳转目标写成
  `.L_<地址>` 标号；每个 `__global__` 块还显示可编辑的 `.regcount N`，保存时只
  更新该 kernel 的 `EIATTR_REGCOUNT`（`1..255` 原样写回，运行风险由用户负责）
- **源码栏 / 预览滚动联动**（像 markdown 的编辑器与预览）：`.nvsass` 源码栏滚到
  哪一条指令，并排的 SASS preview 就滚到同一条；反过来也一样。对齐锚点是指令的
  **段内地址**（源码行尾的 `// @0x0070`），不是行号 —— 源码里插删过指令、或预览
  开着过滤 / 只看差异时，行号两边对不上，地址对得上。不想要就把
  `cubinSass.scrollSync` 设成 `false`
- **把 SASS 源码汇编回 cubin**（命令面板同名命令）：整段两遍汇编 —— 标号解析
  成地址、控制码按**源码行**写 bits 105:121、每条过 nvdisasm 回环；任一条出错就
  一次列出全部诊断（行/列高亮），基底一个字节不动。原样导出再汇编是**逐字节
  一致**的；**增删指令也支持**（重排 section，更新符号、RELA 和 `.nv.info`，
  调试信息按策略处理）。独立 cubin 可变长，宿主 ELF 内嵌 cubin 要求总长度不变，
  详见前面的支持范围表
- **源码保存事务**：解析 → 汇编 → ELF 打包 → 验证，全部通过才更新
  cubin 缓冲区；基底未打开时，在私有临时文件中完成验证后原子替换磁盘基底。
  汇编会检查结构、整段 nvdisasm 回环和控制字段；独立 cubin 的落盘事务还会运行
  可用的 `readelf` / `cuobjdump`，CLI 的驱动加载检查需显式指定 `--smoke`。报告区分
  通过、失败和跳过；任一步失败不写回，虚拟源码保留未保存状态。驱动加载通过仍
  不代表硬件计算语义正确
- **自动刷新**：文件在外面被 `dd` 改写或脚本重新生成，页面跟着更新
- 过滤框支持助记符、寄存器名、`0x00a0` 这样的地址、或一段十六进制字节
- **格子布局**（勾"格子"）：认出这条指令的 **InsKey** 后，按 `data/segtable-sm90.json`
  逐格拆开 —— const / operand / enum / dc_safe / ctrl，enum 直接给名字
  （`S2R` 的 72:79 会显示 `2_SR_TID.X`，不再是一坨 hex）
- **modifier 下拉编辑**：enum 格点一下变下拉框，选项就是段表枚举出的取值
  （`S2R` 的特殊寄存器组有 100 多项，`SR_TID.X` → `SR_CLOCKLO` 一次点击）
- **可编辑**：点控制段的 chip 改 `Rd/Ra/Rb/Rc`、`stall`、`yield`、barrier、`reuse`；
  点字节行直接改这 16 个十六进制字节。改完 SASS 立刻重新反汇编回显

## 编辑

改动**只进缓冲区**，标签页出现脏标记，`Ctrl+S` 才落盘，`Ctrl+Z` 撤销 —— 和其它
编辑器一致。故意不做「点一下立刻写文件」：手改的基底往往是「只编译一次」
的东西，手滑就没了。

- **改字段**：点 `stall=1` 那种 chip，就地变输入框。寄存器可以填 `R12` / `12` / `RZ`；
  `waitmask` 可以填 `0b000101` / `0x5` / `101`；回车提交，Esc 取消。
  值超出字段位宽会拒绝并提示，不会悄悄截断
- **改整条指令**：点 SASS 文本，直接敲 `IADD3 R12, R8, R8, RZ`。换 opcode 会去找
  一条同助记符的真实指令当模板（先本文件、再 `corpus/cubins/`），打完补丁用
  **nvdisasm 回环校验**：造出来的编码必须被读回成一模一样的文本，否则拒绝落盘。
  换 opcode 时**控制段沿用原指令**而不是模板的 —— 模板的 `stall/yield/barrier`
  是别的 cubin 的调度结果，带过来会悄悄毁掉时序实验
- **改字节**：点字节行，按 `xxd` 的样子空格分隔编辑，要够 16 个字节
- **外部改动**：文件在编辑器外被 `dd` 或脚本改写时，缓冲区干净就直接跟随；
  有未保存改动则弹窗问，不会默默覆盖你正在改的东西

### 保存安全闸

源码对应的 cubin 或宿主文件在自定义编辑器中打开时，保存 `.nvsass` 先更新该文件的
编辑缓冲区，再保存二进制标签页才落盘。基底未在自定义编辑器中打开时，保存源码会
在验证通过后直接写回基底文件。汇编失败时源码保留未保存状态，基底保持不变。

保存二进制会在校验后及临时文件写完、提交替换前检查磁盘内容，外部修改或删除会阻止覆盖；
提交前还会检查取消状态和编辑版本，检查失败时保留编辑内容并清理临时文件。需要处理磁盘冲突时，可重新载入或另存为。
“另存为”会检测校验期间目标文件是否被修改、新建或删除。原文件丢失时仍能恢复
有效的 VS Code 备份，重新保存到原位置前将完整校验指令；若原位置已被其他程序
重新创建，则保留新文件并提示冲突。

`Ctrl+S` 落盘前先查一遍：**这次改动过的每条指令都必须能被 nvdisasm 解出来**。
解不出就弹模态框挡住保存，只有显式选「实验性保存（保留非法编码）」才落盘 ——
落盘后标题栏挂一个「实验性」标记，提醒这个文件里有解不出来的编码。

拦在保存这一步而不是编辑这一步，是因为**改字段/改格子/改字节是前端直接写
缓冲区的**，路上没有回环校验（只有换整条指令的那条路有）。只查改动过的那些：
原文件里本来就解不出的位（对齐填充、非指令数据）不该拦着你存自己的改动。
token 是 `INVALID*` 的编码（nvdisasm 读得出、但不是有意义的指令）只提醒不拦 ——
探索这类编码本来就是这个工具的用途。

命令行同一道闸：

```bash
python3 scripts/cubin_sass.py edited.cubin --diff orig.cubin --check-save
# {"ok": false, "changed": 3, "bad": [{"file_off": ..., "section": ".text.f", ...}], ...}
```

**写入位置**也只有一份判据（`edit_site()`）：`--assemble`、`--apply-patch`、
`--insert`/`--delete` 都要求目标偏移落在**可执行 section** 里、16 字节对齐、
整条不越过段末。ELF 头、非可执行 section、半条指令的偏移一律拒绝，
`--force` 也不放行位置（它只放行 patch 的 `before` 比对）。

字段位置来自 `nvisa/model/codec.py`，前端不硬编码任何 bit —— 位运算已和 Python
对拍验证过（改 `Rd=R9`/`Ra=RZ`/`stall=4`/`reuse.A=1` 后 nvdisasm 认出
`FFMA R9, RZ.reuse, R6, R4`）。

### 指令编辑的边界

改指令有两条路：**先试段表构造**
（`nvisa/model/asm_spec.py`，从 `data/segtable-sm90.json` + `data/fieldscan-sm90.json`
逐位造，不要模板），造不出来才退回**模板+补丁**（`nvisa/model/asm.py`，只能改
`FIELDS` 里已标定的寄存器/谓词/控制段）。两条路最后都过 nvdisasm 回环校验，
写不了的会挡住并告诉你 nvdisasm 实际读回了什么。

分支目标直接填**段内绝对地址**（就是左边 addr 列那一套坐标）：在 `0x70` 那行
写 `BRA 0xd40`，编码里存的是 `(0xd40 - 0x70 - 0x10) / 4` 的两补码，位段散在
16:24 和 34:82 两截 —— 这条合成规则记在段表的
`slot_facts` 里。`.ABS` 的目标按绝对地址原样写。

段表构造把原先的前两条限制解掉了：立即数、常量 bank、地址形式、`desc[][]`、
枚举修饰符现在都在语法里（`LOP3.LUT R10, R8, R11, RZ, 0x3c, !PT`、
`LDG.E R2, desc[UR4][R6.64]`、`MUFU.RCP R5, R7` 都能写，且不需要 corpus
里有同款变体）。控制段仍归 `asm.py:FIELDS`：stall/yield/barrier 沿用原指令，
`.reuse` 从文本来。

还写不了的：

- **段表还没学会的助记符/form** —— 退回模板补丁，于是又受「corpus 里得有一条
  同助记符的真实指令」的约束；都没有就报错并列出可用助记符（约 65 个）。
  要加就用 inline PTX 逼 ptxas 生成一条放进模板目录
- **分支/调用的符号标号**（`` BRA `(.L_x_0) ``）—— 标号的地址不在指令自己
  身上，要接汇编器的符号表；**改成数值地址就能写**（见下），报错也会这么说
- **少数字段段表没解释到的形式**（比如 `LDS.U` 的 `.U`）—— 回环会挡住，
  不会悄悄写错
- **往 `yield=0` 的指令上写 `.reuse`** —— 控制段沿用原指令，而 nvdisasm 只在
  `stall>=1 且 yield=1` 时才打印 `.reuse`（reuse cache 要背靠背发射才有意义），所以这种落点上的 `.reuse` 回环永远读不回来；报错里会点明

### 插入 / 删除整条指令

**预览模式：定长增删。**

每行悬停会露出 `+`（在这一行插入）和 `−`（删掉这一行）。段大小不变：插入吃掉
函数尾部对齐填充里的一条 `NOP`，删除在末尾补一条。跨过挪动点的分支目标和
`.nv.info` 里记的指令偏移（`EXIT_INSTR_OFFSETS` 这类）都会跟着改，改完整段交回
nvdisasm 复核 —— 挪过的指令文本必须逐字不变、分支必须仍指着同一条。

做不了的会明确拒绝（不会写出半个坏文件）：窗口跨到下一个函数、窗口末尾不是
`NOP`（kernel 后面还跟着 device function 的 cubin 就是这种）、要删的那条正好是
别人的跳转目标、`BRX` 这类间接跳转。命令行同款：`--insert SASS --at`、
`--delete --at`。

插入额度来自**目标函数尾部可用的 NOP**，不会从其他函数借空间。例如尾部有 2 条
可用 NOP，就有 2 个插入空位；删除一条指令会在末尾补回一个 NOP 空位。NOP 空位
耗尽后，预览不能继续插入。原有 section 的大小和物理指令槽数量始终不变。

**源码模式：独立 cubin 可变长，宿主内嵌 cubin 需等长。**

对独立 `.cubin`，运行 `Cubin: 以 SASS 源码打开` 后，直接添加或删除带控制码的
指令行，再保存源码。后端支持重排已有代码 section，并更新相应的分支、符号和
重定位信息，因此不受预览尾部 NOP 额度限制。涉及不支持的指令形式、无法重定位的
引用或调试信息时仍可能被拒绝。

对可执行文件、`.so`、`.o`，同样可以编辑源码，但汇编后的**整个内嵌 cubin 总字节数**
必须与原来一致。最终以总长度校验为准，不能只按源码行数判断；导致长度变化时会
拒绝写回。需要扩容时，可另行处理独立 cubin，并通过外部构建流程将其重新集成到
宿主程序。

### 格子就地编辑

指令那一行下面的格子，点一下就能改：

- **enum / modifier 格** —— 下拉框，选项是段表实测出来的取值（非法档也列，
  标成「nvdisasm 读不出」；位宽能放下的其它值走「自定义…」）
- **operand 格** —— 输入框：寄存器槽认 `RZ`/`R5`/`UR4`，谓词槽认 `@!P0`/`PT`，
  立即数认 `0x..`/`0b..`/十进制，负数按二补码塞进这一格。段表把一个操作数
  劈成几段的（`IMAD.MOV` 的立即数就是）已经并成一格，不用自己算高低位

两种都是**只动这一格的位**，别的位一位不变；改完整个缓冲区重新过 nvdisasm，
读回的文本就在同一行上 —— 编码非法的话那一行会空掉。

**大位宽与严格输入**：段表里最宽的 operand 槽 81 位（`WARPSYNC_R_II`），
还有 64 位地址、56 位分支偏移 —— 前端一路 **BigInt**，不经过 32 位位运算，也
不经过 `Number`（53 位尾数放不下）。JSON 传输同理：宽过 32 位的格子后端会额外
下发 `raw_str`（十进制字符串），页面只信它。数字输入必须**完整匹配**
`0x..`/`0b..`/十进制，`0x10junk`、`12abc` 这种带非法尾缀的一律拒绝（原来
`parseInt()` 会读到哪算哪，把它们当成 16 和 12 悄悄写进去）。

**PC 相对的分支目标槽不给就地改**：`BRA`/`CALL`/`RET` 的 `II` 槽里存的是
「相对下一条指令的偏移 ÷ scale」的两补码，不是目标地址。页面上这一格显示的是
**绝对目标**（`→ 0x190`），点它会提示改目标要点 SASS 文本整条重敲 —— 那条路
本来就吃绝对地址，scale、符号位、位散布都按 `slot_facts` 的规则来。

### 批量编辑：JSON patch

改动可以导出成一份 patch，在别的 cubin 副本上重放：

```bash
# 导出（编辑器里也有命令：Cubin: 导出改动为 JSON patch）
python3 scripts/cubin_sass.py edited.cubin --diff orig.cubin --export-patch > p.json

# 应用：照抄编码，精确复现
python3 scripts/cubin_sass.py copy.cubin --apply-patch p.json --out copy.cubin
# 有一条打不上时默认整份回滚；确实要半份就加 --partial

# 应用：按文本重新汇编（跨 cubin 复现，目标那条的控制段会被沿用）
python3 scripts/cubin_sass.py other.cubin --apply-patch p.json --by-sass --out other.cubin
```

每条记 `enc` + `origin`，所以
批量扫描工具产出的 `{enc, origin}` JSONL 可以直接喂给
`--apply-patch`（它没有位置信息，配 `--at <文件偏移>`），反过来导出的 patch
扫描侧也读得懂。

patch 带版本（`nv_isa-cubin-patch/2`）：整份记 `format`/`arch`/`mode`，逐条记
`op`/`section`/`addr`/`file_off`/`enc`/`sass`/`before`。版本、架构、模式
（只有 `in-place`）、操作类型（只有 `replace`）任何一项对不上就**整份拒绝**。

**位置的权威是 `(section, addr)` 而不是文件偏移** —— 文件偏移是导出那个 cubin
的坐标，换一个 cubin 就不成立了；section 名同时就是函数身份（ptxas 给每个
kernel/device function 单独出一个 `.text.<mangled>`），对不上就拒绝，`--force`
才退回按文件偏移硬打。`--by-sass` 跨 cubin 复现时，PC 相对分支的目标按
「跳多远」重定位（新目标 = 旧目标 − 源地址 + 目标地址）；符号标号和 `.ABS`
明确拒绝重汇编 —— 前者地址不在指令身上，后者是源 cubin 的地址空间。

**默认 all-or-nothing**：有一条没打成就整份不落地，`--partial` 才允许部分成功
（编辑器里会弹窗问要不要只打上能打的那几条）。

**patch 只表达原地替换**：导出前会校验文件长度、ELF 布局和可执行段之外的字节
都没变 —— 插入/删除挪过指令的 cubin 会被拒（`.nv.info` 里的指令偏移变了，patch 说不出
这件事）。分发这类改动就直接给改完的 cubin。

打之前会核对位置（`edit_site()`，`--force` 也不放行）和 `before`：目标
偏移上不是 patch 记的那条指令就拒绝并告诉你现在是什么（`--force` 照打）；打完
还要过 nvdisasm 回环 —— patch 里没记 `sass` 时那道回环是空的，安全模式下至少
要求打进去的编码解得出来（探索非法编码走 `--force`）。编辑器里应用是逐条登记
成可撤销编辑，撤销栈上每条都看得见。

### 耗时

大 cubin 的首屏走轻量预览：默认不做逐条 `identify()`/`cell_map()`，勾选“格子”
时才补这层分析；多个 kernel 默认只渲染第一个，收起的 kernel 只有一行摘要；每个
展开的 kernel 独立渲染 300 条，底部“继续显示”再展开下一页，过滤输入停顿 120ms
后才重画。这样默认隐藏的格子不会占掉大部分启动时间和 JSON，也不会一次往 webview
塞进上万个 DOM 节点。格子一旦加载，本标签页后续刷新会继续携带它们，保证编辑后的
格子显示同步。

| 操作 | 实测 |
|---|---|
| 改字段 / 改字节（位运算在前端做） | 约 0.4s，都是重新解析整个缓冲区的开销 |
| 改指令，同 opcode（模板=原指令） | 约 0.6s |
| 改指令，换 opcode（要查模板池） | 约 1~2s |
| 首次换 opcode（建 corpus 模板缓存） | 约 8s，之后缓存在 `~/.cache/nvisa-cubin-sass/` |

corpus 模板池按目录 mtime 缓存；往 `corpus/cubins/` 里加了新 cubin 会自动重建。

上面的数字是**冷**的：起一次 nvdisasm 就要 0.25~0.35 秒，而改一条指令的路上要
问它好几次（认原指令、探 `.reuse` 位、回环校验）。两件事把这个数压下来：解码
结果按输入缓存在 `~/.cache/nvisa-nvdisasm/`（键里带 nvdisasm 版本），同一批编码
问第二遍就不再起进程；`.reuse` 的三次探测合成一次批量解码。反复改同一条、
来回撤销重做的时候差别最明显。

## InsKey 识别

modifier 区 72:90 是**逐 opcode** 的含义（`codec.py` 自己的注释：per-opcode meaning
— NOT generic），通用解码器只能打印 raw。要解出名字就得先知道这条指令属于哪个
InsKey，靠 `data/segtable-sm90.json` 里每个 key 的 **const 格**反查：按命中的常量
位数打分取最高。

独立生产库验收（约 470 万条）为：**误判 0 / form 错 2 / 认不出 0.47% /
库外助记符 3.01%**；识别器坚持宁缺毋滥，不确定就返回 `None`。
这个匹配器是**宁缺毋滥**型的：出答案就是对的，不确定就返回 `None`，页面退回
通用解码 —— 不会出现给你看错误 modifier 名字的情况。识别出来的 key 标在 SASS
右边，过滤框也认它。

段表里没枚举到的取值会显示 `4 (未标定)`，而不是编一个名字。

## modifier 下拉编辑

认出 InsKey 的指令，enum 格可以点开选值。选项来自 `segtable`，并用
`fieldscan-sm90.json` 补齐**默认取值** —— segtable 把「不加后缀」那一档记成空条目
丢掉了，只看它会把最常见的 `LDC`（73:75 = 4）显示成「未标定」，其实是
「默认，无后缀」。两份数据合起来才是完整的。

位宽能放下但两份数据都没枚举到的值，可以从下拉里的「自定义…」直接填 ——
探索未标定取值本来就是这个项目在干的事，工具不该假装它们不存在。

改完如果 nvdisasm 解不出来了，会提示一句（改动仍在缓冲区，`Ctrl+Z` 可撤销）；
但注意**解得出不等于合法**，比如 `LDC` 的 73:75 填 6，nvdisasm 会老实读回
`LDC.INVALID6`。

## 配置

| 项 | 默认 | 说明 |
|---|---|---|
| `cubinSass.pythonPath` | `python3` | 解析用的解释器 |
| `cubinSass.scriptPath` | `scripts/cubin_sass.py` | 默认使用扩展自带脚本，自定义相对路径按工作区根解析（没有工作区时按扩展目录） |
| `cubinSass.backendTimeout` | `120` | 后台任务总超时秒数，含排队，范围 1–3600 |
| `cubinSass.backendConcurrency` | `2` | 同时运行的后台任务数，范围 1–8，最多另排队 32 个 |
| `cubinSass.scrollSync` | `true` | 源码与预览滚动联动 |
| `cubinSass.showBytes` | `true` | 字节列默认是否展开 |
| `cubinSass.showCtrl` | `true` | 控制段默认是否展开 |

`pythonPath` 与 `scriptPath` 是 machine 级设置，只读取用户/远程设置，仓库的 `.vscode/settings.json` 不能指定扩展执行什么程序。不受信任的工作区（受限模式）中扩展不会启用。

命令 `Cubin: 取消后台任务` 取消当前窗口的运行中及排队任务。过期预览和已关闭文档的
任务自动取消；Linux 上超时或取消会终止整个 Python 进程组，包含其 CUDA 工具子进程。
后台验证取消或超时时保留编辑内容，不会提供“实验性保存”来绕过未完成的验证。

## 故障排查

| 现象 | 检查方式 |
| --- | --- |
| 找不到 Python | 在用户或远程设置中将 `cubinSass.pythonPath` 设为 Python 3.10+ 解释器的路径。 |
| 只能看到字节与控制字段，没有 SASS | 确认扩展宿主的 `PATH` 包含 CUDA Toolkit 的 `bin` 目录，且能运行 `nvdisasm --version`；更新环境后重启扩展宿主。 |
| Remote-SSH 下本地工具可用，插件仍报缺失 | Python 和 CUDA 工具需要安装在远程主机，并对远程扩展宿主可见。 |
| 扩展没有启用 | 检查工作区是否处于受限模式；扩展不会在不受信任的工作区中启用。 |
| 后台验证超时 | 按任务需要调整 `cubinSass.backendTimeout`，或运行 `Cubin: 取消后台任务` 取消当前工作后重试。 |
| 保存提示磁盘冲突 | 保留当前编辑，重新载入基底或另存为；详细规则见[保存安全闸](#保存安全闸)。 |

预览、反汇编、编辑和回环验证无需 GPU。可选的驱动加载检查需要 CUDA 驱动、兼容设备
及 C 编译器；缺少条件时报告跳过。这类检查仅加载模块，不执行修改后的 kernel，
通过检查也不代表程序计算正确。

## 命令行

仓库中的 `scripts/cubin_sass.py` 可以脱离 VS Code 使用：

```bash
python3 scripts/cubin_sass.py corpus/cubins/fma.sm_90.cubin
python3 scripts/cubin_sass.py edited.cubin --diff corpus/cubins/fma.sm_90.cubin
python3 scripts/cubin_sass.py --help
```

命令行响应为 JSON，失败时返回非零退出码。源码导出、汇编示例见
[支持的文件与编辑模式](#支持的文件与编辑模式)，patch 示例见[批量编辑](#批量编辑json-patch)。
`nvdisasm` 不在 `PATH` 时，预览响应包含 `have_nvdisasm:false`，仍可查看字节与控制字段。

实现结构和运行数据来源见[架构说明](architecture.md)，开发与测试见[贡献指南](../CONTRIBUTING.md)。
