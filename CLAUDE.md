# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在此仓库中工作时提供指导。

## 概述

基于 Robot Framework 的网络 ACL/转发硬件设备（Finslink/Hengming D系列）自动化测试。测试覆盖通过 CLI（Telnet）和 RCP（Rule Control Protocol）下发规则、通过 TRex 打流、报文抓取/校验以及计数验证。

## 测试用例概览

| 文件 | 功能 | 标签 |
|------|------|------|
| `00_Device_Init.robot` | 设备初始化（端口 up、组配置等） | `init` |
| `01_Total_Num.robot` | 按包数/字节数统计的配置生效、修改、告警验证 | `cli` |
| `02_Total_Time.robot` | 按时长统计的配置生效、修改、告警验证 | `cli` |
| `03 Tunnel_identify.robot` | 隧道识别与剥离功能验证 | — |
| `04 Rcp.robot` | RCP 全功能测试（规则增删改查、sni 匹配/阻断、五元组、VLAN、MPLS、优先级、分片、镜像等） | `rcp`, `A` |
| `05_MR.robot` | 缺陷复现验证（MR#8789、MR#8791） | — |
| `06 MTU.robot` | 端口 MTU 遍历测试（64, 9000, 9400 字节） | — |
| `07_Priority.robot` | 规则优先级验证（IPv4+IPv6+L2 共 48 条，逐条删除验证优先级依次生效） | `priority`, `cli` |

### 审阅规则

- **审阅框架时，不需要阅读 `04 Rcp.robot` 中含 "sni" 的测试用例**（如 `rcp_add_sni_acl`、`rcp_add_sni_number`、`rcp_add_sni_https_*` 等），这些是 SNI（Server Name Indication）业务特定用例，与框架通用逻辑无关。
- `04 Rcp.robot` 中不含 "sni" 的用例（如 `rcp_add`、`rcp_modify_rule`、`rcp_priority` 等）仍应正常审阅。

## Python 环境

- 系统 Python: `E:\app\python\python.exe`
- Robot Framework: `E:\app\python\Scripts\robot.exe`
- `Resource/Lib/rcpLib/.venv` **已损坏**，指向不存在的 `C:\python38\python.exe`，不要使用
- Excel 操作用 xlrd/xlwt/xlutils（`.xls` 格式），**不支持** openpyxl（`.xlsx`）

## 如何运行测试

```bash
# 使用系统 Python 运行（PowerShell）
& "E:\app\python\Scripts\robot.exe" Function_Code/07_Priority.robot

# Run with specific test case
& "E:\app\python\Scripts\robot.exe" -t "forward" Function_Code/04\ Rcp.robot

# Run tests matching a tag
& "E:\app\python\Scripts\robot.exe" -i rcp Function_Code/

# 校验语法：不要用 --dryrun，本仓库会卡死（详见下方"Robot Framework 语法注意事项"）
# 直接跑单条用例即可：
& "E:\app\python\Scripts\robot.exe" -t "forward" Function_Code/07_Priority.robot
```

需要安装 Robot Framework 及其依赖（SSHLibrary、Telnet、ExcelLibrary、RequestsLibrary、scapy、trex_stl_lib）。

## 架构

### 目录结构

```
Function_Code/          # Robot Framework 测试套件（.robot 文件）
Resource/
  Business/             # 共享变量（variable.txt），各测试的 pcap/规则数据
    rule_pcap/          # Excel 文件，映射规则与 pcap 文件的关系
    raw_packets/        # 本地 pcap 文件，用于上传至打流服务器
    ripe_packets/       # 从服务器下载的已抓取报文
  Lib/
    rcpLib/             # RCP 客户端库（Python）—— 通过 TCP socket 进行规则的增/删/查
    parseLib/           # 报文解析/校验（Python）—— pcap 分析、比较
    trexLib/            # TRex 打流器封装（Python）
    support.py          # 共享 Python 工具函数（统计解析、列表比较）
    config.py           # 环境相关配置（IP、用户、端口）
  Public/
    initConfiguration.txt   # Telnet CLI 关键字（NewConnection、setLgtypeAndportUp、addGroup）
    sshKeywordSet.txt       # SSH 关键字（OpenConnectionAndLogin、SshExecuteCmd、文件传输）
    instrument.txt          # 打流关键字（tcpreplay + tcpdump）
    Ddevice.txt             # D设备专用关键字（ACL 统计、端口统计、报文校验）
    TC500.txt               # TC500 设备专用关键字
```

### 测试流程模式

大部分测试用例遵循以下通用流程：
1. 打开 Excel 表格读取测试参数（规则配置、pcap 文件名、速率、时长）
2. 向被测设备下发 ACL 规则（通过 CLI Telnet 或 RCP）
3. 使用 TRex/tcpreplay 通过设备发送流量（通过 SSH 连接打流服务器）
4. 在打流服务器上通过 tcpdump 抓取输出报文
5. 校验设备上的命中计数以及抓取报文的内容完整性

### RCP（Rule Control Protocol）

RCP 是用于规则管理的私有 TCP 协议。`RcpApi` 类处理 socket 通信、用户认证以及使用二进制协议进行规则的增删改查。`RcpApiForRf` 将其封装为 Robot Framework 库。配置从动态生成的 `configini.py` 中读取。

### 设备通信

与被测设备的两条通路：
- **Telnet**（端口 9999）—— 基于 CLI 的配置（`acl` 命令、`show` 诊断、`interface` 设置）
- **SSH**（端口 22，root/fa）—— 通过 `luacmd.lua` 进行底层 FPGA 寄存器访问

打流服务器通信通过 SSH（端口 22）进行 tcpreplay、tcpdump 和 pcap 文件传输。

### 共享变量流

`Resource/Business/variable.txt` 定义了全局变量（设备 IP、端口、用户名、密码、路径）。所有 `.robot` 文件和关键字文件都导入此文件。路径变量使用 `${CURDIR}`，它相对于导入文件所在目录进行解析。

### 标签

测试标签控制执行范围：
- `init` — 设备/仪表初始化（最先运行）
- `rcp` — 基于 RCP 的测试（A板和B板通用）
- `A` — 仅 A 板支持的功能
- `cli` — 命令行下发测试

## 核心关键字参考

### CLI 连接 — `initConfiguration.txt`
#### `New Connection Custom`
打开 Telnet 连接（端口 9999）到被测设备并登录，设置 `terminal length 0`。无参数，无返回值。每个 CLI 操作前通常需要调用。
#### `addGroup`
```
addGroup    ${flag}    ${group}    ${id}
```
将 `${group}` 中的端口列表添加到入口组或出口组。`${flag}` 为 `ingroup` 或 `outgroup`。
#### `Wait Device Reboot`
```
Wait Device Reboot    max_wait=660    interval=60
```
冷重启后轮询等待设备完全上线。**不通过简单的端口探测**，而是 telnet 登录成功后 `show version`，校验 `software` 字段是否已填充版本号，并与初始化基准比对。无返回值，调用后**复用当前已登录的连接**。

| 参数 | 默认 | 说明 |
|------|------|------|
| `${max_wait}` | `660` | 最大等待秒数（不含初始 120s 睡眠） |
| `${interval}` | `60` | 每轮轮询间隔秒数 |

**内部流程：**
1. 先 `Sleep 120s`（让设备进入重启流程）
2. 循环：关闭所有连接 → `Telnet.Open` + `Telnet.Login` → `config` → `terminal length 0` → `show version`
3. 用正则 `software\s+:\s+\S` 检查 `software` 行是否已填充版本号：
   - **software 为空** → 设备可登录但未完全启动，继续等待
   - **有版本号** → 与 `${device_show_version_ref}` 比对（归一化 CRLF→LF 后）：
     - ref 为空 → 无基准可比对，直接 `RETURN`（视为上线）
     - 一致 → 完全上线，`RETURN`
     - 不一致 → 上报异常但 `RETURN`（继续执行）
4. Telnet 连接/登录失败 → `EXCEPT` 捕获，继续等待
5. 每轮后 `Sleep ${interval}` 并累计 `${elapsed}`
6. **超时仅 `Log` 警告，不 `Fail`** —— 设备未按时上线时仍继续执行后续步骤

**依赖：** `${device_show_version_ref}` 由 `00_Device_Init.robot:76` 通过 `Set Global Variable` 设置（初始化时抓取的 `show version` 输出）。因此重启类用例必须排在设备初始化用例之后运行，否则 ref 为空会退化为"能登录即上线"的宽松判定。

### SSH 操作 — `sshKeywordSet.txt`
#### `OpenConnectionAndLogin`
```
OpenConnectionAndLogin    alias=tcpreplay
```
打开到打流服务器的 SSH 连接（200 列终端宽度），自动重试登录失败。返回 `${alias}` 用于 `Switch Connection`。
#### `SwithConnectionAndLog`
```
SwithConnectionAndLog    ${machine}
```
切换到 `${machine}` 对应的 SSH 连接。
#### `SshExecuteCmd`
```
${stdout}    ${rc}    SshExecuteCmd    ${cmd}
```
在服务器上执行命令，返回标准输出和返回码。
#### `SshPutFile` / `SshGetFile`
```
SshPutFile    ${machine}    ${src}    ${dest}
SshGetFile    ${src}    ${dest}
```
上传/下载文件到打流服务器。

### 打流与抓包 — `instrument.txt`
#### `tcpreplayAndTcpdump`
```
${rx}    ${tx}    tcpreplayAndTcpdump    ${saveName}    ${pcapfileName}    ${speedForMbps}    ${durationTime}
```
完整打流+抓包流程。返回 `${rx}`（tcpdump 抓到的包数）和 `${tx}`（发送统计）。

**参数说明：**
| 参数 | 说明 |
|------|------|
| `${saveName}` | 抓包保存的文件名前缀 |
| `${pcapfileName}` | pcap 文件名，相对于 `${ssh_server_raw_pcap_path}` |
| `${speedForMbps}` | `0` = 最快速率，非 0 按 Mbps 限速 |
| `${durationTime}` | `"1t"` = 打流 1 次（loop），`"1"` = 打流 1 秒（duration） |
| `${clearStatistics}` | 默认 `1`，发包前 `clear statistics all` + `compareStastics 0 0` 清零 |
| `${tcpdumpWaitTime}` | 默认 `10`，抓包等待秒数 |
| `${twoTcpreplay}` | 默认 `0`；设为 `1` 时支持 2-4 个 pcap 文件同时打流 |
| `${tcpreplayPath}` | 默认 `${ssh_server_raw_pcap_path}`；pcap 在服务器子目录时必须显式传入 |

**返回值：**
- 当 `twoTcpreplay=0`：`${tx}` = `${txPkt} ${txByte + txPkt * 4}`（字符串）
- 当 `twoTcpreplay=1`：`${tx}` = `[txPkt, txByte, txPkt1, txByte1, txPkt2, txByte2, txPkt3, txByte3]`（列表）

### Pcap 生成 — `makePcapFile.py`
#### `makePcapFromRule`
```
${pcapNames}    makePcapFromRule    ${exist}    ${ruleConfigName}    ${title}    ${outputDir}
```
从 RCP 规则配置的 `sipg`/`dipg` 五元组直接生成 pcap，**无需**创建独立的 `*_packet.ini` 文件。参数 `${title}` 支持逗号分隔多个 section。

**五元组 → 报文参数映射：**

| 五元组字段 | 报文参数 | 默认值 |
|-----------|----------|--------|
| `sipg[0]`（ip/mask） | `sip` | — |
| `sipg[1]` | `sport` | `'0'` → `'1024'` |
| `sipg[3]` | `proto` | `'0'` → `'tcp'` |
| `dipg[0]`（ip/mask） | `dip` | — |
| `dipg[1]` | `dport` | `'0'` → `'1024'` |

**pkt_type 自动判定：**

| operate | vlang/mplsg | pkt_type |
|---------|-------------|----------|
| `addRule_FiveTuple` / `addRule` | — | `normal` |
| `addRule_L2` | 有 `vlang` | `vlan` |
| `addRule_L2` | 有 `mplsg` | `mpls` |

固定参数：`pkt_len=300`，`pkt_count=200`。
#### 自定义 outputDir 的双路径同步

当指定 `outputDir` 时（如 `${localRawPcapPath}rcpclearlimit/`），方法会自动计算 `outputDir` 相对于 `self.localPath` 的相对路径，同步更新 `self.remotePath`，并在服务器上创建对应的远程子目录。**如果不处理**，pcap 会上传到服务器根目录而非子目录，导致后续 `tcpreplay` 找不到文件。

配套要求：所有 `tcpreplayAndTcpdump` 调用必须传 `tcpreplayPath=${sshClearLimitPath}` 指向同一子目录（见上文参数表）。
#### `needRegenPcap`
```
${needRegen}    needRegenPcap    ${ruleConfigName}    ${titles}    ${outputDir}
```
检查是否需要重新生成 pcap。`${titles}` 为逗号分隔的 section 名列表。返回 `True`（pcap 不存在或 ini 有更新，需重新生成）或 `False`（可复用已有 pcap）。配合 `Set Variable If` 设置 `exist` 标志：

```robot
${needRegen}    needRegenPcap    rcpClearLimit    ${titleListStr}    ${rcpClearLimitPcapPath}
${existFlag}    Set Variable If    ${needRegen}    0    1
```

`exist=0` 新建模式（生成+上传），`exist=1` 复用模式（跳过上传，显著提速）。
#### `openSsh` / `closeSsh`
批量生成 pcap 前调用 `openSsh` 建立持久连接，生成完成后调用 `closeSsh` 关闭。复用单次 SSH 握手避免每个 pcap 上传都重新认证，大幅加快批量上传速度。

### ACL 统计 — `Ddevice.txt`
#### `getAclHitstatistics`
```
${hitCount}    getAclHitstatistics    ${appIdListOrNot}    ${sleepTime}=10
```
查询 `show acl hit_statistics <app_id>` 并求和。`${appIdListOrNot}` 可以是单个 app_id 或列表。`${sleepTime}` 是查询前等待秒数（给设备时间更新统计），默认 10s。正则提取：`${id}\s+(\S+)`。
#### `compareStastics`
```
${in_all_pkt}    ${in_all_byte}    ${out_all_pkt}    ${out_all_byte}    compareStastics    ${inport}    ${outport}    ${expect_in}    ${expect_out}
```

比较设备端口 rx/tx 统计与预期值（仪表发送/接收数），是最常用的端口统计校验关键字。

**参数说明：**
| 参数 | 说明 |
|------|------|
| `${inport}` | 入口端口列表，如 `${inportId}` = `['1/5']` |
| `${outport}` | 出口端口列表，如 `${outgroup_f_portId_1}` = `['1/5']` |
| `${expect_in}` | 预期的设备 rx 包数；传入 `"00"` 跳过入口比较 |
| `${expect_out}` | 预期的设备 tx 包数；传入 `"00"` 跳过出口比较 |

**内部流程：**
1. 调用 `statistics ${inport} 1` 获取入口组各端口 rx 统计（`${x}=1` = rx-pkts）
2. 调用 `statistics ${outport} 9` 获取出口组各端口 tx 统计（`${x}=9` = tx-pkts）
3. 取入口第一个端口 rx = `${device_in}`，出口最后一个端口 tx = `${device_out}`
4. 串接场景（`ingroup_member_num > 1`）：合并中间端口统计，校验所有中间端口计数一致
5. 断言 `${device_in} == ${expect_in}` 和 `${device_out} == ${expect_out}`

**返回值：** `${in_all_pkt}  ${in_all_byte}  ${out_all_pkt}  ${out_all_byte}` — 入口/出口端口组累计的 rx_pkt, rx_byte, tx_pkt, tx_byte

**常见用法：**
```robot
# 1. 打流前清零验证（配合 tcpreplayA 的 clearStatistics=1 自动调用）
compareStastics    ${inportId}    ${outgroup_f_portId_1}    0    0

# 2. 打流后校验：设备 rx = 仪表发送(${tx}[0])，设备 tx = 仪表接收(${rx})
${rx}    ${tx}    tcpreplayAndTcpdump    test_flow    ${pcapfile}    ${speed}    ${durationTime}
compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}

# 3. 只校验入口（跳过出口）
compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    00

# 4. 只校验出口（跳过入口）
compareStastics    ${inportId}    ${outgroup_f_portId_1}    00    ${rx}
```

另有变体：`compareStastics_mtu`（入口含 MTU 计数）和 `compareStastics_old`（简化版，不支持多成员端口组），参数签名相同。
#### `undoAclAll`
清除所有 ACL 规则：`undo acl all` + `undo sni_limit`，再通过 SSH 执行 `luacmd.lua` 清除配置数据库。用于 Setup/Teardown。
#### `getPortStatistics`
```
${port_statis}    getPortStatistics    ${port}
```
查询 `show statistics interface <port>`，返回字典：`rx-pkts`, `rx-bytes`, `jumbo`, `undersize`, `discard`, `fcsError`, `mtuExceeded`, `fragment`, `tx-pkts`, `tx-bytes`。
#### `getPortInfo`
```
${port_info_dict}    getPortInfo    ${port}
```
查询 `show interface eth <port>`，返回接口属性的字典（admin state, link state, speed 等）。
#### `getCliTime`
```
${timeStr}    getCliTime
```
查询 `show systemtime`，返回第一行时间字符串。
#### `get_next_time_boundary_rcp` — `RcpApiForRf.py`
```
${targetTime}    get_next_time_boundary_rcp    ${currentTime}    ${boundaryType}
```
计算下一个时间边界 00:00:00。`${boundaryType}` 为 `day`（明天0点）、`week`（下周一0点）或 `month`（下月1号0点）。时间格式为 `YYYY.MM.DD-HH:MM:SS`，与设备 CLI 输出一致。
#### `get_date_boundary_info` — `RcpApiForRf.py`
```
&{info}    get_date_boundary_info    ${timeStr}
```
返回字典，包含 `is_month_first`（是否1号）和 `is_monday`（是否周一）。用于判断跳"明天0点"时是否恰好也是周一/月初，以区分验证逻辑。
#### `addRuleDirect` — `RcpApiForRf.py`
```
${req}    ${expect}    ${actual}    ${ruleId}    Add Rule Direct    &{kwargs}
```
绕过 `.ini` 文件，直接使用 kwargs 字典调用 `RcpApi.addRule()` 下发组合规则。kwargs 由 `RuleImport.Build Combined Rule Kwargs` 构建。
#### `addRuleDirect_FiveTuple` — `RcpApiForRf.py`
```
${req}    ${expect}    ${actual}    ${ruleId}    Add Rule Direct Five Tuple    &{kwargs}
```
绕过 `.ini` 文件，直接使用 kwargs 字典调用 `RcpApi.addRule_FiveTuple()` 下发五元组规则。kwargs 由 `RuleImport.Build Five Tuple Rule Kwargs` 构建。

### CIDR 数据加载与规则构建 — `RuleImport.py`

独立工具模块，不依赖 `.ini` 文件。提供 Robot Framework 可调用的关键字。常用于导入文件中大量ip。

#### `Load Cidrs From File`
```
${cidrs}    Load Cidrs From File    ${filepath}    ${sample_size}=${None}
```
从 CIDR 文件（每行一条 `x.x.x.x/mask`）读取所有行，跳过空行和 `#` 注释。`${sample_size}=${None}` 加载全部，传数字则只取前 N 条。

#### `Build Combined Rule Kwargs`
```
&{kwargs}    Build Combined Rule Kwargs    ${cidr_list}    v4|v6    **overrides
```
构建 `addRule`（组合规则）所需的 kwargs 字典。sipg 和 dipg 使用相同的 `${cidr_list}` 全部条目。每个 CIDR 转为 `[cidr, 0, 0, 0, 0]`（端口 0、协议 0、协议掩码 0）。可传入额外 overrides 覆盖默认值。

#### `Build Five Tuple Rule Kwargs`
```
&{kwargs}    Build Five Tuple Rule Kwargs    ${sip_list}    ${dip_list}    v4|v6    **overrides
```
构建 `addRule_FiveTuple`（五元组规则）所需的 kwargs 字典。关键行为：**sipg 和 dipg 条目数必须一致**。若 `${sip_list}` 为空，自动用与 `${dip_list}` 等量的 `0.0.0.0/0`（v4）或 `::/0`（v6）填充；反之亦然。可传入额外 overrides 覆盖默认值。

#### `setSystemTime` — `Ddevice.txt`
```
setSystemTime    ${targetTime}
```
通过 Telnet 下发 `systemtime ${targetTime}` 修改设备时间。使用前必须先 `New Connection Custom`。

#### `queryRcpLimit` — `Ddevice.txt`
```
${totalPass}    ${periodPass}    queryRcpLimit    ${ruleId}    ${title}    ${cliType}
```
查询 RCP 规则的放行量统计，返回 `${totalPass}`（总放行量，hex → int）和 `${periodPass}`（周期放行量）。内部通过 `queryRuleNew`/`queryRuleNew_fivetuple`/`queryRulenew_L2` 获取原始响应，截取 `[-96:-80]`（总量）和 `[-80:-64]`（周期量）并转换。
#### `showSession`
```
${statis_list}    showSession
```
查询 `show flow_table | include flowtable`，返回 `[current, remain]` 会话数。
#### `checkNumOrTimeResult`
```
${exactTime}    ${exactNum}    ${firstPacketUnixTime}    checkNumOrTimeResult    ${pcapFile}    ${expectNum}    ${expectTime}    ${speed}    ${numOrTime}=1    ${wuCha}=3
```
解析抓包文件，校验流量大小（`numOrTime=1`）或时长（`numOrTime=0`）是否符合预期。`${wuCha}` 为允许误差（默认 3s）。
#### `sendMultiCommand`
```
sendMultiCommand    ${command}    ${resultFlag}=0
```
按逗号分割 `${command}` 字符串，逐条通过 Telnet 下发。`resultFlag=0` 检查无 ERROR，`resultFlag=1` 检查有 ERROR。
#### `parserExcelToRcp`
```
${sipG}    ${dipG}    parserExcelToRcp    ${cliAcl}
```
按分号分割 CLI ACL 规则字符串，提取源/目的 IP 五元组列表（RCP 格式）。
#### `get_zxflow_pkts_bytes`
```
${pos_bytes}    ${pos_pkts}    ${rev_bytes}    ${rev_pkts}    get_zxflow_pkts_bytes    ${pcaptitle}    ${tx}
```
从 tx 数据中提取正向/反向 ZX flow 的字节和包数。
#### `netFlowCheck` / `netFlowCheckSingal`
```
netFlowCheck    ${expectResult}    ${exactResult}    ${netFlowType}    ${pktIndex}
```
校验 netFlow 流统计字段（协议、版本、上下行、字节/包计数等）是否符合预期。
#### `check_history_alarm_time`
```
check_history_alarm_time    ${command}
```
查询告警历史，解析时间戳，断言每个告警的 starttime ≤ endtime。

### TC500 设备统计 — `TC500.txt`
#### `statistics`
```
${pkt_list}    ${byte_list}    ${total_pkt}    ${total_byte}    statistics    ${group}    ${x}
```
遍历端口组，查询 `show statistics interface`，汇总包数和字节数。`${x}=1` 为入口组（rx），`${x}=9` 为出口组（tx）。
#### `statistics_mtu`
与 `statistics` 相同，但包数统计中包含 MTU-exceeded 计数（索引 `x+6`）。
#### `netflowDisable`
执行 `netflow disable` 并断言 `show netflow` 状态为 `disable`。

### 默认参数初始化 — `Resource/Business/__init__.robot`
#### `indirect_copy_not_specified` / `direct_copy`
无参数，返回 12 个默认配置变量（device_id, server_out_flag, server7-0_aclgroupid, inport_direct, inportid），用于非直连/直连复制模式。

## Excel 数据驱动测试

### 文件格式约束
- 只支持 `.xls` 格式（xlrd/xlwt/xlutils），**不要用 openpyxl**
- `rule_bj.xls` 是主配置文件，位于 `Resource/Business/rule_pcap/`
- `interface.xls` 是副配置文件，位于 `Resource/Business/rule_pcap/`
- 新增 sheet 时用 `xlutils.copy` 复制现有 workbook，然后 `wb.add_sheet()`


### Excel 列结构示例（参考 `01_Total_Num.robot`）
- 典型列：A=rulePre, B=app_id, C=pcapfile, D=backPcapfile, E=saveName, F=speed, G=durationTime, H=expectNum
- 行 1 为表头，数据从行 2 开始
- 使用 `read cell data by name ${sheetName} A${row}` 读取单元格

## 规则格式约定

### CLI 规则下发
- Forward 规则：`acl stage3_f ipmode ipv4 <match> action forward outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true priority ${priority}`
- **Block 规则不含 `outgroup_f`**：`acl stage3_f ipmode ipv4 <match> action block app_id ${appId} hit_statistics true priority ${priority}`
- 删除规则：`undo acl stage3_f app_id ${app_id}`

### 规则数据来源
- Excel `rule_pri` sheet 中的 `rulePre` 列只含匹配条件部分（`acl stage3_f ipmode ipv4 src_ip x.x.x.x/mask ...`）
- `ruleSuf`（action/outgroup/app_id/hit_statistics/priority）在测试脚本中动态拼接，不在 Excel 中硬编码

## Robot Framework 语法注意事项

- **废弃语法**：`[Return]` 设置已废弃，使用 `RETURN` 语句替代
- **废弃语法**：section header 必须用复数形式 `*** Keywords ***`，不能写 `*** Keyword ***`
- `FOR ${row} IN RANGE 2 ${end}` 中 end 值**不包含**（类似 Python range），如 RANGE 2 34 执行行 2-33
- **`--dryrun` 在本仓库不可用**：RF 7.2.2 的 dry run 遇到 `Run Keyword If    <条件>    <用户关键字>`（该关键字内部再有 `Run Keyword If`，如 `OpenConnectionAndLogin`）会递归检测失效、无限递归，单核 100% CPU 卡数十分钟后以 0xC0000005 崩溃。与具体用例无关，未改动的用例同样触发，因此**不能**拿它做语法校验。改为用 RF 解析 API 查语法错误（`robot.parsing.get_model(path, data_only=True, curdir=...)` + `ModelVisitor` 覆写 `visit_Error`），或直接跑单条用例。
