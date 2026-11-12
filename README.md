# 1URFv4_BJ_NEW — 网络设备 ACL/转发自动化测试

基于 **Robot Framework** 的网络 ACL/转发硬件设备（Finslink/Hengming D 系列）自动化测试项目。
覆盖通过 CLI（Telnet）与 RCP（Rule Control Protocol）下发规则、TRex/tcpreplay 打流、
报文抓取/校验以及命中计数验证的完整闭环。

> ⚠️ 本仓库仅包含**代码、关键字库与配置数据**。
> 大体积抓包数据（`ripe_packets/` 约 18GB）与调试产物不入库，由本地路径或打流服务器存放。

## 目录结构

```
Function_Code/          # Robot Framework 测试套件（.robot 用例）
Resource/
  Business/
    variable.txt        # 全局共享变量（设备 IP、端口、账号、路径）
    rule_pcap/          # Excel 规则-报文映射（rule_bj.xls / interface.xls，.xls 格式）
    raw_packets/        # 本地 raw pcap（打流上传用，约 59MB，已入库）
    ripe_packets/       # 抓取报文（18GB，不入库）
    cidr_data/          # CIDR 列表数据
  Lib/
    rcpLib/             # RCP 客户端（TCP socket 规则增删改查）、makePcapFile、RuleImport
    parseLib/           # 报文解析/校验（pcap 分析）
    trexLib/            # TRex 打流封装
    support.py / config.py
  Public/
    initConfiguration.txt   # Telnet CLI 关键字
    sshKeywordSet.txt       # SSH 关键字
    instrument.txt          # 打流关键字（tcpreplay + tcpdump）
    Ddevice.txt             # D 设备专用关键字
    TC500.txt               # TC500 设备关键字
```

## 测试用例

| 文件 | 功能 | 标签 |
|------|------|------|
| `00_Device_Init.robot` | 设备初始化（端口 up、组配置、show version 基准） | `init` |
| `01_Total_Num.robot` | 按包数/字节数统计的配置生效、修改、告警验证 | `cli` |
| `02_Total_Time.robot` | 按时长统计的配置生效、修改、告警验证 | `cli` |
| `03 Tunnel_identify.robot` | 隧道识别与剥离 | — |
| `04 Rcp.robot` | RCP 全功能测试（规则 CRUD、五元组、VLAN、MPLS、优先级等） | `rcp`, `A` |
| `05_MR.robot` | 缺陷复现验证（MR#8789、MR#8791） | — |
| `06 MTU.robot` | 端口 MTU 遍历（64/9000/9400 字节） | — |
| `07_Priority.robot` | 规则优先级验证（48 条规则逐条删除） | `priority`, `cli` |
| `08_Ingroup.robot` | 入口组场景 | — |

标签：`init`（初始化，最先跑）、`rcp`、`cli`、`A`（仅 A 板）。

## 快速开始

### 环境准备

- Python 3.11+（系统路径示例 `E:\app\python\python.exe`）
- Robot Framework 及依赖：`SSHLibrary`、`Telnet`、`ExcelLibrary`、`RequestsLibrary`、`scapy`、`trex_stl_lib`
- Excel 数据文件只支持 `.xls` 格式（xlrd/xlwt/xlutils），**不支持 openpyxl**

```powershell
# 运行单个套件
& "E:\app\python\Scripts\robot.exe" Function_Code/07_Priority.robot

# 按用例名 / 标签运行
& "E:\app\python\Scripts\robot.exe" -t "forward" "Function_Code/04 Rcp.robot"
& "E:\app\python\Scripts\robot.exe" -i rcp Function_Code/

# ⚠️ 不要用 --dryrun 做语法校验（RF 7.2.2 dryrun 在本仓库会无限递归卡死），
# 改用 robot.parsing.get_model() 解析或直接跑单条用例。
```

### 配置你的环境

所有环境相关参数集中在 `Resource/Business/variable.txt`：
被测设备 IP / Telnet 端口（9999）、打流服务器 SSH（IP / 账号 / 密码）、
RCP 客户端 IP、pcap 存放路径等。首次使用请按你的实际环境修改。

## 测试流程模式

1. 打开 Excel 读取测试参数（规则配置、pcap 文件名、速率、时长）
2. 通过 CLI Telnet 或 RCP 向被测设备下发 ACL 规则
3. TRex/tcpreplay 通过设备打流（SSH 连接打流服务器）
4. 服务器 tcpdump 抓取输出报文并回传
5. 校验设备命中计数（`getAclHitstatistics` / `compareStastics`）与报文内容完整性

## 约定与注意事项

- 规则下发：Forward 规则带 `outgroup_f`，**Block 规则不含**；删除用 `undo acl stage3_f app_id ${app_id}`
- `--dryrun` 不可用（详见上文）；RF 语法用 `RETURN`，section 用复数 `*** Keywords ***`
- 重启类用例需排在 `00_Device_Init.robot` 之后（依赖 `${device_show_version_ref}` 基准）
- 避免在套件目录残留 GBK 编码的 `.txt` 日志（会导致 RIDE "invalid data file"）

## 相关文档

- `CLAUDE.md` — 完整的关键字参考手册（CLI/SSH/打流/统计/RCP API）
- `bjR3.docx` — 需求/规格文档
- `问题记录.txt` — 已知问题与排查记录
