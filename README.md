# Hyper-v_Host_to_Guest_Check

Hyper-V Host <-> Windows Guest 健康检查脚本（支持交互式弹窗输入 / 非交互参数输入），输出 CSV 报告，并同时生成 HTML 报告文件。

> 脚本文件：`hyperv_checks_fixed.ps1`  
> 逻辑评审：`LOGIC_REVIEW.md`

---

## 功能概览

### Host 侧（Hyper-V Host）检查
- VM 是否存在 / 运行状态
- Integration Services 状态（全量枚举）
- VM 网卡：vSwitch 连接情况
- VM 网卡：VLAN（Access / Trunk / Untagged）采集与预期对比（可选）
- VM 网卡：IP 采集（过滤 IPv6 Link-Local、APIPA 等）
- Host -> Guest 连通性：
  - ICMP Ping
  - TCP 端口探测（默认 3389/RDP、5985/WinRM，可自定义）

### Guest 侧（Windows Guest，PowerShell Direct）
（需启用 `-IncludeGuestChecks` 并提供 Guest 管理员凭据）
- Windows 防火墙 Profile 是否启用
- Guest IPv4 配置是否正常（过滤 APIPA/Loopback）
- 默认网关是否存在（默认路由）
- DNS 相关检查（可调“失败算 WARN 还是 FAIL”）

脚本会把所有检查结果汇总输出到 CSV，并生成同名 HTML 报告。  
（HTML 输出路径默认由 CSV 路径改后缀得到）

---

## 运行条件

- Windows PowerShell（建议 5.1+）
- 运行机器需要能访问/管理 Hyper-V Host（远程 WinRM）
- Hyper-V Host 上需具备 Hyper-V 管理组件/命令（如 `Get-VM` / `Get-VMNetworkAdapter` 等）
- 若启用 Guest 检查：需要 PowerShell Direct 可用（Host 与 Guest 的条件满足），并提供 Guest 管理员凭据

> 建议“以管理员身份运行”。脚本也会在开始前做一次 WinRM 预检查（`Test-WSMan`），失败会直接退出。

---

## 快速开始（交互式弹窗）

双击/右键运行（或 PowerShell 里执行）：

```powershell
.\hyperv_checks_fixed.ps1
脚本会弹窗依次询问：

Hyper-V Host（留空默认本机）

VM 名称（逗号分隔）

保存 CSV 路径（同时生成 HTML）

如需 Guest 深度检查：

powershell
Copy code
.\hyperv_checks_fixed.ps1 -IncludeGuestChecks
会额外弹出凭据输入（Guest Admin）。

自动化运行（NonInteractive）
适用于计划任务/无人值守环境（不弹窗）。必须提供必要参数：

powershell
Copy code
$guest = Get-Credential
.\hyperv_checks_fixed.ps1 `
  -NonInteractive `
  -HyperVHost "HV01" `
  -VMName "VM01","VM02" `
  -CsvPath "C:\Temp\HyperV_Check_$(Get-Date -Format yyyyMMdd_HHmm).csv" `
  -IncludeGuestChecks `
  -GuestCredential $guest
参数说明（常用）
-HyperVHost <string>
Hyper-V Host 主机名（留空可默认 localhost/本机）

-VMName <string[]>
目标 VM 名称数组（交互模式可逗号输入）

-Ports <int[]>
Host -> Guest TCP 端口探测列表（默认 3389,5985）

-PingCount <int>
Ping 次数（默认 1）

-TcpTimeoutMs <int>
TCP 连接超时（默认 1000ms）

-IncludeGuestChecks
启用 Guest 内部检查（PowerShell Direct）

-GuestCredential <pscredential>
Guest 管理员凭据（启用 Guest 检查时需要）

-HostCredential <pscredential>
连接 Hyper-V Host 的凭据（可选）

-CsvPath <string>
输出 CSV 路径（非交互必填）

-HtmlPath <string>
输出 HTML 路径（可选；默认由 CsvPath 改后缀）

-ExpectedAccessVlanId <int>
如果 VM 网卡是 Access VLAN，可指定期望 VLAN ID，不匹配则 FAIL

-ExpectedTrunkAllowedVlanList <string>
如果 VM 网卡是 Trunk，可指定期望 Allowed VLAN 列表（逗号字符串），不匹配则 FAIL

-DnsFailureAsFail / -DnsTestName <string>
DNS 检查的严重级别与测试名称（用于更贴合生产标准）

输出示例（CSV 字段）
每一行代表一个检查项：

Target：Host / Guest

VM：VM 名称

Check：检查项名称（如 VM:State、NIC:xxx:VLAN、Ping:1.2.3.4、Port:1.2.3.4:3389）

Status：OK / WARN / FAIL

Detail：详细信息（错误原因、当前值/期望值等）

常见问题
1) “WinRM precheck failed …”
说明脚本连不上 Hyper-V Host 的 WinRM（默认 5985）。
请检查：WinRM 服务、防火墙、网络可达性、凭据、以及远程管理策略。

2) Guest 检查失败
Guest 检查依赖 PowerShell Direct（从 Host 直接进 Guest）。
如果你是跨主机/二跳/委派场景，可能会失败；建议先只跑 Host 侧检查确认基础连通。
（更多风险点见 LOGIC_REVIEW.md）

逻辑评审与改进建议
仓库提供了 LOGIC_REVIEW.md，里面列了已发现的逻辑风险与建议补充检查项（例如端口检查可追踪性、VLAN 判定、DNS 严重级别、二跳依赖、非交互适配等）。
欢迎直接按评审清单继续迭代。

