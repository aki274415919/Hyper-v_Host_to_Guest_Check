# Hyper-V Host to Guest 检查脚本逻辑评审

## 已发现的逻辑风险/问题

1. **端口检查结果可读性不足**  
   当前端口检查的 `Check` 字段仅为 `Port:<端口>`，没有包含目标 IP；当网卡有多个 IP 时，结果难以区分是哪一个 IP 的端口检查记录。

2. **VLAN 检查只采集，不判定风险**  
   VLAN 项固定输出 `Status="OK"`，即使 VLAN 配置异常或与预期不符也不会报错。

3. **Guest 服务检测未区分“服务不存在”**  
   `Get-Service` 失败时会被静默处理，但结果里没有明确标记服务不存在，排障信息不够完整。

4. **Guest DNS 失败的严重级别偏低**  
   在已配置 DNS 服务器但解析全部失败时，状态被标记为 `WARN`；在很多生产场景中应视为 `FAIL`。

5. **远程/二跳依赖未显式检查**  
   主流程依赖 `Invoke-Command -ComputerName` 到 Hyper-V Host，再在 Host 内执行 PSDirect。若 WinRM、委派策略或凭据传递受限，可能导致 Guest 检查失败，但前置条件未被独立检查。

6. **交互式输入限制自动化运行**  
   默认弹窗输入（InputBox/SaveFileDialog）对无人值守（CI、计划任务、Server Core）环境不友好。

## 建议补充的检查项

### Host 侧
- Hyper-V 主机 WinRM 可用性（5985/5986）
- VM 关键 Integration Services 全量状态（Heartbeat 之外：Time Sync、VSS、Data Exchange）
- VM 所在 vSwitch 的上联网卡状态/链路状态
- VM Checkpoint（快照）存在与否（长期快照可作为风险提示）
- 主机磁盘/CSV 可用空间（防止 VM 运行时存储不足）
- VM 复制（Hyper-V Replica）健康状态（如已启用）

### Guest 侧
- DNS 后缀和搜索列表合理性
- 默认路由对应网卡与 DNS 网卡一致性
- NTP/时间同步状态（域环境 Kerberos 强依赖）
- 必要端口监听状态（guest 内 `Get-NetTCPConnection -State Listen`）
- 关键系统服务启动类型（不是仅检查 Running）
- 网卡高级状态（重复 IP、错误网关、禁用网卡）

### 端到端/业务层
- 从 Host 到 Guest 的 WinRM/RDP 认证可达性（不仅 TCP 建连）
- 业务关键域名解析（内部服务 FQDN）
- 关键业务端口实际握手（可选 TLS/应用层探测）

## 结论
当前脚本已覆盖“基础存活 + 基础网络 + 基础 Guest 健康”三大类检查，但**对“配置正确性”和“生产可运维性”**的验证仍偏弱。建议先补齐“前置条件检查 + 结果可追踪性（IP 维度）+ 严重级别标准化（WARN/FAIL）”。
