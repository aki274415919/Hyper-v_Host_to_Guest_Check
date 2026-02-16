<#
.SYNOPSIS
  Hyper-V Host <-> Windows Guest health checks with CSV export + popup inputs.
  (Optimized Version: Added VLAN, Firewall, and Robust DNS checks)

.DESCRIPTION
  - Prompts for Hyper-V Host name and VM names via popup dialogs.
  - Runs host-side checks (State, Switch, VLAN, IP, Ping).
  - Runs guest-internal checks via PowerShell Direct (NetAdapter, DNS, Firewall, Services).
  - Exports results to a CSV file.

.NOTES
  Run as Administrator on a machine with RSAT-Hyper-V tools.
#>

[CmdletBinding()]
param(
    [string]$HyperVHost,
    [string[]]$VMName,
    [int[]]$Ports = @(3389, 5985), # RDP, WinRM
    [switch]$IncludeGuestChecks,
    [pscredential]$GuestCredential,
    [pscredential]$HostCredential,
    [string]$CsvPath,
    [string]$HtmlPath,
    [int]$PingCount = 1,
    [int]$TcpTimeoutMs = 1000,
    [switch]$DnsFailureAsFail,
    [switch]$NonInteractive,
    [int]$ExpectedAccessVlanId
)

# ---------- UI Helpers (Popup) ----------
function Show-InputBox {
    param([string]$Title, [string]$Prompt, [string]$Default = "")
    Add-Type -AssemblyName Microsoft.VisualBasic | Out-Null
    return [Microsoft.VisualBasic.Interaction]::InputBox($Prompt, $Title, $Default)
}

function Show-SaveFileDialog {
    param([string]$Title = "Save CSV", [string]$DefaultFileName = "HyperV-Report.csv")
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Title = $Title
    $dlg.Filter = "CSV files (*.csv)|*.csv"
    $dlg.FileName = $DefaultFileName
    $dlg.OverwritePrompt = $true
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.FileName }
    return $null
}

# ---------- Input Logic ----------
# 1. Ask for Hyper-V Host
if (-not $HyperVHost) {
    if ($NonInteractive) { Write-Error "-HyperVHost is required when -NonInteractive is used."; exit 1 }
    $HyperVHost = Show-InputBox -Title "Hyper-V Host" -Prompt "Enter Hostname (Keep empty for Localhost):" -Default $env:COMPUTERNAME
    if (-not $HyperVHost) { $HyperVHost = "localhost" }
}

# 2. Ask for VM Names
if (-not $VMName -or $VMName.Count -eq 0) {
    if ($NonInteractive) { Write-Error "-VMName is required when -NonInteractive is used."; exit 1 }
    $vmInput = Show-InputBox -Title "Target VMs" -Prompt "Enter VM names (comma separated):" -Default ""
    if (-not $vmInput) { Write-Error "No VM specified."; exit }
    $VMName = $vmInput.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

# 3. Ask for CSV Path
if (-not $CsvPath) {
    if ($NonInteractive) { Write-Error "-CsvPath is required when -NonInteractive is used."; exit 1 }
    $CsvPath = Show-SaveFileDialog -DefaultFileName ("HyperV_Check_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date))
    if (-not $CsvPath) { Write-Error "No CSV path selected."; exit }
}

if (-not $HtmlPath) {
    $HtmlPath = [System.IO.Path]::ChangeExtension($CsvPath, "html")
}

# 4. Ask for Guest Creds (Only if Deep Check is enabled)
if ($IncludeGuestChecks -and -not $GuestCredential) {
    if ($NonInteractive) { Write-Error "-GuestCredential is required when -NonInteractive is used with -IncludeGuestChecks."; exit 1 }
    $GuestCredential = Get-Credential -Message "Enter Admin Creds for Guest OS (PowerShell Direct)"
}

# ---------- Main Logic ----------
$now = Get-Date
$rowsOut = @()

Write-Host ">>> Starting Analysis on host: $HyperVHost..." -ForegroundColor Cyan

# Basic remoting precheck for clearer failure output
try {
    if ($HostCredential) {
        Test-WSMan -ComputerName $HyperVHost -Credential $HostCredential -ErrorAction Stop | Out-Null
    } else {
        Test-WSMan -ComputerName $HyperVHost -ErrorAction Stop | Out-Null
    }
} catch {
    Write-Error "WinRM precheck failed for host '$HyperVHost': $($_.Exception.Message)"
    exit 1
}

# --- PART 1: Host-Side Checks (Remote ScriptBlock) ---
$hostScript = {
    param($VMNames, $Ports, $PingCount, $TcpTimeoutMs, $ExpectedAccessVlanId)

    # Internal Helper: Get IPs ignoring IPv6 Link-Local
    function Get-CleanIPs {
        param($Adapter)
        if ($Adapter.IPAddresses) {
            return $Adapter.IPAddresses | Where-Object { $_ -notmatch '^fe80:' -and $_ -ne '0.0.0.0' }
        }
        return @()
    }

    $result = @()

    foreach ($name in $VMNames) {
        $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
        if (-not $vm) {
            $result += [pscustomobject]@{ VM=$name; Check="VM:Exists"; Status="FAIL"; Detail="VM not found." }
            continue
        }

        # A. VM State
        $result += [pscustomobject]@{ 
            VM=$vm.Name; Check="VM:State"; 
            Status=(if($vm.State -eq 'Running'){"OK"}else{"FAIL"}); 
            Detail="State: $($vm.State)" 
        }

        if ($vm.State -ne 'Running') { continue } # Skip rest if VM is off

        # B. Integration Services (expanded checks)
        foreach ($isName in @("Heartbeat", "Time Synchronization", "Key-Value Pair Exchange", "Backup (volume checkpoint)")) {
            $is = Get-VMIntegrationService -VMName $vm.Name -Name $isName -ErrorAction SilentlyContinue
            if (-not $is) {
                $result += [pscustomobject]@{ VM=$vm.Name; Check="IS:$isName"; Status="WARN"; Detail="Integration service not found" }
                continue
            }

            $isStatus = if ($is.PrimaryStatusDescription -eq 'OK') { "OK" } else { "FAIL" }
            $result += [pscustomobject]@{
                VM=$vm.Name; Check="IS:$isName";
                Status=$isStatus;
                Detail="Enabled=$($is.Enabled); PrimaryStatus=$($is.PrimaryStatusDescription)"
            }
        }

        # C. Network Adapters (Switch, VLAN, IP)
        $adapters = Get-VMNetworkAdapter -VMName $vm.Name
        foreach ($a in $adapters) {
            # C1. Virtual Switch Connection
            $swStatus = if ($a.SwitchName) { "OK" } else { "FAIL" }
            $result += [pscustomobject]@{ VM=$vm.Name; Check="NIC:$($a.Name):Switch"; Status=$swStatus; Detail="Switch: $($a.SwitchName)" }

            # C2. VLAN Check (NEW FEATURE)
            $vlan = Get-VMNetworkAdapterVlan -VMNetworkAdapter $a
            $vlanStatus = "WARN"
            $vlanMsg = "Mode: $($vlan.OperationMode)"
            if ($vlan.OperationMode -eq "Access") {
                if ($vlan.AccessVlanId -gt 0) {
                    $vlanStatus = "OK"
                    $vlanMsg = "Access VLAN $($vlan.AccessVlanId)"

                    if ($ExpectedAccessVlanId -gt 0 -and $vlan.AccessVlanId -ne $ExpectedAccessVlanId) {
                        $vlanStatus = "FAIL"
                        $vlanMsg = "Access VLAN mismatch. Current=$($vlan.AccessVlanId); Expected=$ExpectedAccessVlanId"
                    }
                } else {
                    $vlanMsg = "Access mode with invalid VLAN ID: $($vlan.AccessVlanId)"
                }
            } elseif ($vlan.OperationMode -eq "Untagged") {
                $vlanMsg = "Untagged network"
            } elseif ($vlan.OperationMode -eq "Trunk") {
                $vlanMsg = "Trunk mode; Native VLAN: $($vlan.NativeVlanId); Allowed: $($vlan.AllowedVlanIdList)"
            }
            $result += [pscustomobject]@{ VM=$vm.Name; Check="NIC:$($a.Name):VLAN"; Status=$vlanStatus; Detail=$vlanMsg }

            # C3. IP Addresses
            $ips = Get-CleanIPs -Adapter $a
            $ipStatus = if ($ips.Count -gt 0) { "OK" } else { "WARN" }
            $result += [pscustomobject]@{ VM=$vm.Name; Check="NIC:$($a.Name):IP"; Status=$ipStatus; Detail=($ips -join ", ") }
            
            # C4. Ping & Port Test (Host -> Guest)
            if ($ips) {
                foreach ($ip in $ips) {
                    # Ping
                    if (Test-Connection -ComputerName $ip -Count $PingCount -Quiet) {
                        $result += [pscustomobject]@{ VM=$vm.Name; Check="Ping:$ip"; Status="OK"; Detail="Ping Reply Received" }
                    } else {
                        $result += [pscustomobject]@{ VM=$vm.Name; Check="Ping:$ip"; Status="FAIL"; Detail="No ICMP reply (possible firewall/routing/ACL issue)" }
                    }
                    
                    # Port Check (e.g. 3389)
foreach ($p in $Ports) {
    $sock = $null
    try {
        $sock = New-Object System.Net.Sockets.TcpClient
        # ConnectAsync + Wait avoids false "open" results from BeginConnect/WaitOne
        $task = $sock.ConnectAsync($ip, $p)
        if ($task.Wait($TcpTimeoutMs) -and $sock.Connected) {
            $result += [pscustomobject]@{ VM=$vm.Name; Check=("Port:{0}:{1}" -f $ip, $p); Status="OK"; Detail="Port Open" }
        } else {
            $result += [pscustomobject]@{ VM=$vm.Name; Check=("Port:{0}:{1}" -f $ip, $p); Status="WARN"; Detail="Port Closed/Filtered/Timeout" }
        }
    } catch {
        $result += [pscustomobject]@{ VM=$vm.Name; Check=("Port:{0}:{1}" -f $ip, $p); Status="WARN"; Detail="Connect Error: $($_.Exception.Message)" }
    } finally {
        if ($sock) { $sock.Close(); $sock.Dispose() }
    }
}
}
            }
        }
    }
    return $result
}

# Run Host Checks
$hostInvokeArgs = @{ ComputerName = $HyperVHost; ScriptBlock = $hostScript; ArgumentList = @($VMName, $Ports, $PingCount, $TcpTimeoutMs, $ExpectedAccessVlanId); ErrorAction = 'Stop' }
if ($HostCredential) { $hostInvokeArgs.Credential = $HostCredential }

try {
    $hostResults = Invoke-Command @hostInvokeArgs
    foreach ($r in $hostResults) {
        $rowsOut += [pscustomobject]@{ Target="Host"; VM=$r.VM; Check=$r.Check; Status=$r.Status; Detail=$r.Detail }
    }
} catch {
    Write-Error "Failed to connect to Hyper-V Host. $($_.Exception.Message)"
    exit 1
}


# --- PART 2: Guest-Side Checks (PowerShell Direct) ---
if ($IncludeGuestChecks -and $GuestCredential) {
    Write-Host ">>> Starting Guest Internal Analysis..." -ForegroundColor Cyan
    
    $guestDriver = {
        param($VMNames, $Cred, $DnsFailureAsFail)
        
        $results = @()
        foreach ($vm in $VMNames) {
            # The script block to run INSIDE the Guest
            $innerScript = {
                $localRes = @()
                
                # G1. Firewall Profile (Better signal: "disabled" is the risky state)
$fwEnabled = Get-NetFirewallProfile | Where-Object Enabled -eq $true
if ($fwEnabled) {
    $localRes += [pscustomobject]@{ Check="Guest:Firewall"; Status="OK"; Detail="Enabled: $(($fwEnabled.Name -join ', '))" }
} else {
    $localRes += [pscustomobject]@{ Check="Guest:Firewall"; Status="WARN"; Detail="All Profiles OFF (Security Risk)" }
}

# G2. IP Config (avoid false OK like APIPA 169.254.x.x)
$ipv4 = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -and
        $_.IPAddress -notlike '169.254.*' -and
        $_.IPAddress -ne '127.0.0.1' -and
        $_.InterfaceOperationalStatus -eq 'Up'
    }

if ($ipv4) {
    $localRes += [pscustomobject]@{ Check="Guest:IPConfig"; Status="OK"; Detail="IPv4: $(($ipv4.IPAddress -join ', '))" }
} else {
    $localRes += [pscustomobject]@{ Check="Guest:IPConfig"; Status="FAIL"; Detail="No usable IPv4 (or interface Down)" }
}

# G3. Gateway (prefer default route)
$defRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
    Sort-Object -Property RouteMetric, InterfaceMetric |
    Select-Object -First 1

if ($defRoute) {
    $localRes += [pscustomobject]@{ Check="Guest:Gateway"; Status="OK"; Detail="GW: $($defRoute.NextHop)" }
} else {
    $localRes += [pscustomobject]@{ Check="Guest:Gateway"; Status="WARN"; Detail="No IPv4 default gateway" }
}

# G4. DNS Resolution (no hardcoded internet dependency)
$dnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
    Where-Object { $_ -and $_ -ne '0.0.0.0' } | Select-Object -Unique

# Pick a "safe" name to resolve (prefer internal domain if available)
$testNames = @()
if ($env:USERDNSDOMAIN) { $testNames += $env:USERDNSDOMAIN }
if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { $testNames += $env:USERDOMAIN }
if (-not $testNames) { $testNames += $env:COMPUTERNAME }

$dnsOk = $false
$dnsDetail = @()

if (-not $dnsServers) {
    $localRes += [pscustomobject]@{ Check="Guest:DNS"; Status="FAIL"; Detail="No DNS servers configured" }
} else {
    foreach ($server in $dnsServers) {
        $serverReach = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
        foreach ($name in $testNames) {
            try {
                # -Server makes sure we are testing the configured DNS, not random upstream behavior
                Resolve-DnsName -Name $name -Server $server -QuickTimeout -ErrorAction Stop | Out-Null
                $dnsOk = $true
                $dnsDetail += "$server OK ($name)"
                break
            } catch {
                $dnsDetail += "$server FAIL ($name)"
            }
        }
        if ($dnsOk) { break }
        if (-not $serverReach) { $dnsDetail += "$server unreachable (ICMP)" }
    }

    if ($dnsOk) {
        $localRes += [pscustomobject]@{ Check="Guest:DNS"; Status="OK"; Detail=($dnsDetail -join '; ') }
    } else {
        # Fallback: confirm local DNS client service state (real fallback, not just a comment)
        $dnsSvc = Get-Service -Name "Dnscache" -ErrorAction SilentlyContinue
        $svcMsg = if ($dnsSvc) { "Dnscache=$($dnsSvc.Status)" } else { "Dnscache=Unknown" }
        $dnsStatus = if ($DnsFailureAsFail) { "FAIL" } else { "WARN" }
        $localRes += [pscustomobject]@{ Check="Guest:DNS"; Status=$dnsStatus; Detail="Resolution failed. $svcMsg. Details: $($dnsDetail -join '; ')" }
    }
}

# G5. Key Services

                foreach ($s in @("WinRM", "TermService", "LanmanServer")) {
                    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
                    if (-not $svc) {
                        $localRes += [pscustomobject]@{ Check="Guest:Service:$s"; Status="FAIL"; Detail="Service not found" }
                        continue
                    }

                    $st = if ($svc.Status -eq 'Running') { "OK" } else { "WARN" }
                    $localRes += [pscustomobject]@{ Check="Guest:Service:$s"; Status=$st; Detail="State: $($svc.Status); StartType: $($svc.StartType)" }
                }

                return $localRes
            } # End Inner Script

            try {
                # Invoke via PowerShell Direct (VMName parameter implies VMBus)
                $guestData = Invoke-Command -VMName $vm -Credential $Cred -ScriptBlock $innerScript -ErrorAction Stop
                foreach ($g in $guestData) {
                    $results += [pscustomobject]@{ VM=$vm; Check=$g.Check; Status=$g.Status; Detail=$g.Detail }
                }
            } catch {
                $results += [pscustomobject]@{ VM=$vm; Check="Guest:Connection"; Status="FAIL"; Detail="PSDirect Failed: $($_.Exception.Message)" }
            }
        }
        return $results
    }

    # Run the driver on the Host (Host triggers PSDirect to Guests)
    $guestInvokeArgs = @{ ComputerName = $HyperVHost; ScriptBlock = $guestDriver; ArgumentList = @($VMName, $GuestCredential, $DnsFailureAsFail) }
    if ($HostCredential) { $guestInvokeArgs.Credential = $HostCredential }
    $guestResults = Invoke-Command @guestInvokeArgs
    foreach ($r in $guestResults) {
        $rowsOut += [pscustomobject]@{ Target="Guest"; VM=$r.VM; Check=$r.Check; Status=$r.Status; Detail=$r.Detail }
    }
}

# ---------- Export ----------
$exportRows = $rowsOut | Select-Object Target, VM, Check, Status, Detail
$exportRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

$htmlHead = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #d0d7de; padding: 8px; text-align: left; }
th { background: #f6f8fa; }
.OK { color: #1a7f37; font-weight: 600; }
.WARN { color: #9a6700; font-weight: 600; }
.FAIL { color: #cf222e; font-weight: 700; }
</style>
"@

$htmlRows = foreach ($row in $exportRows) {
    [pscustomobject]@{
        Target = $row.Target
        VM = $row.VM
        Check = $row.Check
        Status = "<span class='$($row.Status)'>$($row.Status)</span>"
        Detail = $row.Detail
    }
}

$htmlTitle = "Hyper-V Host/Guest Diagnostics - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$htmlRows | ConvertTo-Html -Title $htmlTitle -Head $htmlHead | Out-File -FilePath $HtmlPath -Encoding UTF8

Write-Host "`n>>> Report Saved (CSV): $CsvPath" -ForegroundColor Green
Write-Host ">>> Report Saved (HTML): $HtmlPath" -ForegroundColor Green
