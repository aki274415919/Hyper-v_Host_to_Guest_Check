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
    [string]$DnsTestName,
    [switch]$NonInteractive,
    [int]$ExpectedAccessVlanId,
    [string]$ExpectedTrunkAllowedVlanList
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

if (-not $HostCredential -and -not $NonInteractive -and $HyperVHost -ne "localhost" -and $HyperVHost -ne "." -and $HyperVHost -ne $env:COMPUTERNAME) {
    $HostCredential = Get-Credential -Message "Optional: Enter credential for Hyper-V Host remoting (Cancel to use current user)"
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
    param($VMNames, $Ports, $PingCount, $TcpTimeoutMs, $ExpectedAccessVlanId, $ExpectedTrunkAllowedVlanList)

    # Internal Helper: Get IPs ignoring IPv6 Link-Local
    function Get-CleanIPs {
        param($Adapter)
        if ($Adapter.IPAddresses) {
            return $Adapter.IPAddresses | Where-Object { $_ -notmatch '^fe80:' -and $_ -ne '0.0.0.0' -and $_ -notlike '169.254.*' }
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
        $stateStatus = if ($vm.State -eq 'Running') { "OK" } else { "FAIL" }
        $result += [pscustomobject]@{
            VM = $vm.Name
            Check = "VM:State"
            Status = $stateStatus
            Detail = "State: $($vm.State)"
        }

        if ($vm.State -ne 'Running') { continue } # Skip rest if VM is off

        # B. Integration Services (use full list to avoid name mismatches across versions)
        $allIS = Get-VMIntegrationService -VMName $vm.Name -ErrorAction SilentlyContinue
        if (-not $allIS) {
            $result += [pscustomobject]@{ VM=$vm.Name; Check="IS:All"; Status="WARN"; Detail="No integration service data returned" }
        } else {
            foreach ($is in $allIS) {
                $isStatus = if ($is.Enabled -and $is.PrimaryStatusDescription -eq 'OK') { "OK" } else { "WARN" }
                $result += [pscustomobject]@{
                    VM = $vm.Name
                    Check = ("IS:{0}" -f $is.Name)
                    Status = $isStatus
                    Detail = "Enabled=$($is.Enabled); PrimaryStatus=$($is.PrimaryStatusDescription)"
                }
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
                $vlanStatus = "OK"
                $vlanMsg = "Trunk mode; Native VLAN: $($vlan.NativeVlanId); Allowed: $($vlan.AllowedVlanIdList)"
                if ($ExpectedTrunkAllowedVlanList) {
                    $actualAllowed = @($vlan.AllowedVlanIdList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { [int]$_ } | Sort-Object -Unique)
                    $expectedAllowed = @($ExpectedTrunkAllowedVlanList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { [int]$_ } | Sort-Object -Unique)
                    $diff = Compare-Object -ReferenceObject $actualAllowed -DifferenceObject $expectedAllowed
                    if ($diff) {
                        $vlanStatus = "FAIL"
                        $vlanMsg = "Trunk allowed VLAN mismatch. Current=$($actualAllowed -join ','); Expected=$($expectedAllowed -join ',')"
                    }
                }
            }
            $result += [pscustomobject]@{ VM=$vm.Name; Check="NIC:$($a.Name):VLAN"; Status=$vlanStatus; Detail=$vlanMsg }

            # C3. IP Addresses
            $ips = Get-CleanIPs -Adapter $a
            $ipStatus = if ($ips.Count -gt 0) { "OK" } else { "WARN" }
            $ipDetail = if ($ips.Count -gt 0) { ($ips -join ", ") } else { "No IP reported by Hyper-V (integration services may be missing)" }
            $result += [pscustomobject]@{ VM=$vm.Name; Check="NIC:$($a.Name):IP"; Status=$ipStatus; Detail=$ipDetail }
            
            # C4. Ping & Port Test (Host -> Guest)
            if ($ips) {
                foreach ($ip in $ips) {
                    # Ping
                    if (Test-Connection -ComputerName $ip -Count $PingCount -Quiet) {
                        $result += [pscustomobject]@{ VM=$vm.Name; Check=("Ping:{0}" -f $ip); Status="OK"; Detail="Ping Reply Received" }
                    } else {
                        $result += [pscustomobject]@{ VM=$vm.Name; Check=("Ping:{0}" -f $ip); Status="FAIL"; Detail="No ICMP reply (possible firewall/routing/ACL issue)" }
                    }
                    
                    # Port Check (e.g. 3389)
                    foreach ($p in $Ports) {
                        $sock = $null
                        try {
                            $sock = New-Object System.Net.Sockets.TcpClient
                            $task = $sock.ConnectAsync($ip, $p)
                            if ($task.Wait($TcpTimeoutMs) -and $sock.Connected) {
                                $result += [pscustomobject]@{ VM=$vm.Name; Check=("Port:{0}:{1}" -f $ip, $p); Status="OK"; Detail="Port Open" }
                            } elseif (-not $task.IsCompleted) {
                                $result += [pscustomobject]@{ VM=$vm.Name; Check=("Port:{0}:{1}" -f $ip, $p); Status="WARN"; Detail="Port Timeout (path/ACL/routing issue likely)" }
                            } else {
                                $result += [pscustomobject]@{ VM=$vm.Name; Check=("Port:{0}:{1}" -f $ip, $p); Status="WARN"; Detail="Port Closed/Filtered" }
                            }
                        } catch [System.Net.Sockets.SocketException] {
                            $socketCode = $_.Exception.SocketErrorCode
                            $socketDetail = if ($socketCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) {
                                "Connection Refused (target reachable, service/host firewall denied)"
                            } else {
                                "Socket Error: $socketCode"
                            }
                            $result += [pscustomobject]@{ VM=$vm.Name; Check=("Port:{0}:{1}" -f $ip, $p); Status="WARN"; Detail=$socketDetail }
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
$hostInvokeArgs = @{ ComputerName = $HyperVHost; ScriptBlock = $hostScript; ArgumentList = @($VMName, $Ports, $PingCount, $TcpTimeoutMs, $ExpectedAccessVlanId, $ExpectedTrunkAllowedVlanList); ErrorAction = 'Stop' }
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
        param($VMNames, $Cred, $DnsFailureAsFail, $DnsTestName)
        
        $results = @()
        foreach ($vm in $VMNames) {
            # The script block to run INSIDE the Guest
            $innerScript = {
                param($DnsFailureAsFail, $DnsTestName)
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

# Prefer FQDN targets; allow explicit override
$testNames = @()
if ($DnsTestName) { $testNames += $DnsTestName }
if ($env:USERDNSDOMAIN) {
    $testNames += $env:USERDNSDOMAIN
    $testNames += ("{0}.{1}" -f $env:COMPUTERNAME, $env:USERDNSDOMAIN)
}
$testNames += "localhost"
$testNames = $testNames | Where-Object { $_ } | Select-Object -Unique

$dnsOk = $false
$dnsDetail = @()

if (-not $dnsServers) {
    $localRes += [pscustomobject]@{ Check="Guest:DNS"; Status="FAIL"; Detail="No DNS servers configured" }
} else {
    foreach ($server in $dnsServers) {
        $dnsPortReach = Test-NetConnection -ComputerName $server -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue
        $dnsPortState = if ($dnsPortReach) { "TCP53=OK" } else { "TCP53=FAIL (may still work via UDP)" }

        foreach ($name in $testNames) {
            try {
                Resolve-DnsName -Name $name -Server $server -QuickTimeout -ErrorAction Stop | Out-Null
                $dnsOk = $true
                $dnsDetail += ("{0} {1}; DNS=OK ({2})" -f $server, $dnsPortState, $name)
                break
            } catch {
                $dnsDetail += ("{0} {1}; DNS=FAIL ({2})" -f $server, $dnsPortState, $name)
            }
        }

        if ($dnsOk) { break }
    }

    if ($dnsOk) {
        $localRes += [pscustomobject]@{ Check="Guest:DNS"; Status="OK"; Detail=($dnsDetail -join '; ') }
    } else {
        $dnsSvc = Get-Service -Name "Dnscache" -ErrorAction SilentlyContinue
        $svcMsg = if ($dnsSvc) { "Dnscache=$($dnsSvc.Status)" } else { "Dnscache=Unknown" }
        $dnsStatus = if ($DnsFailureAsFail) { "FAIL" } else { "WARN" }
        $localRes += [pscustomobject]@{ Check="Guest:DNS"; Status=$dnsStatus; Detail="Resolution failed. $svcMsg. Details: $($dnsDetail -join '; ')" }
    }
}

# G5. Firewall rules for remote access explainability
$rdpRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True -ErrorAction SilentlyContinue
$rdpRuleOk = $rdpRules -ne $null
$rdpStatus = if ($rdpRuleOk) { "OK" } else { "WARN" }
$rdpDetail = if ($rdpRuleOk) { "Enabled inbound Remote Desktop rules found" } else { "No enabled Remote Desktop firewall rules" }
$localRes += [pscustomobject]@{ Check="Guest:Firewall:RDP"; Status=$rdpStatus; Detail=$rdpDetail }

$winrmRules = Get-NetFirewallRule -DisplayName "*WINRM*" -Enabled True -ErrorAction SilentlyContinue
$winrmRuleOk = $winrmRules -ne $null
$winrmStatus = if ($winrmRuleOk) { "OK" } else { "WARN" }
$winrmDetail = if ($winrmRuleOk) { "Enabled WinRM firewall rules found" } else { "No enabled WinRM firewall rules" }
$localRes += [pscustomobject]@{ Check="Guest:Firewall:WinRM"; Status=$winrmStatus; Detail=$winrmDetail }

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
                $guestData = Invoke-Command -VMName $vm -Credential $Cred -ScriptBlock $innerScript -ArgumentList @($DnsFailureAsFail, $DnsTestName) -ErrorAction Stop
                foreach ($g in $guestData) {
                    $results += [pscustomobject]@{ VM=$vm; Check=$g.Check; Status=$g.Status; Detail=$g.Detail }
                }
            } catch {
                $results += [pscustomobject]@{ VM=$vm; Check="Guest:Connection"; Status="FAIL"; Detail="PSDirect Failed: $($_.Exception.Message). Hint: Run on Hyper-V host directly or ensure remote session is elevated with Hyper-V module; VM must be Running and guest credentials valid; host user must be authorized for the VM (e.g., Hyper-V Administrators)." }
            }
        }
        return $results
    }

    # Run the driver on the Host (Host triggers PSDirect to Guests)
    $guestInvokeArgs = @{ ComputerName = $HyperVHost; ScriptBlock = $guestDriver; ArgumentList = @($VMName, $GuestCredential, $DnsFailureAsFail, $DnsTestName) }
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
        Status = $row.Status
        Detail = $row.Detail
    }
}

$htmlTitle = "Hyper-V Host/Guest Diagnostics - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$htmlRows | ConvertTo-Html -Title $htmlTitle -Head $htmlHead | Out-File -FilePath $HtmlPath -Encoding UTF8

Write-Host "`n>>> Report Saved (CSV): $CsvPath" -ForegroundColor Green
Write-Host ">>> Report Saved (HTML): $HtmlPath" -ForegroundColor Green
