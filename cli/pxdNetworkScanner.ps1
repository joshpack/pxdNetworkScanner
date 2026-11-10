#Requires -Version 5.1
<#
.SYNOPSIS
    pxd Network Scanner (CLI) - everything on your network, and what each device is, right in the console.

.DESCRIPTION
    The console edition of pxd Network Scanner. Nothing is installed and nothing on the PC is changed.
    Run it straight from the web:

        irm pxdtek.com/ns | iex

    (pxdtek.com serves the latest copy of
        https://raw.githubusercontent.com/joshpack/pxdNetworkScanner/main/cli/pxdNetworkScanner.ps1)

    It pings every address on the network, reads the ARP table (which also finds devices that ignore
    ping), then asks each device what it is: open ports, DNS / NetBIOS / Bonjour names, UPnP and SNMP
    descriptions and its web page title. The maker comes from the MAC address. Each device gets a type
    (PC, printer, phone, TV, router, NAS, camera, smart-home device...) with the reasons for the guess.
    Filter by type, show online devices only, search, open a device's details and save a report.

    Needs no administrator rights. The maker list (Wireshark's copy of the IEEE registry, about 3 MB)
    is downloaded into memory at each run; nothing is written to disk unless you export.

    With parameters through the web:
        & ([scriptblock]::Create((irm pxdtek.com/ns))) -Show Printers -List

.PARAMETER Range
    What to scan: 192.168.1.0/24, 192.168.1.1-254 or 172.16.0.20-172.16.0.80 (up to 4096 addresses).
    Default: the network of the adapter with the default gateway (its /24 when it's bigger).
.PARAMETER Show
    Which devices: All (default), Systems (computers and servers), Printers, Phones, Media, Network,
    SmartHome (smart home and cameras) or Unknown.
.PARAMETER List
    Non-interactive: scan, print the table and return.
.PARAMETER Export
    Scan and write a report to this path (.html, .csv, .json or .txt), then return.
.PARAMETER Quick
    Ping and ARP only: no ports, names or descriptions (much faster, much less detail).
#>
[CmdletBinding()]
param(
    [string]$Range,
    [ValidateSet('All', 'Systems', 'Printers', 'Phones', 'Media', 'Network', 'SmartHome', 'Unknown')][string]$Show = 'All',
    [switch]$List,
    [string]$Export,
    [switch]$Quick
)

$script:NsVersion = '1.0.0'
$script:NsUrl = 'pxdtek.com/ns'
# In-memory mode (set by the pxd Toolkit console while it runs this script): nothing is saved on the PC unless the
# user exports a report. The CLI keeps no settings, logs or caches anyway.
$script:NsInMemory = $env:PXD_INMEMORY -eq '1'
$script:NsDot = [string][char]0x25CF      # built at run time so the file stays ASCII (safe for irm | iex)
$script:NsEll = [string][char]0x2026
$script:NsDevices = New-Object System.Collections.Generic.List[object]   # everything seen this session
$script:NsVendors = $null
$script:NsVendorTask = $null
$script:NsError = ''

try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 } catch {}   # TLS 1.2 on PowerShell 5.1

# ======================================================================================
#  Ports, groups
# ======================================================================================

$script:NsPorts = [ordered]@{
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 53 = 'DNS'; 80 = 'Web'; 135 = 'Windows RPC'; 139 = 'NetBIOS'; 443 = 'Web (HTTPS)'
    445 = 'File sharing (SMB)'; 515 = 'LPD printing'; 548 = 'Apple file sharing'; 554 = 'Video stream (RTSP)'; 631 = 'IPP printing'
    1400 = 'Sonos'; 1883 = 'MQTT'; 3389 = 'Remote Desktop'; 5000 = 'Web (5000)'; 5001 = 'Web (5001)'; 5357 = 'Windows device discovery'
    5900 = 'VNC screen sharing'; 7000 = 'AirPlay'; 8006 = 'Proxmox'; 8008 = 'Google Cast / web'; 8009 = 'Google Cast'; 8060 = 'Roku'
    8080 = 'Web (8080)'; 8123 = 'Home Assistant'; 8443 = 'Web (8443)'; 9100 = 'Raw printing'; 32400 = 'Plex'; 62078 = 'iPhone / iPad sync'
}
$script:NsPortNames = @{}; foreach ($e in $script:NsPorts.GetEnumerator()) { $script:NsPortNames[[int]$e.Key] = $e.Value }   # a plain table: [int] on an ordered one means position
$script:NsWebPorts = @(80, 443, 5000, 5001, 8080, 8443, 8006, 8123)
function Test-NsHttps([int]$p) { $p -in @(443, 8443, 5001, 8006) }

$script:NsGroups = @(
    @{ Key = 'All'; Name = 'All devices'; Kinds = @() }
    @{ Key = 'Systems'; Name = 'Computers & servers'; Kinds = @('ThisPc', 'Computer', 'Server', 'VirtualMachine', 'Storage') }
    @{ Key = 'Printers'; Name = 'Printers'; Kinds = @('Printer') }
    @{ Key = 'Phones'; Name = 'Phones & tablets'; Kinds = @('Phone') }
    @{ Key = 'Media'; Name = 'TVs & media'; Kinds = @('Media', 'GameConsole') }
    @{ Key = 'Network'; Name = 'Network gear'; Kinds = @('Router', 'NetworkGear') }
    @{ Key = 'SmartHome'; Name = 'Smart home & cameras'; Kinds = @('SmartHome', 'Camera') }
    @{ Key = 'Unknown'; Name = 'Unknown'; Kinds = @('Unknown') }
)

$script:NsMdnsServices = @(
    '_services._dns-sd._udp', '_device-info._tcp', '_workstation._tcp', '_companion-link._tcp', '_rdlink._tcp', '_smb._tcp', '_afpovertcp._tcp',
    '_ipp._tcp', '_ipps._tcp', '_printer._tcp', '_pdl-datastream._tcp', '_uscan._tcp', '_scanner._tcp', '_airplay._tcp', '_raop._tcp',
    '_googlecast._tcp', '_spotify-connect._tcp', '_sonos._tcp', '_amzn-wplay._tcp', '_hap._tcp', '_homekit._tcp', '_matter._tcp', '_hue._tcp',
    '_esphomelib._tcp', '_home-assistant._tcp', '_apple-mobdev2._tcp', '_ssh._tcp', '_sftp-ssh._tcp', '_http._tcp', '_androidtvremote2._tcp',
    '_nvstream._tcp', '_daap._tcp', '_touch-able._tcp', '_rfb._tcp', '_adisk._tcp', '_sleep-proxy._udp', '_meshcop._udp', '_trel._udp'
)

# ======================================================================================
#  Addresses and ranges
# ======================================================================================

function ConvertTo-NsUint([Net.IPAddress]$ip) { $b = $ip.GetAddressBytes(); [uint32](([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3]) }
function ConvertFrom-NsUint([uint32]$v) { New-Object Net.IPAddress (, [byte[]]@((($v -shr 24) -band 255), (($v -shr 16) -band 255), (($v -shr 8) -band 255), ($v -band 255))) }

function Get-NsRangeText($r) {
    $span = [int64]$r.Last - [int64]$r.First + 1
    for ($bits = 30; $bits -ge 16; $bits--) {
        $size = [int64][math]::Pow(2, 32 - $bits)
        if ($span -eq $size - 2 -and (([int64]$r.First - 1) % $size) -eq 0) { return "$(ConvertFrom-NsUint ([uint32]($r.First - 1)))/$bits" }
    }
    if ($r.First -eq $r.Last) { return "$(ConvertFrom-NsUint $r.First)" }
    "$(ConvertFrom-NsUint $r.First) - $(ConvertFrom-NsUint $r.Last)"
}

function New-NsRange([uint32]$First, [uint32]$Last, $Local = $null) {
    $r = [pscustomobject]@{ First = $First; Last = $Last; LocalIp = $null; LocalMac = ''; Gateway = $null; Broadcast = $null; Adapter = ''; Text = '' }
    if ($Local) { $r.LocalIp = $Local.LocalIp; $r.LocalMac = $Local.LocalMac; $r.Gateway = $Local.Gateway; $r.Broadcast = $Local.Broadcast; $r.Adapter = $Local.Adapter }
    $r.Text = Get-NsRangeText $r
    $r
}

function Test-NsInRange($r, [string]$ip) {
    $a = $null
    if (-not [Net.IPAddress]::TryParse($ip, [ref]$a)) { return $false }
    $v = ConvertTo-NsUint $a
    $v -ge $r.First -and $v -le $r.Last
}

function Get-NsLocalRanges {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne 'Up' -or $nic.NetworkInterfaceType -in @('Loopback', 'Tunnel')) { continue }
        try { $props = $nic.GetIPProperties() } catch { continue }
        $gw = $props.GatewayAddresses | ForEach-Object { $_.Address } | Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.ToString() -ne '0.0.0.0' } | Select-Object -First 1
        foreach ($u in $props.UnicastAddresses) {
            if ($u.Address.AddressFamily -ne 'InterNetwork' -or [Net.IPAddress]::IsLoopback($u.Address)) { continue }
            $ip = ConvertTo-NsUint $u.Address
            if (($ip -shr 16) -eq 0xA9FE) { continue }
            $bits = [int]$u.PrefixLength; if ($bits -le 0 -or $bits -gt 32) { $bits = 24 }
            $hostSize = [int64][math]::Pow(2, 32 - $bits)
            $bc = [uint32]([int64]$ip - ([int64]$ip % $hostSize) + $hostSize - 1)
            if ($bits -lt 24) { $bits = 24 }
            if ($bits -ge 31) { continue }
            $sSize = [int64][math]::Pow(2, 32 - $bits)
            $net = [uint32]([int64]$ip - ([int64]$ip % $sSize))
            $last = [math]::Min([uint32]([int64]$net + $sSize - 1), $bc)
            $name = if ($nic.Name) { $nic.Name } else { $nic.Description }
            $local = [pscustomobject]@{ LocalIp = $u.Address; LocalMac = $nic.GetPhysicalAddress().ToString(); Gateway = $gw; Broadcast = (ConvertFrom-NsUint $bc); Adapter = $name }
            $r = New-NsRange ([uint32]($net + 1)) ([uint32]($last - 1)) $local
            $virtual = $name -match 'vEthernet|VirtualBox|VMware|WSL'
            $out.Add([pscustomobject]@{ R = $r; Gw = [bool]$gw; Virtual = $virtual; Speed = $nic.Speed })
        }
    }
    @($out | Sort-Object @{ e = { $_.Gw }; Descending = $true }, @{ e = { $_.Virtual } }, @{ e = { $_.Speed }; Descending = $true } | ForEach-Object { $_.R })
}

function ConvertTo-NsRange([string]$Text, $Locals) {
    $script:NsError = ''
    $t = $Text.Trim() -replace '\s', ''
    try {
        if ($t -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
            $bits = [int]$Matches[2]; if ($bits -lt 8 -or $bits -gt 32) { throw 'bits' }
            $ip = ConvertTo-NsUint ([Net.IPAddress]::Parse($Matches[1]))
            $size = [int64][math]::Pow(2, 32 - $bits)
            $net = [uint32]([int64]$ip - ([int64]$ip % $size)); $bc = [uint32]([int64]$net + $size - 1)
            if ($bits -ge 31) { $first = $net; $last = $bc } else { $first = [uint32]($net + 1); $last = [uint32]($bc - 1) }
        } elseif ($t -match '^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$') {
            $first = ConvertTo-NsUint ([Net.IPAddress]::Parse($Matches[1])); $last = ConvertTo-NsUint ([Net.IPAddress]::Parse($Matches[2]))
        } elseif ($t -match '^(\d+\.\d+\.\d+\.\d+)-(\d{1,3})$') {
            $first = ConvertTo-NsUint ([Net.IPAddress]::Parse($Matches[1])); $n = [uint32]$Matches[2]; if ($n -gt 255) { throw 'n' }
            $last = [uint32]([int64]$first - ([int64]$first % 256) + $n)
        } elseif ($t -match '^\d+\.\d+\.\d+\.\d+$') {
            $first = ConvertTo-NsUint ([Net.IPAddress]::Parse($t)); $last = $first
        } else { throw 'format' }
        if ($last -lt $first) { $x = $first; $first = $last; $last = $x }
        $count = [int64]$last - [int64]$first + 1
        if ($count -gt 4096) { $script:NsError = "That's $count addresses; up to 4096 can be scanned at once (a /20)."; return $null }
        $local = $Locals | Where-Object { $_.LocalIp -and ((ConvertTo-NsUint $_.LocalIp) -ge $first) -and ((ConvertTo-NsUint $_.LocalIp) -le $last) } | Select-Object -First 1
        if (-not $local) { $local = $Locals | Where-Object { $first -ge ($_.First - 1) -and $last -le ($_.Last + 1) } | Select-Object -First 1 }
        New-NsRange $first $last $local
    } catch {
        $script:NsError = 'Type a range like 192.168.1.0/24, 192.168.1.1-254 or 172.16.0.20-172.16.0.80.'
        $null
    }
}

# ======================================================================================
#  Waiting on many .NET tasks at once (no runspaces needed, works in 5.1 and 7)
# ======================================================================================

function Wait-NsTasks($tasks, [int]$TimeoutMs) {
    $arr = [Threading.Tasks.Task[]]@($tasks | Where-Object { $_ })
    if ($arr.Count -eq 0) { return }
    try { [void][Threading.Tasks.Task]::WaitAll($arr, $TimeoutMs) } catch {}
}

function Test-NsDone($task) { $task -and $task.Status -eq 'RanToCompletion' }

function Write-NsStatus([string]$text) {
    $w = 100; try { $w = [Math]::Max(40, $Host.UI.RawUI.WindowSize.Width - 2) } catch {}
    if ($text.Length -gt $w) { $text = $text.Substring(0, $w) }
    Write-Host ("`r" + $text.PadRight($w)) -NoNewline -ForegroundColor DarkCyan
}
function Clear-NsStatus { $w = 100; try { $w = [Math]::Max(40, $Host.UI.RawUI.WindowSize.Width - 2) } catch {}; Write-Host ("`r" + (' ' * $w) + "`r") -NoNewline }

# ======================================================================================
#  Probes
# ======================================================================================

function Invoke-NsPingSweep($addresses, [int]$TimeoutMs = 900) {
    $found = @{}
    $list = @($addresses | ForEach-Object { "$_" })
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $todo = @($list | Where-Object { -not $found.ContainsKey($_.ToString()) })
        for ($i = 0; $i -lt $todo.Count; $i += 256) {
            $chunk = $todo[$i..([Math]::Min($i + 255, $todo.Count - 1))]
            $jobs = foreach ($ip in $chunk) {
                $p = New-Object Net.NetworkInformation.Ping
                try { [pscustomobject]@{ Ip = "$ip"; P = $p; T = $p.SendPingAsync([Net.IPAddress]::Parse("$ip"), $TimeoutMs) } } catch { $p.Dispose() }
            }
            Wait-NsTasks ($jobs | ForEach-Object { $_.T }) ($TimeoutMs + 1500)
            foreach ($j in $jobs) {
                if ((Test-NsDone $j.T) -and $j.T.Result.Status -eq 'Success') {
                    $ttl = 0; if ($j.T.Result.Options) { $ttl = $j.T.Result.Options.Ttl }
                    $found[$j.Ip] = @{ Ms = [int64]$j.T.Result.RoundtripTime; Ttl = $ttl }
                }
                $j.P.Dispose()
            }
            Write-NsStatus "  Pinging: $([Math]::Min($i + 256, $todo.Count)) of $($todo.Count)$(if ($attempt -gt 0) { ' (second try)' })  -  $($found.Count) answered"
        }
    }
    $found
}

function Get-NsNeighbors {
    $map = @{}
    try {
        foreach ($n in (Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop)) {
            $mac = ([string]$n.LinkLayerAddress) -replace '[-:]', ''
            if ($mac.Length -ne 12 -or $mac -eq '000000000000' -or $mac -eq 'FFFFFFFFFFFF') { continue }
            if (([Convert]::ToByte($mac.Substring(0, 2), 16) -band 1) -eq 1) { continue }   # multicast
            $state = [string]$n.State
            $rank = switch ($state) { 'Permanent' { 6 } 'Reachable' { 5 } 'Stale' { 4 } 'Delay' { 3 } 'Probe' { 2 } default { 0 } }
            $ip = [string]$n.IPAddress
            if (-not $map.ContainsKey($ip) -or $map[$ip].Rank -lt $rank) { $map[$ip] = @{ Mac = $mac.ToUpperInvariant(); State = $state; Rank = $rank } }
        }
    } catch {
        # no NetTCPIP module (old Windows, or a restricted host): arp -a, without states
        foreach ($line in (arp -a 2>$null)) {
            if ($line -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(-[0-9a-f]{2}){5})\s+dynamic') {
                $mac = ($Matches[2] -replace '-', '').ToUpperInvariant()
                $map[$Matches[1]] = @{ Mac = $mac; State = 'Reachable'; Rank = 5 }
            }
        }
    }
    $map
}

function Get-NsOpenPorts($ips, [int]$TimeoutMs = 800) {
    $result = @{}
    $ports = @($script:NsPorts.Keys)
    $list = @($ips)
    for ($i = 0; $i -lt $list.Count; $i += 8) {
        $chunk = $list[$i..([Math]::Min($i + 7, $list.Count - 1))]
        $jobs = foreach ($ip in $chunk) {
            foreach ($port in $ports) {
                $c = New-Object Net.Sockets.TcpClient
                try { [pscustomobject]@{ Ip = $ip; Port = $port; C = $c; T = $c.ConnectAsync($ip, $port) } } catch { $c.Dispose() }
            }
        }
        Wait-NsTasks ($jobs | ForEach-Object { $_.T }) $TimeoutMs
        foreach ($j in $jobs) {
            if (-not $result.ContainsKey($j.Ip)) { $result[$j.Ip] = New-Object System.Collections.Generic.List[int] }
            if ((Test-NsDone $j.T) -and $j.C.Connected) { $result[$j.Ip].Add([int]$j.Port) }
            try { $j.C.Dispose() } catch {}
        }
        Write-NsStatus "  Checking ports: $([Math]::Min($i + 8, $list.Count)) of $($list.Count) devices"
    }
    $result
}

function Get-NsReverseDns($ips) {
    $jobs = foreach ($ip in $ips) { [pscustomobject]@{ Ip = $ip; T = [Net.Dns]::GetHostEntryAsync($ip) } }
    Wait-NsTasks ($jobs | ForEach-Object { $_.T }) 2500
    $out = @{}
    foreach ($j in $jobs) { if ((Test-NsDone $j.T) -and $j.T.Result.HostName -and $j.T.Result.HostName -ne $j.Ip) { $out[$j.Ip] = $j.T.Result.HostName.TrimEnd('.') } }
    $out
}

function Invoke-NsUdpSweep($ips, [int]$Port, [scriptblock]$Packet, [int]$ListenMs) {
    $got = @{}
    $u = $null
    try {
        $u = New-Object Net.Sockets.UdpClient 0
        try { [void]$u.Client.IOControl(-1744830452, [byte[]](0, 0, 0, 0), $null) } catch {}   # ignore "port unreachable"
        $id = 0x5000
        foreach ($ip in $ips) {
            $bytes = [byte[]](& $Packet $id); $id++
            try { [void]$u.Send($bytes, $bytes.Length, (New-Object Net.IPEndPoint ([Net.IPAddress]::Parse($ip)), $Port)) } catch {}
        }
        $until = [DateTime]::UtcNow.AddMilliseconds($ListenMs)
        while ([DateTime]::UtcNow -lt $until -and $got.Count -lt @($ips).Count) {
            if ($u.Client.Poll(100000, [Net.Sockets.SelectMode]::SelectRead)) {
                $ep = New-Object Net.IPEndPoint ([Net.IPAddress]::Any), 0
                try { $data = $u.Receive([ref]$ep); $k = $ep.Address.ToString(); if (-not $got.ContainsKey($k)) { $got[$k] = $data } } catch {}
            }
        }
    } catch {} finally { if ($u) { $u.Dispose() } }
    $got
}

function New-NsNetBiosQuery([int]$id) {
    $q = New-Object System.Collections.Generic.List[byte]
    $q.AddRange([byte[]]((($id -shr 8) -band 255), ($id -band 255), 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20))
    $name = New-Object byte[] 16; $name[0] = 42   # '*'
    foreach ($b in $name) { $q.Add([byte](65 + ($b -shr 4))); $q.Add([byte](65 + ($b -band 15))) }
    $q.AddRange([byte[]](0, 0, 0x21, 0, 1))
    , $q.ToArray()
}

function ConvertFrom-NsNetBios([byte[]]$d) {
    try {
        $i = 12
        while ($i -lt $d.Length -and $d[$i] -ne 0) { $i += $d[$i] + 1 }
        $i += 1 + 2 + 2 + 4 + 2
        $count = $d[$i]; $i++
        $name = ''; $group = ''
        for ($n = 0; $n -lt $count -and $i + 18 -le $d.Length; $n++) {
            $text = [Text.Encoding]::ASCII.GetString($d, $i, 15).TrimEnd(' ', [char]0)
            $suffix = $d[$i + 15]; $isGroup = ($d[$i + 16] -band 0x80) -ne 0
            if ($suffix -eq 0 -and -not $isGroup -and -not $name) { $name = $text }
            elseif ($suffix -eq 0 -and $isGroup -and -not $group) { $group = $text }
            $i += 18
        }
        @{ Name = $name; Group = $group }
    } catch { @{ Name = ''; Group = '' } }
}

$script:NsOidDescr = [byte[]](0x2B, 6, 1, 2, 1, 1, 1, 0)
$script:NsOidName = [byte[]](0x2B, 6, 1, 2, 1, 1, 5, 0)
$script:NsOidDevice = [byte[]](0x2B, 6, 1, 2, 1, 0x19, 3, 2, 1, 3, 1)

function New-NsTlv([byte]$Tag, [byte[]]$Body) {
    $l = New-Object System.Collections.Generic.List[byte]
    $l.Add($Tag)
    if ($Body.Length -lt 128) { $l.Add([byte]$Body.Length) } else { $l.Add(0x81); $l.Add([byte]$Body.Length) }
    $l.AddRange($Body)
    , $l.ToArray()
}

function New-NsSnmpQuery([int]$id) {
    $bind = { param($oid) New-NsTlv 0x30 ([byte[]]((New-NsTlv 0x06 $oid) + [byte[]](5, 0))) }
    $binds = [byte[]]((& $bind $script:NsOidDescr) + (& $bind $script:NsOidName) + (& $bind $script:NsOidDevice))
    $idb = [byte[]](0, (($id -shr 16) -band 255), (($id -shr 8) -band 255), ($id -band 255))
    $pdu = New-NsTlv 0xA0 ([byte[]]((New-NsTlv 0x02 $idb) + (New-NsTlv 0x02 ([byte[]](0))) + (New-NsTlv 0x02 ([byte[]](0))) + (New-NsTlv 0x30 $binds)))
    , (New-NsTlv 0x30 ([byte[]]((New-NsTlv 0x02 ([byte[]](1))) + (New-NsTlv 0x04 ([Text.Encoding]::ASCII.GetBytes('public'))) + $pdu)))
}

function ConvertFrom-NsSnmp([byte[]]$d) {
    $res = @{ Descr = ''; Name = ''; Device = '' }
    $readLen = { param([int]$at) $len = [int]$d[$at]; $at++; if ($len -band 0x80) { $n = $len -band 0x7F; $len = 0; for ($k = 0; $k -lt $n; $k++) { $len = ($len -shl 8) -bor $d[$at]; $at++ } }; @($len, $at) }
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@(0, $d.Length))
    try {
        while ($stack.Count -gt 0) {
            $span = $stack.Pop(); $i = $span[0]; $end = $span[1]
            while ($i -lt $end) {
                $tag = $d[$i]; $r = & $readLen ($i + 1); $len = $r[0]; $start = $r[1]
                if ($start + $len -gt $end) { break }
                if ($tag -eq 0x30 -and $len -gt 2 -and $d[$start] -eq 0x06) {
                    $olen = $d[$start + 1]; $oid = [byte[]]$d[($start + 2)..($start + 1 + $olen)]
                    $v = $start + 2 + $olen
                    if ($d[$v] -eq 0x04) {
                        $r2 = & $readLen ($v + 1); $vlen = $r2[0]; $vs = $r2[1]
                        $text = ([Text.Encoding]::UTF8.GetString($d, $vs, $vlen) -replace '\s+', ' ').Trim()
                        $hex = [BitConverter]::ToString($oid)
                        if ($hex -eq [BitConverter]::ToString($script:NsOidDescr)) { $res.Descr = $text }
                        elseif ($hex -eq [BitConverter]::ToString($script:NsOidName)) { $res.Name = $text }
                        elseif ($hex -eq [BitConverter]::ToString($script:NsOidDevice)) { $res.Device = $text }
                    }
                } elseif ($tag -in @(0x30, 0xA2, 0xA0)) { $stack.Push(@($start, $start + $len)) }
                $i = $start + $len
            }
        }
    } catch {}
    $res
}

# ---------- UPnP (SSDP) ----------

function New-NsAnnounced { [pscustomobject]@{ FriendlyName = ''; Manufacturer = ''; Model = ''; DeviceType = ''; Server = ''; Host = ''; Services = (New-Object System.Collections.Generic.HashSet[string]); Txt = @{}; OwnAddress = $false; Location = '' } }

function Invoke-NsSsdp($LocalIp, [int]$ListenMs = 3000) {
    $found = @{}
    $u = $null
    try {
        $bind = if ($LocalIp) { $LocalIp } else { [Net.IPAddress]::Any }
        $u = New-Object Net.Sockets.UdpClient (New-Object Net.IPEndPoint $bind, 0)
        $u.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::MulticastTimeToLive, 2)
        $target = New-Object Net.IPEndPoint ([Net.IPAddress]::Parse('239.255.255.250')), 1900
        foreach ($st in @('ssdp:all', 'upnp:rootdevice')) {
            $msg = [Text.Encoding]::ASCII.GetBytes("M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: $st`r`nUSER-AGENT: Windows/10 UPnP/1.1 pxdNetworkScanner/1.0`r`n`r`n")
            [void]$u.Send($msg, $msg.Length, $target)
        }
        $until = [DateTime]::UtcNow.AddMilliseconds($ListenMs)
        while ([DateTime]::UtcNow -lt $until) {
            if (-not $u.Client.Poll(100000, [Net.Sockets.SelectMode]::SelectRead)) { continue }
            $ep = New-Object Net.IPEndPoint ([Net.IPAddress]::Any), 0
            try { $data = $u.Receive([ref]$ep) } catch { continue }
            $ip = $ep.Address.ToString()
            if (-not $found.ContainsKey($ip)) { $found[$ip] = New-NsAnnounced }
            $a = $found[$ip]
            $h = @{}
            foreach ($line in ([Text.Encoding]::UTF8.GetString($data) -split "`r`n" | Select-Object -Skip 1)) { $c = $line.IndexOf(':'); if ($c -gt 0) { $k = $line.Substring(0, $c).Trim().ToUpperInvariant(); if (-not $h.ContainsKey($k)) { $h[$k] = $line.Substring($c + 1).Trim() } } }
            if ($h['SERVER'] -and -not $a.Server) { $a.Server = $h['SERVER'] }
            $uri = $null
            if ($h['LOCATION'] -and [Uri]::TryCreate($h['LOCATION'], 'Absolute', [ref]$uri) -and $uri.Host -eq $ip -and (-not $a.Location -or "$($h['ST'])" -match 'rootdevice')) { $a.Location = $h['LOCATION'] }
        }
    } catch {} finally { if ($u) { $u.Dispose() } }

    # Each device's own description (fetched from the device itself only)
    $http = New-NsHttp $false
    $jobs = foreach ($ip in @($found.Keys)) { if ($found[$ip].Location) { [pscustomobject]@{ Ip = $ip; T = $http.GetStringAsync($found[$ip].Location) } } }
    Wait-NsTasks ($jobs | ForEach-Object { $_.T }) 3500
    foreach ($j in $jobs) {
        if (-not (Test-NsDone $j.T)) { continue }
        try {
            [xml]$x = $j.T.Result
            $dev = $x.SelectSingleNode("//*[local-name()='device']")
            if (-not $dev) { continue }
            $get = { param($n) $e = $dev.SelectSingleNode("*[local-name()='$n']"); if ($e) { ($e.InnerText -replace '\s+', ' ').Trim() } else { '' } }
            $a = $found[$j.Ip]
            $a.FriendlyName = & $get 'friendlyName'; $a.Manufacturer = & $get 'manufacturer'
            $model = & $get 'modelName'; $num = & $get 'modelNumber'
            if ($num -and $model -notlike "*$num*" -and $num -notlike "*$model*" -and $num.Length -lt 24 -and $num -notmatch '^[\d.]+$') { $model = "$model $num".Trim() }
            $a.Model = $model
            $dt = (& $get 'deviceType') -split ':'; if ($dt.Count -ge 4) { $a.DeviceType = $dt[-2] }
        } catch {}
    }
    $http.Dispose()
    $found
}

# ---------- Bonjour (mDNS) ----------

function New-NsMdnsQuery {
    $q = New-Object System.Collections.Generic.List[byte]
    $n = $script:NsMdnsServices.Count
    $q.AddRange([byte[]](0, 0, 0, 0, (($n -shr 8) -band 255), ($n -band 255), 0, 0, 0, 0, 0, 0))
    foreach ($s in $script:NsMdnsServices) {
        foreach ($label in ("$s.local" -split '\.')) { $q.Add([byte]$label.Length); $q.AddRange([Text.Encoding]::ASCII.GetBytes($label)) }
        $q.Add(0); $q.AddRange([byte[]](0, 12, 0x80, 1))
    }
    , $q.ToArray()
}

function Read-NsDnsName([byte[]]$d, [ref]$Pos) {
    $parts = New-Object System.Collections.Generic.List[string]
    $p = $Pos.Value; $jumped = $false
    for ($guard = 0; $guard -lt 64 -and $p -lt $d.Length; $guard++) {
        $len = [int]$d[$p]
        if ($len -eq 0) { $p++; break }
        if (($len -band 0xC0) -eq 0xC0) {
            $ptr = (($len -band 0x3F) -shl 8) -bor $d[$p + 1]
            if (-not $jumped) { $Pos.Value = $p + 2 }
            $jumped = $true; $p = $ptr; continue
        }
        $parts.Add([Text.Encoding]::UTF8.GetString($d, $p + 1, $len)); $p += $len + 1
    }
    if (-not $jumped) { $Pos.Value = $p }
    $parts -join '.'
}

function Get-NsServiceOf([string]$name) { if ($name -match '(_[A-Za-z0-9-]+\._(tcp|udp))\.local\.?$') { $Matches[1].ToLowerInvariant() } else { '' } }
function Get-NsInstanceOf([string]$name) { if ($name -match '^(.+?)\._[A-Za-z0-9-]+\._(tcp|udp)\.local\.?$') { $Matches[1].Replace('\032', ' ') } else { '' } }

function ConvertFrom-NsMdns([byte[]]$d, $a, $addresses) {
    try {
        if ($d.Length -lt 12 -or ($d[2] -band 0x80) -eq 0) { return }
        $qd = ([int]$d[4] -shl 8) -bor $d[5]
        $rr = ((([int]$d[6] -shl 8) -bor $d[7]) + (([int]$d[8] -shl 8) -bor $d[9]) + (([int]$d[10] -shl 8) -bor $d[11]))
        $i = 12
        for ($n = 0; $n -lt $qd; $n++) { [void](Read-NsDnsName $d ([ref]$i)); $i += 4 }
        for ($n = 0; $n -lt $rr -and $i -lt $d.Length; $n++) {
            $name = Read-NsDnsName $d ([ref]$i)
            $type = ([int]$d[$i] -shl 8) -bor $d[$i + 1]
            $len = ([int]$d[$i + 8] -shl 8) -bor $d[$i + 9]
            $start = $i + 10; $end = $start + $len
            if ($end -gt $d.Length) { return }
            switch ($type) {
                12 {
                    $p = $start; $target = Read-NsDnsName $d ([ref]$p)
                    if ($name -like '_services._dns-sd*') { $s = Get-NsServiceOf $target; if ($s) { [void]$a.Services.Add($s) }; break }
                    $svc = Get-NsServiceOf $name; if ($svc) { [void]$a.Services.Add($svc) }
                    $inst = Get-NsInstanceOf $target
                    if ($inst -and -not $a.FriendlyName -and $svc -in @('_googlecast._tcp', '_airplay._tcp', '_raop._tcp', '_ipp._tcp', '_printer._tcp', '_sonos._tcp', '_hap._tcp', '_amzn-wplay._tcp', '_companion-link._tcp')) {
                        $a.FriendlyName = if ($svc -eq '_raop._tcp' -and $inst.Contains('@')) { $inst.Substring($inst.IndexOf('@') + 1) } else { $inst }
                    }
                }
                33 { $p = $start + 6; $h = Read-NsDnsName $d ([ref]$p); if ($h -and -not $a.Host) { $a.Host = $h.TrimEnd('.') }; $svc = Get-NsServiceOf $name; if ($svc) { [void]$a.Services.Add($svc) } }
                16 {
                    $p = $start
                    while ($p -lt $end) {
                        $l = [int]$d[$p]; $p++
                        if ($l -eq 0 -or $p + $l -gt $end) { break }
                        $kv = [Text.Encoding]::UTF8.GetString($d, $p, $l); $p += $l
                        $eq = $kv.IndexOf('='); if ($eq -gt 0) { $k = $kv.Substring(0, $eq).ToLowerInvariant(); if (-not $a.Txt.ContainsKey($k)) { $a.Txt[$k] = $kv.Substring($eq + 1) } }
                    }
                }
                1 {
                    if ($len -eq 4) {
                        $ip = "$($d[$start]).$($d[$start + 1]).$($d[$start + 2]).$($d[$start + 3])"
                        if ($null -ne $addresses) { $addresses[$name.TrimEnd('.')] = $ip }
                        if (-not $a.Host -and $name -like '*.local*') { $a.Host = $name.TrimEnd('.') }
                    }
                }
            }
            $i = $end
        }
    } catch {}
    if ($a.Txt['fn']) { $a.FriendlyName = $a.Txt['fn'] }
    foreach ($k in @('md', 'ty', 'usb_mdl', 'product', 'am', 'model', 'rpmd')) { $v = "$($a.Txt[$k])".Trim('(', ')', ' '); if ($v -and -not $a.Model) { $a.Model = $v } }
    if (-not $a.Manufacturer -and $a.Txt['usb_mfg']) { $a.Manufacturer = $a.Txt['usb_mfg'] }
}

function Invoke-NsMdns($LocalIp, [int]$ListenMs = 3200) {
    $found = @{}
    $sockets = New-Object System.Collections.Generic.List[object]
    try {
        $bind = if ($LocalIp) { $LocalIp } else { [Net.IPAddress]::Any }
        $uni = New-Object Net.Sockets.UdpClient (New-Object Net.IPEndPoint $bind, 0)
        $sockets.Add($uni)
        try {
            $multi = New-Object Net.Sockets.UdpClient
            $multi.ExclusiveAddressUse = $false
            $multi.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket, [Net.Sockets.SocketOptionName]::ReuseAddress, $true)
            $multi.Client.Bind((New-Object Net.IPEndPoint ([Net.IPAddress]::Any), 5353))
            if ($LocalIp) { $multi.JoinMulticastGroup([Net.IPAddress]::Parse('224.0.0.251'), $LocalIp) } else { $multi.JoinMulticastGroup([Net.IPAddress]::Parse('224.0.0.251')) }
            $sockets.Add($multi)
        } catch {}
        $query = New-NsMdnsQuery
        $group = New-Object Net.IPEndPoint ([Net.IPAddress]::Parse('224.0.0.251')), 5353
        [void]$uni.Send($query, $query.Length, $group)
        $resent = $false
        $start = [DateTime]::UtcNow
        $until = $start.AddMilliseconds($ListenMs)
        while ([DateTime]::UtcNow -lt $until) {
            if (-not $resent -and ([DateTime]::UtcNow - $start).TotalMilliseconds -gt 700) { [void]$uni.Send($query, $query.Length, $group); $resent = $true }
            $any = $false
            foreach ($s in $sockets) {
                if (-not $s.Client.Poll(30000, [Net.Sockets.SelectMode]::SelectRead)) { continue }
                $ep = New-Object Net.IPEndPoint ([Net.IPAddress]::Any), 0
                try { $data = $s.Receive([ref]$ep) } catch { continue }
                $any = $true
                # Routers that repeat Bonjour between networks send others' answers from their own address:
                # an answer belongs to the address in its A record when it has one.
                $one = New-NsAnnounced; $addrs = @{}
                ConvertFrom-NsMdns $data $one $addrs
                $owner = if ($addrs.Count -gt 0) { @($addrs.Values)[0] } else { $ep.Address.ToString() }
                if (-not $found.ContainsKey($owner)) { $found[$owner] = New-NsAnnounced }
                $a = $found[$owner]
                foreach ($x in $one.Services) { [void]$a.Services.Add($x) }
                foreach ($k in $one.Txt.Keys) { if (-not $a.Txt.ContainsKey($k)) { $a.Txt[$k] = $one.Txt[$k] } }
                if ($one.FriendlyName -and (-not $a.FriendlyName -or $one.Txt.ContainsKey('fn'))) { $a.FriendlyName = $one.FriendlyName }
                if (-not $a.Model) { $a.Model = $one.Model }
                if (-not $a.Manufacturer) { $a.Manufacturer = $one.Manufacturer }
                if (-not $a.Host) { $a.Host = $one.Host }
                if ($addrs.Count -gt 0) { $a.OwnAddress = $true }
            }
            if (-not $any) { Start-Sleep -Milliseconds 20 }
        }
    } catch {} finally { foreach ($s in $sockets) { try { $s.Dispose() } catch {} } }
    $out = @{}
    foreach ($k in $found.Keys) { if ($found[$k].Services.Count -gt 0 -or $found[$k].Host) { $out[$k] = $found[$k] } }
    $out
}

# ---------- Web page titles ----------

function New-NsHttp([bool]$AnyCert) {
    $h = New-Object Net.Http.HttpClientHandler
    $h.UseProxy = $false; $h.AllowAutoRedirect = $true; $h.MaxAutomaticRedirections = 3; $h.UseCookies = $false
    if ($AnyCert) {
        # LAN devices nearly all use self-signed certificates; we only read the page title. A static .NET delegate
        # (not a script block), so it works from the HTTP threads. Not available on every .NET Framework: then
        # HTTPS pages just go without a title.
        try { $h.ServerCertificateCustomValidationCallback = [Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator } catch {}
    }
    $c = New-Object Net.Http.HttpClient $h
    $c.Timeout = [TimeSpan]::FromSeconds(4)
    try { $c.DefaultRequestHeaders.UserAgent.ParseAdd('pxdNetworkScanner/1.0') } catch {}
    $c
}

function Get-NsWebTitles($targets) {
    $out = @{}
    if (@($targets).Count -eq 0) { return $out }
    $http = New-NsHttp $true
    $jobs = foreach ($t in $targets) {
        $url = "$(if (Test-NsHttps $t.Port) { 'https' } else { 'http' })://$($t.Ip)$(if ($t.Port -in @(80, 443)) { '' } else { ':' + $t.Port })/"
        try { [pscustomobject]@{ Ip = $t.Ip; T = $http.GetAsync($url) } } catch {}
    }
    Wait-NsTasks ($jobs | ForEach-Object { $_.T }) 4500
    $reads = foreach ($j in $jobs) {
        if (-not (Test-NsDone $j.T)) { continue }
        $res = $j.T.Result
        $server = "$($res.Headers.Server)"
        $final = $res.RequestMessage.RequestUri
        if (-not $out.ContainsKey($j.Ip)) { $out[$j.Ip] = @{ Title = ''; Server = $server } }
        if ($final -and $final.Host -ne $j.Ip) { continue }   # redirected elsewhere: not this device's page
        [pscustomobject]@{ Ip = $j.Ip; T = $res.Content.ReadAsStringAsync() }
    }
    Wait-NsTasks ($reads | ForEach-Object { $_.T }) 3000
    foreach ($r in $reads) {
        if (-not (Test-NsDone $r.T)) { continue }
        $html = $r.T.Result; if ($html.Length -gt 65536) { $html = $html.Substring(0, 65536) }
        if ($html -match '(?is)<title[^>]*>\s*(.*?)\s*</title>' -and -not $out[$r.Ip].Title) {
            $t = ([Net.WebUtility]::HtmlDecode($Matches[1]) -replace '\s+', ' ').Trim()
            if ($t.Length -gt 90) { $t = $t.Substring(0, 89) + $script:NsEll }
            $out[$r.Ip].Title = $t
        }
    }
    $http.Dispose()
    $out
}

# ---------- MAC makers ----------

function Start-NsVendorDownload {
    if ($script:NsVendors -or $script:NsVendorTask) { return }
    try {
        $script:NsVendorHttp = New-NsHttp $false
        $script:NsVendorHttp.Timeout = [TimeSpan]::FromSeconds(30)
        $script:NsVendorTask = $script:NsVendorHttp.GetStringAsync('https://www.wireshark.org/download/automated/data/manuf')
    } catch {}
}

function Complete-NsVendors {
    if ($script:NsVendors) { return }
    $script:NsVendors = @{}
    if (-not $script:NsVendorTask) { return }
    Wait-NsTasks @($script:NsVendorTask) 20000
    if (-not (Test-NsDone $script:NsVendorTask)) { return }
    $r = New-Object IO.StringReader $script:NsVendorTask.Result
    while ($null -ne ($line = $r.ReadLine())) {
        if ($line.Length -lt 8 -or $line[0] -eq '#') { continue }
        $p = $line.Split("`t")
        if ($p.Count -lt 2) { continue }
        $key = $p[0].Trim(); $bits = 24
        $slash = $key.IndexOf('/'); if ($slash -gt 0) { $bits = [int]$key.Substring($slash + 1); $key = $key.Substring(0, $slash) }
        $hex = $key.Replace(':', '').Replace('-', '').ToUpperInvariant()
        $n = switch ($bits) { 24 { 6 } 28 { 7 } 36 { 9 } default { 0 } }
        if ($n -eq 0 -or $hex.Length -lt $n) { continue }
        $name = if ($p.Count -gt 2 -and $p[2].Trim()) { $p[2].Trim() } else { $p[1].Trim() }
        $script:NsVendors[$hex.Substring(0, $n)] = $name
    }
    $script:NsVendorTask = $null
    try { $script:NsVendorHttp.Dispose() } catch {}
}

$script:NsVendorBetter = @{ '080027' = 'VirtualBox'; '525400' = 'QEMU / KVM'; '00155D' = 'Microsoft Hyper-V'; '00163E' = 'Xen'; '000C29' = 'VMware'; '005056' = 'VMware'; '000569' = 'VMware'; '001C14' = 'VMware'; 'BC2411' = 'Proxmox' }

function Get-NsVendor([string]$mac) {
    if ($mac.Length -lt 6) { return '' }
    $m = $mac.ToUpperInvariant()
    if ($script:NsVendorBetter.ContainsKey($m.Substring(0, 6))) { return $script:NsVendorBetter[$m.Substring(0, 6)] }
    if (-not $script:NsVendors) { return '' }
    $v = $null
    if ($m.Length -ge 9) { $v = $script:NsVendors[$m.Substring(0, 9)] }
    if (-not $v) { $v = $script:NsVendors[$m.Substring(0, 7)] }
    if (-not $v) { $v = $script:NsVendors[$m.Substring(0, 6)] }
    if (-not $v) { return '' }
    $s = $v; $c = $s.IndexOf(','); if ($c -gt 3) { $s = $s.Substring(0, $c) }
    for ($k = 0; $k -lt 3; $k++) { $s = ($s -replace '(?i)\s+(Co\.?|Ltd\.?|Inc\.?|Corp\.?|Corporation|Limited|LLC|GmbH|S\.?A\.?|AB|AG|B\.?V\.?|Pte\.?|Pty\.?)$', '').Trim(' ', '.', ',') }
    if ($s) { $s } else { $v }
}

function Test-NsRandomMac([string]$mac) { $mac.Length -ge 2 -and (([Convert]::ToByte($mac.Substring(0, 2), 16) -band 2) -ne 0) }

# ======================================================================================
#  What each device is
# ======================================================================================

function New-NsDevice([string]$Ip) {
    [pscustomobject]@{
        Ip = $Ip; Mac = ''; Vendor = ''; DnsName = ''; NetBiosName = ''; NetBiosGroup = ''; MdnsName = ''; FriendlyName = ''; Manufacturer = ''; Model = ''
        SsdpType = ''; SsdpServer = ''; SnmpDescr = ''; SnmpName = ''; HttpTitle = ''; HttpServer = ''; Ports = @(); Services = @(); Ttl = 0; LatencyMs = -1
        IsGateway = $false; IsSelf = $false; Kind = 'Unknown'; KindText = ''; Why = @(); Os = ''; Online = $true; FirstSeen = (Get-Date); LastSeen = (Get-Date)
        Sort = [uint32](ConvertTo-NsUint ([Net.IPAddress]::Parse($Ip)))
    }
}

function Test-NsHas($d, [int[]]$ports) { foreach ($p in $ports) { if ($d.Ports -contains $p) { return $true } }; $false }
function Test-NsSvc($d, [string]$prefix) { foreach ($s in $d.Services) { if ($s.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $true } }; $false }
function Get-NsFirst([string]$text, [string[]]$words) { foreach ($w in $words) { if ($text.Contains($w)) { return $w.Trim() } }; '' }

function Test-NsLooksLikeId($d, [string]$name) {
    $n = $name -replace '[-_:]', ''
    if ($d.Mac.Length -eq 12 -and ($n.IndexOf($d.Mac, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or ($n.IndexOf($d.Mac.Substring(6), [StringComparison]::OrdinalIgnoreCase) -ge 0 -and $n.Length -le 16))) { return $true }
    ($n -match '^[A-Za-z]{0,8}[0-9A-Fa-f]{10,}$') -and (($n.ToCharArray() | Where-Object { [char]::IsDigit($_) }).Count -ge 4)
}

function Get-NsShort([string]$h) {
    if (-not $h) { return '' }
    $h = $h.TrimEnd('.'); if ($h.EndsWith('.local', [StringComparison]::OrdinalIgnoreCase)) { $h = $h.Substring(0, $h.Length - 6) }
    $dot = $h.IndexOf('.'); if ($dot -gt 0 -and -not [char]::IsDigit($h[0])) { $h = $h.Substring(0, $dot) }
    $h
}

function Get-NsName($d) {
    if ($d.IsSelf) { return "$(if ($d.NetBiosName) { $d.NetBiosName } else { $env:COMPUTERNAME }) (this PC)" }
    foreach ($n in @($d.FriendlyName, $d.NetBiosName, (Get-NsShort $d.MdnsName), (Get-NsShort $d.DnsName), $d.SnmpName)) { if ($n -and $n -ne $d.Ip -and -not (Test-NsLooksLikeId $d $n)) { return $n } }
    if ($d.Model) {
        $maker = (@(@($d.Manufacturer, $d.Vendor) | Where-Object { $_ })[0] -split '[ ,]')[0]
        if ($maker -and $maker.Length -gt 1 -and $d.Model.IndexOf($maker, [StringComparison]::OrdinalIgnoreCase) -lt 0 -and -not $d.Model.Contains(',')) { return "$maker $($d.Model)" }
        return $d.Model
    }
    if ($d.Vendor) { return "$($d.Vendor) device" }
    if ($d.Kind -notin @('Unknown', 'ThisPc') -and $d.KindText) { return $d.KindText }
    $d.Ip
}

function Get-NsSubtitle($d) {
    $parts = New-Object System.Collections.Generic.List[string]
    $name = Get-NsName $d
    if ($d.Model -and $name.IndexOf($d.Model, [StringComparison]::OrdinalIgnoreCase) -lt 0) { $parts.Add($d.Model) }
    $maker = if ($d.Manufacturer) { $d.Manufacturer } else { $d.Vendor }
    if ($maker -and -not ($parts | Where-Object { $_.IndexOf($maker, [StringComparison]::OrdinalIgnoreCase) -ge 0 }) -and $name.IndexOf($maker, [StringComparison]::OrdinalIgnoreCase) -lt 0) { $parts.Add($maker) }
    if ($parts.Count -eq 0 -and (Test-NsRandomMac $d.Mac)) { $parts.Add('Private MAC address') }
    if ($d.Os -and $parts.Count -lt 2 -and -not ($parts | Where-Object { $_ -like "*$($d.Os)*" })) { $parts.Add($d.Os) }
    $parts -join ' - '
}

$script:NsW = @{
    Printer = @('printer', 'laserjet', 'officejet', 'deskjet', 'designjet', 'pagewide', 'envy ', 'smart tank', 'mfc-', 'hl-l', 'hl-', 'dcp-', 'imageclass', 'imagerunner', 'pixma', 'maxify', 'ecotank', 'workforce', 'expression home', 'ecosys', 'taskalfa', 'bizhub', 'lexmark', 'xerox', 'versalink', 'workcentre', 'ricoh', 'aficio', 'phaser', 'zebra', 'jetdirect', 'brother nc-')
    PrinterMakers = @('brother', 'canon', 'seiko epson', 'epson', 'lexmark', 'xerox', 'kyocera', 'ricoh', 'konica', 'zebra', 'oki', 'sharp', 'hp inc', 'hewlett packard')
    Console = @('xbox', 'playstation', 'nintendo', 'sony interactive')
    Nas = @('synology', 'diskstation', 'qnap', 'asustor', 'truenas', 'freenas', 'unraid', 'terramaster', 'readynas', 'my cloud', 'wd mycloud')
    Camera = @('hikvision', 'dahua', 'reolink', 'amcrest', 'axis communications', 'ip camera', 'ipcam', 'network camera', 'nvr', 'wyze', 'arlo', 'foscam', 'lorex', 'swann', 'eufy', 'doorbell', 'unifi protect')
    Tv = @('smart tv', ' tv', 'tv ', 'bravia', 'webos', 'tizen', 'vizio', 'smartcast', 'roku', 'fire tv', 'firetv', 'apple tv', 'chromecast', 'google tv', 'android tv', 'shield', 'mediarenderer', 'dlna', 'sonos', 'denon', 'yamaha', 'heos', 'bose', 'soundbar', 'receiver')
    NetMakers = @('ubiquiti', 'mikrotik', 'routerboard', 'netgear', 'tp-link', 'cisco', 'aruba', 'ruckus', 'eero', 'linksys', 'zyxel', 'd-link', 'juniper', 'meraki', 'fortinet', 'netgate', 'draytek', 'tenda', 'mercusys', 'edgecore', 'extreme networks', 'cambium', 'grandstream', 'asus router', 'quectel', 'sierra wireless', 'telit', 'inseego', 'franklin wireless')
    Net = @('switch', 'router', 'access point', 'routeros', 'unifi', 'edgeos', 'edgeswitch', 'openwrt', 'dd-wrt', 'pfsense', 'opnsense', 'mesh', 'gateway', 'firewall')
    SmartMakers = @('espressif', 'tuya', 'shelly', 'allterco', 'signify', 'philips lighting', 'ecobee', 'nest labs', 'ring llc', 'belkin', 'lifx', 'itead', 'sonoff', 'wiz', 'govee', 'ikea', 'lutron', 'wyze', 'chamberlain', 'rachio', 'august', 'yale', 'sense labs', 'tado', 'netatmo', 'amazon technologies', 'eufy', 'meross', 'kasa', 'wemo')
    PhoneMakers = @('samsung', 'xiaomi', 'oneplus', 'huawei', 'honor device', 'oppo', 'vivo mobile', 'realme', 'motorola', 'google', 'zte', 'nothing technology', 'fairphone', 'hmd global', 'nokia', 'lg electronics', 'sony mobile', 'tcl')
    PcMakers = @('intel', 'realtek', 'dell', 'lenovo', 'asustek', 'micro-star', 'giga-byte', 'gigabyte', 'asrock', 'hp inc', 'hewlett packard', 'microsoft', 'liteon', 'lite-on', 'azurewave', 'rivet networks', 'killer', 'hon hai', 'foxconn', 'quanta', 'compal', 'wistron', 'pegatron', 'acer', 'toshiba', 'fujitsu', 'framework', 'msi', 'razer', 'clevo', 'qualcomm atheros', 'mediatek', 'broadcom', 'aquantia', 'marvell')
}

function Test-NsAny([string]$text, [string[]]$words) { foreach ($w in $words) { if ($text.Contains($w)) { return $true } }; $false }

function Set-NsKind($d) {
    if (-not $d.Vendor -and $d.Mac.Length -eq 12 -and -not (Test-NsRandomMac $d.Mac)) { $d.Vendor = Get-NsVendor $d.Mac }
    $why = New-Object System.Collections.Generic.List[string]
    $text = (@($d.Vendor, $d.Manufacturer, $d.Model, $d.FriendlyName, $d.SnmpDescr, $d.SnmpName, $d.HttpTitle, $d.HttpServer, $d.SsdpType, $d.SsdpServer, $d.MdnsName, $d.DnsName, $d.NetBiosName) -join ' | ').ToLowerInvariant()
    $vendor = $d.Vendor.ToLowerInvariant()
    $win = Test-NsHas $d @(135, 139, 445, 3389, 5357)
    $apple = $vendor.Contains('apple')
    $txtModel = ("$($d.Model) " + ($d.Services -join ' ')).ToLowerInvariant()
    $W = $script:NsW

    # the operating system, as far as it shows
    $d.Os = ''
    if ($d.IsSelf -or ($win -and ($d.Ttl -eq 0 -or ($d.Ttl -gt 64 -and $d.Ttl -le 128))) -or ($d.NetBiosName -and $d.Ttl -gt 64 -and $d.Ttl -le 128) -or $text.Contains('windows')) { $d.Os = 'Windows' }
    elseif ($apple) { if ($text.Contains('iphone') -or $text.Contains('ipad') -or (Test-NsHas $d 62078)) { $d.Os = 'iOS' } elseif ($d.Model -like '*Mac*' -or (Test-NsHas $d @(22, 548, 5900))) { $d.Os = 'macOS' } }
    elseif ($text.Contains('android')) { $d.Os = 'Android' }
    elseif ((Test-NsAny $text @('ubuntu', 'debian', 'raspbian', 'fedora', 'linux', 'proxmox')) -or (Test-NsHas $d 8006) -or ((Test-NsHas $d 22) -and $d.Ttl -gt 0 -and $d.Ttl -le 64)) { $d.Os = 'Linux' }

    $kind = 'Unknown'; $label = 'Unknown device'
    $pick = {
        if ($d.IsSelf) { $why.Add("it's the PC running this scan"); return @('ThisPc', 'This PC') }

        $hits = New-Object System.Collections.Generic.List[string]
        if ((Test-NsSvc $d '_ipp') -or (Test-NsSvc $d '_printer') -or (Test-NsSvc $d '_pdl-datastream')) { $hits.Add('it offers printing over Bonjour') }
        if (Test-NsHas $d 9100) { $hits.Add('port 9100 (raw printing) is open') }
        if ($d.SsdpType -like '*printer*') { $hits.Add("it calls itself a UPnP $($d.SsdpType)") }
        if ((Test-NsAny $text $W.Printer) -and -not $d.IsGateway) { $hits.Add("its own description says `"$(Get-NsFirst $text $W.Printer)`"") }
        if ($hits.Count -eq 0 -and (Test-NsAny $vendor $W.PrinterMakers) -and (Test-NsHas $d @(631, 515))) { $hits.Add("$($d.Vendor) network card with a printing port open") }
        if ($hits.Count -gt 0 -and -not ($d.IsGateway -and $hits.Count -lt 2)) {
            foreach ($h in $hits) { $why.Add($h) }
            if ((Test-NsSvc $d '_uscan') -or (Test-NsSvc $d '_scanner') -or $text.Contains('mfp') -or $text.Contains('mfc-') -or $text.Contains('all-in-one')) { return @('Printer', 'Printer / scanner') }
            return @('Printer', 'Printer')
        }
        if ($d.IsGateway) { $why.Add("it's this network's default gateway"); return @('Router', 'Router (gateway)') }
        if ($d.SsdpType -like '*InternetGatewayDevice*' -or $d.SsdpType -like '*WFADevice*') { $why.Add("it announces itself as a UPnP $($d.SsdpType)"); return @('Router', 'Router') }
        if ((Test-NsAny $text $W.Console) -or $vendor.Contains('nintendo')) {
            $why.Add("it says `"$(if (Test-NsAny $text $W.Console) { Get-NsFirst $text $W.Console } else { 'nintendo' })`"")
            if ($text.Contains('xbox')) { return @('GameConsole', 'Xbox') }
            if ($text.Contains('playstation') -or $vendor.Contains('sony interactive')) { return @('GameConsole', 'PlayStation') }
            if ($text.Contains('nintendo')) { return @('GameConsole', 'Nintendo console') }
            return @('GameConsole', 'Game console')
        }
        if ($vendor -in @('virtualbox', 'qemu / kvm', 'microsoft hyper-v', 'xen', 'vmware', 'proxmox')) { $why.Add("its MAC address is one $($d.Vendor) gives virtual machines"); return @('VirtualMachine', $(if ($d.Os) { "Virtual machine ($($d.Os))" } else { 'Virtual machine' })) }
        if (Test-NsAny $text $W.Nas) { $why.Add("it says `"$(Get-NsFirst $text $W.Nas)`""); return @('Storage', 'Network storage (NAS)') }
        if ((Test-NsAny $text $W.Camera) -or ((Test-NsHas $d 554) -and -not $win -and -not (Test-NsHas $d 7000) -and -not (Test-NsSvc $d '_airplay'))) {
            $why.Add($(if (Test-NsAny $text $W.Camera) { "it says `"$(Get-NsFirst $text $W.Camera)`"" } else { 'port 554 (video stream, RTSP) is open' }))
            return @('Camera', $(if ($text.Contains('nvr')) { 'Camera recorder (NVR)' } elseif ($text.Contains('doorbell')) { 'Video doorbell' } else { 'Camera' }))
        }
        if (-not $apple -and ((Test-NsAny $text @('macbook', 'imac', 'mac mini', 'macmini')) -or ((Test-NsSvc $d '_rfb') -and ((Test-NsSvc $d '_airplay') -or (Test-NsSvc $d '_raop') -or (Test-NsSvc $d '_companion-link'))))) {
            $why.Add('its name or services are a Mac''s'); return @('Computer', 'Mac')
        }
        if (-not $apple -and ((Test-NsAny $text @('iphone', 'ipad')) -or (Test-NsHas $d 62078) -or (Test-NsSvc $d '_apple-mobdev2') -or ((Test-NsSvc $d '_companion-link') -and $d.Ports.Count -eq 0))) {
            $why.Add($(if (Test-NsHas $d 62078) { 'port 62078 (iPhone / iPad sync) is open' } else { 'its name or services are an iPhone''s' }))
            return @('Phone', $(if ($text.Contains('ipad')) { 'iPad' } elseif ($text.Contains('iphone')) { 'iPhone' } else { 'iPhone or iPad' }))
        }
        if ($apple) {
            if ($txtModel.Contains('appletv')) { $why.Add("its Bonjour model is $($d.Model)"); return @('Media', 'Apple TV') }
            if ($txtModel.Contains('audioaccessory') -or $text.Contains('homepod')) { $why.Add("its Bonjour model is $($d.Model)"); return @('Media', 'HomePod') }
            if ($txtModel.Contains('mac') -or $text.Contains('macbook') -or $text.Contains('imac') -or (Test-NsHas $d @(22, 445, 548, 5900)) -or (Test-NsSvc $d '_smb') -or (Test-NsSvc $d '_afpovertcp') -or (Test-NsSvc $d '_workstation')) { $why.Add('Apple network card with a computer''s ports or model'); return @('Computer', 'Mac') }
            if ($txtModel.Contains('iphone') -or $txtModel.Contains('ipad') -or (Test-NsHas $d 62078) -or (Test-NsSvc $d '_apple-mobdev2')) { $why.Add($(if (Test-NsHas $d 62078) { 'port 62078 (iPhone / iPad sync) is open' } else { 'Apple network card and it answers like a phone' })); return @('Phone', $(if ($txtModel.Contains('ipad')) { 'iPad' } elseif ($txtModel.Contains('iphone')) { 'iPhone' } else { 'iPhone or iPad' })) }
            if ((Test-NsSvc $d '_airplay') -or (Test-NsSvc $d '_raop')) { $why.Add('it takes AirPlay'); return @('Media', 'AirPlay device') }
            $why.Add('Apple network card with nothing open (phones and watches look like this)'); return @('Phone', 'Apple device (likely iPhone or iPad)')
        }
        if ((Test-NsSvc $d '_googlecast') -or ((Test-NsHas $d @(8008, 8009)) -and -not $win)) {
            $why.Add($(if (Test-NsSvc $d '_googlecast') { 'it offers Google Cast' } else { 'Google Cast ports (8008/8009) are open' }))
            $m = "$($d.Model) $($d.FriendlyName)".ToLowerInvariant()
            if (Test-NsAny $m @('nest', 'home mini', 'google home', 'audio', 'speaker')) { return @('Media', 'Smart speaker') }
            return @('Media', $(if ($m.Contains('tv') -or $text.Contains('tv')) { 'Smart TV / Google TV' } else { 'Chromecast / Cast device' }))
        }
        if ((Test-NsSvc $d '_sonos') -or $vendor.Contains('sonos')) { $why.Add('it offers Sonos'); return @('Media', 'Sonos speaker') }
        if ($vendor.Contains('roku') -or (Test-NsHas $d 8060)) { $why.Add($(if ($vendor.Contains('roku')) { 'Roku network card' } else { 'port 8060 (Roku remote) is open' })); return @('Media', $(if ($text.Contains('tv')) { 'Roku TV' } else { 'Roku' })) }
        if (Test-NsSvc $d '_amzn-wplay') { $why.Add('it offers Amazon''s Fire TV casting'); return @('Media', 'Fire TV') }
        if ((Test-NsSvc $d '_airplay') -or (Test-NsSvc $d '_raop') -or (Test-NsSvc $d '_spotify-connect') -or (Test-NsSvc $d '_androidtvremote2') -or $d.SsdpType -like '*MediaRenderer*' -or ((Test-NsAny $text $W.Tv) -and -not $win)) {
            $why.Add($(if ($d.SsdpType -like '*MediaRenderer*') { "it's a UPnP media player (MediaRenderer)" } elseif ((Test-NsSvc $d '_airplay') -or (Test-NsSvc $d '_raop')) { 'it takes AirPlay' } elseif (Test-NsSvc $d '_spotify-connect') { 'it offers Spotify Connect' } elseif (Test-NsSvc $d '_androidtvremote2') { 'it offers the Android TV remote' } else { "it says `"$(Get-NsFirst $text $W.Tv)`"" }))
            return @('Media', $(if ($text.Contains('tv') -or (Test-NsSvc $d '_androidtvremote2')) { 'Smart TV' } else { 'Media player / speaker' }))
        }
        if (Test-NsHas $d 8006) { $why.Add('port 8006 (Proxmox) is open'); return @('Server', 'Proxmox server') }
        $snmpNet = "$($d.SnmpDescr) $($d.HttpTitle)".ToLowerInvariant()
        if ((Test-NsAny $snmpNet $W.Net) -or ((Test-NsAny $vendor $W.NetMakers) -and (-not $win -or $d.SnmpDescr))) {
            if ($vendor.Contains('tp-link') -and -not (Test-NsHas $d @(80, 443)) -and -not $d.SnmpDescr) { $why.Add('TP-Link network card with no web page (their smart plugs and bulbs look like this)'); return @('SmartHome', 'Smart plug / bulb') }
            $why.Add($(if (Test-NsAny $snmpNet $W.Net) { "its own description says `"$(Get-NsFirst $snmpNet $W.Net)`"" } else { "$($d.Vendor) makes network gear" }))
            if (Test-NsAny $vendor @('quectel', 'sierra', 'telit', 'inseego', 'franklin')) { return @('NetworkGear', 'Cellular modem / router') }
            if ($snmpNet.Contains('switch')) { return @('NetworkGear', 'Network switch') }
            if ($snmpNet.Contains('access point') -or $text.Contains('unifi') -or $text.Contains('eero') -or $snmpNet.Contains('mesh')) { return @('NetworkGear', 'Wi-Fi access point') }
            return @('NetworkGear', 'Network device')
        }
        if ((Test-NsSvc $d '_hap') -or (Test-NsSvc $d '_homekit') -or (Test-NsSvc $d '_matter') -or (Test-NsSvc $d '_hue') -or (Test-NsSvc $d '_esphomelib') -or (Test-NsSvc $d '_home-assistant') -or (Test-NsHas $d 8123) -or (Test-NsAny $vendor $W.SmartMakers) -or ((Test-NsHas $d 1883) -and -not $win)) {
            if ((Test-NsHas $d 8123) -or (Test-NsSvc $d '_home-assistant')) { $why.Add('Home Assistant answers on it'); return @('SmartHome', 'Home Assistant hub') }
            if ($vendor.Contains('amazon')) { $why.Add('Amazon network card with no web page (Echo speakers and Fire tablets look like this)'); return @('SmartHome', 'Amazon device (Echo / Fire)') }
            $why.Add($(if (Test-NsAny $vendor $W.SmartMakers) { "$($d.Vendor) makes smart-home gear" } elseif (Test-NsHas $d 1883) { 'port 1883 (MQTT) is open' } else { 'it offers a smart-home service (HomeKit, Matter, Hue or ESPHome)' }))
            return @('SmartHome', $(if ((Test-NsSvc $d '_hue') -or $vendor.Contains('signify') -or $vendor.Contains('philips lighting')) { 'Philips Hue bridge' } else { 'Smart home device' }))
        }
        if (Test-NsHas $d 32400) { $why.Add('port 32400 (Plex) is open'); return @('Server', 'Plex media server') }
        if ($vendor.Contains('raspberry')) { $why.Add('Raspberry Pi network card'); return @('Computer', 'Raspberry Pi') }
        if ($win -or $d.NetBiosName -or (Test-NsSvc $d '_workstation') -or (Test-NsSvc $d '_rdlink')) {
            $bits = @(); if (Test-NsHas $d 445) { $bits += 'file sharing' }; if (Test-NsHas $d 3389) { $bits += 'Remote Desktop' }; if (Test-NsHas $d 135) { $bits += 'Windows RPC' }; if ($d.NetBiosName) { $bits += 'a NetBIOS name' }
            $why.Add('it answers with ' + $(if ($bits) { $bits -join ', ' } else { 'Windows ports open' }))
            $server = $text.Contains('server') -or ((Test-NsHas $d 53) -and (Test-NsHas $d 445))
            if ($d.Os -eq 'Windows') { if ($server) { return @('Server', 'Windows server') } else { return @('Computer', 'Windows PC') } }
            return @('Computer', $(if ($d.Os) { "$($d.Os) computer" } else { 'Computer' }))
        }
        if ((Test-NsHas $d 22) -or $d.Os -eq 'Linux') { $why.Add($(if (Test-NsHas $d 22) { 'SSH (port 22) is open' } else { 'it answers like Linux' })); return @('Server', $(if ($d.Os) { "$($d.Os) computer / server" } else { 'Server' })) }
        if ((Test-NsAny $vendor $W.PcMakers) -and -not (Test-NsRandomMac $d.Mac)) { $why.Add("$($d.Vendor) network card (PCs and laptops)"); return @('Computer', $(if ($d.Vendor -like '*Microsoft*') { 'Microsoft device (Surface / Xbox)' } else { 'Computer' })) }
        if ((Test-NsAny $vendor $W.PhoneMakers) -and $d.Ports.Count -eq 0) { $why.Add("$($d.Vendor) network card with nothing open (phones and tablets look like this)"); return @('Phone', $(if ($d.Os -eq 'Android') { 'Android phone or tablet' } else { 'Phone or tablet' })) }
        if ((Test-NsRandomMac $d.Mac) -and $d.Ports.Count -eq 0) { $why.Add('a private (random) MAC address and nothing open: phones, tablets and some laptops do this on Wi-Fi'); return @('Phone', 'Phone or tablet (private MAC)') }
        if (Test-NsHas $d @(80, 443, 8080, 8443)) {
            $title = ''; if ($d.HttpTitle) { $title = ' ("' + $d.HttpTitle + '")' }
            $why.Add('it only has a web page' + $title); return @('Unknown', 'Device with a web page')
        }
        $why.Add($(if ($d.Vendor) { "made by $($d.Vendor), but nothing it answered says what it is" } else { 'nothing it answered says what it is' }))
        @('Unknown', 'Unknown device')
    }
    $r = & $pick
    $d.Kind = $r[0]; $d.KindText = $r[1]; $d.Why = @($why)
}

# ======================================================================================
#  One scan
# ======================================================================================

function Invoke-NsScan($r, [switch]$Quick) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $now = Get-Date
    Start-NsVendorDownload
    $targets = New-Object System.Collections.Generic.List[object]
    for ($v = [uint64]$r.First; $v -le $r.Last; $v++) { $targets.Add((ConvertFrom-NsUint ([uint32]$v)).ToString()) }
    $gwText = if ($r.Gateway) { $r.Gateway.ToString() } else { '' }

    $pinged = Invoke-NsPingSweep $targets
    $arp = Get-NsNeighbors
    $found = @{}
    $pending = @()
    foreach ($t in $targets) {
        $ip = $t.ToString()
        $n = $arp[$ip]
        if ($pinged.ContainsKey($ip)) { $d = New-NsDevice $ip; $d.LatencyMs = $pinged[$ip].Ms; $d.Ttl = $pinged[$ip].Ttl; if ($n) { $d.Mac = $n.Mac }; $found[$ip] = $d }
        elseif ($n -and $n.Rank -ge 5) { $d = New-NsDevice $ip; $d.Mac = $n.Mac; $found[$ip] = $d }
        elseif ($n -and $n.Rank -ge 2) { $pending += $ip }
    }
    if ($r.LocalIp -and (Test-NsInRange $r $r.LocalIp.ToString())) {
        $ip = $r.LocalIp.ToString()
        if (-not $found.ContainsKey($ip)) { $found[$ip] = New-NsDevice $ip }
        $found[$ip].IsSelf = $true; $found[$ip].Mac = $r.LocalMac; $found[$ip].LatencyMs = 0; $found[$ip].NetBiosName = $env:COMPUTERNAME
    }
    if ($gwText -and $found.ContainsKey($gwText)) { $found[$gwText].IsGateway = $true }

    if (-not $Quick) {
        Write-NsStatus '  Asking the network who''s there (UPnP and Bonjour)...'
        $ssdp = Invoke-NsSsdp $r.LocalIp
        $mdns = Invoke-NsMdns $r.LocalIp
        # late arrivals: an ARP entry that came back to life, or a device that only answered UPnP / Bonjour
        if ($pending) { $again = Get-NsNeighbors; foreach ($ip in $pending) { if ($again[$ip] -and $again[$ip].Rank -ge 5 -and -not $found.ContainsKey($ip)) { $d = New-NsDevice $ip; $d.Mac = $again[$ip].Mac; $found[$ip] = $d } } }
        $late = @($ssdp.Keys) + @($mdns.Keys) | Where-Object { (Test-NsInRange $r $_) -and -not $found.ContainsKey($_) } | Select-Object -Unique
        if ($late) { $arp2 = Get-NsNeighbors; foreach ($ip in $late) { $d = New-NsDevice $ip; if ($arp2[$ip]) { $d.Mac = $arp2[$ip].Mac }; $found[$ip] = $d } }

        $ips = @($found.Values | Where-Object { -not $_.IsSelf } | ForEach-Object { $_.Ip })
        if ($ips.Count -gt 0) {
            $ports = Get-NsOpenPorts $ips
            Write-NsStatus '  Reading names, NetBIOS and SNMP...'
            $dns = Get-NsReverseDns $ips
            $nb = Invoke-NsUdpSweep $ips 137 { param($id) New-NsNetBiosQuery $id } 1800
            $snmp = Invoke-NsUdpSweep $ips 161 { param($id) New-NsSnmpQuery $id } 1800
            $webTargets = foreach ($ip in $ips) { $p = @($ports[$ip]); foreach ($w in $script:NsWebPorts) { if ($p -contains $w) { [pscustomobject]@{ Ip = $ip; Port = $w }; break } } }
            Write-NsStatus '  Reading web pages...'
            $web = Get-NsWebTitles $webTargets
            foreach ($ip in $ips) {
                $d = $found[$ip]
                $d.Ports = @($ports[$ip] | Sort-Object)
                if ($dns[$ip]) { $d.DnsName = $dns[$ip] }
                if ($nb[$ip]) { $x = ConvertFrom-NsNetBios $nb[$ip]; $d.NetBiosName = $x.Name; $d.NetBiosGroup = $x.Group }
                if ($snmp[$ip]) {
                    $x = ConvertFrom-NsSnmp $snmp[$ip]
                    $d.SnmpDescr = if ($x.Descr) { $x.Descr } else { $x.Device }; $d.SnmpName = $x.Name
                    $isPc = "$($x.Descr) $($x.Device)" -match '(?i)linux|windows|intel|amd|cpu|processor'
                    if ($x.Device -and -not $d.Model -and -not $isPc) { $d.Model = $x.Device }
                }
                if ($web[$ip]) { $d.HttpTitle = $web[$ip].Title; $d.HttpServer = $web[$ip].Server }
            }
        }
        foreach ($ip in @($ssdp.Keys)) {
            if (-not $found.ContainsKey($ip)) { continue }
            $d = $found[$ip]; $a = $ssdp[$ip]
            if ($a.FriendlyName -and -not (($a.FriendlyName.Length -gt 20 -and -not $a.FriendlyName.Contains(' ')) -or $a.FriendlyName -match '^[0-9a-fA-F-]{36}$')) { $d.FriendlyName = $a.FriendlyName }
            if ($a.Manufacturer) { $d.Manufacturer = $a.Manufacturer }
            if ($a.Model) { $d.Model = $a.Model }
            if ($a.DeviceType) { $d.SsdpType = $a.DeviceType }
            if ($a.Server) { $d.SsdpServer = $a.Server }
        }
        foreach ($ip in @($mdns.Keys)) {
            if (-not $found.ContainsKey($ip)) { continue }
            $a = $mdns[$ip]
            if ($ip -eq $gwText -and -not $a.OwnAddress) { continue }   # a router repeating others' Bonjour
            $d = $found[$ip]
            if ($a.Host) { $d.MdnsName = $a.Host }
            if ($a.FriendlyName -and (-not $d.FriendlyName -or $d.FriendlyName -eq $d.Model)) { $d.FriendlyName = $a.FriendlyName }
            if ($a.Model -and -not $d.Model) { $d.Model = $a.Model }
            if ($a.Manufacturer -and -not $d.Manufacturer) { $d.Manufacturer = $a.Manufacturer }
            $d.Services = @($a.Services | Where-Object { $script:NsMdnsServices -contains $_ -and $_ -ne '_services._dns-sd._udp' } | Sort-Object)
        }
    }

    Write-NsStatus '  Looking up makers...'
    Complete-NsVendors
    foreach ($d in $found.Values) { Set-NsKind $d }
    Clear-NsStatus

    # Merge into what this session has seen: same MAC and IP, else the same MAC on a new IP, else the same IP.
    foreach ($s in $script:NsDevices) { if (Test-NsInRange $r $s.Ip) { $s.Online = $false } }
    foreach ($d in $found.Values) {
        $kept = $null
        if ($d.Mac) {
            $kept = $script:NsDevices | Where-Object { $_.Mac -eq $d.Mac -and $_.Ip -eq $d.Ip } | Select-Object -First 1
            if (-not $kept) { $kept = $script:NsDevices | Where-Object { $_.Mac -eq $d.Mac -and -not $_.Online } | Select-Object -First 1 }
        }
        if (-not $kept) { $kept = $script:NsDevices | Where-Object { $_.Ip -eq $d.Ip -and (-not $_.Mac -or -not $d.Mac) } | Select-Object -First 1 }
        if ($kept) {
            $first = $kept.FirstSeen
            $i = $script:NsDevices.IndexOf($kept)
            $d.FirstSeen = $first
            $script:NsDevices[$i] = $d
        } else { $script:NsDevices.Add($d) }
    }
    $script:NsLastScan = [pscustomobject]@{ Range = $r.Text; When = (Get-Date); Seconds = $clock.Elapsed.TotalSeconds; Count = $found.Count }
}

# ======================================================================================
#  Showing it
# ======================================================================================

function Get-NsColor([string]$kind) {
    switch ($kind) {
        { $_ -in @('ThisPc', 'Router', 'NetworkGear') } { 'Green' }
        'Printer' { 'Yellow' }
        'Phone' { 'Magenta' }
        { $_ -in @('Media', 'GameConsole') } { 'Red' }
        { $_ -in @('SmartHome', 'Camera') } { 'DarkYellow' }
        'Unknown' { 'DarkGray' }
        default { 'Cyan' }
    }
}

function Get-NsShown([string]$Group, [bool]$OnlineOnly, [string]$Search) {
    $g = $script:NsGroups | Where-Object { $_.Key -eq $Group } | Select-Object -First 1
    @($script:NsDevices | Where-Object {
            ($g.Kinds.Count -eq 0 -or $g.Kinds -contains $_.Kind) -and (-not $OnlineOnly -or $_.Online) -and (Test-NsMatch $_ $Search)
        } | Sort-Object Sort)
}

function Test-NsMatch($d, [string]$q) {
    $q = "$q".Trim(); if (-not $q) { return $true }
    $mac = $q -replace '[:-]', ''
    $hay = @((Get-NsName $d), $d.Ip, $d.KindText, $d.Vendor, $d.Model, $d.Manufacturer, $d.DnsName, $d.MdnsName, $d.NetBiosName, $d.Os, $d.HttpTitle) -join ' | '
    if ($hay.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    if ($mac.Length -ge 2 -and $d.Mac.IndexOf($mac, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    $n = 0; ([int]::TryParse($q, [ref]$n) -and $d.Ports -contains $n)
}

function Get-NsTrim([string]$s, [int]$max) { if ($max -le 1) { return '' }; if ($s.Length -le $max) { $s } else { $s.Substring(0, $max - 1) + $script:NsEll } }
function Format-NsMac([string]$m) { if ($m.Length -eq 12) { ($m -split '(..)' | Where-Object { $_ }) -join ':' } else { $m } }

function Show-NsTable($items) {
    $w = 120; try { $w = $Host.UI.RawUI.WindowSize.Width - 1 } catch {}
    $wide = $w -ge 110
    $typeW = 26; $ipW = 16; $macW = if ($wide) { 18 } else { 0 }
    $nameW = [Math]::Max(16, $w - 6 - 2 - $ipW - $macW - $typeW - 4)
    $subW = $nameW
    Write-Host ''
    Write-Host ('  {0,3}   {1}{2}{3}{4}' -f '#', 'Name'.PadRight($nameW + 1), 'IP address'.PadRight($ipW), $(if ($wide) { 'MAC address'.PadRight($macW) } else { '' }), 'Type') -ForegroundColor DarkGray
    $i = 0
    foreach ($d in $items) {
        $i++
        $script:NsMenu[$i - 1] = $d
        Write-Host ('  {0,3} ' -f $i) -NoNewline -ForegroundColor DarkGray
        Write-Host $script:NsDot -NoNewline -ForegroundColor $(if ($d.Online) { 'Green' } else { 'DarkGray' })
        Write-Host ' ' -NoNewline
        $name = Get-NsTrim (Get-NsName $d) $nameW
        Write-Host $name.PadRight($nameW + 1) -NoNewline -ForegroundColor $(if ($d.Online) { 'White' } else { 'DarkGray' })
        Write-Host $d.Ip.PadRight($ipW) -NoNewline -ForegroundColor $(if ($d.Online) { 'Gray' } else { 'DarkGray' })
        if ($wide) { Write-Host (Format-NsMac $d.Mac).PadRight($macW) -NoNewline -ForegroundColor DarkGray }
        Write-Host (Get-NsTrim $d.KindText $typeW) -ForegroundColor $(if ($d.Online) { Get-NsColor $d.Kind } else { 'DarkGray' })
        $sub = if ($d.Online) { Get-NsSubtitle $d } else { "last seen $($d.LastSeen.ToString('HH:mm'))  -  $(Get-NsSubtitle $d)".TrimEnd(' ', '-') }
        if ($sub) { Write-Host ('        ' + (Get-NsTrim $sub $subW)) -ForegroundColor DarkGray }
    }
    if ($i -eq 0) { Write-Host '        (nothing to show)' -ForegroundColor DarkGray }
}

function Get-NsServiceName([string]$s) {
    $map = @{
        '_ipp._tcp' = 'Printing (IPP)'; '_ipps._tcp' = 'Printing (IPP)'; '_printer._tcp' = 'Printing (LPD)'; '_pdl-datastream._tcp' = 'Printing (raw)'; '_uscan._tcp' = 'Scanning'; '_scanner._tcp' = 'Scanning'
        '_airplay._tcp' = 'AirPlay'; '_raop._tcp' = 'AirPlay audio'; '_googlecast._tcp' = 'Google Cast'; '_spotify-connect._tcp' = 'Spotify Connect'; '_sonos._tcp' = 'Sonos'; '_amzn-wplay._tcp' = 'Fire TV casting'
        '_hap._tcp' = 'HomeKit'; '_homekit._tcp' = 'HomeKit'; '_matter._tcp' = 'Matter'; '_hue._tcp' = 'Philips Hue'; '_esphomelib._tcp' = 'ESPHome'; '_home-assistant._tcp' = 'Home Assistant'
        '_smb._tcp' = 'File sharing (SMB)'; '_afpovertcp._tcp' = 'Apple file sharing'; '_ssh._tcp' = 'SSH'; '_sftp-ssh._tcp' = 'SSH'; '_http._tcp' = 'Web page'; '_rfb._tcp' = 'Screen sharing'
        '_workstation._tcp' = 'Workstation'; '_companion-link._tcp' = 'Apple companion link'; '_apple-mobdev2._tcp' = 'iPhone / iPad sync'; '_androidtvremote2._tcp' = 'Android TV remote'
    }
    if ($map.ContainsKey($s)) { $map[$s] } else { $s }
}

function Get-NsDetailLines($d) {
    $l = New-Object System.Collections.Generic.List[object]
    $add = { param($k, $v) if ("$v") { $l.Add(@($k, "$v")) } }
    & $add 'Type' $d.KindText
    & $add 'Status' $(if ($d.Online) { "Online$(if ($d.LatencyMs -ge 0) { " ($($d.LatencyMs) ms)" })" } else { "Offline, last seen $($d.LastSeen.ToString('yyyy-MM-dd HH:mm'))" })
    & $add 'IP address' "$($d.Ip)$(if ($d.IsGateway) { ' (default gateway)' })"
    & $add 'MAC address' $(if ($d.Mac) { "$(Format-NsMac $d.Mac)$(if (Test-NsRandomMac $d.Mac) { ' (private / random)' })" })
    & $add 'Maker' $d.Vendor
    & $add 'Model' ((@($d.Manufacturer, $d.Model) | Where-Object { $_ } | Select-Object -Unique) -join ' ')
    & $add 'Host names' ((@($d.DnsName, $d.MdnsName, $(if ($d.NetBiosName) { "$($d.NetBiosName) (NetBIOS)" })) | Where-Object { $_ } | Select-Object -Unique) -join ', ')
    & $add 'Workgroup' $d.NetBiosGroup
    & $add 'System' $d.Os
    & $add 'Open ports' (($d.Ports | ForEach-Object { "$_ $($script:NsPortNames[[int]$_])" }) -join ', ')
    & $add 'Services' (($d.Services | ForEach-Object { Get-NsServiceName $_ } | Select-Object -Unique) -join ', ')
    & $add 'Web page' $d.HttpTitle
    & $add 'Web server' $d.HttpServer
    & $add 'UPnP' ((@($d.SsdpType, $d.SsdpServer) | Where-Object { $_ }) -join ' - ')
    & $add 'SNMP' $d.SnmpDescr
    & $add 'Why' ($d.Why -join '; ')
    , $l
}

function Get-NsDetailsText($d) {
    $out = @(Get-NsName $d)
    foreach ($x in (Get-NsDetailLines $d)) { $out += ('  {0,-13}{1}' -f ($x[0] + ':'), $x[1]) }
    $out -join [Environment]::NewLine
}

function Write-NsWrapped([string]$text, [int]$indent, [string]$color = 'Gray') {
    $w = 100; try { $w = $Host.UI.RawUI.WindowSize.Width - 2 } catch {}
    $width = [Math]::Max(30, $w - $indent)
    $line = ''; $first = $true
    foreach ($word in ($text -split ' ')) {
        if (($line + ' ' + $word).Trim().Length -gt $width -and $line) {
            Write-Host $(if ($first) { $line } else { (' ' * $indent) + $line }) -ForegroundColor $color
            $line = $word; $first = $false
        } else { $line = ($line + ' ' + $word).Trim() }
    }
    Write-Host $(if ($first) { $line } else { (' ' * $indent) + $line }) -ForegroundColor $color
}

function Show-NsDetails($d) {
    while ($true) {
        Write-Host ''
        Write-Host "  $(Get-NsName $d)" -ForegroundColor White
        Write-Host ('  ' + ('-' * [Math]::Min(70, (Get-NsName $d).Length + 2))) -ForegroundColor DarkGray
        foreach ($x in (Get-NsDetailLines $d)) {
            Write-Host ('  {0,-13}' -f $x[0]) -NoNewline -ForegroundColor DarkGray
            Write-NsWrapped $x[1] 15 $(if ($x[0] -eq 'Type') { Get-NsColor $d.Kind } elseif ($x[0] -eq 'Why') { 'DarkGray' } else { 'Gray' })
        }
        $web = $script:NsWebPorts | Where-Object { $d.Ports -contains $_ } | Select-Object -First 1
        $keys = @()
        if ($d.Online -and $web) { $keys += 'W open web page' }
        if ($d.Online -and $d.Ports -contains 3389 -and -not $d.IsSelf) { $keys += 'D Remote Desktop' }
        if ($d.Online -and $d.Ports -contains 445 -and -not $d.IsSelf) { $keys += 'F open shares' }
        $keys += 'C copy details'
        if (-not $d.Online -and $d.Mac.Length -eq 12 -and -not (Test-NsRandomMac $d.Mac)) { $keys += 'K wake up (Wake-on-LAN)' }
        $keys += 'Enter back'
        Write-Host ''
        Write-Host ('  ' + ($keys -join '   ')) -ForegroundColor DarkGray
        $k = (Read-NsKey '  Choose').ToLowerInvariant()
        switch ($k) {
            'w' { if ($web) { $url = "$(if (Test-NsHttps $web) { 'https' } else { 'http' })://$($d.Ip)$(if ($web -in @(80, 443)) { '' } else { ":$web" })/"; try { Start-Process $url } catch { Write-Host "  $url" } }; break }
            'd' { if ($d.Ports -contains 3389) { try { Start-Process mstsc.exe "/v:$($d.Ip)" } catch {} }; break }
            'f' { if ($d.Ports -contains 445) { try { Start-Process explorer.exe "\\$($d.Ip)" } catch {} }; break }
            'c' { try { Set-Clipboard -Value (Get-NsDetailsText $d); Write-Host '  Copied.' -ForegroundColor Green } catch { Write-Host "  Couldn't use the clipboard here." -ForegroundColor Yellow }; break }
            'k' {
                if ($d.Mac.Length -eq 12) {
                    try {
                        $m = [byte[]]($d.Mac -split '(..)' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) })
                        $packet = [byte[]](@(0xFF) * 6 + ($m * 16))
                        $u = New-Object Net.Sockets.UdpClient; $u.EnableBroadcast = $true
                        $bc = $script:NsRange.Broadcast; if (-not $bc) { $bc = [Net.IPAddress]::Broadcast }
                        [void]$u.Send($packet, $packet.Length, (New-Object Net.IPEndPoint $bc, 9)); $u.Dispose()
                        Write-Host "  Wake-on-LAN packet sent to $(Format-NsMac $d.Mac). Rescan in a minute." -ForegroundColor Green
                    } catch { Write-Host "  Couldn't send it: $($_.Exception.Message)" -ForegroundColor Yellow }
                }
                break
            }
            default { return }
        }
        if ($script:NsEof) { return }
    }
}

# ======================================================================================
#  Reports
# ======================================================================================

function Export-NsReport([string]$Path, $items) {
    $full = [IO.Path]::GetFullPath($Path)
    $ext = [IO.Path]::GetExtension($full).ToLowerInvariant()
    $net = if ($script:NsLastScan) { $script:NsLastScan.Range } else { 'network' }
    $when = Get-Date
    switch ($ext) {
        '.csv' {
            $rows = foreach ($d in $items) {
                $o = [ordered]@{
                    Status = $(if ($d.Online) { 'Online' } else { 'Offline' }); Name = (Get-NsName $d); Type = $d.KindText; 'IP address' = $d.Ip; 'MAC address' = (Format-NsMac $d.Mac); Maker = $d.Vendor
                    Model = ((@($d.Manufacturer, $d.Model) | Where-Object { $_ } | Select-Object -Unique) -join ' '); 'Host names' = ((@($d.DnsName, $d.MdnsName, $d.NetBiosName) | Where-Object { $_ }) -join ', ')
                    System = $d.Os; 'Open ports' = ($d.Ports -join ' '); 'Web page' = $d.HttpTitle; 'Last seen' = $d.LastSeen.ToString('yyyy-MM-dd HH:mm')
                }
                # a cell starting with = + - @ would run as a formula in Excel
                foreach ($k in @($o.Keys)) { if ("$($o[$k])" -match '^[=+\-@]') { $o[$k] = "'" + $o[$k] } }
                [pscustomobject]$o
            }
            $rows | Export-Csv -Path $full -NoTypeInformation -Encoding UTF8
        }
        '.json' {
            $obj = [ordered]@{ network = $net; scanned = $when.ToString('s'); devices = @($items | ForEach-Object {
                        [ordered]@{ online = $_.Online; name = (Get-NsName $_); type = $_.KindText; kind = $_.Kind; ip = $_.Ip; mac = (Format-NsMac $_.Mac); maker = $_.Vendor; manufacturer = $_.Manufacturer; model = $_.Model
                            dns = $_.DnsName; netbios = $_.NetBiosName; workgroup = $_.NetBiosGroup; mdns = $_.MdnsName; system = $_.Os; ports = @($_.Ports); services = @($_.Services); webTitle = $_.HttpTitle
                            webServer = $_.HttpServer; upnp = $_.SsdpType; snmp = $_.SnmpDescr; latencyMs = $_.LatencyMs; why = @($_.Why); lastSeen = $_.LastSeen.ToString('s') }
                    })
            }
            [IO.File]::WriteAllText($full, ($obj | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
        }
        '.txt' {
            $sb = New-Object Text.StringBuilder
            [void]$sb.AppendLine("pxd Network Scanner: $net, $($when.ToString('yyyy-MM-dd HH:mm'))")
            [void]$sb.AppendLine("$(@($items | Where-Object Online).Count) online, $(@($items | Where-Object { -not $_.Online }).Count) offline").AppendLine()
            foreach ($d in $items) { [void]$sb.AppendLine((Get-NsDetailsText $d)).AppendLine() }
            [IO.File]::WriteAllText($full, $sb.ToString(), (New-Object Text.UTF8Encoding $false))
        }
        default {
            $e = { param($s) [Net.WebUtility]::HtmlEncode("$s") }
            $rows = foreach ($d in $items) {
                $model = (@($d.Vendor, ((@($d.Manufacturer, $d.Model) | Where-Object { $_ } | Select-Object -Unique) -join ' ')) | Where-Object { $_ } | Select-Object -Unique) -join ' - '
                $hosts = (@($d.DnsName, $d.MdnsName, $d.NetBiosName) | Where-Object { $_ }) -join ', '
                "<tr class=`"$(if (-not $d.Online) { 'off' })`"><td class=`"$(if ($d.Online) { 'on' })`">$(if ($d.Online) { '&#9679;' } else { '&#9675;' })</td><td>$(& $e (Get-NsName $d))<div class=`"muted`">$(& $e $hosts)</div></td><td>$(& $e $d.KindText)<div class=`"muted`">$(& $e ($d.Why -join '; '))</div></td><td class=`"mono`">$(& $e $d.Ip)</td><td class=`"mono`">$(& $e (Format-NsMac $d.Mac))</td><td>$(& $e $model)</td><td class=`"mono`">$(& $e ($d.Ports -join ' '))</td><td>$($d.LastSeen.ToString('yyyy-MM-dd HH:mm'))</td></tr>"
            }
            $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network scan $(& $e $net)</title>
<style>
body { margin: 0; padding: 24px; background: #0E1015; color: #E8EAF0; font: 14px/1.45 "Segoe UI", system-ui, sans-serif; }
h1 { margin: 0 0 4px; font-size: 22px; } .muted { color: #8A92A6; }
table { border-collapse: collapse; width: 100%; margin-top: 18px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #272C39; vertical-align: top; }
th { color: #8A92A6; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
tr.off td { color: #6B7285; } .on { color: #19F58C; } .mono { font-family: Consolas, monospace; font-size: 13px; }
</style></head><body>
<h1>pxd Network Scanner</h1>
<div class="muted">$(& $e $net) - $($when.ToString('yyyy-MM-dd HH:mm')) - $(@($items | Where-Object Online).Count) online, $(@($items | Where-Object { -not $_.Online }).Count) offline</div>
<table><thead><tr><th></th><th>Name</th><th>Type</th><th>IP address</th><th>MAC address</th><th>Maker / model</th><th>Open ports</th><th>Last seen</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table></body></html>
"@
            [IO.File]::WriteAllText($full, $html, (New-Object Text.UTF8Encoding $false))
        }
    }
    $full
}

# ======================================================================================
#  Console
# ======================================================================================

$script:NsEof = $false
$script:NsMenu = @{}
function Read-NsKey([string]$Prompt) {
    $k = Read-Host $Prompt
    if ($null -eq $k) { $script:NsEof = $true; return 'q' }   # piped input ran out
    $k.Trim()
}

# ---- PD header ---------------------------------------------------------------------------------------------------
# The PD logo beside the tool's name, shown once when a pxdtek CLI tool starts. The master copy is cli/PdHeader.ps1
# in the pxdtek repo; each tool carries a copy (they run through irm | iex, so they can't load it). Keep them in sync.
# ASCII-only on purpose, so irm | iex never trips on encoding: the solid-block logo is stored as letters
# (U = upper half block, D = lower half block, F = full block) and turned into blocks when it's shown.
# Each run picks one of the two logos at random; a window too narrow for the logo gets a one-line header.
function Show-PdHeader {
    param([string]$Name, [string]$Version = '', [string[]]$About = @(), [string]$Command = '')
    $ascii = @(
        '      -++++++++++-'
        '   :++-          -++:'
        '  ++        +#-     ++'
        ' #-         -+@%-    -#'
        '++    =##*%#%=-=##.   ++'
        '%    +%. .@:+%   *#    %'
        '%    #*   %+:@. .%+    %'
        '++   .##=-=%#%*##=    ++'
        ' #-    -%@+-         -#'
        '  ++     -#+        ++'
        '   :++-          -++:'
        '      -++++++++++-'
    )
    $blocks = @(
        '      DDDUUUUUUDDD'
        '    DUU          UUD'
        '  DU        UFD     UD'
        ' FU         DDFFD    UF'
        'DU    DFUUFFFU UUF    UD'
        'F    DF   F UF   FF    F'
        'F    FF   FD F   FU    F'
        'UD    FDD DFFFDDFU    DU'
        ' FD    UFFUU         DF'
        '  UD     UFD        DU'
        '    UDD          DDU'
        '      UUUDDDDDDUUU'
    )
    $text = New-Object System.Collections.Generic.List[object]
    $text.Add(@($Name, 'White'))
    $text.Add(@(((@($Version, 'pxdtek.com') | Where-Object { $_ }) -join '  -  '), 'DarkGray'))
    if ($About) { $text.Add(@('', 'Gray')); foreach ($a in $About) { $text.Add(@($a, 'Gray')) } }
    if ($Command) { $text.Add(@('', 'Gray')); $text.Add(@($Command, 'DarkCyan')) }
    $textWidth = ($text | ForEach-Object { $_[0].Length } | Measure-Object -Maximum).Maximum

    $w = 0
    try { $w = $Host.UI.RawUI.WindowSize.Width } catch {}
    Write-Host ''
    if ($w -gt 0 -and $w -lt 30 + $textWidth) {
        Write-Host '  (pd) ' -NoNewline -ForegroundColor Cyan
        Write-Host $Name -NoNewline -ForegroundColor White
        Write-Host $(if ($Version) { "  $Version" } else { '' }) -ForegroundColor DarkGray
        Write-Host ''
        return
    }

    if ($null -eq (Get-Variable -Name PdHeaderStyle -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) { $script:PdHeaderStyle = Get-Random -Minimum 0 -Maximum 2 }
    $useBlocks = $script:PdHeaderStyle -eq 1
    $top = [Math]::Max(0, [Math]::Floor(($ascii.Count - $text.Count) / 2))
    for ($i = 0; $i -lt $ascii.Count; $i++) {
        Write-Host '  ' -NoNewline
        if ($useBlocks) {
            $l = $blocks[$i].Replace('U', [string][char]0x2580).Replace('D', [string][char]0x2584).Replace('F', [string][char]0x2588)
            Write-Host $l.PadRight(24) -NoNewline -ForegroundColor Cyan
        } else {
            # dense strokes white, the middle cyan, the edges dark cyan: one colour run at a time
            $run = ''; $col = ''
            foreach ($c in $ascii[$i].PadRight(24).ToCharArray()) {
                $k = if ('@%#'.Contains([string]$c)) { 'White' } elseif ('*+='.Contains([string]$c)) { 'Cyan' } else { 'DarkCyan' }
                if ($k -ne $col -and $run) { Write-Host $run -NoNewline -ForegroundColor $col; $run = '' }
                $col = $k; $run += $c
            }
            if ($run) { Write-Host $run -NoNewline -ForegroundColor $col }
        }
        $j = $i - $top
        if ($j -ge 0 -and $j -lt $text.Count -and $text[$j][0]) { Write-Host ('    ' + $text[$j][0]) -NoNewline -ForegroundColor $text[$j][1] }
        Write-Host ''
    }
    Write-Host ''
}
# ---- end of PD header --------------------------------------------------------------------------------------------

function Select-NsRange($Locals) {
    Write-Host ''
    $i = 0
    foreach ($l in $Locals) { $i++; Write-Host ("   [$i] $($l.Adapter)  -  $($l.Text)  (this PC $($l.LocalIp))") }
    Write-Host '   or type a range: 192.168.1.0/24, 192.168.1.1-254, 172.16.0.20-172.16.0.80' -ForegroundColor DarkGray
    $k = Read-NsKey '  Network'
    if (-not $k) { return $null }
    $n = 0
    if ([int]::TryParse($k, [ref]$n) -and $n -ge 1 -and $n -le @($Locals).Count) { return @($Locals)[$n - 1] }
    $r = ConvertTo-NsRange $k $Locals
    if (-not $r) { Write-Host "  $($script:NsError)" -ForegroundColor Yellow }
    $r
}

function Start-NsConsole($Locals, [string]$Group) {
    Show-PdHeader -Name 'pxd Network Scanner' -Version "CLI $($script:NsVersion)" -Command 'irm pxdtek.com/ns|iex'
    if ($script:NsInMemory) { Write-Host '  In-memory: nothing is saved on this PC.' -ForegroundColor DarkGray }
    $onlineOnly = $false; $search = ''
    Write-Host "  Scanning $($script:NsRange.Text)$(if ($script:NsRange.Adapter) { " on $($script:NsRange.Adapter)" })..." -ForegroundColor DarkCyan
    Invoke-NsScan $script:NsRange -Quick:$Quick
    while (-not $script:NsEof) {
        $g = $script:NsGroups | Where-Object { $_.Key -eq $Group } | Select-Object -First 1
        $items = Get-NsShown $Group $onlineOnly $search
        $script:NsMenu = @{}
        $on = @($script:NsDevices | Where-Object Online).Count; $off = $script:NsDevices.Count - $on
        Write-Host ''
        Write-Host "  $($g.Name)" -NoNewline -ForegroundColor White
        Write-Host "  -  $($script:NsLastScan.Range)  -  $on online$(if ($off) { ", $off offline" })  -  scanned $($script:NsLastScan.When.ToString('HH:mm')) in $([Math]::Round($script:NsLastScan.Seconds, 1)) s$(if ($onlineOnly) { '  -  online only' })$(if ($search) { "  -  '$search'" })" -ForegroundColor DarkGray
        Show-NsTable $items
        Write-Host ''
        $counts = ($script:NsGroups | Select-Object -Skip 1 | ForEach-Object { $k = $_; $n = @($script:NsDevices | Where-Object { $k.Kinds -contains $_.Kind -and (-not $onlineOnly -or $_.Online) }).Count; if ($n) { "$($k.Name) $n" } }) -join ', '
        if ($counts) { Write-Host "  $counts" -ForegroundColor DarkGray }
        Write-Host "  [number] details   T type   O online only $(if ($onlineOnly) { 'off' } else { 'on' })   S search   R rescan   N network   E export   Q quit" -ForegroundColor DarkGray
        $k = Read-NsKey '  Choose'
        switch -Regex ($k.ToLowerInvariant()) {
            '^q$' { return }
            '^t$' {
                $i = 0; foreach ($x in $script:NsGroups) { $i++; Write-Host ("   [$i] $($x.Name)") }
                $p = Read-NsKey '  Show'; $n = 0
                if ([int]::TryParse($p, [ref]$n) -and $n -ge 1 -and $n -le $script:NsGroups.Count) { $Group = $script:NsGroups[$n - 1].Key }
                break
            }
            '^o$' { $onlineOnly = -not $onlineOnly; break }
            '^s$' { $search = Read-NsKey '  Search name, IP, MAC, maker, model or port (Enter clears)'; break }
            '^r$' { Write-Host "  Scanning $($script:NsRange.Text)..." -ForegroundColor DarkCyan; Invoke-NsScan $script:NsRange -Quick:$Quick; break }
            '^n$' {
                $r = Select-NsRange $Locals
                if ($r) { $script:NsRange = $r; Write-Host "  Scanning $($r.Text)..." -ForegroundColor DarkCyan; Invoke-NsScan $r -Quick:$Quick }
                break
            }
            '^e$' {
                $default = Join-Path ([Environment]::GetFolderPath('Desktop')) ("pxd-Network-$(Get-Date -Format 'yyyyMMdd-HHmm').html")
                $p = Read-NsKey "  Save the devices shown as (.html, .csv, .json or .txt; Enter = $default)"
                if ($script:NsEof) { break }
                if (-not $p) { $p = $default }
                try { $full = Export-NsReport $p $items; Write-Host "  Saved $full" -ForegroundColor Green } catch { Write-Host "  Couldn't save: $($_.Exception.Message)" -ForegroundColor Yellow }
                break
            }
            '^\d+$' { $n = [int]$k; if ($script:NsMenu.ContainsKey($n - 1)) { Show-NsDetails $script:NsMenu[$n - 1] }; break }
        }
    }
}

# ======================================================================================
#  Entry
# ======================================================================================

if ($env:OS -ne 'Windows_NT') { Write-Host 'pxd Network Scanner uses Windows networking, so it runs on Windows only.' -ForegroundColor Yellow; return }

$locals = @(Get-NsLocalRanges)
if ($Range) {
    $script:NsRange = ConvertTo-NsRange $Range $locals
    if (-not $script:NsRange) { Write-Host "  $($script:NsError)" -ForegroundColor Yellow; return }
} elseif ($locals.Count -gt 0) {
    $script:NsRange = $locals[0]
} else {
    Write-Host '  No network connection found. Pass -Range 192.168.1.0/24 to scan a range.' -ForegroundColor Yellow; return
}

if ($List -or $Export) {
    if ($script:NsInMemory -and -not $Export) { Write-Host '  In-memory: nothing is saved on this PC.' -ForegroundColor DarkGray }
    Invoke-NsScan $script:NsRange -Quick:$Quick
    $items = Get-NsShown $Show $false ''
    if ($List) {
        Write-Host "  $($script:NsLastScan.Range)  -  $($script:NsLastScan.Count) device(s) answered in $([Math]::Round($script:NsLastScan.Seconds, 1)) s" -ForegroundColor DarkGray
        Show-NsTable $items; Write-Host ''
    }
    if ($Export) { $full = Export-NsReport $Export $items; Write-Host "  Saved $full" -ForegroundColor Green }
    return
}

Start-NsConsole $locals $Show
