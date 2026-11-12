<#
.SYNOPSIS
    Checkmk agent plugin: windows_update_tracker

.DESCRIPTION
    Reports pending Windows updates (with KB number, classification, MSRC severity,
    publish date and the time the update was first seen on this host), the pending
    reboot state (including since when) and the recent update installation history.

    Output: section <<<windows_update_tracker:sep(0)>>>, one JSON object per line.
    All filtering and thresholds are applied on the Checkmk server.

    The Windows Update search is slow (30 s up to several minutes), so this plugin
    MUST run asynchronously, e.g. every 4 hours. Example check_mk.user.yml:

        plugins:
          execution:
            - pattern: $CUSTOM_PLUGINS_PATH$\windows_update_tracker.ps1
              async: yes
              cache_age: 14400
              timeout: 600

    State (first-seen timestamps, reboot-pending-since, last successful search) is
    kept in %ProgramData%\checkmk\agent\state\windows_update_tracker.json.

.NOTES
    Project:  https://github.com/KeksDipp/checkmk-plugins
    License:  GPL-2.0
    Requires: Windows PowerShell 5.1, runs as LocalSystem (Checkmk agent)
#>

$ErrorActionPreference = 'Stop'
$PluginVersion = '1.0.0'
$HistoryDays = 30
$HistoryMaxEntries = 300

$StateDir = if ($env:MK_STATEDIR) { $env:MK_STATEDIR } else { Join-Path $env:ProgramData 'checkmk\agent\state' }
$StateFile = Join-Path $StateDir 'windows_update_tracker.json'

# Update classification category IDs are language independent (names are localized).
$ClassificationIds = @{
    '0fa1201d-4330-4fa8-8ae9-b877473b6441' = 'security'
    'e6cf1350-c01b-414d-a61f-263d14d133b4' = 'critical'
    'e0789628-ce08-4437-be74-2495b842f43b' = 'definition'
    'ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0' = 'driver'
    'b54e7d24-7add-428f-8b75-90a396fa584f' = 'feature_pack'
    '68c5b0a3-d1a6-4553-ae49-01d3a7827828' = 'service_pack'
    'b4832bd8-e735-4761-8daf-37f882276dab' = 'tool'
    '28bc880e-0592-4cbf-8f95-c79b17911d5f' = 'update_rollup'
    'cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83' = 'update'
    '3689bdc8-b205-4af4-8d4a-a63924c5e9d5' = 'upgrade'
}

# IUpdateHistoryEntry.ResultCode
$ResultCodes = @{ 0 = 'not_started'; 1 = 'in_progress'; 2 = 'succeeded'; 3 = 'succeeded_with_errors'; 4 = 'failed'; 5 = 'aborted' }

function ConvertTo-Epoch {
    param($Date, [switch]$AssumeUtc)
    if ($null -eq $Date) { return $null }
    try {
        $dt = [DateTime]$Date
        if ($dt.Year -lt 1980) { return $null }
        if ($AssumeUtc -and $dt.Kind -ne [DateTimeKind]::Local) {
            $dt = [DateTime]::SpecifyKind($dt, [DateTimeKind]::Utc)
        }
        return [int64]([DateTimeOffset]$dt).ToUnixTimeSeconds()
    } catch { return $null }
}

function Get-Now { [int64]([DateTimeOffset]::UtcNow).ToUnixTimeSeconds() }

# JSON line with every non-ASCII character escaped -> no output-encoding issues.
function Write-JsonLine {
    param([hashtable]$Data)
    $json = ConvertTo-Json -InputObject $Data -Compress -Depth 5
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $json.ToCharArray()) {
        if ([int]$ch -gt 127) { [void]$sb.AppendFormat('\u{0:x4}', [int]$ch) } else { [void]$sb.Append($ch) }
    }
    Write-Output $sb.ToString()
}

function Get-Classification {
    param($Categories)
    if ($null -eq $Categories) { return @('other', '') }
    foreach ($cat in $Categories) {
        try {
            if ($cat.Type -eq 'UpdateClassification') {
                $key = $ClassificationIds[[string]$cat.CategoryID.ToLower()]
                if (-not $key) { $key = 'other' }
                return @($key, [string]$cat.Name)
            }
        } catch { }
    }
    return @('other', '')
}

function Get-KbList {
    param($Update, [string]$Title)
    $kbs = @()
    try { foreach ($kb in $Update.KBArticleIDs) { $kbs += ('KB' + $kb) } } catch { }
    if ($kbs.Count -eq 0 -and $Title) {
        foreach ($m in [regex]::Matches($Title, 'KB\d{5,8}')) { $kbs += $m.Value }
    }
    return , @($kbs | Select-Object -Unique)
}

function Read-State {
    $state = @{ first_seen = @{}; reboot_since = $null; last_success = $null; last_pending = @() }
    if (Test-Path -LiteralPath $StateFile) {
        try {
            $raw = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
            if ($raw.first_seen) {
                foreach ($p in $raw.first_seen.PSObject.Properties) { $state.first_seen[$p.Name] = [int64]$p.Value }
            }
            if ($raw.reboot_since) { $state.reboot_since = [int64]$raw.reboot_since }
            if ($raw.last_success) { $state.last_success = [int64]$raw.last_success }
            if ($raw.last_pending) { $state.last_pending = @($raw.last_pending) }
        } catch { }
    }
    return $state
}

function Write-State {
    param([hashtable]$State)
    try {
        if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
        $tmp = "$StateFile.tmp"
        ConvertTo-Json -InputObject $State -Depth 6 -Compress | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $StateFile -Force
    } catch { }
}

function Get-UpdateSource {
    try {
        $wu = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
        $au = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
        if ($au -and $au.UseWUServer -eq 1 -and $wu -and $wu.WUServer) { return "WSUS $($wu.WUServer)" }
    } catch { }
    try {
        $sm = New-Object -ComObject Microsoft.Update.ServiceManager
        foreach ($svc in $sm.Services) { if ($svc.IsDefaultAUService) { return [string]$svc.Name } }
    } catch { }
    return 'unknown'
}

# ---------------------------------------------------------------------------
$now = Get-Now
$state = Read-State

$meta = @{
    type           = 'meta'
    plugin_version = $PluginVersion
    now            = $now
    search_ok      = $false
    search_time    = $now
    last_success   = $state.last_success
    error          = $null
    hresult        = $null
    source         = (Get-UpdateSource)
    wu_start_type  = $null
}
try { $meta.wu_start_type = [string](Get-Service -Name wuauserv).StartType } catch { }

$session = $null
$pending = @()
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'checkmk windows_update_tracker'
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search('IsInstalled=0 and IsHidden=0')

    $seenIds = @{}
    foreach ($u in $result.Updates) {
        $id = [string]$u.Identity.UpdateID
        $seenIds[$id] = $true
        if (-not $state.first_seen.ContainsKey($id)) { $state.first_seen[$id] = $now }
        $cls = Get-Classification $u.Categories
        $title = [string]$u.Title
        $severity = ''
        try { if ($u.MsrcSeverity) { $severity = ([string]$u.MsrcSeverity).ToLower() } } catch { }
        $pending += @{
            type                = 'pending'
            id                  = $id
            kb                  = (Get-KbList $u $title)
            title               = $title
            classification      = $cls[0]
            classification_name = $cls[1]
            severity            = $severity
            published           = (ConvertTo-Epoch $u.LastDeploymentChangeTime)
            first_seen          = $state.first_seen[$id]
            downloaded          = [bool]$u.IsDownloaded
            mandatory           = [bool]$u.IsMandatory
        }
    }
    # Forget updates that are no longer pending
    foreach ($k in @($state.first_seen.Keys)) { if (-not $seenIds.ContainsKey($k)) { $state.first_seen.Remove($k) } }

    $meta.search_ok = $true
    $meta.last_success = $now
    $state.last_success = $now
    $state.last_pending = $pending
} catch {
    $meta.error = [string]$_.Exception.Message
    try { $meta.hresult = '0x{0:X8}' -f $_.Exception.HResult } catch { }
    # Re-report the last successful result so the pending list does not drop to zero
    $pending = @()
    foreach ($p in $state.last_pending) {
        $h = @{}
        foreach ($prop in $p.PSObject.Properties) { $h[$prop.Name] = $prop.Value }
        $pending += $h
    }
}

# --- Pending reboot --------------------------------------------------------
$rebootSources = @()
try { if ((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired) { $rebootSources += 'wu_api' } } catch { }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rebootSources += 'wu_registry' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $rebootSources += 'cbs' }

$bootTime = $null
try { $bootTime = ConvertTo-Epoch (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime } catch { }

if ($rebootSources.Count -gt 0) {
    if (-not $state.reboot_since -or ($bootTime -and $state.reboot_since -lt $bootTime)) { $state.reboot_since = $now }
} else {
    $state.reboot_since = $null
}
$reboot = @{
    type      = 'reboot'
    required  = ($rebootSources.Count -gt 0)
    since     = $state.reboot_since
    sources   = $rebootSources
    boot_time = $bootTime
}

# --- History ---------------------------------------------------------------
$history = @()
try {
    if (-not $session) { $session = New-Object -ComObject Microsoft.Update.Session }
    $hs = $session.CreateUpdateSearcher()
    $count = $hs.GetTotalHistoryCount()
    if ($count -gt 0) {
        $limit = [Math]::Min($count, $HistoryMaxEntries)
        $minEpoch = $now - ($HistoryDays * 86400)
        foreach ($e in $hs.QueryHistory(0, $limit)) {
            $date = ConvertTo-Epoch $e.Date -AssumeUtc
            if ($null -eq $date -or $date -lt $minEpoch) { continue }
            if ($e.Operation -ne 1) { continue }   # 1 = installation, 2 = uninstallation
            $title = [string]$e.Title
            $cls = @('other', '')
            try { $cls = Get-Classification $e.Categories } catch { }
            $history += @{
                type           = 'history'
                id             = [string]$e.UpdateIdentity.UpdateID
                kb             = (Get-KbList $null $title)
                title          = $title
                classification = $cls[0]
                date           = $date
                result         = $ResultCodes[[int]$e.ResultCode]
                hresult        = ('0x{0:X8}' -f $e.HResult)
            }
        }
    }
} catch {
    $meta.history_error = [string]$_.Exception.Message
}

Write-State $state

Write-Output '<<<windows_update_tracker:sep(0)>>>'
Write-JsonLine $meta
foreach ($p in $pending) { Write-JsonLine $p }
Write-JsonLine $reboot
foreach ($h in $history) { Write-JsonLine $h }
