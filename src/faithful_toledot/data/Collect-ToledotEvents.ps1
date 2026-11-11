# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Collect Active Directory change events for toledot. Read-only.

.DESCRIPTION
    Reads the Security and System event logs of this computer and writes the events
    toledot understands to one file in the toledot collection format: a header line,
    one JSON line per event, and an end line with the event count and a SHA-256 of
    everything before it. Field names and values are taken from each event's XML,
    exactly as Windows records them.

    The script changes nothing on the computer. Its only write is the output file,
    which it never overwrites unless -Force is given. Reading the Security log needs
    an elevated session or membership of Event Log Readers; a log that cannot be
    read is recorded in the file as a gap, never skipped silently.

    Runs on Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER OutFile
    The file to write, for example dc01-events.jsonl.

.PARAMETER Since
    Collect events from this time. Default: 7 days ago, or -Days days ago.

.PARAMETER Until
    Collect events before this time. Default: now.

.PARAMETER Days
    Collect the last N days when -Since is not given. Default: 7.

.PARAMETER Channel
    The logs to read. Default: Security and System.

.PARAMETER All
    Collect every event in the period, not only the ones toledot understands. With
    -All the file says it holds whole logs, so absent record numbers then count as
    missing events.

.PARAMETER Force
    Replace -OutFile if it exists.

.PARAMETER ToPipeline
    Write the lines to the output stream instead of a file. toledot's remote
    collection uses this.

.PARAMETER Method
    How the collection was run, recorded in the header: powershell or psrp.

.EXAMPLE
    .\Collect-ToledotEvents.ps1 -OutFile dc01-events.jsonl -Days 30
#>
[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'File')]
    [string] $OutFile,
    [Parameter(ParameterSetName = 'Pipeline')]
    [switch] $ToPipeline,
    [Nullable[datetime]] $Since,
    [Nullable[datetime]] $Until,
    [ValidateRange(1, 3650)]
    [int] $Days = 7,
    [ValidateCount(1, 16)]
    [string[]] $Channel = @('Security', 'System'),
    [switch] $All,
    [Parameter(ParameterSetName = 'File')]
    [switch] $Force,
    [ValidateSet('powershell', 'psrp')]
    [string] $Method = 'powershell'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$CollectorName = 'Collect-ToledotEvents.ps1'
$CollectorVersion = '0.1.0'
# The events toledot understands, by log. Kept in step with toledot's catalog by a
# test in the toledot repository.
$WantedIds = @{
    'Security' = @(
        1100, 1101, 1102, 1104, 1105, 4616, 4624, 4634, 4647, 4648, 4670, 4672, 4704, 4705,
        4706, 4707, 4713, 4716, 4717, 4718, 4719, 4720, 4722, 4723, 4724, 4725, 4726, 4727,
        4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4738, 4739, 4740, 4741, 4742,
        4743, 4744, 4745, 4746, 4747, 4748, 4749, 4750, 4751, 4752, 4753, 4754, 4755, 4756,
        4757, 4758, 4759, 4760, 4761, 4762, 4763, 4764, 4765, 4766, 4767, 4768, 4769, 4776,
        4780, 4781, 4794, 4865, 4866, 4867, 4907, 5136, 5137, 5138, 5139, 5141
    )
    'System'   = @(104)
}
# Event log queries fail when an XPath filter has too many terms, so IDs are asked
# for in ranges, a few at a time, and checked again here.
$MaxTermsPerQuery = 20
$Invariant = [System.Globalization.CultureInfo]::InvariantCulture

# --- Text and JSON ------------------------------------------------------------------

$JsonPattern = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
    '[\x00-\x1f"\\\u007f-\uffff]', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$JsonEscape = [System.Text.RegularExpressions.MatchEvaluator] {
    param($Match)
    $c = $Match.Value[0]
    switch ([int] $c) {
        0x22 { return '\"' }
        0x5C { return '\\' }
        0x0A { return '\n' }
        0x0D { return '\r' }
        0x09 { return '\t' }
        default { return '\u' + ([int] $c).ToString('x4', $Invariant) }
    }
}

function ConvertTo-JsonText($Value) {
    # Every character outside printable ASCII is written as \uXXXX, so each line is
    # plain ASCII whatever the event holds. An unpaired surrogate stays visible as
    # its own escape, and toledot reports that line instead of guessing.
    if ($null -eq $Value) { return 'null' }
    '"' + $JsonPattern.Replace([string] $Value, $JsonEscape) + '"'
}

function ConvertTo-JsonObject($Pairs) {
    # $Pairs is an ordered dictionary of name to text. Values are always text.
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($key in $Pairs.Keys) {
        $parts.Add((ConvertTo-JsonText $key) + ':' + (ConvertTo-JsonText ([string] $Pairs[$key])))
    }
    '{' + ($parts -join ',') + '}'
}

function Format-UtcTime([datetime] $Time) {
    $Time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", $Invariant)
}

function ConvertTo-JsonTimeOrNull([Nullable[datetime]] $Time) {
    if ($null -eq $Time) { return 'null' }
    '"' + (Format-UtcTime $Time) + '"'
}

function ConvertTo-JsonNumberOrNull($Value) {
    if ($null -eq $Value) { return 'null' }
    ([long] $Value).ToString($Invariant)
}

# --- Event XML ----------------------------------------------------------------------

function Read-EventXml([string] $Xml) {
    # Parse one event's XML with DTDs and external entities refused.
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 16MB
    $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader -ArgumentList $Xml), $settings)
    try {
        $document = New-Object System.Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
        $document
    } finally {
        $reader.Dispose()
    }
}

function Get-ChildElement($Node, [string] $Name) {
    foreach ($child in $Node.ChildNodes) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element -and $child.LocalName -eq $Name) {
            return $child
        }
    }
    $null
}

function Add-Field($Fields, [string] $Name, [string] $Value) {
    # A repeated name keeps the first under its name and the later ones as name#2,
    # name#3, as toledot's other readers do.
    if (-not $Fields.Contains($Name)) { $Fields[$Name] = $Value; return }
    $n = 2
    while ($Fields.Contains("$Name#$n")) { $n++ }
    $Fields["$Name#$n"] = $Value
}

function Get-EventFields([string] $Xml) {
    # Return the System fields toledot keeps and the EventData or UserData fields,
    # by name, in the order the event holds them.
    $event = (Read-EventXml $Xml).DocumentElement
    $system = [ordered] @{}
    $data = [ordered] @{}
    $systemNode = Get-ChildElement $event 'System'
    if ($null -ne $systemNode) {
        foreach ($child in $systemNode.ChildNodes) {
            if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            switch ($child.LocalName) {
                'Correlation' { $system['ActivityID'] = $child.GetAttribute('ActivityID') }
                'Execution' {
                    $system['ProcessID'] = $child.GetAttribute('ProcessID')
                    $system['ThreadID'] = $child.GetAttribute('ThreadID')
                }
                'Security' { $system['UserID'] = $child.GetAttribute('UserID') }
                { $_ -in @('Level', 'Task', 'Opcode', 'Keywords') } { $system[$child.LocalName] = $child.InnerText }
            }
        }
    }
    $eventData = Get-ChildElement $event 'EventData'
    $userData = Get-ChildElement $event 'UserData'
    if ($null -ne $eventData) {
        $position = 0
        foreach ($child in $eventData.ChildNodes) {
            if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            if ($child.LocalName -eq 'Data') {
                $position++
                $name = $child.GetAttribute('Name')
                if (-not $name) { $name = "param$position" }
                Add-Field $data $name $child.InnerText
            } elseif ($child.LocalName -eq 'Binary') {
                Add-Field $data 'Binary' $child.InnerText
            }
        }
    } elseif ($null -ne $userData) {
        $wrapper = $null
        foreach ($child in $userData.ChildNodes) {
            if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) { $wrapper = $child; break }
        }
        if ($null -ne $wrapper) {
            foreach ($child in $wrapper.ChildNodes) {
                if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                $parts = @($child.SelectNodes('.//text()') | ForEach-Object { $_.Value } |
                        Where-Object { $_.Trim() })
                $value = if ($child.HasChildNodes -and $child.FirstChild.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                    $parts -join ' '
                } else { $child.InnerText }
                Add-Field $data $child.LocalName $value
            }
        }
    }
    @{ System = $system; Data = $data }
}

function Format-EventLine([long] $RecordId, [int] $EventId, [int] $Version, [datetime] $Time,
    [string] $Computer, [string] $LogName, [string] $Provider, [string] $Xml) {
    $fields = Get-EventFields $Xml
    '{"record_id":' + $RecordId.ToString($Invariant) +
    ',"event_id":' + $EventId.ToString($Invariant) +
    ',"version":' + $Version.ToString($Invariant) +
    ',"time":"' + (Format-UtcTime $Time) + '"' +
    ',"computer":' + (ConvertTo-JsonText $Computer) +
    ',"channel":' + (ConvertTo-JsonText $LogName) +
    ',"provider":' + (ConvertTo-JsonText $Provider) +
    ',"system":' + (ConvertTo-JsonObject $fields.System) +
    ',"data":' + (ConvertTo-JsonObject $fields.Data) + '}'
}

# --- Queries ------------------------------------------------------------------------

function Get-IdRanges([int[]] $Ids) {
    # Collapse sorted IDs into "EventID=n" and "(EventID>=a and EventID<=b)" terms.
    $terms = New-Object System.Collections.Generic.List[string]
    $sorted = @($Ids | Sort-Object -Unique)
    $i = 0
    while ($i -lt $sorted.Count) {
        $j = $i
        while ($j + 1 -lt $sorted.Count -and $sorted[$j + 1] -eq $sorted[$j] + 1) { $j++ }
        if ($j -eq $i) { $terms.Add("EventID=$($sorted[$i])") }
        else { $terms.Add("(EventID>=$($sorted[$i]) and EventID<=$($sorted[$j]))") }
        $i = $j + 1
    }
    , $terms.ToArray()
}

function Get-QueryText([string[]] $Terms, [datetime] $From, [Nullable[datetime]] $To) {
    $time = "TimeCreated[@SystemTime>='$(Format-UtcTime $From)'"
    if ($null -ne $To) { $time += " and @SystemTime<'$(Format-UtcTime $To)'" }
    $time += ']'
    if ($Terms.Count -eq 0) { return "*[System[$time]]" }
    "*[System[($($Terms -join ' or ')) and $time]]"
}

function Get-LogFacts([string] $Name, $Gaps) {
    $facts = [ordered] @{
        channel = $Name; oldest_record_id = $null; oldest_time = $null; newest_record_id = $null
        record_count = $null; max_size_bytes = $null; mode = 'unknown'
    }
    try {
        $config = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList $Name
        $facts.max_size_bytes = $config.MaximumSizeInBytes
        $facts.mode = switch ([string] $config.LogMode) {
            'Circular' { 'circular' } 'Retain' { 'retain' } 'AutoBackup' { 'autobackup' } default { 'unknown' }
        }
        $config.Dispose()
        $session = New-Object System.Diagnostics.Eventing.Reader.EventLogSession
        $info = $session.GetLogInformation($Name, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
        $facts.record_count = $info.RecordCount
        foreach ($reverse in @($false, $true)) {
            $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery -ArgumentList @(
                $Name, [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*')
            $query.ReverseDirection = $reverse
            $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader -ArgumentList $query
            try {
                $record = $reader.ReadEvent()
                if ($null -ne $record) {
                    if ($reverse) { $facts.newest_record_id = $record.RecordId }
                    else {
                        $facts.oldest_record_id = $record.RecordId
                        $facts.oldest_time = $record.TimeCreated
                    }
                    $record.Dispose()
                }
            } finally { $reader.Dispose() }
        }
    } catch {
        $Gaps.Add([ordered] @{ area = "the $Name log's size and oldest record"; reason = $_.Exception.Message })
    }
    $facts
}

function ConvertTo-LogJson($Facts) {
    '{"channel":' + (ConvertTo-JsonText $Facts.channel) +
    ',"oldest_record_id":' + (ConvertTo-JsonNumberOrNull $Facts.oldest_record_id) +
    ',"oldest_time":' + (ConvertTo-JsonTimeOrNull $Facts.oldest_time) +
    ',"newest_record_id":' + (ConvertTo-JsonNumberOrNull $Facts.newest_record_id) +
    ',"record_count":' + (ConvertTo-JsonNumberOrNull $Facts.record_count) +
    ',"max_size_bytes":' + (ConvertTo-JsonNumberOrNull $Facts.max_size_bytes) +
    ',"mode":"' + $Facts.mode + '"}'
}

# --- Output -------------------------------------------------------------------------

function New-LineWriter([string] $Path, [bool] $Pipeline) {
    # Writes lines as UTF-8 with "\n" endings and keeps a running SHA-256 of them.
    # A file is never written under its final name: lines go to a new temporary file
    # next to it, created with CreateNew so it cannot be a file that already exists,
    # and Publish-Output moves it into place only once the end line is written.
    $writer = [pscustomobject] @{
        Stream = $null; Hash = [System.Security.Cryptography.SHA256]::Create()
        Pipeline = $Pipeline; Count = 0; TempPath = $null
    }
    if (-not $Pipeline) {
        $writer.TempPath = $Path + '.' + [guid]::NewGuid().ToString('N') + '.part'
        $writer.Stream = New-Object System.IO.FileStream -ArgumentList @(
            $writer.TempPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
    }
    $writer
}

function Write-Line($Writer, [string] $Line, [switch] $Last) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Line + "`n")
    if (-not $Last) { [void] $Writer.Hash.TransformBlock($bytes, 0, $bytes.Length, $null, 0) }
    if ($Writer.Pipeline) { Write-Output $Line } else { $Writer.Stream.Write($bytes, 0, $bytes.Length) }
}

function Get-HashText($Writer) {
    [void] $Writer.Hash.TransformFinalBlock([byte[]] @(), 0, 0)
    -join ($Writer.Hash.Hash | ForEach-Object { $_.ToString('x2', $Invariant) })
}

function Close-LineWriter($Writer) {
    # Safe to call twice: the stream is released the first time.
    if ($null -ne $Writer.Stream) { $Writer.Stream.Flush(); $Writer.Stream.Dispose(); $Writer.Stream = $null }
    $Writer.Hash.Dispose()
}

function Publish-Output($Writer, [string] $Path, [bool] $Replace) {
    # Called after the stream is closed. Without -Force the move fails if the name is
    # taken, even by a file that appeared after the start. With -Force the old file is
    # replaced in one step where the file system allows. File.Move with overwrite is
    # .NET Core 3.0 and later only, and this script must also run on Windows PowerShell
    # 5.1 (.NET Framework), so File.Replace is used when the target exists and a plain
    # move when it does not. Delete-then-move would leave no file at all if it failed
    # in between.
    if ($Replace -and [System.IO.File]::Exists($Path)) {
        # [NullString]::Value, because PowerShell turns a plain $null into "" for a
        # string argument, and "" is refused as the backup name.
        [System.IO.File]::Replace($Writer.TempPath, $Path, [NullString]::Value)
    } else {
        [System.IO.File]::Move($Writer.TempPath, $Path)
    }
}

# --- Collection ---------------------------------------------------------------------

function Get-ComputerName {
    try { [System.Net.Dns]::GetHostEntry([string] '').HostName } catch { $env:COMPUTERNAME }
}

function Get-OperatorName {
    try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $null }
}

function Invoke-Collection {
    $from = if ($null -ne $Since) { [datetime] $Since } else { (Get-Date).AddDays(-$Days) }
    $to = $Until
    if ($null -ne $to -and $to -le $from) { throw '-Until must be later than -Since.' }
    $gaps = New-Object System.Collections.Generic.List[object]
    if (-not $ToPipeline) {
        # .NET resolves a relative path against the process directory, which is not
        # PowerShell's current location; resolve it the way the user sees it.
        $script:OutFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
    }
    if (-not $ToPipeline -and -not $Force -and [System.IO.File]::Exists($OutFile)) {
        throw "$OutFile already exists. Use -Force to replace it."
    }
    $writer = New-LineWriter $OutFile ([bool] $ToPipeline)
    $published = $false
    try {
        $ids = New-Object System.Collections.Generic.List[int]
        if (-not $All) {
            foreach ($name in $Channel) {
                if ($WantedIds.ContainsKey($name)) { foreach ($id in $WantedIds[$name]) { $ids.Add($id) } }
            }
        }
        $logs = @(foreach ($name in $Channel) { ConvertTo-LogJson (Get-LogFacts $name $gaps) })
        $channels = @($Channel | ForEach-Object { ConvertTo-JsonText $_ }) -join ','
        $idText = @($ids | Sort-Object -Unique | ForEach-Object { $_.ToString($Invariant) }) -join ','
        $header = '{"toledot_events":1' +
        ',"collector":{"name":"' + $CollectorName + '","version":"' + $CollectorVersion + '","method":"' + $Method + '"}' +
        ',"collected_at":"' + (Format-UtcTime (Get-Date)) + '"' +
        ',"computer":' + (ConvertTo-JsonText (Get-ComputerName)) +
        ',"operator":' + (ConvertTo-JsonText (Get-OperatorName)) +
        ',"query":{"channels":[' + $channels + '],"event_ids":[' + $idText + ']' +
        ',"since":' + (ConvertTo-JsonTimeOrNull $from) + ',"until":' + (ConvertTo-JsonTimeOrNull $to) + '}' +
        ',"logs":[' + ($logs -join ',') + ']}'
        Write-Line $writer $header
        foreach ($name in $Channel) {
            Read-Channel $writer $name $from $to $gaps
        }
        $gapText = @($gaps | ForEach-Object {
                '{"area":' + (ConvertTo-JsonText $_.area) + ',"reason":' + (ConvertTo-JsonText $_.reason) + '}'
            }) -join ','
        $hash = Get-HashText $writer
        Write-Line $writer ('{"end":true,"events":' + $writer.Count + ',"sha256":"' + $hash + '","gaps":[' + $gapText + ']}') -Last
        Close-LineWriter $writer
        if (-not $ToPipeline) {
            Publish-Output $writer $OutFile ([bool] $Force)
            $published = $true
        }
    } finally {
        Close-LineWriter $writer
        # Whatever went wrong, OutFile is untouched and no partial file is left.
        if (-not $ToPipeline -and -not $published) { [System.IO.File]::Delete($writer.TempPath) }
    }
}

function Read-Channel($Writer, [string] $Name, [datetime] $From, [Nullable[datetime]] $To, $Gaps) {
    $wanted = $null
    $termSets = @(, @())
    if (-not $All) {
        if (-not $WantedIds.ContainsKey($Name)) { return }
        $wanted = New-Object System.Collections.Generic.HashSet[int]
        foreach ($id in $WantedIds[$Name]) { [void] $wanted.Add($id) }
        $terms = Get-IdRanges $WantedIds[$Name]
        $termSets = @(for ($i = 0; $i -lt $terms.Count; $i += $MaxTermsPerQuery) {
                , @($terms[$i..([Math]::Min($i + $MaxTermsPerQuery, $terms.Count) - 1)])
            })
    }
    foreach ($terms in $termSets) {
        try {
            $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery -ArgumentList @(
                $Name, [System.Diagnostics.Eventing.Reader.PathType]::LogName, (Get-QueryText $terms $From $To))
            $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader -ArgumentList $query
        } catch {
            $Gaps.Add([ordered] @{ area = "the $Name log"; reason = $_.Exception.Message })
            return
        }
        try {
            while ($true) {
                try { $record = $reader.ReadEvent() } catch {
                    $Gaps.Add([ordered] @{ area = "the $Name log"; reason = "reading stopped: $($_.Exception.Message)" })
                    break
                }
                if ($null -eq $record) { break }
                try {
                    if ($null -ne $wanted -and -not $wanted.Contains($record.Id)) { continue }
                    $version = if ($null -ne $record.Version) { [int] $record.Version } else { 0 }
                    $line = Format-EventLine $record.RecordId $record.Id $version $record.TimeCreated `
                        $record.MachineName $record.LogName $record.ProviderName $record.ToXml()
                    Write-Line $Writer $line
                    $Writer.Count++
                } catch {
                    $Gaps.Add([ordered] @{ area = "record $($record.RecordId) of the $Name log"; reason = $_.Exception.Message })
                } finally {
                    $record.Dispose()
                }
            }
        } finally {
            $reader.Dispose()
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Collection
}
