#Requires -Version 7.0
<#
.SYNOPSIS
    Logging and utility functions for M365 Compromise Evidence Collection.

.DESCRIPTION
    Provides structured logging, transcript management, safe file export,
    and common helper utilities used across all evidence collection modules.
#>

# ---------------------------------------------------------------------------
# Module-scoped state
# ---------------------------------------------------------------------------
$script:LogEntries       = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:TranscriptPath   = $null
$script:CollectedFiles   = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Indicators       = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:CollectionErrors = [System.Collections.Generic.List[PSCustomObject]]::new()

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

function Write-EvidenceLog {
    <#
    .SYNOPSIS
        Writes a structured log entry and outputs to the console.
    .PARAMETER Message
        The log message.
    .PARAMETER Level
        Log level: Info, Warning, Error, Success, Section.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Section')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = [PSCustomObject]@{
        Timestamp = $timestamp
        Level     = $Level
        Message   = $Message
    }
    $script:LogEntries.Add($entry)

    $prefix = switch ($Level) {
        'Info'    { "[INFO]   " }
        'Warning' { "[WARN]   " }
        'Error'   { "[ERROR]  " }
        'Success' { "[OK]     " }
        'Section' { "[------] " }
    }

    $color = switch ($Level) {
        'Info'    { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
        'Section' { 'White' }
    }

    Write-Host "$timestamp $prefix $Message" -ForegroundColor $color
}

function Start-EvidenceTranscript {
    <#
    .SYNOPSIS
        Starts a PowerShell transcript in the case log folder.
    .PARAMETER LogFolder
        Path to the 03-Logs subfolder.
    .PARAMETER UserPrincipalName
        UPN for the case, used in the filename.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogFolder,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $safeUpn   = Get-SafeFileName -Name $UserPrincipalName
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:TranscriptPath = Join-Path $LogFolder "Transcript_${safeUpn}_${timestamp}.txt"

    try {
        Start-Transcript -Path $script:TranscriptPath -Append -Force | Out-Null
        Write-EvidenceLog "Transcript started: $($script:TranscriptPath)" -Level Info
    }
    catch {
        Write-EvidenceLog "Failed to start transcript: $_" -Level Warning
    }
}

function Stop-EvidenceTranscript {
    <#
    .SYNOPSIS
        Stops the active transcript if one is running.
    #>
    [CmdletBinding()]
    param()

    try {
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Transcript may not be active; safe to ignore.
    }
}

function Export-EvidenceData {
    <#
    .SYNOPSIS
        Exports data to a file and registers it in the file manifest.
    .DESCRIPTION
        Supports CSV, JSON, and TXT output. Automatically handles empty data
        gracefully and logs the export.
    .PARAMETER Data
        The object(s) to export.
    .PARAMETER FilePath
        Full path to the output file.
    .PARAMETER Format
        File format: CSV, JSON, or TXT.
    .PARAMETER Description
        Human-readable description for the manifest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $Data,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [ValidateSet('CSV', 'JSON', 'TXT', 'HTML')]
        [string]$Format,

        [Parameter(Mandatory)]
        [string]$Description
    )

    # Ensure parent directory exists
    $parentDir = Split-Path -Path $FilePath -Parent
    if (-not (Test-Path $parentDir)) {
        New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
    }

    $isEmpty = ($null -eq $Data) -or
               ($Data -is [System.Collections.ICollection] -and $Data.Count -eq 0) -or
               ($Data -is [string] -and [string]::IsNullOrWhiteSpace($Data))

    if ($isEmpty) {
        switch ($Format) {
            'CSV' {
                [System.IO.File]::WriteAllText($FilePath, [string]::Empty, [System.Text.UTF8Encoding]::new($false))
            }
            'JSON' {
                $emptyJson = if ($Data -is [System.Collections.IDictionary]) { '{}' } else { '[]' }
                [System.IO.File]::WriteAllText($FilePath, $emptyJson, [System.Text.UTF8Encoding]::new($false))
            }
            'TXT' {
                "[No data returned for: $Description]" | Out-File -FilePath $FilePath -Encoding utf8
            }
            'HTML' {
                '<!DOCTYPE html><html><body><p>No data returned.</p></body></html>' | Out-File -FilePath $FilePath -Encoding utf8
            }
        }

        Write-EvidenceLog "No data for: $Description (valid empty $Format file written)" -Level Warning
    }
    else {
        switch ($Format) {
            'CSV' {
                if ($Data -is [System.Collections.IEnumerable] -and $Data -isnot [string]) {
                    $Data | Export-Csv -Path $FilePath -NoTypeInformation -Encoding utf8
                }
                else {
                    @($Data) | Export-Csv -Path $FilePath -NoTypeInformation -Encoding utf8
                }
            }
            'JSON' {
                $Data | ConvertTo-Json -Depth 25 -EnumsAsStrings | Out-File -FilePath $FilePath -Encoding utf8
            }
            'TXT' {
                if ($Data -is [string]) {
                    $Data | Out-File -FilePath $FilePath -Encoding utf8
                }
                else {
                    $Data | Out-String | Out-File -FilePath $FilePath -Encoding utf8
                }
            }
            'HTML' {
                if ($Data -is [string]) {
                    $Data | Out-File -FilePath $FilePath -Encoding utf8
                }
                else {
                    $Data | Out-String | Out-File -FilePath $FilePath -Encoding utf8
                }
            }
        }
        Write-EvidenceLog "Exported: $Description -> $(Split-Path $FilePath -Leaf)" -Level Success
    }

    # Register in manifest
    $script:CollectedFiles.Add([PSCustomObject]@{
        File        = Split-Path $FilePath -Leaf
        FullPath    = $FilePath
        Format      = $Format
        Description = $Description
        Timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        HasData     = -not $isEmpty
    })
}

function Register-CollectionError {
    <#
    .SYNOPSIS
        Records an error encountered during evidence collection.
    .PARAMETER FunctionName
        The function where the error occurred.
    .PARAMETER ErrorMessage
        Description of what went wrong.
    .PARAMETER ErrorRecord
        The original ErrorRecord if available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FunctionName,

        [Parameter(Mandatory)]
        [string]$ErrorMessage,

        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $detail = if ($ErrorRecord) { $ErrorRecord.Exception.Message } else { '' }

    $script:CollectionErrors.Add([PSCustomObject]@{
        Timestamp    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Function     = $FunctionName
        Message      = $ErrorMessage
        Detail       = $detail
    })

    Write-EvidenceLog "$FunctionName : $ErrorMessage" -Level Error
    if ($detail) {
        Write-EvidenceLog "  Detail: $detail" -Level Error
    }
}

function Register-Indicator {
    <#
    .SYNOPSIS
        Registers a suspicious indicator found during evidence collection.
    .PARAMETER Category
        Category of indicator (e.g., Forwarding, InboxRule, Permission).
    .PARAMETER Description
        What was found.
    .PARAMETER Severity
        High, Medium, or Low.
    .PARAMETER RawDetail
        Additional raw data for context.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Description,

        [ValidateSet('High', 'Medium', 'Low')]
        [string]$Severity = 'Medium',

        [string]$RawDetail = ''
    )

    $script:Indicators.Add([PSCustomObject]@{
        Timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Category    = $Category
        Severity    = $Severity
        Description = $Description
        RawDetail   = $RawDetail
    })

    Write-EvidenceLog "INDICATOR [$Severity] $Category : $Description" -Level Warning
}

function Get-SafeFileName {
    <#
    .SYNOPSIS
        Converts a string to a safe filename by replacing invalid characters.
    .PARAMETER Name
        The string to sanitize.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $escaped = [regex]::Escape($invalid)
    return ($Name -replace "[$escaped]", '_')
}

function Get-LogEntries       { return $script:LogEntries }
function Get-CollectedFiles   { return $script:CollectedFiles }
function Get-CollectionErrors { return $script:CollectionErrors }
function Get-Indicators       { return $script:Indicators }
function Get-TranscriptPath   { return $script:TranscriptPath }

function Reset-LoggingState {
    <#
    .SYNOPSIS
        Resets all module-level state. Useful if re-running in the same session.
    #>
    [CmdletBinding()]
    param()

    $script:LogEntries       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:CollectedFiles   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:Indicators       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:CollectionErrors = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:TranscriptPath   = $null
}

# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'Write-EvidenceLog'
    'Start-EvidenceTranscript'
    'Stop-EvidenceTranscript'
    'Export-EvidenceData'
    'Register-CollectionError'
    'Register-Indicator'
    'Get-SafeFileName'
    'Get-LogEntries'
    'Get-CollectedFiles'
    'Get-CollectionErrors'
    'Get-Indicators'
    'Get-TranscriptPath'
    'Reset-LoggingState'
)
