#Requires -Version 7.0
<#
.SYNOPSIS
    M365 Compromise Evidence Collection Tool - Main Orchestrator.

.DESCRIPTION
    Collects read-only forensic evidence from Microsoft 365 for a potentially
    compromised user account. Gathers data from Entra ID (Azure AD) via
    Microsoft Graph and Exchange Online, producing a structured case folder
    with analyst-ready exports, raw JSON for forensics, and an incident summary.

    This is the entry point that technicians run. It orchestrates all modules
    in sequence: prerequisites check, case folder setup, service connections,
    evidence collection, and summary generation.

.PARAMETER UserPrincipalName
    The UPN (email address) of the compromised user to investigate.

.PARAMETER CaseFolder
    Path to the root case folder. Parent directory must already exist.
    A subfolder structure will be created inside this path.

.PARAMETER TenantId
    Optional. Tenant ID or domain for MSP/partner scenarios where the
    technician needs to connect to a specific customer tenant.

.PARAMETER SkipGraph
    Skip Microsoft Graph collection (Entra ID evidence). Useful if you
    only need Exchange data or Graph access is unavailable.

.PARAMETER SkipExchange
    Skip Exchange Online collection. Useful if you only need Entra data
    or Exchange access is unavailable.

.EXAMPLE
    ./Start-M365CompromiseEvidence.ps1 -UserPrincipalName "user@contoso.com" -CaseFolder "C:\Cases\Contoso-2025-01-15"

.EXAMPLE
    ./Start-M365CompromiseEvidence.ps1 -UserPrincipalName "user@contoso.com" -CaseFolder "C:\Cases\Contoso" -TenantId "contoso.onmicrosoft.com" -SkipExchange

.NOTES
    Version: 1.0.0
    Author:  M365 Compromise Response Team
    License: MIT
    This tool is READ-ONLY. It does not modify, delete, or remediate anything.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[^@]+@[^@]+\.[^@]+$')]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [ValidateScript({
        $parent = Split-Path -Path $_ -Parent
        if (-not $parent) { $parent = '.' }
        if (Test-Path $parent) { $true }
        else { throw "Parent directory does not exist: $parent" }
    })]
    [string]$CaseFolder,

    [string]$TenantId,

    [switch]$SkipGraph,

    [switch]$SkipExchange
)

# ===========================================================================
# Script version
# ===========================================================================
$script:ToolVersion = '1.0.0'
$script:ToolName    = 'M365 Compromise Evidence Collection Tool'

# ===========================================================================
# Import modules from ./Modules/ relative to this script's location
# ===========================================================================
$modulesPath = Join-Path $PSScriptRoot 'Modules'

Import-Module (Join-Path $modulesPath 'Logging.psm1') -Force
Import-Module (Join-Path $modulesPath 'Prerequisites.psm1') -Force
Import-Module (Join-Path $modulesPath 'CaseFolder.psm1') -Force
Import-Module (Join-Path $modulesPath 'Connection.psm1') -Force
Import-Module (Join-Path $modulesPath 'EntraEvidence.psm1') -Force
Import-Module (Join-Path $modulesPath 'ExchangeEvidence.psm1') -Force
Import-Module (Join-Path $modulesPath 'Summary.psm1') -Force

# ===========================================================================
# Main execution body - wrapped in try/finally for clean teardown
# ===========================================================================
try {
    # ------------------------------------------------------------------
    # Step 1: Reset logging state for a clean run
    # ------------------------------------------------------------------
    Reset-LoggingState

    # ------------------------------------------------------------------
    # Step 2: Verify PowerShell version
    # ------------------------------------------------------------------
    if (-not (Test-PowerShellVersion)) {
        Write-EvidenceLog 'Aborting: PowerShell 7.0 or later is required.' -Level Error
        exit 1
    }

    # ------------------------------------------------------------------
    # Step 3: Check module prerequisites
    # ------------------------------------------------------------------
    $prereqResult = Test-Prerequisites
    if (-not $prereqResult.Pass) {
        Write-EvidenceLog 'Aborting: One or more required modules are missing or outdated. See above for install commands.' -Level Error
        exit 1
    }

    # ------------------------------------------------------------------
    # Step 4: Create case folder structure
    # ------------------------------------------------------------------
    $casePaths = New-CaseFolderStructure -CaseFolder $CaseFolder -UserPrincipalName $UserPrincipalName

    # ------------------------------------------------------------------
    # Step 5: Start transcript logging
    # ------------------------------------------------------------------
    Start-EvidenceTranscript -LogFolder $casePaths.Logs -UserPrincipalName $UserPrincipalName

    # ------------------------------------------------------------------
    # Step 6: Print banner with case information
    # ------------------------------------------------------------------
    $bannerTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss (UTC zzz)'

    Write-EvidenceLog '========================================================' -Level Section
    Write-EvidenceLog "$script:ToolName" -Level Section
    Write-EvidenceLog "Version: $script:ToolVersion" -Level Section
    Write-EvidenceLog '========================================================' -Level Section
    Write-EvidenceLog "Timestamp:    $bannerTimestamp" -Level Info
    Write-EvidenceLog "Target UPN:   $UserPrincipalName" -Level Info
    Write-EvidenceLog "Case Folder:  $CaseFolder" -Level Info
    if ($TenantId) {
        Write-EvidenceLog "Tenant ID:    $TenantId" -Level Info
    }
    if ($SkipGraph)    { Write-EvidenceLog 'Graph collection:    SKIPPED (flag set)' -Level Warning }
    if ($SkipExchange) { Write-EvidenceLog 'Exchange collection: SKIPPED (flag set)' -Level Warning }
    Write-EvidenceLog '========================================================' -Level Section

    # ------------------------------------------------------------------
    # Step 7: Connect to Microsoft 365 services
    # ------------------------------------------------------------------
    $connectParams = @{}
    if ($TenantId)     { $connectParams['TenantId']     = $TenantId }
    if ($SkipExchange) { $connectParams['SkipExchange']  = $true }
    if ($SkipGraph)    { $connectParams['SkipGraph']     = $true }

    $connectionResult = Connect-IncidentServices @connectParams

    # ------------------------------------------------------------------
    # Step 8: Entra ID / Graph evidence collection
    # ------------------------------------------------------------------
    if ($connectionResult.GraphConnected) {
        Write-EvidenceLog '--- Collecting Entra ID evidence via Microsoft Graph ---' -Level Section

        $entraParams = @{
            UserPrincipalName = $UserPrincipalName
            OutputFolder      = $casePaths.Entra
            RawFolder         = $casePaths.Raw
        }

        Export-EntraUserProfile      @entraParams
        Export-EntraAuthMethods      @entraParams
        Export-EntraDirectoryRoles   @entraParams
        Export-EntraSignInLogs       @entraParams
        Export-EntraRiskData         @entraParams
        Export-EntraAuditLogs        @entraParams
        Export-EntraAppAssignments   @entraParams

        Write-EvidenceLog 'Entra ID evidence collection complete.' -Level Success
    }
    else {
        if (-not $SkipGraph) {
            Write-EvidenceLog 'Graph is not connected - skipping Entra ID evidence collection.' -Level Warning
        }
    }

    # ------------------------------------------------------------------
    # Step 9: Exchange Online evidence collection
    # ------------------------------------------------------------------
    if ($connectionResult.ExchangeConnected) {
        Write-EvidenceLog '--- Collecting Exchange Online evidence ---' -Level Section

        $exchangeParams = @{
            UserPrincipalName = $UserPrincipalName
            OutputFolder      = $casePaths.Exchange
            RawFolder         = $casePaths.Raw
        }

        Export-ExchangeMailboxDetails       @exchangeParams
        Export-ExchangeInboxRules           @exchangeParams
        Export-ExchangeMailboxPermissions   @exchangeParams
        Export-ExchangeForwarding           @exchangeParams
        Export-ExchangeCalendarDelegates    @exchangeParams
        Export-ExchangeTransportRules       @exchangeParams
        Export-ExchangeConnectors           @exchangeParams
        Export-ExchangeMessageTrace         @exchangeParams

        Write-EvidenceLog 'Exchange Online evidence collection complete.' -Level Success
    }
    else {
        if (-not $SkipExchange) {
            Write-EvidenceLog 'Exchange is not connected - skipping Exchange Online evidence collection.' -Level Warning
        }
    }

    # ------------------------------------------------------------------
    # Step 10: Generate incident summary and manifests
    # ------------------------------------------------------------------
    Write-EvidenceLog '--- Generating incident summary ---' -Level Section
    New-IncidentSummary -CaseFolder $CaseFolder -UserPrincipalName $UserPrincipalName -CasePaths $casePaths

    # ------------------------------------------------------------------
    # Step 11: Final status report
    # ------------------------------------------------------------------
    $collectedFiles  = Get-CollectedFiles
    $collectionErrors = Get-CollectionErrors
    $indicators      = Get-Indicators

    $fileCount      = ($collectedFiles  | Measure-Object).Count
    $errorCount     = ($collectionErrors | Measure-Object).Count
    $indicatorCount = ($indicators      | Measure-Object).Count

    Write-EvidenceLog '========================================================' -Level Section
    Write-EvidenceLog 'COLLECTION COMPLETE' -Level Section
    Write-EvidenceLog '========================================================' -Level Section
    Write-EvidenceLog "Files collected:     $fileCount" -Level Info
    Write-EvidenceLog "Errors encountered:  $errorCount" -Level $(if ($errorCount -gt 0) { 'Warning' } else { 'Success' })
    Write-EvidenceLog "Indicators found:    $indicatorCount" -Level $(if ($indicatorCount -gt 0) { 'Warning' } else { 'Info' })

    $summaryPath = Join-Path $casePaths.Deliverables 'IncidentSummary.md'
    if (Test-Path $summaryPath) {
        Write-EvidenceLog "Summary report:      $summaryPath" -Level Info
    }
    else {
        # Try .txt extension as fallback
        $summaryPathTxt = Join-Path $casePaths.Deliverables 'IncidentSummary.txt'
        if (Test-Path $summaryPathTxt) {
            Write-EvidenceLog "Summary report:      $summaryPathTxt" -Level Info
        }
        else {
            Write-EvidenceLog "Summary report:      $($casePaths.Deliverables)" -Level Info
        }
    }

    Write-EvidenceLog '========================================================' -Level Section
    if ($indicatorCount -gt 0) {
        Write-EvidenceLog "ACTION REQUIRED: $indicatorCount suspicious indicator(s) found. Review the incident summary immediately." -Level Warning
    }
    if ($errorCount -gt 0) {
        Write-EvidenceLog "NOTE: $errorCount error(s) occurred during collection. Some evidence may be incomplete." -Level Warning
    }
    Write-EvidenceLog "Case folder: $CaseFolder" -Level Info
}
finally {
    # ==================================================================
    # Guaranteed cleanup: disconnect services and stop transcript
    # even if the script crashes or the user cancels (Ctrl+C).
    # ==================================================================
    try { Disconnect-IncidentServices } catch { <# Swallow - best effort cleanup #> }
    try { Stop-EvidenceTranscript }     catch { <# Swallow - best effort cleanup #> }
}
