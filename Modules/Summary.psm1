#Requires -Version 7.0
<#
.SYNOPSIS
    Incident summary and file manifest generation.

.DESCRIPTION
    Produces the final incident summary report, file manifest, error log,
    indicators export, and collection log. This module is called at the end
    of the evidence collection workflow to consolidate all findings into
    client-deliverable and analyst-reference artefacts.
#>

# ---------------------------------------------------------------------------
# Private: Screenshot checklist items (mirrors CaseFolder.psm1)
# ---------------------------------------------------------------------------
$script:ManualReviewItems = @(
    '01_UserOverview - User overview page showing status, sign-in activity'
    '02_AuthMethods - Authentication methods page (visual confirmation of MFA)'
    '03_SignInLogs_Suspicious - Any suspicious sign-in entries with full detail expanded'
    '04_RiskySignIns - Risky sign-ins page if Entra P2 is available'
    '05_ConditionalAccess - Conditional Access policies that apply to this user'
    '06_DeviceList - Registered/joined devices for this user'
    '07_AppConsents - Enterprise applications the user has consented to'
    '08_MailboxProperties - Mailbox properties overview'
    '09_MailFlowRules - Mail flow rules (transport rules) list'
    '10_InboxRules - User inbox rules visible in admin center'
    '11_Connectors - Inbound and outbound connectors list'
    '12_MessageTrace_Suspicious - Any suspicious message trace results expanded'
    '13_IncidentQueue - Any related incidents in the incident queue'
    '14_AlertQueue - Any related alerts'
    '15_ThreatExplorer - Threat Explorer results for sent/received mail (if available)'
    '16_AuditLogSearch - Audit log search results for the user (if not fully captured by script)'
    '17_ContentSearch - Content search results if relevant'
)

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

function New-IncidentSummary {
    <#
    .SYNOPSIS
        Generates the final incident summary report, file manifest, and log exports.
    .DESCRIPTION
        Consolidates all collected evidence metadata, errors, indicators, and log
        entries into deliverable files. The primary output is an IncidentSummary.txt
        in the client-deliverables folder, plus CSV exports of manifest, errors,
        indicators, and the full collection log in the logs folder.
    .PARAMETER CaseFolder
        Root path for the case folder.
    .PARAMETER UserPrincipalName
        The compromised user's UPN.
    .PARAMETER CasePaths
        PSCustomObject returned by New-CaseFolderStructure with properties:
        Notes, Entra, Exchange, Logs, Deliverables, Raw, Screenshots.
    .EXAMPLE
        New-IncidentSummary -CaseFolder $caseRoot -UserPrincipalName 'user@contoso.com' -CasePaths $paths
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CaseFolder,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [PSCustomObject]$CasePaths
    )

    Write-EvidenceLog '--- Generating incident summary ---' -Level Section

    try {
        # ---------------------------------------------------------------
        # Gather state from the Logging module
        # ---------------------------------------------------------------
        $collectedFiles   = Get-CollectedFiles
        $collectionErrors = Get-CollectionErrors
        $indicators       = Get-Indicators
        $logEntries       = Get-LogEntries

        # ---------------------------------------------------------------
        # Build the IncidentSummary.txt content
        # ---------------------------------------------------------------
        $sb = [System.Text.StringBuilder]::new()

        # -- Header --
        [void]$sb.AppendLine('================================================================================')
        [void]$sb.AppendLine('M365 COMPROMISE EVIDENCE COLLECTION - INCIDENT SUMMARY')
        [void]$sb.AppendLine('================================================================================')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("User Principal Name : $UserPrincipalName")
        [void]$sb.AppendLine("Collection Date     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$sb.AppendLine("Technician          : [TO BE FILLED IN BY TECHNICIAN]")

        # Attempt to extract tenant from UPN domain portion
        $tenant = if ($UserPrincipalName -match '@(.+)$') { $Matches[1] } else { 'Unknown' }
        [void]$sb.AppendLine("Tenant Domain       : $tenant")
        [void]$sb.AppendLine("Case Folder         : $CaseFolder")
        [void]$sb.AppendLine('')

        # -- Data Collected Successfully --
        [void]$sb.AppendLine('================================================================================')
        [void]$sb.AppendLine('DATA COLLECTED SUCCESSFULLY')
        [void]$sb.AppendLine('================================================================================')

        $successFiles = @($collectedFiles | Where-Object { $_.HasData -eq $true })

        if ($successFiles.Count -gt 0) {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("Total files with data: $($successFiles.Count)")
            [void]$sb.AppendLine('')

            foreach ($file in $successFiles) {
                [void]$sb.AppendLine("  [+] $($file.File)")
                [void]$sb.AppendLine("      $($file.Description)")
                [void]$sb.AppendLine("      Exported: $($file.Timestamp)")
                [void]$sb.AppendLine('')
            }
        }
        else {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('  No files with data were collected.')
            [void]$sb.AppendLine('')
        }

        # -- Data Collection Failures --
        [void]$sb.AppendLine('================================================================================')
        [void]$sb.AppendLine('DATA COLLECTION FAILURES')
        [void]$sb.AppendLine('================================================================================')

        if ($collectionErrors.Count -gt 0) {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("Total errors: $($collectionErrors.Count)")
            [void]$sb.AppendLine('')

            foreach ($err in $collectionErrors) {
                [void]$sb.AppendLine("  [!] $($err.Function)")
                [void]$sb.AppendLine("      $($err.Message)")
                if (-not [string]::IsNullOrWhiteSpace($err.Detail)) {
                    [void]$sb.AppendLine("      Detail: $($err.Detail)")
                }
                [void]$sb.AppendLine("      Time: $($err.Timestamp)")
                [void]$sb.AppendLine('')
            }
        }
        else {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('  No errors were recorded during collection.')
            [void]$sb.AppendLine('')
        }

        # -- Items Requiring Manual Review --
        [void]$sb.AppendLine('================================================================================')
        [void]$sb.AppendLine('ITEMS REQUIRING MANUAL REVIEW')
        [void]$sb.AppendLine('================================================================================')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('The following items require manual screenshot capture from the admin portals.')
        [void]$sb.AppendLine('See 06-Screenshots-Manual/ManualScreenshotChecklist.md for full instructions.')
        [void]$sb.AppendLine('')

        foreach ($item in $script:ManualReviewItems) {
            [void]$sb.AppendLine("  [ ] $item")
        }
        [void]$sb.AppendLine('')

        # -- Suspicious Indicators Found --
        [void]$sb.AppendLine('================================================================================')
        [void]$sb.AppendLine('SUSPICIOUS INDICATORS FOUND')
        [void]$sb.AppendLine('================================================================================')

        if ($indicators.Count -gt 0) {
            # Sort: High first, then Medium, then Low
            $severityOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
            $sortedIndicators = @($indicators | Sort-Object { $severityOrder[$_.Severity] })

            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("Total indicators: $($sortedIndicators.Count)")

            $highCount   = @($sortedIndicators | Where-Object { $_.Severity -eq 'High' }).Count
            $mediumCount = @($sortedIndicators | Where-Object { $_.Severity -eq 'Medium' }).Count
            $lowCount    = @($sortedIndicators | Where-Object { $_.Severity -eq 'Low' }).Count
            [void]$sb.AppendLine("  High: $highCount  |  Medium: $mediumCount  |  Low: $lowCount")
            [void]$sb.AppendLine('')

            foreach ($ind in $sortedIndicators) {
                [void]$sb.AppendLine("  [$($ind.Severity.ToUpper())] $($ind.Category)")
                [void]$sb.AppendLine("      $($ind.Description)")
                if (-not [string]::IsNullOrWhiteSpace($ind.RawDetail)) {
                    [void]$sb.AppendLine("      Detail: $($ind.RawDetail)")
                }
                [void]$sb.AppendLine("      Detected: $($ind.Timestamp)")
                [void]$sb.AppendLine('')
            }
        }
        else {
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('  No suspicious indicators were detected during automated collection.')
            [void]$sb.AppendLine('  This does NOT mean the account is clean - manual review is still required.')
            [void]$sb.AppendLine('')
        }

        # -- Recommended Next Steps --
        [void]$sb.AppendLine('================================================================================')
        [void]$sb.AppendLine('RECOMMENDED NEXT STEPS')
        [void]$sb.AppendLine('================================================================================')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('  1. Review all suspicious indicators listed above and investigate each finding.')
        [void]$sb.AppendLine('     Pay special attention to HIGH severity items that may indicate active')
        [void]$sb.AppendLine('     attacker persistence (forwarding rules, OAuth apps, delegated access).')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('  2. Capture all manual screenshots from the checklist in 06-Screenshots-Manual/.')
        [void]$sb.AppendLine('     These provide visual evidence that complements the automated data collection.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('  3. Brief the client on initial findings. Provide a high-level assessment of')
        [void]$sb.AppendLine('     the compromise scope and any urgent actions (e.g., password reset, MFA')
        [void]$sb.AppendLine('     enforcement, forwarding rule removal) that should be taken immediately.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('  4. Proceed to remediation when ready. Use the evidence collected here to')
        [void]$sb.AppendLine('     guide the remediation plan. Ensure all persistence mechanisms are removed')
        [void]$sb.AppendLine('     before restoring normal account access.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('  5. Document all actions taken in 00-Notes/TechnicianNotes.txt for the')
        [void]$sb.AppendLine('     incident record.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('================================================================================')
        [void]$sb.AppendLine("Report generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$sb.AppendLine('================================================================================')

        # ---------------------------------------------------------------
        # Export the incident summary as TXT
        # ---------------------------------------------------------------
        $summaryPath = Join-Path $CasePaths.Deliverables 'IncidentSummary.txt'

        Export-EvidenceData -Data $sb.ToString() `
            -FilePath $summaryPath `
            -Format 'TXT' `
            -Description 'Incident summary report with findings, errors, and next steps'

        # ---------------------------------------------------------------
        # Export supporting CSV files to the Logs folder
        # ---------------------------------------------------------------

        # File Manifest
        $manifestPath = Join-Path $CasePaths.Logs 'FileManifest.csv'
        Export-EvidenceData -Data $collectedFiles `
            -FilePath $manifestPath `
            -Format 'CSV' `
            -Description 'File manifest of all collected evidence files'

        # Collection Errors
        $errorsPath = Join-Path $CasePaths.Logs 'CollectionErrors.csv'
        Export-EvidenceData -Data $collectionErrors `
            -FilePath $errorsPath `
            -Format 'CSV' `
            -Description 'Errors encountered during evidence collection'

        # Indicators
        $indicatorsPath = Join-Path $CasePaths.Logs 'Indicators.csv'
        Export-EvidenceData -Data $indicators `
            -FilePath $indicatorsPath `
            -Format 'CSV' `
            -Description 'Suspicious indicators detected during collection'

        # Full Collection Log
        $logPath = Join-Path $CasePaths.Logs 'CollectionLog.csv'
        Export-EvidenceData -Data $logEntries `
            -FilePath $logPath `
            -Format 'CSV' `
            -Description 'Complete collection session log'

        # ---------------------------------------------------------------
        # Summary statistics to console
        # ---------------------------------------------------------------
        $totalFiles  = $collectedFiles.Count
        $dataFiles   = $successFiles.Count
        $errorCount  = $collectionErrors.Count
        $indCount    = $indicators.Count

        Write-EvidenceLog "Summary complete: $dataFiles files with data (of $totalFiles total), $errorCount errors, $indCount indicators" -Level Success
        Write-EvidenceLog "Incident summary saved to: $summaryPath" -Level Info
    }
    catch {
        Register-CollectionError -FunctionName 'New-IncidentSummary' `
            -ErrorMessage 'Failed to generate incident summary.' `
            -ErrorRecord $_
    }
}

# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'New-IncidentSummary'
)
