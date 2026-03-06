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

function ConvertTo-HtmlEncoded {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Text
    )

    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function ConvertTo-SeverityRank {
    [CmdletBinding()]
    param(
        [string]$Severity
    )

    switch ($Severity) {
        'High' { return 3 }
        'Medium' { return 2 }
        'Low' { return 1 }
        default { return 0 }
    }
}

function Get-RecommendationItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Indicators,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$CollectionErrors
    )

    $items = [System.Collections.Generic.List[string]]::new()
    [void]$items.Add('Validate the affected account owner, establish an incident timeline, and preserve the generated evidence folder.')

    $indicatorCategories = @($Indicators | Select-Object -ExpandProperty Category -Unique)

    if ($indicatorCategories -contains 'Forwarding' -or $indicatorCategories -contains 'ExternalForwarding' -or $indicatorCategories -contains 'SuspiciousInboxRule') {
        [void]$items.Add('Review inbox rules and mailbox forwarding immediately; remove attacker-controlled forwarding or deletion rules after preserving evidence.')
    }
    if ($indicatorCategories -contains 'MailboxPermission' -or $indicatorCategories -contains 'CalendarPermission') {
        [void]$items.Add('Audit delegated access on the mailbox and calendar, then revoke any unauthorized SendAs, Full Access, SendOnBehalf, or delegate permissions.')
    }
    if ($indicatorCategories -contains 'SuspiciousAppConsent') {
        [void]$items.Add('Inspect OAuth consent grants and enterprise applications for the user; revoke suspicious consents and rotate impacted secrets if required.')
    }
    if ($indicatorCategories -contains 'SignInAnomaly' -or $indicatorCategories -contains 'RiskStatus') {
        [void]$items.Add('Review recent sign-in activity and conditional access impact; reset the password, revoke refresh tokens, and confirm MFA methods are trusted.')
    }
    if ($indicatorCategories -contains 'PrivilegedRole') {
        [void]$items.Add('Validate whether the account should hold privileged roles; remove unnecessary administrative access and review related admin actions.')
    }
    if (@($CollectionErrors).Count -gt 0) {
        [void]$items.Add('Review collection errors before closing the investigation; some evidence sources were incomplete and may require portal screenshots or manual export.')
    }

    return @($items | Select-Object -Unique)
}

function New-IncidentHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CaseFolder,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [PSCustomObject]$CasePaths,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$CollectedFiles,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$CollectionErrors,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Indicators,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$LogEntries
    )

    $severityLabel = 'Low'
    if (@($Indicators | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) {
        $severityLabel = 'High'
    }
    elseif (@($Indicators | Where-Object { $_.Severity -eq 'Medium' }).Count -gt 0) {
        $severityLabel = 'Medium'
    }

    $severityClass = "sev-$($severityLabel.ToLowerInvariant())"
    $successFiles = @($CollectedFiles | Where-Object { $_.HasData -eq $true })
    $sortedIndicators = @($Indicators | Sort-Object @{ Expression = { -(ConvertTo-SeverityRank -Severity $_.Severity) } }, Timestamp)
    $priorityIndicators = @($sortedIndicators | Select-Object -First 8)
    $recentLogs = @($LogEntries | Select-Object -Last 10)
    $recommendations = @(Get-RecommendationItems -Indicators $Indicators -CollectionErrors $CollectionErrors)
    $tenant = if ($UserPrincipalName -match '@(.+)$') { $Matches[1] } else { 'Unknown' }

    $priorityRows = if ($priorityIndicators.Count -gt 0) {
        ($priorityIndicators | ForEach-Object {
            "<tr><td><span class='severity-pill sev-$($_.Severity.ToLowerInvariant())'>$(ConvertTo-HtmlEncoded $_.Severity)</span></td><td>$(ConvertTo-HtmlEncoded $_.Category)</td><td>$(ConvertTo-HtmlEncoded $_.Description)</td><td>$(ConvertTo-HtmlEncoded $_.Timestamp)</td></tr>"
        }) -join "`n"
    }
    else {
        "<tr><td colspan='4'>No automated indicators were detected. Manual review is still required.</td></tr>"
    }

    $indicatorRows = if (@($Indicators).Count -gt 0) {
        ($sortedIndicators | ForEach-Object {
            "<tr><td><span class='severity-pill sev-$($_.Severity.ToLowerInvariant())'>$(ConvertTo-HtmlEncoded $_.Severity)</span></td><td>$(ConvertTo-HtmlEncoded $_.Category)</td><td>$(ConvertTo-HtmlEncoded $_.Description)</td><td><details><summary>View detail</summary><pre>$(ConvertTo-HtmlEncoded $_.RawDetail)</pre></details></td><td>$(ConvertTo-HtmlEncoded $_.Timestamp)</td></tr>"
        }) -join "`n"
    }
    else {
        "<tr><td colspan='5'>No automated indicators were detected.</td></tr>"
    }

    $errorRows = if (@($CollectionErrors).Count -gt 0) {
        ($CollectionErrors | ForEach-Object {
            "<tr><td>$(ConvertTo-HtmlEncoded $_.Function)</td><td>$(ConvertTo-HtmlEncoded $_.Message)</td><td><details><summary>View detail</summary><pre>$(ConvertTo-HtmlEncoded $_.Detail)</pre></details></td><td>$(ConvertTo-HtmlEncoded $_.Timestamp)</td></tr>"
        }) -join "`n"
    }
    else {
        "<tr><td colspan='4'>No collection errors were recorded.</td></tr>"
    }

    $fileRows = if (@($CollectedFiles).Count -gt 0) {
        ($CollectedFiles | ForEach-Object {
            $status = if ($_.HasData) { 'Collected' } else { 'Empty' }
            "<tr><td>$(ConvertTo-HtmlEncoded $_.File)</td><td>$(ConvertTo-HtmlEncoded $_.Format)</td><td>$(ConvertTo-HtmlEncoded $_.Description)</td><td>$(ConvertTo-HtmlEncoded $status)</td><td>$(ConvertTo-HtmlEncoded $_.Timestamp)</td></tr>"
        }) -join "`n"
    }
    else {
        "<tr><td colspan='5'>No files were registered in the manifest.</td></tr>"
    }

    $manualReviewItems = ($script:ManualReviewItems | ForEach-Object {
        "<li>$(ConvertTo-HtmlEncoded $_)</li>"
    }) -join "`n"

    $recommendationItems = ($recommendations | ForEach-Object {
        "<li>$(ConvertTo-HtmlEncoded $_)</li>"
    }) -join "`n"

    $recentLogItems = ($recentLogs | ForEach-Object {
        "<li><strong>$(ConvertTo-HtmlEncoded $_.Timestamp)</strong> - $(ConvertTo-HtmlEncoded $_.Level): $(ConvertTo-HtmlEncoded $_.Message)</li>"
    }) -join "`n"

    $summaryNarrative = if (@($Indicators).Count -gt 0) {
        "Automated review identified $(@($Indicators).Count) indicator(s) for $(ConvertTo-HtmlEncoded $UserPrincipalName), with an overall risk rating of $(ConvertTo-HtmlEncoded $severityLabel). Review the priority findings and recommended actions before remediation."
    }
    else {
        "Automated review completed for $(ConvertTo-HtmlEncoded $UserPrincipalName) with no direct indicators flagged by the script. Manual portal review is still required before ruling out compromise activity."
    }

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident Report - $(ConvertTo-HtmlEncoded $UserPrincipalName)</title>
<style>
:root {
  --bg: #f4f1ea;
  --panel: #fffdf9;
  --ink: #1f2933;
  --muted: #5f6c7b;
  --border: #d9d1c4;
  --accent: #174e4f;
  --high: #a12d2f;
  --medium: #b86a06;
  --low: #33658a;
  --ok: #2d6a4f;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Georgia, "Times New Roman", serif;
  background: linear-gradient(180deg, #efe7da 0%, var(--bg) 45%, #f7f4ee 100%);
  color: var(--ink);
}
.page {
  max-width: 1180px;
  margin: 0 auto;
  padding: 32px 20px 56px;
}
.hero {
  background: radial-gradient(circle at top right, rgba(23,78,79,0.18), transparent 35%), var(--panel);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 28px;
  box-shadow: 0 18px 40px rgba(31,41,51,0.08);
}
.eyebrow { color: var(--accent); text-transform: uppercase; letter-spacing: 0.08em; font-size: 12px; font-weight: 700; }
h1 { margin: 8px 0 10px; font-size: 34px; line-height: 1.1; }
.lede { margin: 0; max-width: 78ch; color: var(--muted); font-size: 16px; }
.hero-grid, .stats, .section-grid { display: grid; gap: 16px; }
.hero-grid { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-top: 22px; }
.stats { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin-top: 22px; }
.card, .stat, .section {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 18px;
}
.stat-value { font-size: 28px; font-weight: 700; margin-top: 8px; }
.label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
.risk-banner {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  margin-top: 16px;
  padding: 10px 14px;
  border-radius: 999px;
  font-weight: 700;
}
.sev-high { background: rgba(161,45,47,0.12); color: var(--high); }
.sev-medium { background: rgba(184,106,6,0.12); color: var(--medium); }
.sev-low { background: rgba(51,101,138,0.12); color: var(--low); }
nav { margin: 22px 0 12px; display: flex; flex-wrap: wrap; gap: 10px; }
nav a {
  color: var(--accent);
  text-decoration: none;
  padding: 8px 12px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: rgba(255,255,255,0.7);
}
.section-grid { grid-template-columns: 1.25fr 0.95fr; margin-top: 18px; }
.section { margin-top: 18px; }
h2 { margin: 0 0 14px; font-size: 23px; }
h3 { margin: 0 0 12px; font-size: 18px; }
p, li { line-height: 1.55; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
.severity-pill {
  display: inline-block;
  min-width: 70px;
  text-align: center;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
}
.severity-pill.sev-high { background: rgba(161,45,47,0.12); color: var(--high); }
.severity-pill.sev-medium { background: rgba(184,106,6,0.12); color: var(--medium); }
.severity-pill.sev-low { background: rgba(51,101,138,0.12); color: var(--low); }
details summary { cursor: pointer; color: var(--accent); }
pre {
  white-space: pre-wrap;
  word-break: break-word;
  background: #f7f2ea;
  border-radius: 12px;
  padding: 12px;
  margin-top: 8px;
  font-family: Consolas, "Courier New", monospace;
  font-size: 12px;
}
ul.action-list, ul.checklist, ul.log-list { margin: 0; padding-left: 18px; }
.callout {
  border-left: 4px solid var(--medium);
  background: #fff7ea;
  padding: 14px 16px;
  border-radius: 12px;
}
@media (max-width: 900px) {
  .section-grid { grid-template-columns: 1fr; }
}
@media print {
  body { background: white; }
  .page { max-width: none; padding: 0; }
  nav { display: none; }
  .hero, .card, .stat, .section { box-shadow: none; }
}
</style>
</head>
<body>
<div class="page">
  <section class="hero">
    <div class="eyebrow">Suspected Compromised Account</div>
    <h1>Incident Review for $(ConvertTo-HtmlEncoded $UserPrincipalName)</h1>
    <p class="lede">$summaryNarrative</p>
    <div class="risk-banner $severityClass">Overall Risk: $(ConvertTo-HtmlEncoded $severityLabel)</div>
    <div class="hero-grid">
      <div class="card"><div class="label">Tenant Domain</div><div class="stat-value">$(ConvertTo-HtmlEncoded $tenant)</div></div>
      <div class="card"><div class="label">Case Folder</div><div class="stat-value" style="font-size:16px">$(ConvertTo-HtmlEncoded $CaseFolder)</div></div>
      <div class="card"><div class="label">Collection Time</div><div class="stat-value" style="font-size:16px">$(ConvertTo-HtmlEncoded (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))</div></div>
    </div>
    <div class="stats">
      <div class="stat"><div class="label">Indicators</div><div class="stat-value">$(@($Indicators).Count)</div></div>
      <div class="stat"><div class="label">High Severity</div><div class="stat-value">$(@($Indicators | Where-Object { $_.Severity -eq 'High' }).Count)</div></div>
      <div class="stat"><div class="label">Errors</div><div class="stat-value">$(@($CollectionErrors).Count)</div></div>
      <div class="stat"><div class="label">Evidence Files</div><div class="stat-value">$(@($CollectedFiles).Count)</div></div>
      <div class="stat"><div class="label">Files With Data</div><div class="stat-value">$($successFiles.Count)</div></div>
    </div>
  </section>

  <nav>
    <a href="#priority-findings">Priority Findings</a>
    <a href="#recommended-actions">Recommended Actions</a>
    <a href="#indicators">Indicators</a>
    <a href="#manual-review">Manual Review</a>
    <a href="#collection-issues">Collection Issues</a>
    <a href="#evidence">Collected Evidence</a>
  </nav>

  <div class="section-grid">
    <section class="section" id="priority-findings">
      <h2>Priority Findings</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detected</th></tr>
        </thead>
        <tbody>
$priorityRows
        </tbody>
      </table>
    </section>

    <section class="section" id="recommended-actions">
      <h2>Recommended Actions</h2>
      <div class="callout">
        Prioritize containment first, then validate persistence mechanisms and evidence gaps before closing the incident.
      </div>
      <ul class="action-list" style="margin-top:14px;">
$recommendationItems
      </ul>
    </section>
  </div>

  <section class="section" id="indicators">
    <h2>All Indicators</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Category</th><th>Description</th><th>Detail</th><th>Timestamp</th></tr>
      </thead>
      <tbody>
$indicatorRows
      </tbody>
    </table>
  </section>

  <div class="section-grid">
    <section class="section" id="manual-review">
      <h2>Manual Review Checklist</h2>
      <ul class="checklist">
$manualReviewItems
      </ul>
    </section>

    <section class="section">
      <h2>Recent Collection Notes</h2>
      <ul class="log-list">
$recentLogItems
      </ul>
    </section>
  </div>

  <section class="section" id="collection-issues">
    <h2>Collection Issues</h2>
    <table>
      <thead>
        <tr><th>Function</th><th>Issue</th><th>Detail</th><th>Timestamp</th></tr>
      </thead>
      <tbody>
$errorRows
      </tbody>
    </table>
  </section>

  <section class="section" id="evidence">
    <h2>Collected Evidence</h2>
    <table>
      <thead>
        <tr><th>File</th><th>Format</th><th>Description</th><th>Status</th><th>Timestamp</th></tr>
      </thead>
      <tbody>
$fileRows
      </tbody>
    </table>
  </section>
</div>
</body>
</html>
"@
}

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

        $htmlSummaryPath = Join-Path $CasePaths.Deliverables 'IncidentSummary.html'
        $htmlReport = New-IncidentHtmlReport `
            -CaseFolder $CaseFolder `
            -UserPrincipalName $UserPrincipalName `
            -CasePaths $CasePaths `
            -CollectedFiles $collectedFiles `
            -CollectionErrors $collectionErrors `
            -Indicators $indicators `
            -LogEntries $logEntries

        Export-EvidenceData -Data $htmlReport `
            -FilePath $htmlSummaryPath `
            -Format 'HTML' `
            -Description 'HTML incident report for review and client briefing'

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
        Write-EvidenceLog "HTML incident report saved to: $htmlSummaryPath" -Level Info
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
