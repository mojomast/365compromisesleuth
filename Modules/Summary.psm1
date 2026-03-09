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

function Get-IndicatorThemeKey {
    [CmdletBinding()]
    param(
        [string]$Category
    )

    switch ($Category) {
        'Forwarding' { return 'MailboxPersistence' }
        'ExternalForwarding' { return 'MailboxPersistence' }
        'SuspiciousInboxRule' { return 'MailboxPersistence' }
        'HighVolumeOutbound' { return 'MailboxPersistence' }
        'SignInAnomaly' { return 'UnauthorizedAccess' }
        'RiskStatus' { return 'UnauthorizedAccess' }
        'AccountStatus' { return 'UnauthorizedAccess' }
        'SuspiciousAppConsent' { return 'OAuthPersistence' }
        'MailboxPermission' { return 'AccessExpansion' }
        'CalendarPermission' { return 'AccessExpansion' }
        'PrivilegedRole' { return 'AccessExpansion' }
        'TransportRule' { return 'AccessExpansion' }
        'Connector' { return 'AccessExpansion' }
        default { return 'GeneralReview' }
    }
}

function Get-ThemeTitle {
    [CmdletBinding()]
    param(
        [string]$ThemeKey
    )

    switch ($ThemeKey) {
        'MailboxPersistence' { return 'Mailbox Persistence or Data Exfiltration' }
        'UnauthorizedAccess' { return 'Potential Unauthorized Access' }
        'OAuthPersistence' { return 'OAuth or Application Persistence' }
        'AccessExpansion' { return 'Access Expansion or Delegated Control' }
        default { return 'Other Review Findings' }
    }
}

function Get-IndicatorWhyItMatters {
    [CmdletBinding()]
    param(
        [string]$Category
    )

    switch ($Category) {
        'Forwarding' { return 'Mail may be automatically copied outside the intended mailbox.' }
        'ExternalForwarding' { return 'External forwarding can indicate active data theft or persistence.' }
        'SuspiciousInboxRule' { return 'Inbox rules can hide attacker activity, delete evidence, or exfiltrate email.' }
        'HighVolumeOutbound' { return 'Unexpected outbound volume can indicate bulk exfiltration or spam abuse.' }
        'SignInAnomaly' { return 'Sign-in patterns suggest account use outside normal geography or behavior.' }
        'RiskStatus' { return 'Identity Protection has flagged activity or state associated with compromise risk.' }
        'AccountStatus' { return 'A suspected account remains active and can still be used by an attacker.' }
        'SuspiciousAppConsent' { return 'Delegated app consent can provide persistent access without the user password.' }
        'MailboxPermission' { return 'Additional mailbox permissions can let other identities read or send mail.' }
        'CalendarPermission' { return 'Calendar delegates can expose meeting data and signal broader mailbox access.' }
        'PrivilegedRole' { return 'Privileged roles increase tenant-wide impact if the account is compromised.' }
        'TransportRule' { return 'Mail flow rules can redirect, copy, or inspect messages outside normal controls.' }
        'Connector' { return 'Unexpected connectors can alter trusted mail flow into or out of the tenant.' }
        default { return 'This finding requires analyst review to determine scope and impact.' }
    }
}

function Get-IndicatorExcerpt {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Text,

        [int]$MaxLength = 140
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $trimmed = ($Text -replace '\s+', ' ').Trim()
    if ($trimmed.Length -le $MaxLength) {
        return $trimmed
    }

    return $trimmed.Substring(0, $MaxLength - 3) + '...'
}

function Get-ThemeEvidenceFiles {
    [CmdletBinding()]
    param(
        [string]$ThemeKey,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$CollectedFiles
    )

    $pattern = switch ($ThemeKey) {
        'MailboxPersistence' { 'InboxRules|Forwarding|Mailbox|MessageTrace' }
        'UnauthorizedAccess' { 'UserProfile|Authentication|SignIn|Risk|Audit' }
        'OAuthPersistence' { 'OAuth|AppRole|Consent|Application' }
        'AccessExpansion' { 'Permission|DirectoryRoles|GroupMembership|TransportRule|Connector|Calendar' }
        default { '.' }
    }

    return @($CollectedFiles | Where-Object {
        $_.HasData -eq $true -and (($_.File -match $pattern) -or ($_.Description -match $pattern))
    } | Select-Object -First 4)
}

function Get-ConfidenceAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Indicators,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$CollectionErrors,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$CollectedFiles
    )

    $successFiles = @($CollectedFiles | Where-Object { $_.HasData -eq $true })
    $emptyFiles = @($CollectedFiles | Where-Object { $_.HasData -eq $false })
    $missingSources = [System.Collections.Generic.List[string]]::new()

    foreach ($err in @($CollectionErrors)) {
        [void]$missingSources.Add($err.Function)
    }
    foreach ($file in $emptyFiles) {
        [void]$missingSources.Add($file.File)
    }

    $missingSources = @($missingSources | Select-Object -Unique)

    if (@($CollectionErrors).Count -eq 0 -and $successFiles.Count -ge 8) {
        return [PSCustomObject]@{
            Label          = 'High'
            Summary        = 'Core evidence sources produced data and the current assessment is supported by multiple collected artifacts.'
            MissingSources = $missingSources
        }
    }

    if (@($CollectionErrors).Count -le 3 -and $successFiles.Count -ge 5) {
        return [PSCustomObject]@{
            Label          = 'Partial'
            Summary        = 'The report is supported by several evidence sources, but some failed or empty collections reduce confidence in the full scope.'
            MissingSources = $missingSources
        }
    }

    return [PSCustomObject]@{
        Label          = 'Limited'
        Summary        = 'Evidence gaps materially limit confidence. Manual portal review and targeted re-collection are needed before final conclusions.'
        MissingSources = $missingSources
    }
}

function Get-OpenQuestions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Indicators,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$CollectionErrors,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$CollectedFiles
    )

    $questions = [System.Collections.Generic.List[string]]::new()

    if (@($Indicators).Count -eq 0) {
        [void]$questions.Add('No automated indicators were detected. Does manual portal review reveal suspicious activity that the scripted checks did not capture?')
    }

    foreach ($err in @($CollectionErrors | Select-Object -First 4)) {
        [void]$questions.Add("Can the evidence gap in $($err.Function) be closed with a re-run or manual export?")
    }

    foreach ($file in @($CollectedFiles | Where-Object { $_.HasData -eq $false } | Select-Object -First 3)) {
        [void]$questions.Add("Why did $($file.File) return no data, and is that expected for this tenant or mailbox?")
    }

    return @($questions | Select-Object -Unique)
}

function Get-PhasedRecommendations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Indicators,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$CollectionErrors
    )

    $items = [System.Collections.Generic.List[PSCustomObject]]::new()
    $indicatorCategories = @($Indicators | Select-Object -ExpandProperty Category -Unique)

    [void]$items.Add([PSCustomObject]@{
        Phase  = 'Contain Now'
        Action = 'Confirm the user identity, preserve the case folder, and document who approved any containment changes because this report may become part of the incident record.'
    })

    if ($indicatorCategories -contains 'Forwarding' -or $indicatorCategories -contains 'ExternalForwarding' -or $indicatorCategories -contains 'SuspiciousInboxRule') {
        [void]$items.Add([PSCustomObject]@{
            Phase  = 'Contain Now'
            Action = 'Disable malicious inbox rules and forwarding settings because the evidence suggests mailbox persistence or data exfiltration.'
        })
    }
    if ($indicatorCategories -contains 'SuspiciousAppConsent') {
        [void]$items.Add([PSCustomObject]@{
            Phase  = 'Contain Now'
            Action = 'Revoke suspicious OAuth grants and review enterprise applications because delegated app consent can preserve attacker access after a password reset.'
        })
    }
    if ($indicatorCategories -contains 'SignInAnomaly' -or $indicatorCategories -contains 'RiskStatus' -or $indicatorCategories -contains 'AccountStatus') {
        [void]$items.Add([PSCustomObject]@{
            Phase  = 'Contain Now'
            Action = 'Reset the password, revoke active sessions, and validate MFA methods because the findings suggest active or recent unauthorized sign-in activity.'
        })
    }
    if ($indicatorCategories -contains 'MailboxPermission' -or $indicatorCategories -contains 'CalendarPermission' -or $indicatorCategories -contains 'PrivilegedRole') {
        [void]$items.Add([PSCustomObject]@{
            Phase  = 'Validate Scope'
            Action = 'Review delegated access, mailbox permissions, and role assignments because the compromise may have expanded beyond the mailbox owner.'
        })
    }
    if ($indicatorCategories -contains 'TransportRule' -or $indicatorCategories -contains 'Connector') {
        [void]$items.Add([PSCustomObject]@{
            Phase  = 'Validate Scope'
            Action = 'Inspect transport rules and connectors because tenant-level mail flow changes can affect additional users or hide exfiltration paths.'
        })
    }
    if (@($CollectionErrors).Count -gt 0) {
        [void]$items.Add([PSCustomObject]@{
            Phase  = 'Close Evidence Gaps'
            Action = 'Re-run failed collection areas or capture portal screenshots because collection errors reduce confidence in the final scope assessment.'
        })
    }

    [void]$items.Add([PSCustomObject]@{
        Phase  = 'Remediate and Monitor'
        Action = 'Remove confirmed persistence, confirm secure MFA enrollment, and monitor for recurrence because containment is incomplete until persistence is removed and activity stays clean.'
    })

    return @($items | Select-Object -Unique Phase, Action)
}

function Get-NotableTimelineItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Indicators,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$CollectionErrors,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$LogEntries
    )

    $timeline = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($indicator in @($Indicators)) {
        [void]$timeline.Add([PSCustomObject]@{
            Timestamp = $indicator.Timestamp
            Type      = 'Finding'
            Detail    = "[$($indicator.Severity)] $($indicator.Description)"
        })
    }

    foreach ($err in @($CollectionErrors)) {
        [void]$timeline.Add([PSCustomObject]@{
            Timestamp = $err.Timestamp
            Type      = 'Gap'
            Detail    = "$($err.Function): $($err.Message)"
        })
    }

    foreach ($log in @($LogEntries | Where-Object {
        $_.Level -in @('Section', 'Success', 'Warning', 'Error')
    } | Select-Object -First 12)) {
        [void]$timeline.Add([PSCustomObject]@{
            Timestamp = $log.Timestamp
            Type      = 'Collection'
            Detail    = $log.Message
        })
    }

    return @($timeline | Sort-Object Timestamp, Type | Select-Object -First 18)
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
        [System.Collections.IEnumerable]$LogEntries,

        [AllowNull()]
        [PSCustomObject]$AnalysisResult = $null
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
    $phasedRecommendations = @(Get-PhasedRecommendations -Indicators $Indicators -CollectionErrors $CollectionErrors)
    $confidence = Get-ConfidenceAssessment -Indicators $Indicators -CollectionErrors $CollectionErrors -CollectedFiles $CollectedFiles
    $openQuestions = @(Get-OpenQuestions -Indicators $Indicators -CollectionErrors $CollectionErrors -CollectedFiles $CollectedFiles)
    $timelineItems = @(Get-NotableTimelineItems -Indicators $Indicators -CollectionErrors $CollectionErrors -LogEntries $LogEntries)
    $tenant = if ($UserPrincipalName -match '@(.+)$') { $Matches[1] } else { 'Unknown' }
    $themeOrder = @('UnauthorizedAccess', 'MailboxPersistence', 'OAuthPersistence', 'AccessExpansion', 'GeneralReview')
    $themeRows = [System.Collections.Generic.List[string]]::new()

    foreach ($themeKey in $themeOrder) {
        $themeIndicators = @($sortedIndicators | Where-Object { (Get-IndicatorThemeKey -Category $_.Category) -eq $themeKey })
        if ($themeIndicators.Count -eq 0) {
            continue
        }

        $themeTitle = Get-ThemeTitle -ThemeKey $themeKey
        $firstSeen = ($themeIndicators | Select-Object -First 1).Timestamp
        $lastSeen = ($themeIndicators | Select-Object -Last 1).Timestamp
        $themeSummary = switch ($themeKey) {
            'UnauthorizedAccess' { "Evidence suggests the account was used or remained usable in a way that warrants unauthorized-access review, with $($themeIndicators.Count) related finding(s) between $firstSeen and $lastSeen." }
            'MailboxPersistence' { "Mailbox rules or mail-routing findings suggest persistence or exfiltration behavior, with $($themeIndicators.Count) supporting indicator(s) between $firstSeen and $lastSeen." }
            'OAuthPersistence' { "Application consent evidence suggests possible token-based persistence, with $($themeIndicators.Count) related indicator(s) between $firstSeen and $lastSeen." }
            'AccessExpansion' { "Delegation, permission, or tenant mail-flow findings suggest the compromise may have expanded beyond a single mailbox, with $($themeIndicators.Count) related indicator(s) between $firstSeen and $lastSeen." }
            default { "Additional findings require analyst review, with $($themeIndicators.Count) indicator(s) observed between $firstSeen and $lastSeen." }
        }

        $supportingFacts = ($themeIndicators | Select-Object -First 4 | ForEach-Object {
            $detailExcerpt = Get-IndicatorExcerpt -Text $_.RawDetail
            $fact = "<li><strong>$(ConvertTo-HtmlEncoded $_.Timestamp)</strong> - $(ConvertTo-HtmlEncoded $_.Description)"
            if ($detailExcerpt) {
                $fact += "<br><span class='muted-inline'>$(ConvertTo-HtmlEncoded $detailExcerpt)</span>"
            }
            $fact += '</li>'
            $fact
        }) -join "`n"

        [void]$themeRows.Add(@"
<article class="theme-card">
  <h3>$(ConvertTo-HtmlEncoded $themeTitle)</h3>
  <p>$(ConvertTo-HtmlEncoded $themeSummary)</p>
  <ul class="theme-facts">
$supportingFacts
  </ul>
</article>
"@)
    }

    if ($themeRows.Count -eq 0) {
        [void]$themeRows.Add('<article class="theme-card"><h3>No Confirmed Incident Theme</h3><p>No automated indicator group was strong enough to build a narrative theme. Manual review remains required.</p></article>')
    }

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
            "<tr><td><span class='severity-pill sev-$($_.Severity.ToLowerInvariant())'>$(ConvertTo-HtmlEncoded $_.Severity)</span></td><td>$(ConvertTo-HtmlEncoded $_.Category)</td><td>$(ConvertTo-HtmlEncoded $_.Description)</td><td>$(ConvertTo-HtmlEncoded (Get-IndicatorWhyItMatters -Category $_.Category))</td><td><details><summary>View detail</summary><pre>$(ConvertTo-HtmlEncoded $_.RawDetail)</pre></details></td><td>$(ConvertTo-HtmlEncoded $_.Timestamp)</td></tr>"
        }) -join "`n"
    }
    else {
        "<tr><td colspan='6'>No automated indicators were detected.</td></tr>"
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

    $recommendationItems = ($phasedRecommendations | ForEach-Object {
        "<li><strong>$(ConvertTo-HtmlEncoded $_.Phase):</strong> $(ConvertTo-HtmlEncoded $_.Action)</li>"
    }) -join "`n"

    $recentLogItems = ($recentLogs | ForEach-Object {
        "<li><strong>$(ConvertTo-HtmlEncoded $_.Timestamp)</strong> - $(ConvertTo-HtmlEncoded $_.Level): $(ConvertTo-HtmlEncoded $_.Message)</li>"
    }) -join "`n"

    $timelineHtml = if ($timelineItems.Count -gt 0) {
        ($timelineItems | ForEach-Object {
            "<li><strong>$(ConvertTo-HtmlEncoded $_.Timestamp)</strong> - <span class='timeline-type'>$(ConvertTo-HtmlEncoded $_.Type)</span>: $(ConvertTo-HtmlEncoded $_.Detail)</li>"
        }) -join "`n"
    }
    else {
        '<li>No notable events were available for timeline construction.</li>'
    }

    $evidenceSupportRows = foreach ($themeKey in $themeOrder) {
        $themeIndicators = @($sortedIndicators | Where-Object { (Get-IndicatorThemeKey -Category $_.Category) -eq $themeKey })
        if ($themeIndicators.Count -eq 0) { continue }
        $themeFiles = @(Get-ThemeEvidenceFiles -ThemeKey $themeKey -CollectedFiles $CollectedFiles)
        $fileText = if ($themeFiles.Count -gt 0) { (($themeFiles | Select-Object -ExpandProperty File) -join ', ') } else { 'No strong backing file match' }
        "<tr><td>$(ConvertTo-HtmlEncoded (Get-ThemeTitle -ThemeKey $themeKey))</td><td>$($themeIndicators.Count)</td><td>$(ConvertTo-HtmlEncoded $fileText)</td></tr>"
    }
    $evidenceSupportHtml = if (@($evidenceSupportRows).Count -gt 0) { $evidenceSupportRows -join "`n" } else { "<tr><td colspan='3'>No themed evidence groupings were available.</td></tr>" }

    $openQuestionsHtml = if ($openQuestions.Count -gt 0) {
        ($openQuestions | ForEach-Object { "<li>$(ConvertTo-HtmlEncoded $_)</li>" }) -join "`n"
    }
    else {
        '<li>No major unanswered questions were automatically identified.</li>'
    }

    $missingSourcesText = if (@($confidence.MissingSources).Count -gt 0) {
        ($confidence.MissingSources -join ', ')
    }
    else {
        'No major evidence gaps were registered by the collection engine.'
    }

    $summaryNarrative = if (@($Indicators).Count -gt 0) {
        $topCategories = @($sortedIndicators | Select-Object -ExpandProperty Category -Unique | Select-Object -First 3)
        $firstIndicator = ($sortedIndicators | Select-Object -First 1).Timestamp
        $lastIndicator = ($sortedIndicators | Select-Object -Last 1).Timestamp
        "Automated review identified $(@($Indicators).Count) indicator(s) for $(ConvertTo-HtmlEncoded $UserPrincipalName), led by $(ConvertTo-HtmlEncoded ($topCategories -join ', ')). The strongest evidence spans from $(ConvertTo-HtmlEncoded $firstIndicator) to $(ConvertTo-HtmlEncoded $lastIndicator), and the current assessment is $(ConvertTo-HtmlEncoded $severityLabel.ToLowerInvariant()) risk with $(ConvertTo-HtmlEncoded $confidence.Label.ToLowerInvariant()) confidence."
    }
    else {
        "Automated review completed for $(ConvertTo-HtmlEncoded $UserPrincipalName) with no direct indicators flagged by the script. Confidence is $(ConvertTo-HtmlEncoded $confidence.Label.ToLowerInvariant()), and manual portal review is still required before ruling out compromise activity."
    }

    # -------------------------------------------------------------------
    # Build analysis sections HTML (if AnalysisResult is available)
    # -------------------------------------------------------------------
    $signInSummaryHtml   = ''
    $ipLocationTableHtml = ''
    $compromiseWindowHtml = ''
    $auditCorrelationHtml = ''

    if ($null -ne $AnalysisResult) {
        # -- Sign-In Analysis summary card --
        $sis = $AnalysisResult.SignInSummary
        if ($null -ne $sis) {
            $signInSummaryHtml = @"
  <section class="section" id="signin-analysis">
    <h2>Sign-In Analysis</h2>
    <div class="stats" style="grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));">
      <div class="stat"><div class="label">Total Sign-Ins</div><div class="stat-value">$(ConvertTo-HtmlEncoded $sis.TotalSignIns)</div></div>
      <div class="stat"><div class="label">Unique IPs</div><div class="stat-value">$(ConvertTo-HtmlEncoded $sis.UniqueIPs)</div></div>
      <div class="stat"><div class="label">Countries</div><div class="stat-value">$(ConvertTo-HtmlEncoded $sis.UniqueCountries)</div></div>
      <div class="stat"><div class="label">Unique Apps</div><div class="stat-value">$(ConvertTo-HtmlEncoded $sis.UniqueApps)</div></div>
      <div class="stat"><div class="label">Successful</div><div class="stat-value" style="color:var(--ok);">$(ConvertTo-HtmlEncoded $sis.SuccessCount)</div></div>
      <div class="stat"><div class="label">Failed</div><div class="stat-value" style="color:var(--high);">$(ConvertTo-HtmlEncoded $sis.FailureCount)</div></div>
      <div class="stat"><div class="label">Interactive</div><div class="stat-value">$(ConvertTo-HtmlEncoded $sis.InteractiveCount)</div></div>
      <div class="stat"><div class="label">Non-Interactive</div><div class="stat-value">$(ConvertTo-HtmlEncoded $sis.NonInteractiveCount)</div></div>
    </div>
    <p style="margin-top:12px;color:var(--muted);">Window: $(ConvertTo-HtmlEncoded $sis.FirstSeen) to $(ConvertTo-HtmlEncoded $sis.LastSeen) | Countries: $(ConvertTo-HtmlEncoded $sis.CountryList)</p>
"@
            # Anomalous sign-ins sub-section
            $anomalies = @($AnalysisResult.AnomalousSignIns)
            if ($anomalies.Count -gt 0) {
                $anomRows = ($anomalies | Select-Object -First 15 | ForEach-Object {
                    $typeClass = switch ($_.Type) {
                        'ImpossibleTravel' { 'sev-high' }
                        'NewIP'            { 'sev-medium' }
                        'NewApp'           { 'sev-low' }
                        default            { '' }
                    }
                    "<tr><td><span class='severity-pill $typeClass'>$(ConvertTo-HtmlEncoded $_.Type)</span></td><td>$(ConvertTo-HtmlEncoded $_.Detail)</td><td>$(ConvertTo-HtmlEncoded $_.FirstSignIn)</td><td>$(ConvertTo-HtmlEncoded $_.FirstIP)</td></tr>"
                }) -join "`n"
                $signInSummaryHtml += @"

    <h3 style="margin-top:18px;">Anomalous Sign-In Events</h3>
    <table>
      <thead><tr><th>Type</th><th>Detail</th><th>First Seen</th><th>IP</th></tr></thead>
      <tbody>
$anomRows
      </tbody>
    </table>
"@
            }

            # Failed auth patterns sub-section
            $failPatterns = @($AnalysisResult.FailedAuthPatterns)
            if ($failPatterns.Count -gt 0) {
                $failRows = ($failPatterns | Select-Object -First 15 | ForEach-Object {
                    $patClass = switch ($_.Pattern) {
                        'PasswordSpray' { 'sev-high' }
                        'BruteForce'    { 'sev-high' }
                        default         { 'sev-low' }
                    }
                    "<tr><td><span class='severity-pill $patClass'>$(ConvertTo-HtmlEncoded $_.Pattern)</span></td><td>$(ConvertTo-HtmlEncoded $_.IPAddress)</td><td>$(ConvertTo-HtmlEncoded $_.FailCount) / $(ConvertTo-HtmlEncoded $_.TotalAttempts)</td><td>$(ConvertTo-HtmlEncoded $_.FailRate)</td><td>$(ConvertTo-HtmlEncoded $_.UniqueErrors)</td><td>$(ConvertTo-HtmlEncoded $_.FirstAttempt)</td><td>$(ConvertTo-HtmlEncoded $_.LastAttempt)</td></tr>"
                }) -join "`n"
                $signInSummaryHtml += @"

    <h3 style="margin-top:18px;">Failed Authentication Patterns</h3>
    <table>
      <thead><tr><th>Pattern</th><th>IP Address</th><th>Fail / Total</th><th>Fail Rate</th><th>Error Codes</th><th>First</th><th>Last</th></tr></thead>
      <tbody>
$failRows
      </tbody>
    </table>
"@
            }

            $signInSummaryHtml += "`n  </section>"
        }

        # -- IP / Location table --
        $ipData  = @($AnalysisResult.IPAnalysis)
        $locData = @($AnalysisResult.LocationAnalysis)
        if ($ipData.Count -gt 0 -or $locData.Count -gt 0) {
            $ipLocationTableHtml = @"
  <section class="section" id="ip-location">
    <h2>IP Addresses &amp; Locations</h2>
"@
            if ($ipData.Count -gt 0) {
                $ipRows = ($ipData | Select-Object -First 25 | ForEach-Object {
                    "<tr><td>$(ConvertTo-HtmlEncoded $_.IPAddress)</td><td>$(ConvertTo-HtmlEncoded $_.Count)</td><td style='color:var(--ok);'>$(ConvertTo-HtmlEncoded $_.SuccessCount)</td><td style='color:var(--high);'>$(ConvertTo-HtmlEncoded $_.FailCount)</td><td>$(ConvertTo-HtmlEncoded $_.Countries)</td><td>$(ConvertTo-HtmlEncoded $_.Apps)</td><td>$(ConvertTo-HtmlEncoded $_.FirstSeen)</td><td>$(ConvertTo-HtmlEncoded $_.LastSeen)</td></tr>"
                }) -join "`n"
                $ipLocationTableHtml += @"

    <h3>IP Address Activity</h3>
    <table>
      <thead><tr><th>IP Address</th><th>Count</th><th>Success</th><th>Fail</th><th>Countries</th><th>Apps</th><th>First Seen</th><th>Last Seen</th></tr></thead>
      <tbody>
$ipRows
      </tbody>
    </table>
"@
            }
            if ($locData.Count -gt 0) {
                $locRows = ($locData | Select-Object -First 20 | ForEach-Object {
                    "<tr><td>$(ConvertTo-HtmlEncoded $_.Country)</td><td>$(ConvertTo-HtmlEncoded $_.City)</td><td>$(ConvertTo-HtmlEncoded $_.Count)</td><td>$(ConvertTo-HtmlEncoded $_.UniqueIPs)</td><td>$(ConvertTo-HtmlEncoded $_.FirstSeen)</td><td>$(ConvertTo-HtmlEncoded $_.LastSeen)</td></tr>"
                }) -join "`n"
                $ipLocationTableHtml += @"

    <h3 style="margin-top:18px;">Location Summary</h3>
    <table>
      <thead><tr><th>Country</th><th>City</th><th>Sign-Ins</th><th>Unique IPs</th><th>First Seen</th><th>Last Seen</th></tr></thead>
      <tbody>
$locRows
      </tbody>
    </table>
"@
            }
            $ipLocationTableHtml += "`n  </section>"
        }

        # -- Compromise Window --
        $cw = $AnalysisResult.CompromiseWindow
        if ($null -ne $cw) {
            $keyEventsHtml = if ($cw.KeyEvents -and @($cw.KeyEvents).Count -gt 0) {
                ($cw.KeyEvents | ForEach-Object { "<li>$(ConvertTo-HtmlEncoded $_)</li>" }) -join "`n"
            } else { '<li>No key events identified.</li>' }

            $cwConfClass = switch ($cw.Confidence) {
                'High'   { 'sev-high' }
                'Medium' { 'sev-medium' }
                default  { 'sev-low' }
            }

            $compromiseWindowHtml = @"
  <section class="section" id="compromise-window">
    <h2>Estimated Compromise Window</h2>
    <div class="callout">
      <strong>Window:</strong> $(ConvertTo-HtmlEncoded $cw.WindowStart) to $(ConvertTo-HtmlEncoded $cw.WindowEnd)
      (<strong>$(ConvertTo-HtmlEncoded $cw.DurationDescription)</strong>)
      &mdash; Confidence: <span class="severity-pill $cwConfClass">$(ConvertTo-HtmlEncoded $cw.Confidence)</span>
      &mdash; $(ConvertTo-HtmlEncoded $cw.TotalSignals) corroborating signal(s)
    </div>
    <h3 style="margin-top:14px;">Key Bounding Events</h3>
    <ul class="action-list">
$keyEventsHtml
    </ul>
  </section>
"@
        }

        # -- Audit Correlation --
        $auditEvents = @($AnalysisResult.AuditTimeline)
        if ($auditEvents.Count -gt 0) {
            $auditRows = ($auditEvents | Select-Object -First 30 | ForEach-Object {
                $etClass = switch ($_.EventType) {
                    'PasswordChange' { 'sev-medium' }
                    'MFAChange'      { 'sev-high' }
                    'RoleChange'     { 'sev-high' }
                    'AppConsent'     { 'sev-high' }
                    default          { 'sev-low' }
                }
                "<tr><td>$(ConvertTo-HtmlEncoded $_.Timestamp)</td><td><span class='severity-pill $etClass'>$(ConvertTo-HtmlEncoded $_.EventType)</span></td><td>$(ConvertTo-HtmlEncoded $_.Activity)</td><td>$(ConvertTo-HtmlEncoded $_.InitiatedBy)</td><td>$(ConvertTo-HtmlEncoded $_.Target)</td><td>$(ConvertTo-HtmlEncoded $_.Result)</td></tr>"
            }) -join "`n"

            $auditCorrelationHtml = @"
  <section class="section" id="audit-correlation">
    <h2>Audit Event Correlation</h2>
    <p style="color:var(--muted);">High-value directory changes detected during the investigation window: password resets, MFA modifications, role changes, and application consents.</p>
    <table>
      <thead><tr><th>Timestamp</th><th>Event Type</th><th>Activity</th><th>Initiated By</th><th>Target</th><th>Result</th></tr></thead>
      <tbody>
$auditRows
      </tbody>
    </table>
  </section>
"@
        }
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
.muted-inline { color: var(--muted); }
.theme-grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
.theme-card { border: 1px solid var(--border); border-radius: 16px; padding: 16px; background: #fffcf7; }
.theme-facts { margin: 0; padding-left: 18px; }
.timeline-list { margin: 0; padding-left: 18px; }
.timeline-type { color: var(--accent); font-weight: 700; }
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
    <a href="#what-happened">What Happened</a>
    <a href="#timeline">Timeline</a>
    <a href="#signin-analysis">Sign-In Analysis</a>
    <a href="#ip-location">IPs &amp; Locations</a>
    <a href="#compromise-window">Compromise Window</a>
    <a href="#audit-correlation">Audit Correlation</a>
    <a href="#evidence-support">Supporting Evidence</a>
    <a href="#recommended-actions">Recommended Actions</a>
    <a href="#indicators">Indicators</a>
    <a href="#manual-review">Manual Review</a>
    <a href="#collection-issues">Collection Issues</a>
    <a href="#evidence">Collected Evidence</a>
  </nav>

  <div class="section-grid">
    <section class="section" id="what-happened">
      <h2>What Happened</h2>
      <div class="theme-grid">
$($themeRows -join "`n")
      </div>
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

  <div class="section-grid">
    <section class="section" id="timeline">
      <h2>Timeline of Notable Activity</h2>
      <ul class="timeline-list">
$timelineHtml
      </ul>
    </section>

    <section class="section" id="evidence-support">
      <h2>Evidence That Supports This Assessment</h2>
      <table>
        <thead>
          <tr><th>Theme</th><th>Indicators</th><th>Supporting Files</th></tr>
        </thead>
        <tbody>
$evidenceSupportHtml
        </tbody>
      </table>
      <div class="callout" style="margin-top:14px;">
        <strong>Coverage / Confidence: $(ConvertTo-HtmlEncoded $confidence.Label)</strong><br>
        $(ConvertTo-HtmlEncoded $confidence.Summary)<br>
        <strong>Known gaps:</strong> $(ConvertTo-HtmlEncoded $missingSourcesText)
      </div>
    </section>
  </div>

$signInSummaryHtml

$ipLocationTableHtml

$compromiseWindowHtml

$auditCorrelationHtml

  <section class="section">
    <h2>Open Questions</h2>
    <ul class="action-list">
$openQuestionsHtml
    </ul>
  </section>

  <section class="section">
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

  <section class="section" id="indicators">
    <h2>All Indicators</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Category</th><th>Description</th><th>Why It Matters</th><th>Detail</th><th>Timestamp</th></tr>
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
        [PSCustomObject]$CasePaths,

        [AllowNull()]
        [PSCustomObject]$AnalysisResult = $null
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
        $reportCollectedFiles = @($collectedFiles)

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
            -CollectedFiles @($reportCollectedFiles) `
            -CollectionErrors @($collectionErrors) `
            -Indicators @($indicators) `
            -LogEntries @($logEntries) `
            -AnalysisResult $AnalysisResult

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
