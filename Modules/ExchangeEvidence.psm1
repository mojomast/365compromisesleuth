#Requires -Version 7.0
<#
.SYNOPSIS
    Exchange Online evidence collection for M365 Compromise Response.

.DESCRIPTION
    Collects mailbox details, inbox rules, permissions, forwarding
    configuration, calendar delegates, transport rules, connectors,
    and message trace data from Exchange Online. All operations are
    read-only and exports go through Export-EvidenceData.
#>

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

$script:AcceptedDomains = $null

function Get-ExchangeAcceptedDomains {
    [CmdletBinding()]
    param()

    if ($null -ne $script:AcceptedDomains) {
        return $script:AcceptedDomains
    }

    try {
        $domains = @(Get-AcceptedDomain -ErrorAction Stop | Select-Object -ExpandProperty DomainName)
        $script:AcceptedDomains = @($domains | ForEach-Object { $_.ToString().ToLowerInvariant() } | Sort-Object -Unique)
    }
    catch {
        Write-EvidenceLog "Could not retrieve accepted domains (using UPN domain fallback): $($_.Exception.Message)" -Level Warning
        return @()
    }

    return $script:AcceptedDomains
}

function Get-ExchangeTargetEmailAddress {
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Target
    )

    if ($null -eq $Target) {
        return $null
    }

    $targetText = if ($Target -is [string]) {
        $Target
    }
    elseif ($Target.PSObject.Properties['PrimarySmtpAddress']) {
        [string]$Target.PrimarySmtpAddress
    }
    elseif ($Target.PSObject.Properties['Address']) {
        [string]$Target.Address
    }
    else {
        [string]$Target
    }

    if ($targetText -match '(?i)(?:smtp:)?([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})') {
        return $Matches[1].ToLowerInvariant()
    }

    return $null
}

function Add-NormalizedRecipientKey {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Keys,

        [AllowNull()]
        $Candidate
    )

    if ($null -eq $Candidate) {
        return
    }

    $text = $Candidate.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return
    }

    if ($text -match '^(?i)smtp:(.+@.+)$') {
        $text = $Matches[1]
    }

    [void]$Keys.Add($text.ToLowerInvariant())
}

function Get-NormalizedRecipientKeys {
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Value
    )

    $keys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($item in @($Value)) {
        if ($null -eq $item) {
            continue
        }

        foreach ($propertyName in @(
            'PrimarySmtpAddress',
            'WindowsEmailAddress',
            'Address',
            'UserPrincipalName',
            'Alias',
            'LegacyExchangeDN',
            'DistinguishedName',
            'Guid',
            'ExchangeGuid',
            'Identity'
        )) {
            if ($item.PSObject.Properties[$propertyName]) {
                Add-NormalizedRecipientKey -Keys $keys -Candidate $item.$propertyName
            }
        }

        if ($item.PSObject.Properties['EmailAddresses']) {
            foreach ($address in @($item.EmailAddresses)) {
                Add-NormalizedRecipientKey -Keys $keys -Candidate $address
            }
        }

        Add-NormalizedRecipientKey -Keys $keys -Candidate $item
    }

    return $keys
}

function Test-RecipientCollectionMatchesMailbox {
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Recipients,

        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$MailboxKeys
    )

    if ($null -eq $MailboxKeys -or $MailboxKeys.Count -eq 0) {
        return $false
    }

    if ($null -eq $Recipients -or @($Recipients).Count -eq 0) {
        return $false
    }

    $recipientKeys = Get-NormalizedRecipientKeys -Value $Recipients
    return $recipientKeys.Overlaps($MailboxKeys)
}

function ConvertTo-PlainExchangeObject {
    [CmdletBinding()]
    param(
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [string] -or
        $InputObject -is [char] -or
        $InputObject -is [bool] -or
        $InputObject -is [byte] -or
        $InputObject -is [int16] -or
        $InputObject -is [int32] -or
        $InputObject -is [int64] -or
        $InputObject -is [uint16] -or
        $InputObject -is [uint32] -or
        $InputObject -is [uint64] -or
        $InputObject -is [single] -or
        $InputObject -is [double] -or
        $InputObject -is [decimal] -or
        $InputObject -is [datetime] -or
        $InputObject -is [datetimeoffset] -or
        $InputObject -is [timespan] -or
        $InputObject -is [guid] -or
        $InputObject -is [uri]) {
        return $InputObject
    }

    if ($InputObject.GetType().IsEnum) {
        return $InputObject.ToString()
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $dictionaryResult = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $dictionaryResult[$key.ToString()] = ConvertTo-PlainExchangeObject -InputObject $InputObject[$key]
        }
        return [PSCustomObject]$dictionaryResult
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        return @($InputObject | ForEach-Object { ConvertTo-PlainExchangeObject -InputObject $_ })
    }

    $result = [ordered]@{}
    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.MemberType -notin @('Property', 'NoteProperty', 'AliasProperty', 'ScriptProperty')) {
            continue
        }

        try {
            $result[$property.Name] = ConvertTo-PlainExchangeObject -InputObject $property.Value
        }
        catch {
            $result[$property.Name] = [string]$property.Value
        }
    }

    return [PSCustomObject]$result
}

function Resolve-DefaultCalendarFolderIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Mailbox
    )

    if (Get-Command -Name 'Get-EXOMailboxFolderStatistics' -ErrorAction SilentlyContinue) {
        $stats = @(Get-EXOMailboxFolderStatistics -Identity $Mailbox -FolderScope Calendar -ErrorAction Stop)
    }
    else {
        $stats = @(Get-MailboxFolderStatistics -Identity $Mailbox -FolderScope Calendar -ErrorAction Stop)
    }

    $defaultCalendar = @($stats | Where-Object { $_.FolderType -eq 'Calendar' } | Select-Object -First 1)
    if (-not $defaultCalendar) {
        $defaultCalendar = @(
            $stats |
            Sort-Object @{ Expression = { ($_.FolderPath -split '/').Count } }, FolderPath |
            Select-Object -First 1
        )
    }

    if (-not $defaultCalendar) {
        throw "Could not resolve the default calendar folder for $Mailbox."
    }

    if ($defaultCalendar[0].PSObject.Properties['Identity'] -and -not [string]::IsNullOrWhiteSpace([string]$defaultCalendar[0].Identity)) {
        return [string]$defaultCalendar[0].Identity
    }

    $folderPath = ($defaultCalendar[0].FolderPath -replace '/', '\\').TrimStart('\\')
    return "${Mailbox}:\\$folderPath"
}

function Test-IsExternalExchangeTarget {
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Target,

        [Parameter(Mandatory)]
        [string]$FallbackDomain
    )

    $emailAddress = Get-ExchangeTargetEmailAddress -Target $Target
    if (-not $emailAddress) {
        return $false
    }

    $domain = ($emailAddress -split '@')[-1].ToLowerInvariant()
    $acceptedDomains = @(Get-ExchangeAcceptedDomains)

    if ($acceptedDomains.Count -gt 0) {
        return $domain -notin $acceptedDomains
    }

    return $domain -ne $FallbackDomain.ToLowerInvariant()
}

function Get-PagedMessageTrace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$BaseParameters,

        [string]$TraceLabel = 'message trace'
    )

    $pageSize = 5000
    $results = [System.Collections.Generic.List[object]]::new()
    $traceCommand = if (Get-Command -Name 'Get-MessageTraceV2' -ErrorAction SilentlyContinue) {
        'Get-MessageTraceV2'
    }
    else {
        'Get-MessageTrace'
    }

    if ($traceCommand -eq 'Get-MessageTraceV2') {
        $traceParams = @{}
        foreach ($key in $BaseParameters.Keys) {
            $traceParams[$key] = $BaseParameters[$key]
        }

        $traceParams['ResultSize'] = $pageSize
        $batchNumber = 1
        $seenKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        do {
            $pageResults = @(Get-MessageTraceV2 @traceParams -ErrorAction Stop)
            foreach ($item in $pageResults) {
                $dedupeKey = "{0}|{1}|{2}" -f $item.MessageTraceId, $item.RecipientAddress, $item.Received
                if ($seenKeys.Add($dedupeKey)) {
                    $results.Add($item)
                }
            }

            if ($batchNumber -gt 1 -and $pageResults.Count -gt 0) {
                Write-EvidenceLog "Collected batch $batchNumber for $TraceLabel ($($pageResults.Count) rows)." -Level Info
            }

            if ($pageResults.Count -lt $pageSize) {
                break
            }

            $lastItem = $pageResults[-1]
            $traceParams['EndDate'] = $lastItem.Received
            $traceParams['StartingRecipientAddress'] = $lastItem.RecipientAddress
            $batchNumber++
        } while ($true)
    }
    else {
        $page = 1
        do {
            $pageResults = @(Get-MessageTrace @BaseParameters -PageSize $pageSize -Page $page -ErrorAction Stop)
            foreach ($item in $pageResults) {
                $results.Add($item)
            }

            if ($page -gt 1 -and $pageResults.Count -gt 0) {
                Write-EvidenceLog "Collected page $page for $TraceLabel ($($pageResults.Count) rows)." -Level Info
            }

            $page++
        } while ($pageResults.Count -eq $pageSize)
    }

    return @($results)
}

function Export-ExchangeMailboxDetails {
    <#
    .SYNOPSIS
        Exports mailbox properties and statistics for the specified user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting mailbox details for $UserPrincipalName..." -Level Info

    try {
        $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop
        $mailboxJson = ConvertTo-PlainExchangeObject -InputObject ($mailbox | Select-Object *)

        $jsonPath = Join-Path $OutputFolder 'Mailbox.json'
        Export-EvidenceData -Data $mailboxJson -FilePath $jsonPath -Format 'JSON' -Description 'Mailbox properties'

        # Statistics
        try {
            $stats = Get-MailboxStatistics -Identity $UserPrincipalName -ErrorAction Stop
            $statsJson = ConvertTo-PlainExchangeObject -InputObject ($stats | Select-Object *)
            $statsPath = Join-Path $OutputFolder 'MailboxStatistics.json'
            Export-EvidenceData -Data $statsJson -FilePath $statsPath -Format 'JSON' -Description 'Mailbox statistics'
        }
        catch {
            Write-EvidenceLog "Could not retrieve mailbox statistics (non-fatal): $($_.Exception.Message)" -Level Warning
        }

        # Flattened CSV
        $flatMailbox = [PSCustomObject]@{
            DisplayName                = $mailbox.DisplayName
            PrimarySmtpAddress         = $mailbox.PrimarySmtpAddress
            MailboxType                = $mailbox.RecipientTypeDetails
            IsMailboxEnabled           = $mailbox.IsMailboxEnabled
            AuditEnabled               = $mailbox.AuditEnabled
            ForwardingAddress          = $mailbox.ForwardingAddress
            ForwardingSmtpAddress      = $mailbox.ForwardingSmtpAddress
            DeliverToMailboxAndForward  = $mailbox.DeliverToMailboxAndForward
            LitigationHoldEnabled      = $mailbox.LitigationHoldEnabled
            ArchiveStatus              = $mailbox.ArchiveStatus
            RetentionPolicy            = $mailbox.RetentionPolicy
            WhenCreated                = $mailbox.WhenCreated
            WhenChanged                = $mailbox.WhenChanged
        }

        $csvPath = Join-Path $OutputFolder 'Mailbox.csv'
        Export-EvidenceData -Data @($flatMailbox) -FilePath $csvPath -Format 'CSV' -Description 'Mailbox properties (key fields)'

        # Flag forwarding
        if (-not [string]::IsNullOrWhiteSpace($mailbox.ForwardingAddress)) {
            Register-Indicator -Category 'Forwarding' `
                -Description "Mailbox has ForwardingAddress set: $($mailbox.ForwardingAddress)" `
                -Severity 'High' `
                -RawDetail "ForwardingAddress=$($mailbox.ForwardingAddress), DeliverToMailboxAndForward=$($mailbox.DeliverToMailboxAndForward)"
        }
        if (-not [string]::IsNullOrWhiteSpace($mailbox.ForwardingSmtpAddress)) {
            Register-Indicator -Category 'Forwarding' `
                -Description "Mailbox has ForwardingSmtpAddress set: $($mailbox.ForwardingSmtpAddress)" `
                -Severity 'High' `
                -RawDetail "ForwardingSmtpAddress=$($mailbox.ForwardingSmtpAddress), DeliverToMailboxAndForward=$($mailbox.DeliverToMailboxAndForward)"
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeMailboxDetails' `
            -ErrorMessage "Failed to collect mailbox details for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

function Export-ExchangeInboxRules {
    <#
    .SYNOPSIS
        Exports inbox rules for the specified user, including hidden rules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting inbox rules for $UserPrincipalName..." -Level Info

    try {
        $fallbackDomain = ($UserPrincipalName -split '@')[1]
        $rules = @(Get-InboxRule -Mailbox $UserPrincipalName -IncludeHidden -ErrorAction Stop)

        $jsonPath = Join-Path $OutputFolder 'InboxRules.json'
        Export-EvidenceData -Data $rules -FilePath $jsonPath -Format 'JSON' -Description 'Inbox rules (including hidden)'

        # Flattened CSV
        $flatRules = @($rules | ForEach-Object {
            [PSCustomObject]@{
                Name                    = $_.Name
                Enabled                 = $_.Enabled
                Priority                = $_.Priority
                Description             = $_.Description
                ForwardTo               = ($_.ForwardTo -join '; ')
                ForwardAsAttachmentTo   = ($_.ForwardAsAttachmentTo -join '; ')
                RedirectTo              = ($_.RedirectTo -join '; ')
                DeleteMessage           = $_.DeleteMessage
                MoveToFolder            = $_.MoveToFolder
                MarkAsRead              = $_.MarkAsRead
                SubjectContainsWords    = ($_.SubjectContainsWords -join '; ')
                FromAddressContainsWords = ($_.FromAddressContainsWords -join '; ')
                Identity                = $_.Identity
                RuleIdentity            = $_.RuleIdentity
            }
        })

        $csvPath = Join-Path $OutputFolder 'InboxRules.csv'
        Export-EvidenceData -Data $flatRules -FilePath $csvPath -Format 'CSV' -Description 'Inbox rules summary'

        # Flag suspicious rules
        foreach ($rule in $rules) {
            # Check forwarding
            $forwardTargets = @()
            if ($rule.ForwardTo)             { $forwardTargets += $rule.ForwardTo }
            if ($rule.ForwardAsAttachmentTo) { $forwardTargets += $rule.ForwardAsAttachmentTo }
            if ($rule.RedirectTo)            { $forwardTargets += $rule.RedirectTo }

            if ($forwardTargets.Count -gt 0) {
                $externalTargets = @($forwardTargets | Where-Object {
                    Test-IsExternalExchangeTarget -Target $_ -FallbackDomain $fallbackDomain
                })
                if ($externalTargets.Count -gt 0) {
                    Register-Indicator -Category 'SuspiciousInboxRule' `
                        -Description "Inbox rule '$($rule.Name)' forwards/redirects to external: $($externalTargets -join ', ')" `
                        -Severity 'High' `
                        -RawDetail "RuleName=$($rule.Name), Targets=$($forwardTargets -join ', ')"
                }
            }

            # Check delete
            if ($rule.DeleteMessage -eq $true) {
                Register-Indicator -Category 'SuspiciousInboxRule' `
                    -Description "Inbox rule '$($rule.Name)' deletes messages." `
                    -Severity 'High' `
                    -RawDetail "RuleName=$($rule.Name), DeleteMessage=True"
            }

            # Check blank or suspicious names
            if ([string]::IsNullOrWhiteSpace($rule.Name) -or $rule.Name -match '^\s+$' -or $rule.Name -match '^\.$') {
                Register-Indicator -Category 'SuspiciousInboxRule' `
                    -Description "Inbox rule has blank or suspicious name (may be attacker-created)." `
                    -Severity 'High' `
                    -RawDetail "RuleName='$($rule.Name)', RuleId=$($rule.RuleIdentity)"
            }
        }

        Write-EvidenceLog "Collected $($rules.Count) inbox rules." -Level Info
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeInboxRules' `
            -ErrorMessage "Failed to collect inbox rules for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

function Export-ExchangeMailboxPermissions {
    <#
    .SYNOPSIS
        Exports Full Access, SendAs, and SendOnBehalf permissions for the mailbox.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting mailbox permissions for $UserPrincipalName..." -Level Info

    # Full Access
    try {
        $fullAccess = @(Get-MailboxPermission -Identity $UserPrincipalName -ErrorAction Stop)

        $jsonPath = Join-Path $OutputFolder 'MailboxPermissions_FullAccess.json'
        Export-EvidenceData -Data $fullAccess -FilePath $jsonPath -Format 'JSON' -Description 'Mailbox permissions - Full Access'

        $csvPath = Join-Path $OutputFolder 'MailboxPermissions_FullAccess.csv'
        $flatFA = @($fullAccess | ForEach-Object {
            [PSCustomObject]@{
                Identity     = $_.Identity
                User         = $_.User
                AccessRights = ($_.AccessRights -join '; ')
                IsInherited  = $_.IsInherited
                Deny         = $_.Deny
            }
        })
        Export-EvidenceData -Data $flatFA -FilePath $csvPath -Format 'CSV' -Description 'Mailbox permissions - Full Access'

        # Flag non-standard
        $nonStandard = @($fullAccess | Where-Object {
            $_.User -notmatch 'NT AUTHORITY\\SELF' -and
            $_.User -notmatch 'NT AUTHORITY\\SYSTEM' -and
            $_.IsInherited -eq $false -and
            $_.Deny -eq $false
        })
        foreach ($perm in $nonStandard) {
            Register-Indicator -Category 'MailboxPermission' `
                -Description "Non-default Full Access permission: $($perm.User) has $($perm.AccessRights -join ', ')" `
                -Severity 'Medium' `
                -RawDetail "User=$($perm.User), AccessRights=$($perm.AccessRights -join ', ')"
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeMailboxPermissions' `
            -ErrorMessage "Failed to collect Full Access permissions for $UserPrincipalName." `
            -ErrorRecord $_
    }

    # SendAs
    try {
        $sendAs = @(Get-RecipientPermission -Identity $UserPrincipalName -ErrorAction Stop)

        $jsonPath = Join-Path $OutputFolder 'MailboxPermissions_SendAs.json'
        Export-EvidenceData -Data $sendAs -FilePath $jsonPath -Format 'JSON' -Description 'Mailbox permissions - SendAs'

        $csvPath = Join-Path $OutputFolder 'MailboxPermissions_SendAs.csv'
        $flatSA = @($sendAs | ForEach-Object {
            [PSCustomObject]@{
                Identity     = $_.Identity
                Trustee      = $_.Trustee
                AccessRights = ($_.AccessRights -join '; ')
                AccessControlType = $_.AccessControlType
            }
        })
        Export-EvidenceData -Data $flatSA -FilePath $csvPath -Format 'CSV' -Description 'Mailbox permissions - SendAs'

        $effectiveSendAs = @(
            $sendAs |
            Where-Object {
                $_.Trustee -and
                $_.Trustee -notmatch '^NT AUTHORITY\\SELF$' -and
                ($_.AccessRights -contains 'SendAs')
            } |
            Group-Object { $_.Trustee.ToString().Trim().ToLowerInvariant() } |
            ForEach-Object {
                $allowEntries = @($_.Group | Where-Object { $_.AccessControlType -eq 'Allow' })
                $denyEntries = @($_.Group | Where-Object { $_.AccessControlType -eq 'Deny' })

                if ($allowEntries.Count -gt 0 -and $denyEntries.Count -eq 0) {
                    $allowEntries
                }
            }
        )

        foreach ($perm in $effectiveSendAs) {
            Register-Indicator -Category 'MailboxPermission' `
                -Description "Non-default SendAs permission: $($perm.Trustee)" `
                -Severity 'Medium' `
                -RawDetail "Trustee=$($perm.Trustee), AccessRights=$($perm.AccessRights -join ', ')"
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeMailboxPermissions' `
            -ErrorMessage "Failed to collect SendAs permissions for $UserPrincipalName." `
            -ErrorRecord $_
    }

    # SendOnBehalf
    try {
        $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop
        $sendOnBehalf = $mailbox.GrantSendOnBehalfTo

        $sobData = @($sendOnBehalf | ForEach-Object {
            [PSCustomObject]@{
                GrantedTo = $_
            }
        })

        $jsonPath = Join-Path $OutputFolder 'MailboxPermissions_SendOnBehalf.json'
        Export-EvidenceData -Data $sobData -FilePath $jsonPath -Format 'JSON' -Description 'Mailbox permissions - SendOnBehalf'

        $csvPath = Join-Path $OutputFolder 'MailboxPermissions_SendOnBehalf.csv'
        Export-EvidenceData -Data $sobData -FilePath $csvPath -Format 'CSV' -Description 'Mailbox permissions - SendOnBehalf'

        if ($sendOnBehalf -and $sendOnBehalf.Count -gt 0) {
            Register-Indicator -Category 'MailboxPermission' `
                -Description "SendOnBehalf granted to: $($sendOnBehalf -join ', ')" `
                -Severity 'Medium' `
                -RawDetail "GrantSendOnBehalfTo=$($sendOnBehalf -join ', ')"
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeMailboxPermissions' `
            -ErrorMessage "Failed to collect SendOnBehalf permissions for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

function Export-ExchangeForwarding {
    <#
    .SYNOPSIS
        Consolidates all forwarding configuration into a single summary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting forwarding summary for $UserPrincipalName..." -Level Info

    try {
        $fallbackDomain = ($UserPrincipalName -split '@')[1]
        $forwardingItems = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Check mailbox properties
        try {
            $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop

            if (-not [string]::IsNullOrWhiteSpace($mailbox.ForwardingAddress)) {
                $forwardingItems.Add([PSCustomObject]@{
                    Source      = 'MailboxProperty'
                    Type        = 'ForwardingAddress'
                    Target      = $mailbox.ForwardingAddress
                    DeliverToBoth = $mailbox.DeliverToMailboxAndForward
                    RuleName    = $null
                })
            }
            if (-not [string]::IsNullOrWhiteSpace($mailbox.ForwardingSmtpAddress)) {
                $forwardingItems.Add([PSCustomObject]@{
                    Source      = 'MailboxProperty'
                    Type        = 'ForwardingSmtpAddress'
                    Target      = $mailbox.ForwardingSmtpAddress
                    DeliverToBoth = $mailbox.DeliverToMailboxAndForward
                    RuleName    = $null
                })
            }
        }
        catch {
            Write-EvidenceLog "Could not check mailbox forwarding properties (non-fatal): $($_.Exception.Message)" -Level Warning
        }

        # Check inbox rules
        try {
            $rules = @(Get-InboxRule -Mailbox $UserPrincipalName -IncludeHidden -ErrorAction Stop)

            foreach ($rule in $rules) {
                if ($rule.ForwardTo) {
                    foreach ($target in $rule.ForwardTo) {
                        $forwardingItems.Add([PSCustomObject]@{
                            Source      = 'InboxRule'
                            Type        = 'ForwardTo'
                            Target      = $target
                            DeliverToBoth = $null
                            RuleName    = $rule.Name
                        })
                    }
                }
                if ($rule.ForwardAsAttachmentTo) {
                    foreach ($target in $rule.ForwardAsAttachmentTo) {
                        $forwardingItems.Add([PSCustomObject]@{
                            Source      = 'InboxRule'
                            Type        = 'ForwardAsAttachmentTo'
                            Target      = $target
                            DeliverToBoth = $null
                            RuleName    = $rule.Name
                        })
                    }
                }
                if ($rule.RedirectTo) {
                    foreach ($target in $rule.RedirectTo) {
                        $forwardingItems.Add([PSCustomObject]@{
                            Source      = 'InboxRule'
                            Type        = 'RedirectTo'
                            Target      = $target
                            DeliverToBoth = $null
                            RuleName    = $rule.Name
                        })
                    }
                }
            }
        }
        catch {
            Write-EvidenceLog "Could not check inbox rules for forwarding (non-fatal): $($_.Exception.Message)" -Level Warning
        }

        $jsonPath = Join-Path $OutputFolder 'ForwardingSummary.json'
        Export-EvidenceData -Data $forwardingItems -FilePath $jsonPath -Format 'JSON' -Description 'Forwarding summary (mailbox + inbox rules consolidated)'

        # Flag external forwarding
        if ($forwardingItems.Count -gt 0) {
            $externalItems = @($forwardingItems | Where-Object {
                Test-IsExternalExchangeTarget -Target $_.Target -FallbackDomain $fallbackDomain
            })

            if ($externalItems.Count -gt 0) {
                Register-Indicator -Category 'ExternalForwarding' `
                    -Description "External forwarding detected: $($externalItems.Count) forwarding rule(s)/setting(s) point outside the tenant." `
                    -Severity 'High' `
                    -RawDetail (($externalItems | ForEach-Object { "$($_.Source):$($_.Type)->$($_.Target)" }) -join '; ')
            }
        }

        Write-EvidenceLog "Forwarding summary: $($forwardingItems.Count) forwarding configuration(s) found." -Level Info
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeForwarding' `
            -ErrorMessage "Failed to generate forwarding summary for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

function Export-ExchangeCalendarDelegates {
    <#
    .SYNOPSIS
        Exports calendar folder permissions for the specified user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting calendar permissions for $UserPrincipalName..." -Level Info

    try {
        $calendarIdentity = Resolve-DefaultCalendarFolderIdentity -Mailbox $UserPrincipalName
        $calPerms = @(Get-MailboxFolderPermission -Identity $calendarIdentity -ErrorAction Stop)

        $jsonPath = Join-Path $OutputFolder 'CalendarPermissions.json'
        Export-EvidenceData -Data $calPerms -FilePath $jsonPath -Format 'JSON' -Description 'Calendar folder permissions'

        $flatPerms = @($calPerms | ForEach-Object {
            [PSCustomObject]@{
                FolderName   = $_.FolderName
                User         = $_.User.DisplayName
                AccessRights = ($_.AccessRights -join '; ')
                SharingPermissionFlags = $_.SharingPermissionFlags
            }
        })

        $csvPath = Join-Path $OutputFolder 'CalendarPermissions.csv'
        Export-EvidenceData -Data $flatPerms -FilePath $csvPath -Format 'CSV' -Description 'Calendar folder permissions'

        # Flag unusual permissions
        $privilegedAccess = @('Editor', 'Owner', 'PublishingEditor', 'PublishingAuthor')
        foreach ($perm in $calPerms) {
            $userName = $perm.User.DisplayName
            if ($userName -in @('Default', 'Anonymous')) { continue }

            $rights = $perm.AccessRights | ForEach-Object { $_.ToString() }
            $hasPrivileged = @($rights | Where-Object { $_ -in $privilegedAccess })

            if ($hasPrivileged.Count -gt 0) {
                Register-Indicator -Category 'CalendarPermission' `
                    -Description "Calendar permission: $userName has $($hasPrivileged -join ', ') access." `
                    -Severity 'Medium' `
                    -RawDetail "User=$userName, AccessRights=$($rights -join ', ')"
            }
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeCalendarDelegates' `
            -ErrorMessage "Failed to collect calendar permissions for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

function Export-ExchangeTransportRules {
    <#
    .SYNOPSIS
        Exports tenant-wide transport rules (mail flow rules).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting transport rules (tenant-wide)..." -Level Info

    try {
        $mailboxKeys = $null
        try {
            $mailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop
            $mailboxKeys = Get-NormalizedRecipientKeys -Value @($mailbox, $UserPrincipalName)
        }
        catch {
            Write-EvidenceLog "Could not resolve mailbox identifiers for transport rule matching; using UPN-only matching: $($_.Exception.Message)" -Level Warning
            $mailboxKeys = Get-NormalizedRecipientKeys -Value @($UserPrincipalName)
        }

        $rules = @(Get-TransportRule -ErrorAction Stop)

        $jsonPath = Join-Path $OutputFolder 'TransportRules.json'
        Export-EvidenceData -Data $rules -FilePath $jsonPath -Format 'JSON' -Description 'Transport rules (tenant-wide mail flow rules)'

        $flatRules = @($rules | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.Name
                State       = $_.State
                Priority    = $_.Priority
                Mode        = $_.Mode
                Description = $_.Description
                WhenChanged = $_.WhenChanged
                SentTo      = ($_.SentTo -join '; ')
                SentToMemberOf = ($_.SentToMemberOf -join '; ')
                From        = ($_.From -join '; ')
                BlindCopyTo = ($_.BlindCopyTo -join '; ')
                RedirectMessageTo = ($_.RedirectMessageTo -join '; ')
                CopyTo      = ($_.CopyTo -join '; ')
            }
        })

        $csvPath = Join-Path $OutputFolder 'TransportRules.csv'
        Export-EvidenceData -Data $flatRules -FilePath $csvPath -Format 'CSV' -Description 'Transport rules summary'

        # Flag rules that affect the compromised user
        foreach ($rule in $rules) {
            $affectsUser = $false
            $reason = ''

            if ($rule.SentTo -and (Test-RecipientCollectionMatchesMailbox -Recipients $rule.SentTo -MailboxKeys $mailboxKeys)) {
                $affectsUser = $true; $reason = "SentTo matches"
            }
            if ($rule.From -and (Test-RecipientCollectionMatchesMailbox -Recipients $rule.From -MailboxKeys $mailboxKeys)) {
                $affectsUser = $true; $reason = "From matches"
            }

            $hasRedirect = $rule.RedirectMessageTo -or $rule.BlindCopyTo -or $rule.CopyTo
            if ($affectsUser -and $hasRedirect) {
                Register-Indicator -Category 'TransportRule' `
                    -Description "Transport rule '$($rule.Name)' redirects/BCCs mail for the compromised user ($reason)." `
                    -Severity 'Medium' `
                    -RawDetail "RuleName=$($rule.Name), State=$($rule.State), RedirectTo=$($rule.RedirectMessageTo -join ', '), BCC=$($rule.BlindCopyTo -join ', ')"
            }
        }

        Write-EvidenceLog "Collected $($rules.Count) transport rules." -Level Info
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeTransportRules' `
            -ErrorMessage "Failed to collect transport rules." `
            -ErrorRecord $_
    }
}

function Export-ExchangeConnectors {
    <#
    .SYNOPSIS
        Exports inbound and outbound connectors for the tenant.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting Exchange connectors (tenant-wide)..." -Level Info

    # Inbound connectors
    try {
        $inbound = @(Get-InboundConnector -ErrorAction Stop)

        $jsonPath = Join-Path $OutputFolder 'InboundConnectors.json'
        Export-EvidenceData -Data $inbound -FilePath $jsonPath -Format 'JSON' -Description 'Inbound connectors'

        # Flag recently created connectors (last 30 days)
        $thirtyDaysAgo = (Get-Date).AddDays(-30)
        foreach ($conn in $inbound) {
            if ($conn.WhenCreated -and $conn.WhenCreated -gt $thirtyDaysAgo) {
                Register-Indicator -Category 'Connector' `
                    -Description "Recently created inbound connector: '$($conn.Name)' (created $($conn.WhenCreated))" `
                    -Severity 'Medium' `
                    -RawDetail "Name=$($conn.Name), Enabled=$($conn.Enabled), WhenCreated=$($conn.WhenCreated)"
            }
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeConnectors' `
            -ErrorMessage "Failed to collect inbound connectors." `
            -ErrorRecord $_
    }

    # Outbound connectors
    try {
        $outbound = @(Get-OutboundConnector -ErrorAction Stop)

        $jsonPath = Join-Path $OutputFolder 'OutboundConnectors.json'
        Export-EvidenceData -Data $outbound -FilePath $jsonPath -Format 'JSON' -Description 'Outbound connectors'

        $thirtyDaysAgo = (Get-Date).AddDays(-30)
        foreach ($conn in $outbound) {
            if ($conn.WhenCreated -and $conn.WhenCreated -gt $thirtyDaysAgo) {
                Register-Indicator -Category 'Connector' `
                    -Description "Recently created outbound connector: '$($conn.Name)' (created $($conn.WhenCreated))" `
                    -Severity 'Medium' `
                    -RawDetail "Name=$($conn.Name), Enabled=$($conn.Enabled), WhenCreated=$($conn.WhenCreated)"
            }
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeConnectors' `
            -ErrorMessage "Failed to collect outbound connectors." `
            -ErrorRecord $_
    }
}

function Export-ExchangeMessageTrace {
    <#
    .SYNOPSIS
        Exports message trace data for sent and received messages (last 7 days).
    .DESCRIPTION
        Note: Exchange Online message trace only goes back 10 days via PowerShell.
        For older data, use Start-HistoricalSearch (async, not suitable here).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting message trace for $UserPrincipalName (last 7 days)..." -Level Info

    $startDate = (Get-Date).AddDays(-7)
    $endDate   = Get-Date

    $sentMessages     = @()
    $receivedMessages = @()

    # Sent messages
    try {
        $sentMessages = @(Get-PagedMessageTrace -BaseParameters @{
                SenderAddress = $UserPrincipalName
                StartDate     = $startDate
                EndDate       = $endDate
            } -TraceLabel 'sent message trace')

        $csvPath = Join-Path $OutputFolder 'MessageTrace_Sent.csv'
        Export-EvidenceData -Data $sentMessages -FilePath $csvPath -Format 'CSV' -Description 'Message trace - sent messages (last 7 days)'

        Write-EvidenceLog "Collected $($sentMessages.Count) sent message trace entries." -Level Info
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeMessageTrace' `
            -ErrorMessage "Failed to collect sent message trace for $UserPrincipalName." `
            -ErrorRecord $_
    }

    # Received messages
    try {
        $receivedMessages = @(Get-PagedMessageTrace -BaseParameters @{
                RecipientAddress = $UserPrincipalName
                StartDate        = $startDate
                EndDate          = $endDate
            } -TraceLabel 'received message trace')

        $csvPath = Join-Path $OutputFolder 'MessageTrace_Received.csv'
        Export-EvidenceData -Data $receivedMessages -FilePath $csvPath -Format 'CSV' -Description 'Message trace - received messages (last 7 days)'

        Write-EvidenceLog "Collected $($receivedMessages.Count) received message trace entries." -Level Info
    }
    catch {
        Register-CollectionError -FunctionName 'Export-ExchangeMessageTrace' `
            -ErrorMessage "Failed to collect received message trace for $UserPrincipalName." `
            -ErrorRecord $_
    }

    # Combined raw JSON export
    if ($RawFolder) {
        $combined = @{
            Sent     = $sentMessages
            Received = $receivedMessages
            Metadata = @{
                UserPrincipalName = $UserPrincipalName
                StartDate         = $startDate.ToString('o')
                EndDate           = $endDate.ToString('o')
                SentCount         = $sentMessages.Count
                ReceivedCount     = $receivedMessages.Count
            }
        }
        $rawPath = Join-Path $RawFolder 'MessageTrace_Raw.json'
        Export-EvidenceData -Data $combined -FilePath $rawPath -Format 'JSON' -Description 'Message trace raw (sent + received, last 7 days)'
    }

    # Flag high-volume outbound
    if ($sentMessages.Count -gt 0) {
        $fallbackDomain = ($UserPrincipalName -split '@')[1]
        $externalRecipients = @($sentMessages |
            Where-Object { Test-IsExternalExchangeTarget -Target $_.RecipientAddress -FallbackDomain $fallbackDomain } |
            Select-Object -ExpandProperty RecipientAddress -Unique)

        if ($externalRecipients.Count -gt 100) {
            Register-Indicator -Category 'HighVolumeOutbound' `
                -Description "High outbound volume: $($externalRecipients.Count) unique external recipients in 7 days (threshold: 100)." `
                -Severity 'High' `
                -RawDetail "TotalSent=$($sentMessages.Count), UniqueExternalRecipients=$($externalRecipients.Count)"
        }
    }
}

# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'Export-ExchangeMailboxDetails'
    'Export-ExchangeInboxRules'
    'Export-ExchangeMailboxPermissions'
    'Export-ExchangeForwarding'
    'Export-ExchangeCalendarDelegates'
    'Export-ExchangeTransportRules'
    'Export-ExchangeConnectors'
    'Export-ExchangeMessageTrace'
)
