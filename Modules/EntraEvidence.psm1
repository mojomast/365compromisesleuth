#Requires -Version 7.0
<#
.SYNOPSIS
    Entra ID (Azure AD) evidence collection via Microsoft Graph.

.DESCRIPTION
    Collects user profile, authentication methods, directory roles,
    sign-in logs, risk data, audit logs, and application assignments
    from Microsoft Graph for a potentially compromised user account.
    All data is read-only and exported via Export-EvidenceData.
#>

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

function Export-EntraUserProfile {
    <#
    .SYNOPSIS
        Exports the full Entra ID user profile for the specified UPN.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting Entra user profile for $UserPrincipalName..." -Level Info

    try {
        $user = Get-MgUser -UserId $UserPrincipalName -Property * -ErrorAction Stop

        # Full JSON export
        $jsonPath = Join-Path $OutputFolder 'UserProfile.json'
        Export-EvidenceData -Data $user -FilePath $jsonPath -Format 'JSON' -Description 'Entra ID user profile (full)'

        # Flattened CSV with key fields
        $flatUser = [PSCustomObject]@{
            DisplayName                 = $user.DisplayName
            UserPrincipalName           = $user.UserPrincipalName
            Mail                        = $user.Mail
            AccountEnabled              = $user.AccountEnabled
            CreatedDateTime             = $user.CreatedDateTime
            LastPasswordChangeDateTime  = $user.LastPasswordChangeDateTime
            OnPremisesSyncEnabled       = $user.OnPremisesSyncEnabled
            UserType                    = $user.UserType
            JobTitle                    = $user.JobTitle
            Department                  = $user.Department
            OfficeLocation              = $user.OfficeLocation
            MobilePhone                 = $user.MobilePhone
            BusinessPhones              = ($user.BusinessPhones -join '; ')
            ProxyAddresses              = ($user.ProxyAddresses -join '; ')
            Id                          = $user.Id
        }
        $csvPath = Join-Path $OutputFolder 'UserProfile.csv'
        Export-EvidenceData -Data @($flatUser) -FilePath $csvPath -Format 'CSV' -Description 'Entra ID user profile (key fields)'

        # Flag if account is still enabled (compromised but active)
        if ($user.AccountEnabled -eq $true) {
            Register-Indicator -Category 'AccountStatus' `
                -Description "Account is still ENABLED for $UserPrincipalName - compromised account remains active." `
                -Severity 'Medium' `
                -RawDetail "AccountEnabled=$($user.AccountEnabled), LastPasswordChange=$($user.LastPasswordChangeDateTime)"
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Export-EntraUserProfile' `
            -ErrorMessage "Failed to collect user profile for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

function Export-EntraAuthMethods {
    <#
    .SYNOPSIS
        Exports authentication methods registered for the specified user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting authentication methods for $UserPrincipalName..." -Level Info

    try {
        $authMethods = @(Get-MgUserAuthenticationMethod -UserId $UserPrincipalName -ErrorAction Stop)

        # Full JSON export
        $jsonPath = Join-Path $OutputFolder 'AuthenticationMethods.json'
        Export-EvidenceData -Data $authMethods -FilePath $jsonPath -Format 'JSON' -Description 'Authentication methods (all)'

        # Collect detailed method info
        $details = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($method in $authMethods) {
            $methodType = ($method.AdditionalProperties['@odata.type'] -replace '#microsoft\.graph\.', '')
            $details.Add([PSCustomObject]@{
                Id         = $method.Id
                MethodType = $methodType
            })
        }

        # Try to get phone methods for detail
        try {
            $phoneMethods = @(Get-MgUserAuthenticationPhoneMethod -UserId $UserPrincipalName -ErrorAction Stop)
            foreach ($pm in $phoneMethods) {
                $details.Add([PSCustomObject]@{
                    Id         = $pm.Id
                    MethodType = "Phone: $($pm.PhoneType) - $($pm.PhoneNumber)"
                })
            }
        }
        catch {
            Write-EvidenceLog "Could not retrieve phone auth methods (non-fatal): $($_.Exception.Message)" -Level Warning
        }

        # Try to get email methods
        try {
            $emailMethods = @(Get-MgUserAuthenticationEmailMethod -UserId $UserPrincipalName -ErrorAction Stop)
            foreach ($em in $emailMethods) {
                $details.Add([PSCustomObject]@{
                    Id         = $em.Id
                    MethodType = "Email: $($em.EmailAddress)"
                })
            }
        }
        catch {
            Write-EvidenceLog "Could not retrieve email auth methods (non-fatal): $($_.Exception.Message)" -Level Warning
        }

        # Try to get Microsoft Authenticator methods
        try {
            $maMethods = @(Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $UserPrincipalName -ErrorAction Stop)
            foreach ($ma in $maMethods) {
                $details.Add([PSCustomObject]@{
                    Id         = $ma.Id
                    MethodType = "MicrosoftAuthenticator: $($ma.DisplayName) ($($ma.DeviceTag))"
                })
            }
        }
        catch {
            Write-EvidenceLog "Could not retrieve Authenticator app methods (non-fatal): $($_.Exception.Message)" -Level Warning
        }

        # Summary CSV
        $csvPath = Join-Path $OutputFolder 'AuthenticationMethods.csv'
        Export-EvidenceData -Data $details -FilePath $csvPath -Format 'CSV' -Description 'Authentication methods summary'
    }
    catch {
        Register-CollectionError -FunctionName 'Export-EntraAuthMethods' `
            -ErrorMessage "Failed to collect authentication methods for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

function Export-EntraDirectoryRoles {
    <#
    .SYNOPSIS
        Exports directory role and group memberships for the specified user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting directory roles and group memberships for $UserPrincipalName..." -Level Info

    try {
        $memberOf = @(Get-MgUserMemberOf -UserId $UserPrincipalName -All -ErrorAction Stop)

        # Separate directory roles from groups
        $directoryRoles = @($memberOf | Where-Object {
            $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.directoryRole'
        })
        $groups = @($memberOf | Where-Object {
            $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group'
        })

        # Directory roles - JSON
        $rolesData = @($directoryRoles | ForEach-Object {
            [PSCustomObject]@{
                Id          = $_.Id
                DisplayName = $_.AdditionalProperties['displayName']
                Description = $_.AdditionalProperties['description']
                RoleTemplateId = $_.AdditionalProperties['roleTemplateId']
            }
        })
        $rolesJsonPath = Join-Path $OutputFolder 'DirectoryRoles.json'
        Export-EvidenceData -Data $rolesData -FilePath $rolesJsonPath -Format 'JSON' -Description 'Directory role assignments'

        $rolesCsvPath = Join-Path $OutputFolder 'DirectoryRoles.csv'
        Export-EvidenceData -Data $rolesData -FilePath $rolesCsvPath -Format 'CSV' -Description 'Directory role assignments'

        # Group memberships - JSON
        $groupsData = @($groups | ForEach-Object {
            [PSCustomObject]@{
                Id          = $_.Id
                DisplayName = $_.AdditionalProperties['displayName']
                Description = $_.AdditionalProperties['description']
                GroupTypes  = ($_.AdditionalProperties['groupTypes'] -join '; ')
                MailEnabled = $_.AdditionalProperties['mailEnabled']
                SecurityEnabled = $_.AdditionalProperties['securityEnabled']
            }
        })
        $groupsJsonPath = Join-Path $OutputFolder 'GroupMemberships.json'
        Export-EvidenceData -Data $groupsData -FilePath $groupsJsonPath -Format 'JSON' -Description 'Group memberships'

        $groupsCsvPath = Join-Path $OutputFolder 'GroupMemberships.csv'
        Export-EvidenceData -Data $groupsData -FilePath $groupsCsvPath -Format 'CSV' -Description 'Group memberships'

        # Flag high-privilege roles
        $privilegedRoles = @(
            'Global Administrator'
            'Exchange Administrator'
            'Security Administrator'
            'SharePoint Administrator'
            'Privileged Role Administrator'
            'User Administrator'
            'Helpdesk Administrator'
            'Application Administrator'
            'Cloud Application Administrator'
            'Authentication Administrator'
            'Privileged Authentication Administrator'
            'Conditional Access Administrator'
        )

        foreach ($role in $rolesData) {
            if ($role.DisplayName -in $privilegedRoles) {
                Register-Indicator -Category 'PrivilegedRole' `
                    -Description "User holds privileged role: $($role.DisplayName)" `
                    -Severity 'High' `
                    -RawDetail "RoleId=$($role.Id), RoleTemplateId=$($role.RoleTemplateId)"
            }
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Export-EntraDirectoryRoles' `
            -ErrorMessage "Failed to collect directory roles for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

function Export-EntraSignInLogs {
    <#
    .SYNOPSIS
        Exports sign-in logs for the specified user from the last 7 days.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting sign-in logs for $UserPrincipalName (last 7 days)..." -Level Info

    try {
        $dateFilter = (Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filter = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $dateFilter"

        $signIns = @(Get-MgAuditLogSignIn -Filter $filter -Top 500 -All -ErrorAction Stop)

        # Raw JSON export
        if ($RawFolder) {
            $rawPath = Join-Path $RawFolder 'SignInLogs_Raw.json'
            Export-EvidenceData -Data $signIns -FilePath $rawPath -Format 'JSON' -Description 'Sign-in logs raw (last 7 days)'
        }

        # Analyst-friendly CSV with flattened fields
        $flatSignIns = @($signIns | ForEach-Object {
            $location = $_.Location
            $status   = $_.Status
            $device   = $_.DeviceDetail

            [PSCustomObject]@{
                CreatedDateTime         = $_.CreatedDateTime
                AppDisplayName          = $_.AppDisplayName
                IPAddress               = $_.IPAddress
                City                    = $location.City
                State                   = $location.State
                Country                 = $location.CountryOrRegion
                StatusErrorCode         = $status.ErrorCode
                StatusFailureReason     = $status.FailureReason
                ClientAppUsed           = $_.ClientAppUsed
                DeviceBrowser           = $device.Browser
                DeviceOS                = $device.OperatingSystem
                DeviceDisplayName       = $device.DisplayName
                IsInteractive           = $_.IsInteractive
                RiskLevelDuringSignIn   = $_.RiskLevelDuringSignIn
                ConditionalAccessStatus = $_.ConditionalAccessStatus
                ResourceDisplayName     = $_.ResourceDisplayName
            }
        })

        $csvPath = Join-Path $OutputFolder 'SignInLogs.csv'
        Export-EvidenceData -Data $flatSignIns -FilePath $csvPath -Format 'CSV' -Description 'Sign-in logs analyst view (last 7 days)'

        # Flag if sign-ins from many distinct countries
        $countries = @($flatSignIns | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Country) } |
            Select-Object -ExpandProperty Country -Unique)

        if ($countries.Count -gt 3) {
            Register-Indicator -Category 'SignInAnomaly' `
                -Description "Sign-ins detected from $($countries.Count) distinct countries in the last 7 days: $($countries -join ', ')" `
                -Severity 'Medium' `
                -RawDetail "Countries: $($countries -join ', ')"
        }

        Write-EvidenceLog "Collected $($signIns.Count) sign-in log entries." -Level Info
    }
    catch {
        Register-CollectionError -FunctionName 'Export-EntraSignInLogs' `
            -ErrorMessage "Failed to collect sign-in logs for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

function Export-EntraRiskData {
    <#
    .SYNOPSIS
        Exports risky user status and risk detections (requires Entra ID P2).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting risk data for $UserPrincipalName (requires Entra P2)..." -Level Info

    # Risky User
    try {
        $riskyUser = @(Get-MgRiskyUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction Stop)

        $jsonPath = Join-Path $OutputFolder 'RiskyUser.json'
        Export-EvidenceData -Data $riskyUser -FilePath $jsonPath -Format 'JSON' -Description 'Risky user status (Entra ID P2)'

        foreach ($ru in $riskyUser) {
            if ($ru.RiskState -in @('atRisk', 'confirmedCompromised')) {
                Register-Indicator -Category 'RiskStatus' `
                    -Description "User risk state is '$($ru.RiskState)' with risk level '$($ru.RiskLevel)'." `
                    -Severity 'High' `
                    -RawDetail "RiskState=$($ru.RiskState), RiskLevel=$($ru.RiskLevel), RiskLastUpdated=$($ru.RiskLastUpdatedDateTime)"
            }
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403|Forbidden|license|Premium|P2') {
            Write-EvidenceLog "Risky user data not available (likely requires Entra ID P2 license): $msg" -Level Warning
        }
        else {
            Register-CollectionError -FunctionName 'Export-EntraRiskData' `
                -ErrorMessage "Failed to collect risky user data for $UserPrincipalName." `
                -ErrorRecord $_
        }
    }

    # Risk Detections
    try {
        $riskDetections = @(Get-MgRiskDetection -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction Stop)

        $jsonPath = Join-Path $OutputFolder 'RiskDetections.json'
        Export-EvidenceData -Data $riskDetections -FilePath $jsonPath -Format 'JSON' -Description 'Risk detections (Entra ID P2)'
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403|Forbidden|license|Premium|P2') {
            Write-EvidenceLog "Risk detections not available (likely requires Entra ID P2 license): $msg" -Level Warning
        }
        else {
            Register-CollectionError -FunctionName 'Export-EntraRiskData' `
                -ErrorMessage "Failed to collect risk detections for $UserPrincipalName." `
                -ErrorRecord $_
        }
    }
}

function Export-EntraAuditLogs {
    <#
    .SYNOPSIS
        Exports directory audit logs targeting the specified user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting audit logs for $UserPrincipalName (last 7 days)..." -Level Info

    try {
        $dateFilter = (Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $auditLogs = $null

        # Try the targeted filter first
        try {
            $filter = "targetResources/any(t: t/userPrincipalName eq '$UserPrincipalName') and activityDateTime ge $dateFilter"
            $auditLogs = @(Get-MgAuditLogDirectoryAudit -Filter $filter -Top 500 -All -ErrorAction Stop)
        }
        catch {
            Write-EvidenceLog "Targeted audit log filter failed, trying broader initiatedBy filter..." -Level Warning
            try {
                $filter = "initiatedBy/user/userPrincipalName eq '$UserPrincipalName' and activityDateTime ge $dateFilter"
                $auditLogs = @(Get-MgAuditLogDirectoryAudit -Filter $filter -Top 500 -All -ErrorAction Stop)
            }
            catch {
                Write-EvidenceLog "Broader audit log filter also failed. Collecting recent audit logs and filtering client-side..." -Level Warning
                $filter = "activityDateTime ge $dateFilter"
                $allLogs = @(Get-MgAuditLogDirectoryAudit -Filter $filter -Top 1000 -All -ErrorAction Stop)
                $auditLogs = @($allLogs | Where-Object {
                    $upnMatch = $false
                    foreach ($target in $_.TargetResources) {
                        if ($target.UserPrincipalName -eq $UserPrincipalName) {
                            $upnMatch = $true
                            break
                        }
                    }
                    if (-not $upnMatch -and $_.InitiatedBy.User.UserPrincipalName -eq $UserPrincipalName) {
                        $upnMatch = $true
                    }
                    $upnMatch
                })
            }
        }

        # JSON export
        $jsonPath = Join-Path $OutputFolder 'AuditLogs.json'
        Export-EvidenceData -Data $auditLogs -FilePath $jsonPath -Format 'JSON' -Description 'Directory audit logs (last 7 days)'

        # CSV export with flattened fields
        $flatAudit = @($auditLogs | ForEach-Object {
            $initiatedBy = if ($_.InitiatedBy.User) {
                $_.InitiatedBy.User.UserPrincipalName
            } elseif ($_.InitiatedBy.App) {
                $_.InitiatedBy.App.DisplayName
            } else { '' }

            $targetNames = ($_.TargetResources | ForEach-Object {
                $_.UserPrincipalName ?? $_.DisplayName ?? $_.Id
            }) -join '; '

            [PSCustomObject]@{
                ActivityDateTime = $_.ActivityDateTime
                ActivityDisplayName = $_.ActivityDisplayName
                Category         = $_.Category
                Result           = $_.Result
                InitiatedBy      = $initiatedBy
                TargetResources  = $targetNames
                OperationType    = $_.OperationType
                LoggedByService  = $_.LoggedByService
                CorrelationId    = $_.CorrelationId
            }
        })

        $csvPath = Join-Path $OutputFolder 'AuditLogs.csv'
        Export-EvidenceData -Data $flatAudit -FilePath $csvPath -Format 'CSV' -Description 'Directory audit logs analyst view (last 7 days)'

        Write-EvidenceLog "Collected $($auditLogs.Count) audit log entries." -Level Info
    }
    catch {
        Register-CollectionError -FunctionName 'Export-EntraAuditLogs' `
            -ErrorMessage "Failed to collect audit logs for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

function Export-EntraAppAssignments {
    <#
    .SYNOPSIS
        Exports app role assignments and OAuth consent grants for the specified user.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$RawFolder
    )

    Write-EvidenceLog "Collecting app assignments and OAuth consents for $UserPrincipalName..." -Level Info

    # App Role Assignments
    try {
        $appRoles = @(Get-MgUserAppRoleAssignment -UserId $UserPrincipalName -All -ErrorAction Stop)

        $jsonPath = Join-Path $OutputFolder 'AppRoleAssignments.json'
        Export-EvidenceData -Data $appRoles -FilePath $jsonPath -Format 'JSON' -Description 'App role assignments'
    }
    catch {
        Register-CollectionError -FunctionName 'Export-EntraAppAssignments' `
            -ErrorMessage "Failed to collect app role assignments for $UserPrincipalName." `
            -ErrorRecord $_
    }

    # OAuth Permission Grants (Delegated consents)
    try {
        $oauthGrants = @(Get-MgUserOauth2PermissionGrant -UserId $UserPrincipalName -All -ErrorAction Stop)

        # Resolve service principal names
        $enrichedGrants = @($oauthGrants | ForEach-Object {
            $grant = $_
            $spName = ''
            try {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction Stop
                $spName = $sp.DisplayName
            }
            catch {
                $spName = "(Unable to resolve: $($grant.ClientId))"
            }

            [PSCustomObject]@{
                Id                = $grant.Id
                ClientId          = $grant.ClientId
                ClientDisplayName = $spName
                ConsentType       = $grant.ConsentType
                PrincipalId       = $grant.PrincipalId
                ResourceId        = $grant.ResourceId
                Scope             = $grant.Scope
                ExpiryTime        = $grant.ExpiryTime
            }
        })

        $jsonPath = Join-Path $OutputFolder 'OAuthConsents.json'
        Export-EvidenceData -Data $enrichedGrants -FilePath $jsonPath -Format 'JSON' -Description 'OAuth consent grants (delegated permissions)'

        # Flag suspicious broad scopes
        $suspiciousScopes = @(
            'Mail.Read', 'Mail.ReadWrite', 'Mail.Send',
            'Mail.ReadBasic', 'MailboxSettings.ReadWrite',
            'Files.ReadWrite.All', 'Files.Read.All',
            'Contacts.ReadWrite', 'Contacts.Read',
            'User.ReadWrite.All', 'Directory.ReadWrite.All',
            'full_access_as_app'
        )

        foreach ($grant in $enrichedGrants) {
            if ([string]::IsNullOrWhiteSpace($grant.Scope)) { continue }
            $grantedScopes = $grant.Scope -split '\s+'
            $flagged = @($grantedScopes | Where-Object { $_ -in $suspiciousScopes })

            if ($flagged.Count -gt 0) {
                Register-Indicator -Category 'SuspiciousAppConsent' `
                    -Description "App '$($grant.ClientDisplayName)' has suspicious consent scopes: $($flagged -join ', ')" `
                    -Severity 'High' `
                    -RawDetail "ClientId=$($grant.ClientId), AllScopes=$($grant.Scope)"
            }
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Export-EntraAppAssignments' `
            -ErrorMessage "Failed to collect OAuth consent grants for $UserPrincipalName." `
            -ErrorRecord $_
    }
}

# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'Export-EntraUserProfile'
    'Export-EntraAuthMethods'
    'Export-EntraDirectoryRoles'
    'Export-EntraSignInLogs'
    'Export-EntraRiskData'
    'Export-EntraAuditLogs'
    'Export-EntraAppAssignments'
)
