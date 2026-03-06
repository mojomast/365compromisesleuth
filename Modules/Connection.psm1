#Requires -Version 7.0
<#
.SYNOPSIS
    Service connection management for Microsoft Graph and Exchange Online.

.DESCRIPTION
    Handles authentication to Microsoft Graph (delegated permissions) and
    Exchange Online PowerShell. Read-only scopes only - no write permissions.
#>

# ---------------------------------------------------------------------------
# Configuration: required Graph scopes (read-only)
# ---------------------------------------------------------------------------
$script:RequiredGraphScopes = @(
    'User.Read.All'
    'UserAuthenticationMethod.Read.All'
    'Directory.Read.All'
    'IdentityRiskyUser.Read.All'
    'IdentityRiskEvent.Read.All'
    'AuditLog.Read.All'
    'Application.Read.All'
    'DelegatedPermissionGrant.Read.All'
)

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

function Connect-IncidentServices {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph and Exchange Online with read-only scopes.
    .DESCRIPTION
        Authenticates using interactive delegated permissions. The technician
        must have appropriate admin roles in the target tenant.
        If -TenantId is provided, it connects to that specific tenant
        (useful for partner/MSP scenarios).
    .PARAMETER TenantId
        Optional. The tenant ID or domain to connect to.
    .PARAMETER SkipExchange
        Optional. Skip Exchange Online connection (useful for testing Graph only).
    .PARAMETER SkipGraph
        Optional. Skip Graph connection (useful for testing Exchange only).
    .OUTPUTS
        PSCustomObject with GraphConnected and ExchangeConnected booleans.
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,

        [switch]$SkipExchange,

        [switch]$SkipGraph
    )

    Write-EvidenceLog '--- Connecting to incident services ---' -Level Section

    $graphOk    = $false
    $exchangeOk = $false

    # --- Microsoft Graph ---
    if (-not $SkipGraph) {
        $graphOk = Connect-IncidentGraph -TenantId $TenantId
    }
    else {
        Write-EvidenceLog 'Skipping Microsoft Graph connection (SkipGraph flag).' -Level Warning
    }

    # --- Exchange Online ---
    if (-not $SkipExchange) {
        $exchangeOk = Connect-IncidentExchange -TenantId $TenantId
    }
    else {
        Write-EvidenceLog 'Skipping Exchange Online connection (SkipExchange flag).' -Level Warning
    }

    return [PSCustomObject]@{
        GraphConnected    = $graphOk
        ExchangeConnected = $exchangeOk
    }
}

function Disconnect-IncidentServices {
    <#
    .SYNOPSIS
        Cleanly disconnects from Graph and Exchange Online sessions.
    #>
    [CmdletBinding()]
    param()

    Write-EvidenceLog '--- Disconnecting services ---' -Level Section

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-EvidenceLog 'Disconnected from Microsoft Graph.' -Level Info
    }
    catch {
        Write-EvidenceLog "Graph disconnect warning: $_" -Level Warning
    }

    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-EvidenceLog 'Disconnected from Exchange Online.' -Level Info
    }
    catch {
        Write-EvidenceLog "Exchange disconnect warning: $_" -Level Warning
    }
}

# ---------------------------------------------------------------------------
# Private helper functions
# ---------------------------------------------------------------------------

function Resolve-ExchangeDelegatedOrganization {
    [CmdletBinding()]
    param(
        [string]$TenantId
    )

    if (-not $TenantId) {
        return $null
    }

    if ($TenantId -match '^[0-9a-fA-F-]{36}$') {
        return $TenantId
    }

    if ($TenantId -match '(?i)\.onmicrosoft\.com$') {
        return $TenantId
    }

    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $graphContext) {
        throw 'A non-.onmicrosoft.com tenant domain requires an active Graph connection to resolve the Exchange delegated organization.'
    }

    $organization = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
    $initialDomain = @($organization.VerifiedDomains | Where-Object { $_.IsInitial -eq $true } | Select-Object -ExpandProperty Name -First 1)

    if ($initialDomain) {
        return $initialDomain[0]
    }

    throw 'Unable to resolve the tenant initial .onmicrosoft.com domain for Exchange delegated access.'
}

function Get-ExchangeConnectionAttempts {
    [CmdletBinding()]
    param(
        [string]$TenantId
    )

    $attempts = [System.Collections.Generic.List[hashtable]]::new()

    if (-not $TenantId) {
        $attempts.Add(@{
            Name       = 'interactive default context'
            Parameters = @{}
        })
        return $attempts
    }

    $isGuid = $TenantId -match '^[0-9a-fA-F-]{36}$'
    $isOnMicrosoft = $TenantId -match '(?i)\.onmicrosoft\.com$'
    $resolvedDelegatedOrganization = $null

    if ($isGuid -or $isOnMicrosoft) {
        $resolvedDelegatedOrganization = $TenantId
    }
    else {
        try {
            $resolvedDelegatedOrganization = Resolve-ExchangeDelegatedOrganization -TenantId $TenantId
        }
        catch {
            Write-EvidenceLog "Could not resolve delegated Exchange organization from '$TenantId': $($_.Exception.Message)" -Level Warning
        }
    }

    if ($resolvedDelegatedOrganization) {
        $attempts.Add(@{
            Name       = "delegated organization '$resolvedDelegatedOrganization'"
            Parameters = @{ DelegatedOrganization = $resolvedDelegatedOrganization }
        })
    }

    if (-not $isGuid) {
        $attempts.Add(@{
            Name       = "organization '$TenantId'"
            Parameters = @{ Organization = $TenantId }
        })
    }

    if ($isGuid) {
        $attempts.Add(@{
            Name       = 'interactive default context'
            Parameters = @{}
        })
    }

    if ($attempts.Count -eq 0) {
        throw "Unable to determine a safe Exchange connection strategy for tenant identifier '$TenantId'."
    }

    return $attempts
}

function Connect-IncidentGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with required read-only scopes.
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId
    )

    Write-EvidenceLog 'Connecting to Microsoft Graph...' -Level Info
    Write-EvidenceLog "Requesting scopes: $($script:RequiredGraphScopes -join ', ')" -Level Info

    try {
        $connectParams = @{
            Scopes    = $script:RequiredGraphScopes
            NoWelcome = $true
        }

        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
            Write-EvidenceLog "Target tenant: $TenantId" -Level Info
        }

        Connect-MgGraph @connectParams -ErrorAction Stop

        # Verify connection
        $context = Get-MgContext
        if ($context) {
            Write-EvidenceLog "Graph connected as: $($context.Account)" -Level Success
            Write-EvidenceLog "Tenant ID: $($context.TenantId)" -Level Info

            # Check which scopes were granted
            $grantedScopes = $context.Scopes
            $missingScopes = $script:RequiredGraphScopes | Where-Object { $_ -notin $grantedScopes }
            if ($missingScopes) {
                Write-EvidenceLog "Warning: Some scopes were not granted: $($missingScopes -join ', ')" -Level Warning
                Write-EvidenceLog "Some evidence collection may fail. This may require admin consent." -Level Warning
            }
            return $true
        }
        else {
            Write-EvidenceLog 'Graph connection succeeded but no context returned.' -Level Error
            return $false
        }
    }
    catch {
        Register-CollectionError -FunctionName 'Connect-IncidentGraph' `
            -ErrorMessage 'Failed to connect to Microsoft Graph.' `
            -ErrorRecord $_
        return $false
    }
}

function Connect-IncidentExchange {
    <#
    .SYNOPSIS
        Connects to Exchange Online PowerShell.
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId
    )

    Write-EvidenceLog 'Connecting to Exchange Online...' -Level Info

    try {
        $connectAttempts = @(Get-ExchangeConnectionAttempts -TenantId $TenantId)
        $lastError = $null

        foreach ($attempt in $connectAttempts) {
            $connectParams = @{ ShowBanner = $false }
            foreach ($key in $attempt.Parameters.Keys) {
                $connectParams[$key] = $attempt.Parameters[$key]
            }

            try {
                Write-EvidenceLog "Exchange connection attempt using $($attempt.Name)..." -Level Info
                Connect-ExchangeOnline @connectParams -ErrorAction Stop
                Write-EvidenceLog 'Exchange Online connected successfully.' -Level Success
                return $true
            }
            catch {
                $lastError = $_
                Write-EvidenceLog "Exchange connection attempt failed using $($attempt.Name): $($_.Exception.Message)" -Level Warning
            }
        }

        throw $lastError
    }
    catch {
        Register-CollectionError -FunctionName 'Connect-IncidentExchange' `
            -ErrorMessage 'Failed to connect to Exchange Online.' `
            -ErrorRecord $_
        return $false
    }
}

# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'Connect-IncidentServices'
    'Disconnect-IncidentServices'
)
