#Requires -Version 7.0
<#
.SYNOPSIS
    Prerequisite validation for M365 Compromise Evidence Collection.

.DESCRIPTION
    Checks that required PowerShell modules are installed and at minimum
    versions. Provides guidance for installing missing modules.
#>

# ---------------------------------------------------------------------------
# Configuration: required modules and minimum versions
# ---------------------------------------------------------------------------
$script:RequiredModules = @(
    @{ Name = 'Microsoft.Graph.Authentication';               MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Users';                        MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Identity.SignIns';             MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Applications';                 MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Reports';                      MinVersion = '2.0.0' }
    @{ Name = 'ExchangeOnlineManagement';                     MinVersion = '3.0.0' }
)

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates that all required PowerShell modules are available.
    .DESCRIPTION
        Checks each required module for presence and minimum version.
        Returns a result object indicating overall pass/fail and details per module.
        Does NOT install modules automatically - provides install commands instead.
    .OUTPUTS
        PSCustomObject with Pass (bool) and Details (array) properties.
    .EXAMPLE
        $result = Test-Prerequisites
        if (-not $result.Pass) { $result.Details | Where-Object { -not $_.Installed } }
    #>
    [CmdletBinding()]
    param()

    Write-EvidenceLog '--- Checking prerequisites ---' -Level Section

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allPassed = $true

    foreach ($req in $script:RequiredModules) {
        $moduleName = $req.Name
        $minVersion = [version]$req.MinVersion

        $installed = Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue |
                     Sort-Object Version -Descending |
                     Select-Object -First 1

        if (-not $installed) {
            $results.Add([PSCustomObject]@{
                Module         = $moduleName
                RequiredVersion = $minVersion.ToString()
                InstalledVersion = 'NOT INSTALLED'
                Installed      = $false
                VersionOk      = $false
                InstallCommand = "Install-Module -Name $moduleName -Scope CurrentUser -Force"
            })
            $allPassed = $false
            Write-EvidenceLog "MISSING: $moduleName (required >= $minVersion)" -Level Error
        }
        elseif ($installed.Version -lt $minVersion) {
            $results.Add([PSCustomObject]@{
                Module         = $moduleName
                RequiredVersion = $minVersion.ToString()
                InstalledVersion = $installed.Version.ToString()
                Installed      = $true
                VersionOk      = $false
                InstallCommand = "Update-Module -Name $moduleName -Force"
            })
            $allPassed = $false
            Write-EvidenceLog "OUTDATED: $moduleName v$($installed.Version) (required >= $minVersion)" -Level Warning
        }
        else {
            $results.Add([PSCustomObject]@{
                Module         = $moduleName
                RequiredVersion = $minVersion.ToString()
                InstalledVersion = $installed.Version.ToString()
                Installed      = $true
                VersionOk      = $true
                InstallCommand = $null
            })
            Write-EvidenceLog "OK: $moduleName v$($installed.Version)" -Level Success
        }
    }

    if ($allPassed) {
        Write-EvidenceLog 'All prerequisites satisfied.' -Level Success
    }
    else {
        Write-EvidenceLog 'Some prerequisites are missing or outdated.' -Level Error
        Write-EvidenceLog 'Run the following commands to install/update:' -Level Info
        foreach ($item in $results | Where-Object { $_.InstallCommand }) {
            Write-EvidenceLog "  $($item.InstallCommand)" -Level Info
        }
    }

    return [PSCustomObject]@{
        Pass    = $allPassed
        Details = $results
    }
}

function Test-PowerShellVersion {
    <#
    .SYNOPSIS
        Checks that the running PowerShell version is 7.0 or later.
    .OUTPUTS
        Boolean. True if version requirement is met.
    #>
    [CmdletBinding()]
    param()

    $current = $PSVersionTable.PSVersion
    if ($current.Major -ge 7) {
        Write-EvidenceLog "PowerShell version: $current" -Level Success
        return $true
    }
    else {
        Write-EvidenceLog "PowerShell 7+ required. Current version: $current" -Level Error
        return $false
    }
}

# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'Test-Prerequisites'
    'Test-PowerShellVersion'
)
