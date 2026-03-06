#Requires -Version 7.0
<#
.SYNOPSIS
    Case folder structure creation and management.

.DESCRIPTION
    Creates the standardized case folder hierarchy and populates
    template files for technician notes and manual screenshot checklists.
#>

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

function New-CaseFolderStructure {
    <#
    .SYNOPSIS
        Creates the standard case folder tree for evidence collection.
    .DESCRIPTION
        Builds the required subfolder hierarchy. If the folder already exists,
        it will not overwrite existing files - safe to re-run.
    .PARAMETER CaseFolder
        Root path for the case folder.
    .PARAMETER UserPrincipalName
        The compromised user's UPN, used in template file content.
    .PARAMETER TemplatesPath
        Path to the Templates directory containing note/checklist templates.
    .OUTPUTS
        PSCustomObject with paths to each subfolder.
    .EXAMPLE
        $paths = New-CaseFolderStructure -CaseFolder 'C:\Cases\Contoso-2025-01-15' -UserPrincipalName 'user@contoso.com'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CaseFolder,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [string]$TemplatesPath
    )

    Write-EvidenceLog '--- Creating case folder structure ---' -Level Section

    $subfolders = @{
        Notes          = '00-Notes'
        Entra          = '01-Entra'
        Exchange       = '02-Exchange'
        Logs           = '03-Logs'
        Deliverables   = '04-Client-Deliverables'
        Raw            = '05-Raw'
        Screenshots    = '06-Screenshots-Manual'
    }

    $paths = @{}

    foreach ($key in $subfolders.Keys) {
        $fullPath = Join-Path $CaseFolder $subfolders[$key]
        if (-not (Test-Path $fullPath)) {
            New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
            Write-EvidenceLog "Created: $($subfolders[$key])" -Level Info
        }
        else {
            Write-EvidenceLog "Exists:  $($subfolders[$key])" -Level Info
        }
        $paths[$key] = $fullPath
    }

    # --- Populate template files ---
    $notesFile = Join-Path $paths['Notes'] 'TechnicianNotes.txt'
    if (-not (Test-Path $notesFile)) {
        $notesContent = Get-TechnicianNotesTemplate -UserPrincipalName $UserPrincipalName
        $notesContent | Out-File -FilePath $notesFile -Encoding utf8
        Write-EvidenceLog 'Created technician notes template.' -Level Info
    }

    $checklistFile = Join-Path $paths['Screenshots'] 'ManualScreenshotChecklist.md'
    if (-not (Test-Path $checklistFile)) {
        $checklistContent = Get-ManualScreenshotChecklist -UserPrincipalName $UserPrincipalName
        $checklistContent | Out-File -FilePath $checklistFile -Encoding utf8
        Write-EvidenceLog 'Created manual screenshot checklist.' -Level Info
    }

    # Return the paths as a structured object
    return [PSCustomObject]$paths
}

# ---------------------------------------------------------------------------
# Template generators
# ---------------------------------------------------------------------------

function Get-TechnicianNotesTemplate {
    <#
    .SYNOPSIS
        Generates the technician notes template content.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    return @"
================================================================================
INCIDENT RESPONSE - TECHNICIAN NOTES
================================================================================
Case Created:     $timestamp
Compromised User: $UserPrincipalName

TIMELINE OF EVENTS
-------------------
When was the compromise reported?   :
When was the compromise discovered? :
When did the compromise likely start? :
When was the password last changed? :

INITIAL OBSERVATIONS
-------------------
How was the compromise reported (user report, alert, client, etc.)?
:

What suspicious activity was observed?
:

ACTIONS TAKEN (log each action with timestamp)
-------------------
$timestamp - Evidence collection script started


CLIENT COMMUNICATION
-------------------
Client contact name:
Client contact email/phone:
Client notified at:

NOTES
-------------------


================================================================================
"@
}

function Get-ManualScreenshotChecklist {
    <#
    .SYNOPSIS
        Generates a checklist of items that require manual screenshot capture.
    .DESCRIPTION
        Some evidence is best captured as screenshots from the admin portal
        because API data may not be complete or is easier to read visually.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    return @"
# Manual Screenshot Checklist
**User:** $UserPrincipalName
**Date:** $(Get-Date -Format 'yyyy-MM-dd')

## Instructions
Capture the following screenshots from the Microsoft 365 admin portals.
Save each screenshot in this folder (06-Screenshots-Manual) with the
naming convention: `NN_Description.png`

## Entra ID / Azure AD Portal (entra.microsoft.com)

- [ ] 01_UserOverview - User overview page showing status, sign-in activity
- [ ] 02_AuthMethods - Authentication methods page (visual confirmation of MFA)
- [ ] 03_SignInLogs_Suspicious - Any suspicious sign-in entries with full detail expanded
- [ ] 04_RiskySignIns - Risky sign-ins page if Entra P2 is available
- [ ] 05_ConditionalAccess - Conditional Access policies that apply to this user
- [ ] 06_DeviceList - Registered/joined devices for this user
- [ ] 07_AppConsents - Enterprise applications the user has consented to

## Exchange Admin Center (admin.exchange.microsoft.com)

- [ ] 08_MailboxProperties - Mailbox properties overview
- [ ] 09_MailFlowRules - Mail flow rules (transport rules) list
- [ ] 10_InboxRules - User inbox rules visible in admin center
- [ ] 11_Connectors - Inbound and outbound connectors list
- [ ] 12_MessageTrace_Suspicious - Any suspicious message trace results expanded

## Microsoft 365 Defender (security.microsoft.com)

- [ ] 13_IncidentQueue - Any related incidents in the incident queue
- [ ] 14_AlertQueue - Any related alerts
- [ ] 15_ThreatExplorer - Threat Explorer results for sent/received mail (if available)

## Microsoft Purview (compliance.microsoft.com)

- [ ] 16_AuditLogSearch - Audit log search results for the user (if not fully captured by script)
- [ ] 17_ContentSearch - Content search results if relevant

## Notes
- Save screenshots as PNG for clarity
- Include browser URL bar in screenshots when possible for provenance
- Annotate suspicious items with red boxes/arrows if helpful
"@
}

# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'New-CaseFolderStructure'
)
