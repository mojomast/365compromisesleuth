# M365 Compromise Evidence Collection Tool

Read-only evidence collection tool for Microsoft 365 compromise investigations. Collects Entra ID (Azure AD) and Exchange Online evidence into a structured case folder with analyst-friendly exports, raw JSON for forensics, and a consolidated incident summary.

**This tool is READ-ONLY.** It does not modify, delete, or remediate anything in the target tenant.

## Prerequisites

### PowerShell 7+

This tool requires PowerShell 7.0 or later. Download from [https://github.com/PowerShell/PowerShell](https://github.com/PowerShell/PowerShell).

### Required Modules

| Module | Minimum Version |
|--------|----------------|
| Microsoft.Graph.Authentication | 2.0.0 |
| Microsoft.Graph.Users | 2.0.0 |
| Microsoft.Graph.Identity.DirectoryManagement | 2.0.0 |
| Microsoft.Graph.Identity.SignIns | 2.0.0 |
| Microsoft.Graph.Applications | 2.0.0 |
| Microsoft.Graph.Reports | 2.0.0 |
| ExchangeOnlineManagement | 3.0.0 |

**Install all at once:**

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Applications, Microsoft.Graph.Reports, ExchangeOnlineManagement -Scope CurrentUser -Force
```

### Required Azure AD Roles

The technician running this tool needs:

- **Global Reader** (or equivalent read-only admin role) for Entra ID / Graph data
- **Exchange Administrator** (or equivalent) for Exchange Online data
- For partner/MSP scenarios, delegated admin permissions (GDAP) with appropriate roles

### Required Graph Permission Scopes

The tool requests these delegated (interactive) scopes, all read-only:

- `User.Read.All`
- `UserAuthenticationMethod.Read.All`
- `Directory.Read.All`
- `IdentityRiskyUser.Read.All`
- `IdentityRiskEvent.Read.All`
- `AuditLog.Read.All`
- `Application.Read.All`
- `DelegatedPermissionGrant.Read.All`

Admin consent may be required for some scopes in the target tenant.

## Quick Start

```powershell
# Basic usage with prompt for compromised account
./Start-M365CompromiseEvidence.ps1 -CaseFolder "C:\Cases\Contoso-2025-01-15"

# Basic usage with target user supplied up front
./Start-M365CompromiseEvidence.ps1 -UserPrincipalName "user@contoso.com" -CaseFolder "C:\Cases\Contoso-2025-01-15"

# Partner/MSP connecting to a customer tenant
./Start-M365CompromiseEvidence.ps1 -UserPrincipalName "user@contoso.com" -CaseFolder "C:\Cases\Contoso-2025-01-15" -TenantId "contoso.onmicrosoft.com"

# Collect only Entra ID data (skip Exchange)
./Start-M365CompromiseEvidence.ps1 -UserPrincipalName "user@contoso.com" -CaseFolder "C:\Cases\Contoso-2025-01-15" -SkipExchange

# Collect only Exchange data (skip Graph)
./Start-M365CompromiseEvidence.ps1 -UserPrincipalName "user@contoso.com" -CaseFolder "C:\Cases\Contoso-2025-01-15" -SkipGraph
```

## Parameters

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `UserPrincipalName` | No | String | Email address of the compromised user; if omitted, the script prompts for it |
| `CaseFolder` | Yes | String | Path to the case folder (parent must exist) |
| `TenantId` | No | String | Tenant ID or domain for MSP/partner scenarios |
| `SkipGraph` | No | Switch | Skip Entra ID / Graph evidence collection |
| `SkipExchange` | No | Switch | Skip Exchange Online evidence collection |

The account you sign in with should be your administrator/investigator account. The `UserPrincipalName` value is the compromised target account the tool examines.

## Case Folder Structure

```
CaseFolder/
├── 00-Notes/                      Technician notes template
│   └── TechnicianNotes.txt
├── 01-Entra/                      Entra ID / Azure AD evidence
│   ├── UserProfile.json / .csv
│   ├── AuthenticationMethods.json / .csv
│   ├── DirectoryRoles.json / .csv
│   ├── GroupMemberships.json / .csv
│   ├── SignInLogs.csv
│   ├── RiskyUser.json
│   ├── RiskDetections.json
│   ├── AuditLogs.json / .csv
│   ├── AppRoleAssignments.json
│   └── OAuthConsents.json
├── 02-Exchange/                   Exchange Online evidence
│   ├── Mailbox.json / .csv
│   ├── MailboxStatistics.json
│   ├── InboxRules.json / .csv
│   ├── MailboxPermissions_FullAccess.json / .csv
│   ├── MailboxPermissions_SendAs.json / .csv
│   ├── MailboxPermissions_SendOnBehalf.json / .csv
│   ├── ForwardingSummary.json
│   ├── CalendarPermissions.json / .csv
│   ├── TransportRules.json / .csv
│   ├── InboundConnectors.json
│   ├── OutboundConnectors.json
│   ├── MessageTrace_Sent.csv
│   └── MessageTrace_Received.csv
├── 03-Logs/                       Collection logs and manifests
│   ├── Transcript_*.txt
│   ├── FileManifest.csv
│   ├── CollectionErrors.csv
│   ├── Indicators.csv
│   └── CollectionLog.csv
├── 04-Client-Deliverables/        Incident summary report
│   ├── IncidentSummary.txt
│   └── IncidentSummary.html
├── 05-Raw/                        Raw JSON for forensic analysis
│   ├── SignInLogs_Raw.json
│   └── MessageTrace_Raw.json
└── 06-Screenshots-Manual/         Manual screenshot checklist
    └── ManualScreenshotChecklist.md
```

## What Gets Collected

### Entra ID Evidence (Microsoft Graph)

| Function | Description |
|----------|-------------|
| `Export-EntraUserProfile` | Full user profile with key fields flattened to CSV |
| `Export-EntraAuthMethods` | Authentication methods including phone, email, and Authenticator app details |
| `Export-EntraDirectoryRoles` | Directory role assignments and group memberships; flags privileged roles |
| `Export-EntraSignInLogs` | Sign-in logs (last 7 days) with flattened location/status/device; flags multi-country sign-ins |
| `Export-EntraRiskData` | Risky user status and risk detections (requires Entra P2); flags at-risk users |
| `Export-EntraAuditLogs` | Directory audit logs (last 7 days) covering password changes, MFA changes, role assignments |
| `Export-EntraAppAssignments` | App role assignments and OAuth consent grants; flags suspicious broad scopes |

### Exchange Online Evidence

| Function | Description |
|----------|-------------|
| `Export-ExchangeMailboxDetails` | Mailbox properties and statistics; flags forwarding addresses |
| `Export-ExchangeInboxRules` | All inbox rules including hidden; flags forwarding, deletion, and suspicious rules |
| `Export-ExchangeMailboxPermissions` | Full Access, SendAs, and SendOnBehalf permissions; flags non-default access |
| `Export-ExchangeForwarding` | Consolidated forwarding summary from mailbox properties and inbox rules |
| `Export-ExchangeCalendarDelegates` | Calendar folder permissions; flags elevated access (Editor/Owner) |
| `Export-ExchangeTransportRules` | Tenant-wide transport rules; flags rules affecting the compromised user |
| `Export-ExchangeConnectors` | Inbound and outbound connectors; flags recently created connectors |
| `Export-ExchangeMessageTrace` | Sent/received message trace (last 7 days); flags high-volume outbound |

## Most Valuable Evidence (Prioritized)

When time is limited, focus on these first:

1. **Inbox rules and forwarding settings** - The #1 indicator of active compromise. Attackers almost always set up forwarding or deletion rules.
2. **Mailbox permissions** - Reveals persistence mechanisms (Full Access, SendAs delegations added by attacker).
3. **Sign-in logs** - Shows attacker access patterns, source IPs, locations, and apps used.
4. **Authentication methods** - Shows if the attacker registered their own MFA device (phone, authenticator app).
5. **OAuth consent grants** - Shows malicious app persistence (apps with Mail.Read, Mail.Send, Files.ReadWrite.All).

## Licensing Notes

Some evidence collection requires specific Microsoft 365 licensing:

| Feature | License Required |
|---------|-----------------|
| Risky user status | Entra ID P2 (included in Microsoft 365 E5) |
| Risk detections | Entra ID P2 |
| Sign-in log risk fields | Entra ID P2 |
| Full audit log retention (180 days) | Exchange Online Plan 2 or Microsoft 365 E5 |
| Threat Explorer screenshots | Microsoft 365 E5 or Defender for Office 365 Plan 2 |
| Message trace via PowerShell | Limited to 10 days (all plans) |

The tool handles missing licenses gracefully - it logs a warning and continues rather than failing.

## Known Limitations

- **Unified Audit Log** (`Search-UnifiedAuditLog`) is not included. It is slow, heavily rate-limited, requires complex filtering, and is better queried interactively in the Microsoft Purview portal.
- **Historical message trace** (>10 days) requires `Start-HistoricalSearch`, which is an asynchronous job that can take hours. Not suitable for immediate evidence collection.
- **Conditional Access policy evaluation** per user is complex and better captured as screenshots from the Entra portal.
- **Device compliance state** requires Intune integration and a different module set. Capture as a screenshot from the Entra user device list.
- **Graph sign-in log queries** can be slow on large tenants. The `-Top 500` with a 7-day date filter keeps queries bounded.
- **Exchange cmdlets** are generally slower than Graph (expect 2-5 minutes total for Exchange collection).
- **Message trace** is capped at 5,000 results per page and 1M total. The 7-day window keeps this manageable.

## Manual Screenshot Checklist

Some evidence is best captured as screenshots from admin portals. The tool generates a checklist at `06-Screenshots-Manual/ManualScreenshotChecklist.md` covering 17 items across:

- Entra ID portal (user overview, auth methods, risky sign-ins, conditional access, devices, app consents)
- Exchange Admin Center (mailbox properties, mail flow rules, inbox rules, connectors, message trace)
- Microsoft 365 Defender (incident queue, alert queue, Threat Explorer)
- Microsoft Purview (audit log search, content search)

## Phase 2 Roadmap (Remediation)

The following remediation features are planned but **not yet implemented**. This tool remains read-only.

- Revoke all refresh tokens / sign-out sessions
- Reset password
- Block sign-in
- Remove suspicious inbox rules
- Remove external forwarding
- Remove suspicious OAuth app consents
- Remove unauthorized delegates/permissions
- Disable suspicious connectors
- Enable mailbox audit logging if not already on
- Force MFA re-registration
- Submit indicators to Defender

## Architecture

```
Start-M365CompromiseEvidence.ps1    (orchestrator)
  ├── Modules/Logging.psm1          (logging, export, indicators, errors)
  ├── Modules/Prerequisites.psm1    (module/version checks)
  ├── Modules/CaseFolder.psm1       (folder structure + templates)
  ├── Modules/Connection.psm1       (Graph + Exchange authentication)
  ├── Modules/EntraEvidence.psm1    (7 Graph collection functions)
  ├── Modules/ExchangeEvidence.psm1 (8 Exchange collection functions)
  └── Modules/Summary.psm1          (incident summary + manifests)
```

All modules follow consistent patterns:
- Every function uses `try/catch` with `Register-CollectionError` on failure
- Every export uses `Export-EvidenceData` (never writes files directly)
- Suspicious findings call `Register-Indicator` with category, description, severity
- Console output goes through `Write-EvidenceLog` only
- Safe to re-run (folder creation is idempotent, file exports overwrite)

## HTML Incident Report

The tool also generates `04-Client-Deliverables/IncidentSummary.html` for technician review and client briefings. It includes:

- Executive summary with risk level and collection counts
- Priority findings sorted by severity
- Recommended actions based on observed indicators and evidence gaps
- Full indicator table with expandable detail
- Manual review checklist, collection issues, and evidence manifest tables

## License

MIT
