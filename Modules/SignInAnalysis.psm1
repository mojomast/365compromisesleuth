#Requires -Version 7.0
<#
.SYNOPSIS
    Post-collection analysis of sign-in logs, audit logs, and Exchange
    evidence to identify compromise indicators and estimate the breach window.

.DESCRIPTION
    Reads exported evidence files from disk after collection completes,
    performs deep analysis (IP clustering, impossible travel, failed auth
    patterns, new device/app detection, audit event correlation), and
    returns a structured analysis object for the HTML report.
#>

# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

function Invoke-CompromiseAnalysis {
    <#
    .SYNOPSIS
        Runs post-collection analysis across all evidence files and returns
        a structured result for the incident report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$CasePaths,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    Write-EvidenceLog '--- Running post-collection compromise analysis ---' -Level Section

    $result = [PSCustomObject]@{
        SignInSummary       = $null
        IPAnalysis          = @()
        LocationAnalysis    = @()
        AppAnalysis         = @()
        FailedAuthPatterns  = @()
        AnomalousSignIns    = @()
        AuditTimeline       = @()
        CompromiseWindow    = $null
        RiskSignals         = @()
    }

    try {
        # ---------------------------------------------------------------
        # Load sign-in logs from disk
        # ---------------------------------------------------------------
        $signInPath = Join-Path $CasePaths.Entra 'SignInLogs.csv'
        $signIns = @()
        if (Test-Path $signInPath) {
            $raw = Import-Csv -Path $signInPath -ErrorAction SilentlyContinue
            if ($raw) { $signIns = @($raw) }
        }

        if ($signIns.Count -eq 0) {
            Write-EvidenceLog 'No sign-in log data available for analysis.' -Level Warning
            return $result
        }

        Write-EvidenceLog "Analyzing $($signIns.Count) sign-in log entries..." -Level Info

        # ---------------------------------------------------------------
        # Parse timestamps once
        # ---------------------------------------------------------------
        foreach ($entry in $signIns) {
            $entry | Add-Member -NotePropertyName 'ParsedTime' -NotePropertyValue ([datetime]::MinValue) -Force
            try {
                $entry.ParsedTime = [datetime]::Parse($entry.CreatedDateTime).ToUniversalTime()
            }
            catch { }
        }
        $signIns = @($signIns | Where-Object { $_.ParsedTime -ne [datetime]::MinValue } |
            Sort-Object ParsedTime)

        # ---------------------------------------------------------------
        # 1. Sign-In Summary
        # ---------------------------------------------------------------
        $totalSignIns       = $signIns.Count
        $uniqueIPs          = @($signIns | Select-Object -ExpandProperty IPAddress -Unique)
        $uniqueCountries    = @($signIns | Where-Object { $_.Country } | Select-Object -ExpandProperty Country -Unique)
        $uniqueApps         = @($signIns | Where-Object { $_.AppDisplayName } | Select-Object -ExpandProperty AppDisplayName -Unique)
        $interactiveCount   = @($signIns | Where-Object { $_.IsInteractive -eq 'True' }).Count
        $nonInteractiveCount = $totalSignIns - $interactiveCount
        $successCount       = @($signIns | Where-Object { $_.StatusErrorCode -eq '0' }).Count
        $failureCount       = $totalSignIns - $successCount
        $firstSeen          = $signIns[0].ParsedTime
        $lastSeen           = $signIns[-1].ParsedTime

        $result.SignInSummary = [PSCustomObject]@{
            TotalSignIns       = $totalSignIns
            UniqueIPs          = $uniqueIPs.Count
            UniqueCountries    = $uniqueCountries.Count
            UniqueApps         = $uniqueApps.Count
            InteractiveCount   = $interactiveCount
            NonInteractiveCount = $nonInteractiveCount
            SuccessCount       = $successCount
            FailureCount       = $failureCount
            FirstSeen          = $firstSeen.ToString('yyyy-MM-dd HH:mm:ss UTC')
            LastSeen           = $lastSeen.ToString('yyyy-MM-dd HH:mm:ss UTC')
            CountryList        = ($uniqueCountries -join ', ')
        }

        # ---------------------------------------------------------------
        # 2. IP Address Analysis (frequency, first/last seen, countries)
        # ---------------------------------------------------------------
        $ipGroups = $signIns | Group-Object IPAddress
        $ipAnalysis = @($ipGroups | ForEach-Object {
            $entries = @($_.Group | Sort-Object ParsedTime)
            $countries = @($entries | Where-Object { $_.Country } | Select-Object -ExpandProperty Country -Unique)
            $successEntries = @($entries | Where-Object { $_.StatusErrorCode -eq '0' })
            $failEntries    = @($entries | Where-Object { $_.StatusErrorCode -ne '0' })
            $apps = @($entries | Where-Object { $_.AppDisplayName } | Select-Object -ExpandProperty AppDisplayName -Unique)

            [PSCustomObject]@{
                IPAddress    = $_.Name
                Count        = $_.Count
                SuccessCount = $successEntries.Count
                FailCount    = $failEntries.Count
                Countries    = ($countries -join ', ')
                Apps         = ($apps -join ', ')
                FirstSeen    = $entries[0].ParsedTime.ToString('yyyy-MM-dd HH:mm UTC')
                LastSeen     = $entries[-1].ParsedTime.ToString('yyyy-MM-dd HH:mm UTC')
            }
        } | Sort-Object Count -Descending)
        $result.IPAnalysis = $ipAnalysis

        # ---------------------------------------------------------------
        # 3. Location Analysis
        # ---------------------------------------------------------------
        $locGroups = $signIns | Where-Object { $_.Country } |
            Group-Object { "$($_.Country)|$($_.City)" }
        $result.LocationAnalysis = @($locGroups | ForEach-Object {
            $entries = @($_.Group | Sort-Object ParsedTime)
            $parts = $_.Name -split '\|'
            [PSCustomObject]@{
                Country   = $parts[0]
                City      = if ($parts.Count -gt 1) { $parts[1] } else { '' }
                Count     = $_.Count
                UniqueIPs = @($entries | Select-Object -ExpandProperty IPAddress -Unique).Count
                FirstSeen = $entries[0].ParsedTime.ToString('yyyy-MM-dd HH:mm UTC')
                LastSeen  = $entries[-1].ParsedTime.ToString('yyyy-MM-dd HH:mm UTC')
            }
        } | Sort-Object Count -Descending)

        # ---------------------------------------------------------------
        # 4. App / Client Analysis
        # ---------------------------------------------------------------
        $appGroups = $signIns | Where-Object { $_.AppDisplayName } |
            Group-Object AppDisplayName
        $result.AppAnalysis = @($appGroups | ForEach-Object {
            $entries = @($_.Group | Sort-Object ParsedTime)
            [PSCustomObject]@{
                Application  = $_.Name
                Count        = $_.Count
                UniqueIPs    = @($entries | Select-Object -ExpandProperty IPAddress -Unique).Count
                SuccessCount = @($entries | Where-Object { $_.StatusErrorCode -eq '0' }).Count
                FailCount    = @($entries | Where-Object { $_.StatusErrorCode -ne '0' }).Count
                FirstSeen    = $entries[0].ParsedTime.ToString('yyyy-MM-dd HH:mm UTC')
                LastSeen     = $entries[-1].ParsedTime.ToString('yyyy-MM-dd HH:mm UTC')
            }
        } | Sort-Object Count -Descending)

        # ---------------------------------------------------------------
        # 5. Failed Auth Patterns (brute force / password spray detection)
        # ---------------------------------------------------------------
        try {
            Write-EvidenceLog 'Analyzing failed authentication patterns...' -Level Info
            $failedSignIns = @($signIns | Where-Object { $_.StatusErrorCode -ne '0' })

            if ($failedSignIns.Count -gt 0) {
                $failedByIP = $failedSignIns | Group-Object IPAddress
                $allByIP    = $signIns | Group-Object IPAddress

                $failPatterns = [System.Collections.Generic.List[PSCustomObject]]::new()

                foreach ($group in $failedByIP) {
                    $ipName       = $group.Name
                    $failEntries  = @($group.Group | Sort-Object ParsedTime)
                    $failCount    = $failEntries.Count
                    $allForIP     = @($allByIP | Where-Object { $_.Name -eq $ipName })
                    $totalForIP   = if ($allForIP.Count -gt 0) { $allForIP[0].Count } else { $failCount }
                    $failRate     = if ($totalForIP -gt 0) { [math]::Round(($failCount / $totalForIP) * 100, 1) } else { 0 }
                    $errorCodes   = @($failEntries | Select-Object -ExpandProperty StatusErrorCode -Unique)
                    $firstAttempt = $failEntries[0].ParsedTime
                    $lastAttempt  = $failEntries[-1].ParsedTime
                    $spanMinutes  = ($lastAttempt - $firstAttempt).TotalMinutes

                    $pattern = 'FailedAuth'
                    if ($errorCodes.Count -ge 3 -and $spanMinutes -lt 30) {
                        $pattern = 'PasswordSpray'
                    }
                    elseif ($failCount -ge 10) {
                        $pattern = 'BruteForce'
                    }

                    [void]$failPatterns.Add([PSCustomObject]@{
                        IPAddress       = $ipName
                        TotalAttempts   = $totalForIP
                        FailCount       = $failCount
                        FailRate        = "$failRate%"
                        UniqueErrors    = ($errorCodes -join ', ')
                        FirstAttempt    = $firstAttempt.ToString('yyyy-MM-dd HH:mm UTC')
                        LastAttempt     = $lastAttempt.ToString('yyyy-MM-dd HH:mm UTC')
                        Pattern         = $pattern
                    })

                    if ($failCount -ge 10 -or $failRate -ge 80) {
                        Register-Indicator -Category 'SignInAnomaly' `
                            -Description "Suspicious failed auth from $ipName : $failCount failures ($failRate%), pattern: $pattern" `
                            -Severity 'High' `
                            -RawDetail "IP=$ipName, Fails=$failCount/$totalForIP, Errors=$($errorCodes -join ',')"
                    }
                }

                $result.FailedAuthPatterns = @($failPatterns | Sort-Object FailCount -Descending)
                Write-EvidenceLog "Identified $($failPatterns.Count) IP(s) with failed auth activity." -Level Info
            }
        }
        catch {
            Write-EvidenceLog "Failed auth pattern analysis encountered an error: $($_.Exception.Message)" -Level Warning
        }

        # ---------------------------------------------------------------
        # 6. Anomalous Sign-Ins (impossible travel, new IPs, new apps)
        # ---------------------------------------------------------------
        try {
            Write-EvidenceLog 'Detecting anomalous sign-in patterns...' -Level Info
            $anomalies = [System.Collections.Generic.List[PSCustomObject]]::new()

            # 6a. Impossible travel - consecutive successful sign-ins from
            #     different countries within 60 minutes
            $successSorted = @($signIns | Where-Object { $_.StatusErrorCode -eq '0' -and $_.Country } |
                Sort-Object ParsedTime)

            for ($i = 1; $i -lt $successSorted.Count; $i++) {
                $prev = $successSorted[$i - 1]
                $curr = $successSorted[$i]

                if ($prev.Country -ne $curr.Country) {
                    $deltaMin = ($curr.ParsedTime - $prev.ParsedTime).TotalMinutes
                    if ($deltaMin -le 60 -and $deltaMin -ge 0) {
                        [void]$anomalies.Add([PSCustomObject]@{
                            Type             = 'ImpossibleTravel'
                            FirstSignIn      = $prev.ParsedTime.ToString('yyyy-MM-dd HH:mm UTC')
                            FirstCountry     = $prev.Country
                            FirstCity        = $prev.City
                            FirstIP          = $prev.IPAddress
                            SecondSignIn     = $curr.ParsedTime.ToString('yyyy-MM-dd HH:mm UTC')
                            SecondCountry    = $curr.Country
                            SecondCity       = $curr.City
                            SecondIP         = $curr.IPAddress
                            TimeDeltaMinutes = [math]::Round($deltaMin, 1)
                            Detail           = "$($prev.Country) -> $($curr.Country) in $([math]::Round($deltaMin,0)) min"
                        })

                        Register-Indicator -Category 'SignInAnomaly' `
                            -Description "Impossible travel: $($prev.Country) to $($curr.Country) in $([math]::Round($deltaMin,0)) minutes" `
                            -Severity 'High' `
                            -RawDetail "From $($prev.IPAddress) ($($prev.City), $($prev.Country)) at $($prev.ParsedTime.ToString('HH:mm')) to $($curr.IPAddress) ($($curr.City), $($curr.Country)) at $($curr.ParsedTime.ToString('HH:mm'))"
                    }
                }
            }

            # 6b. New/unusual IPs - only appeared in the last 24 hours of data
            if ($signIns.Count -gt 0) {
                $cutoff24h = $signIns[-1].ParsedTime.AddHours(-24)
                $recentIPs = @($signIns | Where-Object { $_.ParsedTime -ge $cutoff24h } |
                    Select-Object -ExpandProperty IPAddress -Unique)
                $olderIPs  = @($signIns | Where-Object { $_.ParsedTime -lt $cutoff24h } |
                    Select-Object -ExpandProperty IPAddress -Unique)

                foreach ($ip in $recentIPs) {
                    if ($ip -notin $olderIPs -and -not [string]::IsNullOrWhiteSpace($ip)) {
                        $ipEntries = @($signIns | Where-Object { $_.IPAddress -eq $ip } | Sort-Object ParsedTime)
                        $country   = ($ipEntries | Where-Object { $_.Country } | Select-Object -First 1).Country
                        [void]$anomalies.Add([PSCustomObject]@{
                            Type             = 'NewIP'
                            FirstSignIn      = $ipEntries[0].ParsedTime.ToString('yyyy-MM-dd HH:mm UTC')
                            FirstCountry     = $country
                            FirstCity        = ($ipEntries | Where-Object { $_.City } | Select-Object -First 1).City
                            FirstIP          = $ip
                            SecondSignIn     = ''
                            SecondCountry    = ''
                            SecondCity       = ''
                            SecondIP         = ''
                            TimeDeltaMinutes = 0
                            Detail           = "IP $ip first seen in last 24h ($($ipEntries.Count) events, country: $country)"
                        })
                    }
                }
            }

            # 6c. New/unusual apps - only appeared in the last 24 hours with
            #     at least one successful auth
            if ($signIns.Count -gt 0) {
                $cutoff24h  = $signIns[-1].ParsedTime.AddHours(-24)
                $recentApps = @($signIns | Where-Object {
                    $_.ParsedTime -ge $cutoff24h -and $_.StatusErrorCode -eq '0' -and $_.AppDisplayName
                } | Select-Object -ExpandProperty AppDisplayName -Unique)
                $olderApps  = @($signIns | Where-Object {
                    $_.ParsedTime -lt $cutoff24h -and $_.AppDisplayName
                } | Select-Object -ExpandProperty AppDisplayName -Unique)

                foreach ($app in $recentApps) {
                    if ($app -notin $olderApps) {
                        $appEntries = @($signIns | Where-Object { $_.AppDisplayName -eq $app } | Sort-Object ParsedTime)
                        [void]$anomalies.Add([PSCustomObject]@{
                            Type             = 'NewApp'
                            FirstSignIn      = $appEntries[0].ParsedTime.ToString('yyyy-MM-dd HH:mm UTC')
                            FirstCountry     = ($appEntries | Where-Object { $_.Country } | Select-Object -First 1).Country
                            FirstCity        = ($appEntries | Where-Object { $_.City } | Select-Object -First 1).City
                            FirstIP          = ($appEntries | Select-Object -First 1).IPAddress
                            SecondSignIn     = ''
                            SecondCountry    = ''
                            SecondCity       = ''
                            SecondIP         = ''
                            TimeDeltaMinutes = 0
                            Detail           = "App '$app' first seen in last 24h ($($appEntries.Count) events)"
                        })
                    }
                }
            }

            $result.AnomalousSignIns = @($anomalies)
            Write-EvidenceLog "Detected $($anomalies.Count) anomalous sign-in event(s)." -Level Info
        }
        catch {
            Write-EvidenceLog "Anomalous sign-in detection encountered an error: $($_.Exception.Message)" -Level Warning
        }

        # ---------------------------------------------------------------
        # 7. Audit Log Correlation (password/MFA/role changes, app consents)
        # ---------------------------------------------------------------
        try {
            Write-EvidenceLog 'Correlating audit log events...' -Level Info
            $auditPath = Join-Path $CasePaths.Entra 'AuditLogs.csv'
            $auditEvents = [System.Collections.Generic.List[PSCustomObject]]::new()

            if (Test-Path $auditPath) {
                $rawAudit = Import-Csv -Path $auditPath -ErrorAction SilentlyContinue
                if ($rawAudit) {
                    $passwordActivities = @(
                        'Change password'
                        'Reset password'
                        'Change user password'
                        'Reset user password'
                        'Set force change user password'
                    )
                    $mfaActivities = @(
                        'User registered security info'
                        'User deleted security info'
                        'Admin registered security info'
                        'User registered all required security info'
                    )
                    $roleActivities = @(
                        'Add member to role'
                        'Remove member from role'
                        'Add eligible member to role'
                        'Remove eligible member from role'
                    )
                    $consentActivities = @(
                        'Consent to application'
                        'Add OAuth2PermissionGrant'
                        'Add app role assignment to service principal'
                        'Add delegated permission grant'
                    )

                    foreach ($entry in @($rawAudit)) {
                        $activity = $entry.ActivityDisplayName
                        $eventType = $null

                        if ($activity -in $passwordActivities) {
                            $eventType = 'PasswordChange'
                        }
                        elseif ($activity -in $mfaActivities -or
                                $activity -match 'authentication method' -or
                                $activity -match 'strong authentication') {
                            $eventType = 'MFAChange'
                        }
                        elseif ($activity -in $roleActivities) {
                            $eventType = 'RoleChange'
                        }
                        elseif ($activity -in $consentActivities) {
                            $eventType = 'AppConsent'
                        }

                        if ($eventType) {
                            [void]$auditEvents.Add([PSCustomObject]@{
                                Timestamp   = $entry.ActivityDateTime
                                EventType   = $eventType
                                Activity    = $activity
                                InitiatedBy = $entry.InitiatedBy
                                Target      = $entry.TargetResources
                                Result      = $entry.Result
                            })
                        }
                    }

                    # Register indicators for significant audit events
                    $pwChanges  = @($auditEvents | Where-Object { $_.EventType -eq 'PasswordChange' })
                    $mfaChanges = @($auditEvents | Where-Object { $_.EventType -eq 'MFAChange' })
                    $roleChanges = @($auditEvents | Where-Object { $_.EventType -eq 'RoleChange' })
                    $appConsents = @($auditEvents | Where-Object { $_.EventType -eq 'AppConsent' })

                    if ($pwChanges.Count -gt 0) {
                        Register-Indicator -Category 'SignInAnomaly' `
                            -Description "Password changed $($pwChanges.Count) time(s) during investigation window" `
                            -Severity 'Medium' `
                            -RawDetail (($pwChanges | ForEach-Object { "$($_.Timestamp): $($_.Activity) by $($_.InitiatedBy)" }) -join '; ')
                    }
                    if ($mfaChanges.Count -gt 0) {
                        Register-Indicator -Category 'SignInAnomaly' `
                            -Description "MFA/auth method changed $($mfaChanges.Count) time(s) during investigation window" `
                            -Severity 'High' `
                            -RawDetail (($mfaChanges | ForEach-Object { "$($_.Timestamp): $($_.Activity) by $($_.InitiatedBy)" }) -join '; ')
                    }
                    if ($roleChanges.Count -gt 0) {
                        Register-Indicator -Category 'PrivilegedRole' `
                            -Description "Directory role membership changed $($roleChanges.Count) time(s) during investigation window" `
                            -Severity 'High' `
                            -RawDetail (($roleChanges | ForEach-Object { "$($_.Timestamp): $($_.Activity) targeting $($_.Target)" }) -join '; ')
                    }
                    if ($appConsents.Count -gt 0) {
                        Register-Indicator -Category 'SuspiciousAppConsent' `
                            -Description "Application consent granted $($appConsents.Count) time(s) during investigation window" `
                            -Severity 'High' `
                            -RawDetail (($appConsents | ForEach-Object { "$($_.Timestamp): $($_.Activity) by $($_.InitiatedBy)" }) -join '; ')
                    }

                    Write-EvidenceLog "Correlated $($auditEvents.Count) significant audit event(s)." -Level Info
                }
            }
            else {
                Write-EvidenceLog 'No audit log CSV found for correlation.' -Level Warning
            }

            $result.AuditTimeline = @($auditEvents | Sort-Object Timestamp)
        }
        catch {
            Write-EvidenceLog "Audit log correlation encountered an error: $($_.Exception.Message)" -Level Warning
        }

        # ---------------------------------------------------------------
        # 8. Compromise Window Estimation
        # ---------------------------------------------------------------
        try {
            Write-EvidenceLog 'Estimating compromise window...' -Level Info
            $windowEvents = [System.Collections.Generic.List[PSCustomObject]]::new()

            # Gather timestamps from anomalous sign-ins
            foreach ($anom in @($result.AnomalousSignIns)) {
                if ($anom.FirstSignIn) {
                    try {
                        $ts = [datetime]::Parse($anom.FirstSignIn).ToUniversalTime()
                        [void]$windowEvents.Add([PSCustomObject]@{
                            Time        = $ts
                            Source      = 'SignInAnomaly'
                            Description = $anom.Detail
                        })
                    } catch { }
                }
            }

            # Gather timestamps from failed auth patterns (spray/brute)
            foreach ($fp in @($result.FailedAuthPatterns | Where-Object { $_.Pattern -ne 'FailedAuth' })) {
                try {
                    $ts = [datetime]::Parse($fp.FirstAttempt).ToUniversalTime()
                    [void]$windowEvents.Add([PSCustomObject]@{
                        Time        = $ts
                        Source      = 'FailedAuth'
                        Description = "$($fp.Pattern) from $($fp.IPAddress)"
                    })
                } catch { }
            }

            # Gather timestamps from audit events
            foreach ($ae in @($result.AuditTimeline)) {
                if ($ae.Timestamp) {
                    try {
                        $ts = [datetime]::Parse($ae.Timestamp).ToUniversalTime()
                        [void]$windowEvents.Add([PSCustomObject]@{
                            Time        = $ts
                            Source      = 'AuditEvent'
                            Description = "$($ae.EventType): $($ae.Activity)"
                        })
                    } catch { }
                }
            }

            if ($windowEvents.Count -gt 0) {
                $sorted = @($windowEvents | Sort-Object Time)
                $windowStart = $sorted[0].Time
                $windowEnd   = $sorted[-1].Time
                $duration    = $windowEnd - $windowStart
                $durationDesc = ''
                if ($duration.TotalDays -ge 1) {
                    $durationDesc = "$([math]::Floor($duration.TotalDays)) day(s), $($duration.Hours) hour(s)"
                }
                else {
                    $durationDesc = "$([math]::Floor($duration.TotalHours)) hour(s), $($duration.Minutes) minute(s)"
                }

                $hasSigAnomaly  = ($result.AnomalousSignIns | Where-Object { $_.Type -eq 'ImpossibleTravel' }).Count -gt 0
                $hasAuditEvents = $result.AuditTimeline.Count -gt 0
                $hasFailPatterns = ($result.FailedAuthPatterns | Where-Object { $_.Pattern -ne 'FailedAuth' }).Count -gt 0

                $confidence = 'Low'
                if ($hasSigAnomaly -and $hasAuditEvents) { $confidence = 'High' }
                elseif ($hasSigAnomaly -or $hasAuditEvents) { $confidence = 'Medium' }
                elseif ($hasFailPatterns) { $confidence = 'Low' }

                $keyEvents = @($sorted | Select-Object -First 3 | ForEach-Object {
                    "$($_.Time.ToString('yyyy-MM-dd HH:mm UTC')): $($_.Description)"
                })
                $keyEvents += @($sorted | Select-Object -Last 1 | ForEach-Object {
                    "$($_.Time.ToString('yyyy-MM-dd HH:mm UTC')): $($_.Description) [latest]"
                })

                $result.CompromiseWindow = [PSCustomObject]@{
                    WindowStart         = $windowStart.ToString('yyyy-MM-dd HH:mm:ss UTC')
                    WindowEnd           = $windowEnd.ToString('yyyy-MM-dd HH:mm:ss UTC')
                    DurationHours       = [math]::Round($duration.TotalHours, 1)
                    DurationDescription = $durationDesc
                    Confidence          = $confidence
                    KeyEvents           = $keyEvents
                    TotalSignals        = $windowEvents.Count
                }

                Write-EvidenceLog "Estimated compromise window: $($windowStart.ToString('yyyy-MM-dd HH:mm')) to $($windowEnd.ToString('yyyy-MM-dd HH:mm')) ($durationDesc), confidence: $confidence" -Level Info
            }
            else {
                Write-EvidenceLog 'No suspicious events available to estimate compromise window.' -Level Info
            }
        }
        catch {
            Write-EvidenceLog "Compromise window estimation encountered an error: $($_.Exception.Message)" -Level Warning
        }

        # ---------------------------------------------------------------
        # 9. Risk Signals (Entra ID Protection data)
        # ---------------------------------------------------------------
        try {
            Write-EvidenceLog 'Loading Entra risk signal data...' -Level Info
            $riskSignals = [System.Collections.Generic.List[PSCustomObject]]::new()

            $riskDetectPath = Join-Path $CasePaths.Entra 'RiskDetections.json'
            if (Test-Path $riskDetectPath) {
                $rawDetections = Get-Content -Path $riskDetectPath -Raw -ErrorAction SilentlyContinue |
                    ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($rawDetections) {
                    foreach ($det in @($rawDetections)) {
                        [void]$riskSignals.Add([PSCustomObject]@{
                            DetectionType    = $det.riskEventType
                            RiskLevel        = $det.riskLevel
                            RiskState        = $det.riskState
                            Activity         = $det.activity
                            IPAddress        = $det.ipAddress
                            DetectedDateTime = $det.detectedDateTime
                            Location         = if ($det.location) { "$($det.location.city), $($det.location.countryOrRegion)" } else { '' }
                            Source           = $det.source
                            Detail           = $det.additionalInfo
                        })
                    }
                }
            }

            $riskyUserPath = Join-Path $CasePaths.Entra 'RiskyUser.json'
            if (Test-Path $riskyUserPath) {
                $rawRisky = Get-Content -Path $riskyUserPath -Raw -ErrorAction SilentlyContinue |
                    ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($rawRisky) {
                    foreach ($ru in @($rawRisky)) {
                        [void]$riskSignals.Add([PSCustomObject]@{
                            DetectionType    = 'RiskyUserState'
                            RiskLevel        = $ru.riskLevel
                            RiskState        = $ru.riskState
                            Activity         = $ru.riskDetail
                            IPAddress        = ''
                            DetectedDateTime = $ru.riskLastUpdatedDateTime
                            Location         = ''
                            Source           = 'IdentityProtection'
                            Detail           = "UserDisplayName=$($ru.userDisplayName), UserPrincipalName=$($ru.userPrincipalName)"
                        })
                    }
                }
            }

            $result.RiskSignals = @($riskSignals)
            if ($riskSignals.Count -gt 0) {
                Write-EvidenceLog "Loaded $($riskSignals.Count) risk signal(s) from Entra ID Protection." -Level Info
            }
            else {
                Write-EvidenceLog 'No risk signal data available (may require Entra ID P2).' -Level Info
            }
        }
        catch {
            Write-EvidenceLog "Risk signal loading encountered an error: $($_.Exception.Message)" -Level Warning
        }
    }
    catch {
        Write-EvidenceLog "Compromise analysis encountered an unexpected error: $($_.Exception.Message)" -Level Warning
    }

    return $result
}

# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'Invoke-CompromiseAnalysis'
)
