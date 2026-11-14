#  IAM PowerShell Automation 

### Bulk Active Directory User & Group Management

> **Identity and Access Management** · PowerShell 5.1 / 7+ · Windows Server 2019/2022

-----

##  Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Lab Environment Setup](#lab-environment-setup)
- [Script Reference](#script-reference)
  - [Module 02 — Bulk User Creation](#module-02--bulk-user-creation)
  - [Module 03 — Bulk User Modification](#module-03--bulk-user-modification)
  - [Module 04 — Group Management](#module-04--group-management)
  - [Module 05 — Offboarding](#module-05--offboarding)
  - [Module 06 — IAM Reporting](#module-06--iam-reporting)
- [Lab Task Checklist](#lab-task-checklist)
- [Quick Command Reference](#quick-command-reference)
- [IAM Principles](#iam-principles)
- [Repository Structure](#repository-structure)

-----

## Overview

This lab provides a production-pattern PowerShell toolkit for IAM teams managing Active Directory user lifecycle and group membership at scale. Every script follows enterprise IAM practices:

|Principle          |Implementation                                             |
|-------------------|-----------------------------------------------------------|
|**Idempotency**    |Scripts check existing state before acting — safe to re-run|
|**Dry-Run First**  |All destructive scripts support `-WhatIf`                  |
|**Audit Trail**    |Timestamped CSV run logs exported after every operation    |
|**Least Privilege**|Group sync removes stale access, not just adds             |

**Lab Info:**

|Field         |Value                                  |
|--------------|---------------------------------------|
|Skill Level   |Intermediate                           |
|Pre-Requisites|Basic PowerShell, AD fundamentals, RSAT|
|Estimated Time|~2.5 hours                             |
|Target OU     |`OU=IAM_Lab,DC=corp,DC=local`          |
|Log Output    |`C:\IAM_Lab\`                          |

-----

## Prerequisites

- Windows Server 2019/2022 domain-joined (or workstation with RSAT)
- PowerShell 5.1+ (PS 7+ recommended)
- ActiveDirectory PowerShell module
- Account with Create/Modify/Delete rights on target OU
- Execution policy: `RemoteSigned` or `Bypass`

-----

## Lab Environment Setup

### 1. Verify the AD Module



```powershell
# Check if ActiveDirectory module is available
Get-Module -Name ActiveDirectory -ListAvailable

# Install RSAT on Windows 10/11 if missing
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"

# Import into current session
Import-Module ActiveDirectory

# Confirm connectivity
Get-ADDomain | Select-Object DNSRoot, PDCEmulator, RIDMaster
```

-----

### 2. Build the Lab OU Structure



>  **Run once.** Creates an isolated OU hierarchy — no production OUs are touched.

```powershell
$domain  = "DC=corp,DC=local"
$labRoot = "OU=IAM_Lab,$domain"

# Top-level lab OU
New-ADOrganizationalUnit -Name "IAM_Lab" -Path $domain -ProtectedFromAccidentalDeletion $false

# Child OUs
foreach ($ou in "Users","Disabled","ServiceAccounts","Groups") {
    New-ADOrganizationalUnit -Name $ou -Path $labRoot
}

Write-Host "OU structure created." -ForegroundColor Green
```

**Expected ADUC structure:**

```
corp.local
└── IAM_Lab
    ├── Users
    ├── Disabled
    ├── ServiceAccounts
    └── Groups
```

-----

### 3. Create the Input CSV

Save to `C:\IAM_Lab\users.csv`. In production this is generated from your HRIS export (Workday, UKG, etc.).

```csv
FirstName,LastName,SamAccountName,Department,Title,Manager,Office,EmployeeID
John,Smith,jsmith,Nursing,RN Staff Nurse,mgr.jones,Nashville,EMP001
Maria,Garcia,mgarcia,IT,IAM Analyst,mgr.chen,Nashville,EMP002
Derek,Brown,dbrown,Finance,AR Specialist,mgr.patel,Memphis,EMP003
Sarah,Lee,slee,Nursing,Charge Nurse,mgr.jones,Memphis,EMP004
Carlos,Reyes,creyes,IT,Sys Admin,mgr.chen,Nashville,EMP005
```

-----

## Script Reference

### Module 02 — Bulk User Creation

**File:** `Scripts/New-BulkADUsers.ps1`

Provisions AD users from CSV with standardized UPN format, initial password, OU placement, and duplicate detection.



> Running with `-WhatIf` first simulates all actions without making any changes. After reviewing the output, remove `-WhatIf` for the live run.


> Re-running the same script skips existing users and logs them as `Skipped-Exists` — no duplicates, no errors.

```powershell
#Requires -Module ActiveDirectory

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)] [string]$CsvPath,
    [string]$TargetOU        = "OU=Users,OU=IAM_Lab,DC=corp,DC=local",
    [string]$UPNSuffix       = "@corp.local",
    [string]$DefaultPassword = "Welcome1!ChangeMe",
    [switch]$ForcePasswordChange = $true
)

$users   = Import-Csv -Path $CsvPath
$results = @()
$secPwd  = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force

foreach ($u in $users) {
    $upn = "$($u.SamAccountName)$UPNSuffix"
    $cn  = "$($u.FirstName) $($u.LastName)"

    # Skip if user already exists
    if (Get-ADUser -Filter {SamAccountName -eq $u.SamAccountName} -ErrorAction SilentlyContinue) {
        Write-Warning "SKIP: $($u.SamAccountName) already exists."
        $results += [PSCustomObject]@{ User=$u.SamAccountName; Status="Skipped-Exists" }
        continue
    }

    try {
        New-ADUser `
            -SamAccountName        $u.SamAccountName `
            -UserPrincipalName     $upn `
            -GivenName             $u.FirstName `
            -Surname               $u.LastName `
            -DisplayName           $cn `
            -Name                  $cn `
            -Department            $u.Department `
            -Title                 $u.Title `
            -Office                $u.Office `
            -EmployeeID            $u.EmployeeID `
            -Manager               $u.Manager `
            -AccountPassword       $secPwd `
            -ChangePasswordAtLogon $ForcePasswordChange `
            -Enabled               $true `
            -Path                  $TargetOU `
            -WhatIf:$WhatIfPreference

        $results += [PSCustomObject]@{ User=$u.SamAccountName; Status="Created" }
        Write-Host "[+] Created: $cn ($upn)" -ForegroundColor Cyan
    }
    catch {
        $results += [PSCustomObject]@{ User=$u.SamAccountName; Status="ERROR: $_" }
        Write-Warning "FAILED: $($u.SamAccountName) — $_"
    }
}

$reportPath = "C:\IAM_Lab\provision_log_$(Get-Date -f yyyyMMdd_HHmm).csv"
$results | Export-Csv -Path $reportPath -NoTypeInformation
Write-Host "`nDone. Report: $reportPath" -ForegroundColor Green
```

**Usage:**

```powershell
# Always dry-run first — no changes are made
.\New-BulkADUsers.ps1 -CsvPath "C:\IAM_Lab\users.csv" -WhatIf

# Live run after reviewing dry-run output
.\New-BulkADUsers.ps1 -CsvPath "C:\IAM_Lab\users.csv"
```

-----

### Module 03 — Bulk User Modification

**File:** `Scripts/Update-BulkADUsers.ps1`

Updates AD attributes from a delta CSV. Only columns present in the CSV row are modified — all other attributes are untouched.

```powershell
#Requires -Module ActiveDirectory

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string]$CsvPath
)

$fieldMap = @{
    Title      = "Title"
    Department = "Department"
    Office     = "Office"
    Manager    = "Manager"
    EmployeeID = "EmployeeID"
}

$users = Import-Csv -Path $CsvPath
$log   = @()

foreach ($u in $users) {
    $adUser = Get-ADUser -Filter {SamAccountName -eq $u.SamAccountName} -ErrorAction SilentlyContinue
    if (-not $adUser) {
        Write-Warning "NOT FOUND: $($u.SamAccountName)"
        $log += [PSCustomObject]@{ User=$u.SamAccountName; Status="NotFound" }
        continue
    }

    $params = @{}
    foreach ($col in $fieldMap.Keys) {
        if ($u.PSObject.Properties.Name -contains $col -and $u.$col) {
            $params[$fieldMap[$col]] = $u.$col
        }
    }

    try {
        Set-ADUser -Identity $u.SamAccountName @params -WhatIf:$WhatIfPreference
        $log += [PSCustomObject]@{ User=$u.SamAccountName; Status="Updated"; Fields=($params.Keys -join ",") }
        Write-Host "[~] Updated: $($u.SamAccountName)" -ForegroundColor Yellow
    }
    catch {
        $log += [PSCustomObject]@{ User=$u.SamAccountName; Status="ERROR: $_" }
    }
}

$log | Export-Csv "C:\IAM_Lab\update_log_$(Get-Date -f yyyyMMdd_HHmm).csv" -NoTypeInformation
Write-Host "Complete." -ForegroundColor Green
```

**Force password reset on a group:**

```powershell
# All users in the lab OU
Get-ADUser -Filter * -SearchBase "OU=Users,OU=IAM_Lab,DC=corp,DC=local" |
    Set-ADUser -ChangePasswordAtLogon $true

# Or target a specific security group
Get-ADGroupMember -Identity "GRP_Nursing_Staff" -Recursive |
    Where-Object { $_.objectClass -eq "user" } |
    ForEach-Object { Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true }
```

-----

### Module 04 — Group Management

#### Department-Based Group Sync



> The sync script reconciles both directions: adds users whose department matches AND removes users whose department no longer matches. A transfer from Nursing → Finance automatically strips the Nursing group membership.

**File:** `Scripts/Sync-DeptGroups.ps1`

```powershell
$deptGroupMap = @{
    "Nursing" = "GRP_Nursing_Staff"
    "Finance" = "GRP_Finance_Readonly"
    "IT"      = "GRP_IT_Admins"
}

$ou       = "OU=Users,OU=IAM_Lab,DC=corp,DC=local"
$allUsers = Get-ADUser -Filter * -SearchBase $ou -Properties Department

foreach ($dept in $deptGroupMap.Keys) {
    $targetGroup   = $deptGroupMap[$dept]
    $deptUsers     = $allUsers | Where-Object { $_.Department -eq $dept }
    $currentMember = Get-ADGroupMember -Identity $targetGroup | Select-Object -Exp SamAccountName

    # Add missing members
    $toAdd = $deptUsers | Where-Object { $_.SamAccountName -notin $currentMember }
    if ($toAdd) {
        Add-ADGroupMember -Identity $targetGroup -Members $toAdd
        Write-Host "[+] Added $($toAdd.Count) users to $targetGroup" -ForegroundColor Cyan
    }

    # Remove members whose department changed (revoke excess access)
    $toRemove = $currentMember | Where-Object { $_ -notin $deptUsers.SamAccountName }
    if ($toRemove) {
        Remove-ADGroupMember -Identity $targetGroup -Members $toRemove -Confirm:$false
        Write-Warning "[-] Removed $($toRemove.Count) stale members from $targetGroup"
    }
}
```

#### Create Role-Based Security Groups

**File:** `Scripts/New-RoleGroups.ps1`

```powershell
$groupOU = "OU=Groups,OU=IAM_Lab,DC=corp,DC=local"

$groups = @(
    @{ Name="GRP_Nursing_Staff";         Scope="Global";    Category="Security" },
    @{ Name="GRP_Finance_Readonly";      Scope="Global";    Category="Security" },
    @{ Name="GRP_IT_Admins";             Scope="Global";    Category="Security" },
    @{ Name="GRP_VPN_Users";             Scope="Universal"; Category="Security" },
    @{ Name="GRP_MFA_Exempt_Breakglass"; Scope="Global";    Category="Security" }
)

foreach ($g in $groups) {
    if (-not (Get-ADGroup -Filter {Name -eq $g.Name} -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $g.Name `
                    -GroupScope    $g.Scope `
                    -GroupCategory $g.Category `
                    -Path          $groupOU `
                    -Description   "IAM Lab — created $(Get-Date -f yyyy-MM-dd)"
        Write-Host "[+] $($g.Name)" -ForegroundColor Cyan
    } else {
        Write-Warning "EXISTS: $($g.Name)"
    }
}
```

#### Bulk Membership Assignment

**File:** `Scripts/Add-BulkGroupMembers.ps1`

> CSV format: `SamAccountName,GroupName`

```powershell
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$CsvPath)

Import-Csv $CsvPath | ForEach-Object {
    try {
        Add-ADGroupMember -Identity $_.GroupName -Members $_.SamAccountName -WhatIf:$WhatIfPreference
        Write-Host "[+] $($_.SamAccountName) → $($_.GroupName)" -ForegroundColor Green
    }
    catch { Write-Warning "ERR: $($_.SamAccountName) — $_" }
}
```

#### Find Stale Group Members

**File:** `Scripts/Find-StaleGroupMembers.ps1`

```powershell
$disabledWithGroups = Get-ADUser -Filter {Enabled -eq $false} `
    -Properties MemberOf, Department, DistinguishedName |
    Where-Object { $_.MemberOf.Count -gt 0 }

$report = foreach ($user in $disabledWithGroups) {
    foreach ($grp in $user.MemberOf) {
        [PSCustomObject]@{
            SamAccountName = $user.SamAccountName
            DisplayName    = $user.DisplayName
            Department     = $user.Department
            Group          = ($grp -split ",")[0] -replace "CN=",""
            Risk           = "DISABLED_WITH_ACCESS"
        }
    }
}

$report | Format-Table -AutoSize
$report | Export-Csv "C:\IAM_Lab\stale_members_$(Get-Date -f yyyyMMdd).csv" -NoTypeInformation
```

-----

### Module 05 — Offboarding

**File:** `Scripts/Invoke-Offboard.ps1`



> Always run with `-WhatIf` first to confirm all 4 steps are correct before going live.

Executes the full offboard sequence per account:

1. `Disable-ADAccount` — blocks logon immediately
1. Strip **all** group memberships
1. Stamp `Description` with termination date
1. `Move-ADObject` to `OU=Disabled`
1. Export timestamped run log

```powershell
#Requires -Module ActiveDirectory

[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$SamAccountName,
    [string]$CsvPath,
    [string]$TermDate   = (Get-Date -f "yyyy-MM-dd"),
    [string]$DisabledOU = "OU=Disabled,OU=IAM_Lab,DC=corp,DC=local"
)

$targets = if ($CsvPath) { (Import-Csv $CsvPath).SamAccountName } else { $SamAccountName }
$log     = @()

foreach ($sam in $targets) {
    $user = Get-ADUser -Filter {SamAccountName -eq $sam} -Properties MemberOf,DisplayName -EA SilentlyContinue
    if (-not $user) { Write-Warning "NOT FOUND: $sam"; continue }

    Write-Host "`n[OFFBOARD] $($user.DisplayName) ($sam)" -ForegroundColor Red

    # 1 — Disable
    Disable-ADAccount -Identity $sam -WhatIf:$WhatIfPreference

    # 2 — Strip all group memberships
    $groups = $user.MemberOf
    foreach ($g in $groups) {
        Remove-ADGroupMember -Identity $g -Members $sam -Confirm:$false -WhatIf:$WhatIfPreference
    }
    Write-Host "  Stripped $($groups.Count) group membership(s)"

    # 3 — Stamp description
    Set-ADUser -Identity $sam -Description "TERMINATED:$TermDate | IAM Offboard" -WhatIf:$WhatIfPreference

    # 4 — Move to Disabled OU
    Move-ADObject -Identity $user.DistinguishedName -TargetPath $DisabledOU -WhatIf:$WhatIfPreference

    $log += [PSCustomObject]@{
        SamAccountName = $sam
        DisplayName    = $user.DisplayName
        GroupsRemoved  = $groups.Count
        TermDate       = $TermDate
        Status         = "Offboarded"
    }
}

$log | Export-Csv "C:\IAM_Lab\offboard_log_$(Get-Date -f yyyyMMdd_HHmm).csv" -NoTypeInformation
Write-Host "`nOffboard complete. $($log.Count) account(s) processed." -ForegroundColor DarkYellow
```

**Usage:**

```powershell
# Single user — dry run
.\Invoke-Offboard.ps1 -SamAccountName jsmith -WhatIf

# Single user — live
.\Invoke-Offboard.ps1 -SamAccountName jsmith

# Bulk from termination CSV
.\Invoke-Offboard.ps1 -CsvPath "C:\IAM_Lab\terminations.csv" -TermDate "2025-06-15"
```

> 📋 **HIPAA Note:** The offboard run log is your access revocation evidence. Retain for a minimum of **6 years** per HIPAA documentation requirements.

-----

### Module 06 — IAM Reporting

#### Privileged Group Membership Audit

**File:** `Scripts/Get-PrivilegedGroupReport.ps1`


> Disabled accounts still holding privileged group membership are flagged as `DISABLED-REVIEW` — a common finding in IAM audits.

```powershell
$privilegedGroups = @(
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators"
)

$report = foreach ($group in $privilegedGroups) {
    try {
        Get-ADGroupMember -Identity $group -Recursive | ForEach-Object {
            $member = Get-ADObject -Identity $_.distinguishedName -Properties Enabled,LastLogonDate
            [PSCustomObject]@{
                PrivilegedGroup = $group
                Member          = $_.SamAccountName
                ObjectType      = $_.objectClass
                Enabled         = $member.Enabled
                LastLogon       = $member.LastLogonDate
                ReviewFlag      = if ($member.Enabled -eq $false) { "DISABLED-REVIEW" } else { "OK" }
            }
        }
    } catch { Write-Warning "Could not query: $group" }
}

$report | Sort-Object PrivilegedGroup, Member | Format-Table -AutoSize
$report | Export-Csv "C:\IAM_Lab\privileged_group_report_$(Get-Date -f yyyyMMdd).csv" -NoTypeInformation
```

#### Stale Account Detection (90-day)

**File:** `Scripts/Get-StaleAccounts.ps1`

```powershell
$cutoff = (Get-Date).AddDays(-90)

Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $cutoff} `
           -Properties LastLogonDate, Department, Title, Manager |
    Select-Object SamAccountName, DisplayName, Department, Title, LastLogonDate |
    Sort-Object LastLogonDate |
    Export-Csv "C:\IAM_Lab\stale_accounts_90d_$(Get-Date -f yyyyMMdd).csv" -NoTypeInformation

Write-Host "Stale account report exported."
```

**Automate delivery via email:**

```powershell
Send-MailMessage -To "iam-team@corp.local" `
    -Subject "Monthly Stale Account Report" `
    -Attachments "C:\IAM_Lab\stale_accounts_90d_$(Get-Date -f yyyyMMdd).csv" `
    -SmtpServer "smtp.corp.local" `
    -From "iam-noreply@corp.local"
```

-----

##  Task Checklist

### Module 01 — Environment

- [ ] `Get-Module ActiveDirectory` loads without errors
- [ ] IAM_Lab OU created with `Users`, `Disabled`, `ServiceAccounts`, `Groups` sub-OUs
- [ ] `users.csv` created at `C:\IAM_Lab\` with minimum 5 test users

### Module 02 — Bulk User Creation

- [ ] Dry run (`-WhatIf`) shows all 5 users in `What if:` output — no changes made
- [ ] Live run creates all users, confirmed in ADUC under `OU=Users,OU=IAM_Lab`
- [ ] `provision_log_*.csv` reviewed — all statuses show `Created`
- [ ] Second run confirms duplicates logged as `Skipped-Exists`, no errors

### Module 03 — Bulk Modification

- [ ] `delta.csv` created with 2–3 users with changed `Title` or `Department`
- [ ] Script run with `-WhatIf`, reviewed before live execution
- [ ] Attributes confirmed updated in ADUC after live run

### Module 04 — Group Management

- [ ] All 5 role groups created in `OU=Groups,OU=IAM_Lab`
- [ ] Users assigned to groups from membership CSV
- [ ] Transfer one user’s `Department`, re-run `Sync-DeptGroups.ps1`, confirm group reassignment
- [ ] Disable one user, run `Find-StaleGroupMembers.ps1`, confirm `DISABLED_WITH_ACCESS` flag

### Module 05 — Offboarding

- [ ] `-WhatIf` for one user shows all 4 steps in output
- [ ] Live run — account disabled, groups stripped, Description stamped, moved to `OU=Disabled`
- [ ] `offboard_log_*.csv` `GroupsRemoved` count matches pre-offboard group count

### Module 06 — Reporting

- [ ] `Get-PrivilegedGroupReport.ps1` runs — all privileged groups listed
- [ ] `Get-StaleAccounts.ps1` runs — `stale_accounts_90d_*.csv` exported

-----

## Quick Command Reference

```powershell
# ── PROVISIONING ──────────────────────────────────────────────────────────────
.\New-BulkADUsers.ps1 -CsvPath "C:\IAM_Lab\users.csv" -WhatIf     # dry run
.\New-BulkADUsers.ps1 -CsvPath "C:\IAM_Lab\users.csv"              # live

# ── ATTRIBUTE UPDATE ──────────────────────────────────────────────────────────
.\Update-BulkADUsers.ps1 -CsvPath "C:\IAM_Lab\delta.csv" -WhatIf
.\Update-BulkADUsers.ps1 -CsvPath "C:\IAM_Lab\delta.csv"

# ── GROUPS ────────────────────────────────────────────────────────────────────
.\New-RoleGroups.ps1
.\Add-BulkGroupMembers.ps1 -CsvPath "C:\IAM_Lab\memberships.csv"
.\Sync-DeptGroups.ps1
.\Find-StaleGroupMembers.ps1

# ── OFFBOARDING ───────────────────────────────────────────────────────────────
.\Invoke-Offboard.ps1 -SamAccountName jsmith -WhatIf
.\Invoke-Offboard.ps1 -SamAccountName jsmith
.\Invoke-Offboard.ps1 -CsvPath "C:\IAM_Lab\terminations.csv"

# ── REPORTING ─────────────────────────────────────────────────────────────────
.\Get-PrivilegedGroupReport.ps1
.\Get-StaleAccounts.ps1

# ── USEFUL ONE-LINERS ─────────────────────────────────────────────────────────

# Force password reset — all users in lab OU
Get-ADUser -Filter * -SearchBase "OU=Users,OU=IAM_Lab,DC=corp,DC=local" |
    Set-ADUser -ChangePasswordAtLogon $true

# All Domain Admins members including nested groups
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object SamAccountName

# Accounts not logged in for 90+ days
$cutoff = (Get-Date).AddDays(-90)
Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $cutoff} `
    -Properties LastLogonDate | Sort-Object LastLogonDate

# Disabled users still holding group memberships
Get-ADUser -Filter {Enabled -eq $false} -Properties MemberOf |
    Where-Object { $_.MemberOf.Count -gt 0 } |
    Select-Object SamAccountName, @{N="Groups";E={$_.MemberOf.Count}}
```

-----

## IAM Principles

### Why `-WhatIf` Matters

All scripts use `[CmdletBinding(SupportsShouldProcess)]`. This enables the PowerShell `-WhatIf` common parameter which simulates execution without making any changes. Every bulk IAM operation should be validated with a dry run before live execution.

### Why Idempotency Matters

Provisioning scripts check for existing accounts before creating them. A failed or partial run can be safely re-executed — users already created are skipped with `Skipped-Exists` status in the run log, and no duplicate objects or errors are produced.

### Why Two-Directional Group Sync Matters

`Sync-DeptGroups.ps1` reconciles group membership in both directions. A transfer from Nursing → Finance automatically:

- Adds user to `GRP_Finance_Readonly`
- Removes user from `GRP_Nursing_Staff`

Scripts that only add — never remove — result in accumulated excessive access, which is a least-privilege violation and surfaces as a finding in IAM access reviews (SailPoint, Saviynt certifications).

### Offboard Sequence Order

The offboard script executes steps in a specific order for a reason:

```
Disable → Strip Groups → Stamp Description → Move OU
```

Disabling first ensures the account cannot authenticate during the brief window when groups are being stripped. Moving to `OU=Disabled` last ensures the account is in the correct location regardless of whether a group-removal step fails.

-----

## Repository Structure

```
IAM-PowerShell-Lab/
├── README.md
├── screenshots/
│   ├── 01_env_setup.png
│   ├── 02_ou_structure.png
│   ├── 03_bulk_provision.png
│   ├── 04_idempotency.png
│   ├── 05_group_sync.png
│   ├── 06_offboard.png
│   └── 07_priv_report.png
├── Scripts/
│   ├── New-BulkADUsers.ps1
│   ├── Update-BulkADUsers.ps1
│   ├── New-RoleGroups.ps1
│   ├── Add-BulkGroupMembers.ps1
│   ├── Sync-DeptGroups.ps1
│   ├── Find-StaleGroupMembers.ps1
│   ├── Invoke-Offboard.ps1
│   ├── Get-PrivilegedGroupReport.ps1
│   └── Get-StaleAccounts.ps1
├── Templates/
│   ├── users.csv
│   ├── delta.csv
│   ├── memberships.csv
│   └── terminations.csv
└── Logs/
    └── .gitkeep
```

-----

*IAM PowerShell Automation Lab · Identity and Access Management · PowerShell 5.1 / 7+*
