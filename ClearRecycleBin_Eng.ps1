#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ===================== FUNCTIONS =====================

function Test-IsAdministrator {
    $currentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal        = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Convert-Size {
    param(
        [Parameter(Mandatory)]
        [long]$Bytes
    )

    if ($Bytes -ge 1GB) {
        "{0:N2} GB" -f ($Bytes / 1GB)
    }
    elseif ($Bytes -ge 1MB) {
        "{0:N2} MB" -f ($Bytes / 1MB)
    }
    elseif ($Bytes -ge 1KB) {
        "{0:N2} KB" -f ($Bytes / 1KB)
    }
    else {
        "$Bytes B"
    }
}

function Get-UserRecycleBinInfo {
    <#
        Returns one object per user profile containing:
        - UserName
        - SID
        - ProfilePath
        - BinPaths (Recycle Bin locations on local drives)
        - SizeBytes (total size of deleted user files)
    #>

    Write-Verbose "Retrieving user profiles via Win32_UserProfile"

    $profileList = Get-CimInstance -ClassName Win32_UserProfile |
        Where-Object {
            $_.LocalPath -like 'C:\Users\*' -and
            -not $_.Special -and
            $_.SID
        }

    if (-not $profileList) {
        Write-Warning "No user profiles found under C:\Users."
        return @()
    }

    # Local drives
    $drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
    if (-not $drives) {
        Write-Warning "No local drives found (DriveType=3)."
        return @()
    }

    $result = @()

    foreach ($profile in $profileList) {
        $sidString = $profile.SID

        # Translate SID to DOMAIN\User
        try {
            $sid   = New-Object System.Security.Principal.SecurityIdentifier($sidString)
            $ntAcc = $sid.Translate([System.Security.Principal.NTAccount])
            $userName = $ntAcc.Value
        }
        catch {
            $userName = "SID:$sidString"
        }

        $binPaths   = @()
        [long]$size = 0

        foreach ($drive in $drives) {
            $driveRoot    = $drive.DeviceID + '\'
            $recycleRoot  = Join-Path -Path $driveRoot -ChildPath '$Recycle.Bin'
            $userBinPath  = Join-Path -Path $recycleRoot -ChildPath $sidString

            if (Test-Path -LiteralPath $userBinPath) {
                $binPaths += $userBinPath

                try {
                    $sum = Get-ChildItem -LiteralPath $userBinPath -Recurse -Force -ErrorAction SilentlyContinue |
                           Where-Object {
                               -not $_.PSIsContainer -and
                               $_.Name -ne 'desktop.ini' -and
                               $_.Name -notlike '$I*'
                           } |
                           Measure-Object -Property Length -Sum

                    if ($null -ne $sum -and
                        $sum.PSObject.Properties.Name -contains 'Sum' -and
                        $null -ne $sum.Sum) {

                        $size += [long]$sum.Sum
                    }
                }
                catch {
                    Write-Warning "Unable to read contents of: $userBinPath. Error: $($_.Exception.Message)"
                }
            }
        }

        if ($binPaths.Count -gt 0 -or $size -gt 0) {
            $result += [pscustomobject]@{
                UserName    = $userName
                SID         = $sidString
                ProfilePath = $profile.LocalPath
                BinPaths    = $binPaths
                SizeBytes   = $size
            }
        }
    }

    return $result
}

function Show-UserRecycleBinSummary {
    param(
        [Parameter(Mandatory)]
        [array]$UserBins
    )

    if (-not $UserBins -or $UserBins.Count -eq 0) {
        Write-Host "No Recycle Bins found for any user profile." -ForegroundColor Yellow
        return @()
    }

    Write-Host ""
    Write-Host "================= RECYCLE BIN SUMMARY =================" -ForegroundColor Cyan

    $index = 1
    $displayList = foreach ($u in $UserBins) {
        [pscustomobject]@{
            Index       = $index++
            UserName    = $u.UserName
            ProfilePath = $u.ProfilePath
            Size        = Convert-Size -Bytes $u.SizeBytes
            RawSize     = $u.SizeBytes
        }
    }

    $displayListSorted = $displayList | Sort-Object -Property RawSize -Descending

    [void]($displayListSorted |
        Format-Table Index, UserName, ProfilePath, Size -AutoSize)

    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""

    return $displayListSorted
}

function Show-IndexList {
    param(
        [Parameter(Mandatory)]
        [array]$DisplayList
    )

    Write-Host "List of accounts with their indexes:" -ForegroundColor Cyan
    $DisplayList |
        Sort-Object Index |
        ForEach-Object {
            Write-Host ("[{0}] - {1}" -f $_.Index, $_.UserName)
        }
    Write-Host ""
}

function Show-UserRecycleBinFiles {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$UserBin
    )

    Write-Host ""
    Write-Host "========== Files in Recycle Bin for: $($UserBin.UserName) ==========" -ForegroundColor Yellow
    Write-Host "Profile: $($UserBin.ProfilePath)" -ForegroundColor Yellow
    Write-Host ""

    $allFiles = @()

    foreach ($path in $UserBin.BinPaths) {
        if (Test-Path -LiteralPath $path) {
            try {
                $files = Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
                         Where-Object {
                             -not $_.PSIsContainer -and
                             $_.Name -ne 'desktop.ini' -and
                             $_.Name -notlike '$I*'
                         } |
                         Select-Object @{
                                Name = 'RecycleBinPath'
                                Expression = { $path }
                         }, @{
                                Name = 'Name'
                                Expression = { $_.Name }
                         }, @{
                                Name = 'LengthBytes'
                                Expression = { $_.Length }
                         }, @{
                                Name = 'Size'
                                Expression = { Convert-Size -Bytes $_.Length }
                         }, LastWriteTime

                if ($files) {
                    $allFiles += $files
                }
            }
            catch {
                Write-Warning "Unable to read files in '$path'. Error: $($_.Exception.Message)"
            }
        }
    }

    if (-not $allFiles -or $allFiles.Count -eq 0) {
        Write-Host "No files found (except metadata/desktop.ini)." -ForegroundColor Yellow
        return
    }

    $allFiles |
        Sort-Object -Property LengthBytes -Descending |
        Format-Table RecycleBinPath, Name, Size, LastWriteTime -AutoSize

    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor Yellow
}

function Clear-UserRecycleBin {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$UserBin
    )

    $sizeText = Convert-Size -Bytes $UserBin.SizeBytes
    Write-Host ""
    Write-Host "Clearing Recycle Bin for: $($UserBin.UserName)" -ForegroundColor Yellow
    Write-Host "Profile: $($UserBin.ProfilePath)" -ForegroundColor Yellow
    Write-Host "Current size: $sizeText" -ForegroundColor Yellow
    Write-Host ""

    foreach ($path in $UserBin.BinPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }

        Write-Host "Recycle Bin path: $path" -ForegroundColor Cyan

        # Ensure it's always an array
        $files = @(
            Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                -not $_.PSIsContainer -and
                $_.Name -ne 'desktop.ini' -and
                $_.Name -notlike '$I*'
            }
        )

        if ($files.Count -eq 0) {
            Write-Host "  (No files to delete)" -ForegroundColor DarkYellow
            continue
        }

        foreach ($file in $files) {
            $fSize = Convert-Size -Bytes $file.Length
            Write-Host ("  - Deleting file: {0} ({1})" -f $file.Name, $fSize)

            try {
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "Could not delete file $($file.FullName). Error: $($_.Exception.Message)"
            }
        }

        Write-Host ""
    }

    Write-Host "Completed for: $($UserBin.UserName)" -ForegroundColor Green
}

# ===================== MAIN EXECUTION =====================

if (-not (Test-IsAdministrator)) {
    Write-Error "This script must be run as Administrator. Aborting."
    exit 1
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " RECYCLE BIN INSPECTION & CLEANUP TOOL      " -ForegroundColor Cyan
Write-Host " (All user profiles under C:\Users\...)     " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$allUserBins = Get-UserRecycleBinInfo

if (-not $allUserBins -or $allUserBins.Count -eq 0) {
    Write-Host "No Recycle Bins found for any user profile." -ForegroundColor Yellow
    exit 0
}

# Show summary
$displayList = Show-UserRecycleBinSummary -UserBins $allUserBins

# Optional: show index list
$answerIndexList = Read-Host "Do you want to list all accounts with index numbers? (Y/N)"
if ($answerIndexList -in @('Y','y','Yes','yes')) {
    Show-IndexList -DisplayList $displayList
}

# ===================== FILE LISTING =====================

$answerList = Read-Host "Do you want to list files in any user's Recycle Bin? (Y/N)"
if ($answerList -in @('Y','y','Yes','yes')) {
    Write-Host ""
    Write-Host "Enter the index of the users. Example: '1', '1,3,5', or 'all'." -ForegroundColor Cyan
    $selectionList = Read-Host "Selection (list)"

    $selectedForList = @()

    if ($selectionList -match '^(all|ALL|All)$') {
        $selectedForList = $allUserBins
    }
    else {
        $indexes = @(
            $selectionList -split '[,; ]+' |
            Where-Object { $_ -match '^\d+$' } |
            ForEach-Object { [int]$_ }
        )

        if ($indexes.Count -gt 0) {
            foreach ($i in $indexes) {
                $entry = $displayList | Where-Object { $_.Index -eq $i }
                if ($entry) {
                    $userBin = $allUserBins | Where-Object {
                        $_.ProfilePath -eq $entry.ProfilePath -and
                        $_.UserName   -eq $entry.UserName
                    }
                    if ($userBin) {
                        $selectedForList += $userBin
                    }
                }
            }
        }
    }

    foreach ($user in $selectedForList) {
        Show-UserRecycleBinFiles -UserBin $user
        if ($selectedForList.Count -gt 1) {
            Read-Host "Press Enter to continue to the next user..."
        }
    }

    Read-Host "File listing complete. Press Enter to continue..."
}

# ===================== EMPTY RECYCLE BIN =====================

$answer = Read-Host "Do you want to empty the Recycle Bin for any user? (Y/N)"
if ($answer -notin @('Y','y','Yes','yes')) {
    Write-Host "No Recycle Bins were emptied." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Current summary:" -ForegroundColor Cyan
$displayList = Show-UserRecycleBinSummary -UserBins $allUserBins

$answerIndexList2 = Read-Host "Do you want to show the index list again? (Y/N)"
if ($answerIndexList2 -in @('Y','y','Yes','yes')) {
    Show-IndexList -DisplayList $displayList
}

Write-Host "Enter the index of the users to empty. Example: '1', '1,3,5', or 'all'." -ForegroundColor Cyan
$selection = Read-Host "Selection (empty)"

$selectedUsers = @()

if ($selection -match '^(all|ALL|All)$') {
    $selectedUsers = $allUserBins
}
else {
    $indexes = @(
        $selection -split '[,; ]+' |
        Where-Object { $_ -match '^\d+$' } |
        ForEach-Object { [int]$_ }
    )

    if ($indexes.Count -eq 0) {
        Write-Host "Invalid selection. No Recycle Bins emptied." -ForegroundColor Yellow
        exit 0
    }

    foreach ($i in $indexes) {
        $entry = $displayList | Where-Object { $_.Index -eq $i }
        if ($entry) {
            $userBin = $allUserBins | Where-Object {
                $_.ProfilePath -eq $entry.ProfilePath -and
                $_.UserName   -eq $entry.UserName
            }
            if ($userBin) {
                $selectedUsers += $userBin
            }
        }
    }

    if ($selectedUsers.Count -eq 0) {
        Write-Host "No valid users found. No Recycle Bins emptied." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host ""
Write-Host "WARNING: This will permanently delete all files in the selected Recycle Bins." -ForegroundColor Red
$final = Read-Host "Are you sure? (Y/N)"

if ($final -notin @('Y','y','Yes','yes')) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

foreach ($user in $selectedUsers) {
    Clear-UserRecycleBin -UserBin $user
}

Write-Host ""
Write-Host "Done. You may run the script again to verify results." -ForegroundColor Green
exit 0
