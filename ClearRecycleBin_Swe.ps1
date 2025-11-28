#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ===================== FUNKTIONER =====================

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
        Returnerar ett objekt per användarprofil med:
        - UserName    (DOMÄN\användare eller dator\lokalkonto)
        - SID
        - ProfilePath
        - BinPaths    (alla papperskorgsmappar på lokala diskar)
        - SizeBytes   (total storlek)
    #>

    Write-Verbose "Hämtar användarprofiler via Win32_UserProfile"

    $profileList = Get-CimInstance -ClassName Win32_UserProfile |
        Where-Object {
            $_.LocalPath -like 'C:\Users\*' -and
            -not $_.Special -and
            $_.SID
        }

    if (-not $profileList) {
        Write-Warning "Inga användarprofiler hittades under C:\Users."
        return @()
    }

    # Lokala diskar (DriveType = 3)
    $drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
    if (-not $drives) {
        Write-Warning "Inga lokala diskar hittades (DriveType=3)."
        return @()
    }

    $result = @()

    foreach ($profile in $profileList) {
        $sidString = $profile.SID

        # Översätt SID till NT-konto (DOMÄN\användare)
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
                    Write-Warning "Kunde inte läsa innehåll i: $userBinPath. Fel: $($_.Exception.Message)"
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
        Write-Host "Inga papperskorgar hittades för användarprofiler." -ForegroundColor Yellow
        return @()
    }

    Write-Host ""
    Write-Host "================= SAMMANSTÄLLNING PAPPERSKORGAR =================" -ForegroundColor Cyan

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

    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host ""

    return $displayListSorted
}

function Show-IndexList {
    param(
        [Parameter(Mandatory)]
        [array]$DisplayList
    )

    Write-Host "Lista över konton och index:" -ForegroundColor Cyan
    $DisplayList |
        Where-Object { $_.PSObject.Properties.Name -contains 'Index' } |
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
    Write-Host "========== Filer i papperskorgen för: $($UserBin.UserName) ==========" -ForegroundColor Yellow
    Write-Host "Profil: $($UserBin.ProfilePath)" -ForegroundColor Yellow
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
                                Name = 'DiskPapperskorgPath'
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
                Write-Warning "Kunde inte läsa filer i '$path'. Fel: $($_.Exception.Message)"
            }
        }
    }

    if (-not $allFiles -or $allFiles.Count -eq 0) {
        Write-Host "Inga filer (förutom metadata/desktop.ini) hittades i papperskorgen för denna användare." -ForegroundColor Yellow
        return
    }

    $allFiles |
        Sort-Object -Property LengthBytes -Descending |
        Format-Table DiskPapperskorgPath, Name, Size, LastWriteTime -AutoSize

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
    Write-Host "Tömmer papperskorg för: $($UserBin.UserName)" -ForegroundColor Yellow
    Write-Host "Profil: $($UserBin.ProfilePath)" -ForegroundColor Yellow
    Write-Host "Nuvarande storlek: $sizeText" -ForegroundColor Yellow
    Write-Host ""

    foreach ($path in $UserBin.BinPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }

        Write-Host "Korg: $path" -ForegroundColor Cyan

        # ALLTID array, även om 0 eller 1 fil hittas
        $files = @(
            Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                -not $_.PSIsContainer -and
                $_.Name -ne 'desktop.ini' -and
                $_.Name -notlike '$I*'
            }
        )

        if ($files.Count -eq 0) {
            Write-Host "  (Inga filer att ta bort)" -ForegroundColor DarkYellow
            continue
        }

        foreach ($file in $files) {
            $fSize = Convert-Size -Bytes $file.Length
            Write-Host ("  - Tar bort fil: {0} ({1})" -f $file.Name, $fSize)

            try {
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "Kunde inte ta bort filen $($file.FullName). Fel: $($_.Exception.Message)"
            }
        }

        Write-Host ""
    }

    Write-Host "Klart för: $($UserBin.UserName)" -ForegroundColor Green
}


# ===================== HUVUDKÖRNING =====================

if (-not (Test-IsAdministrator)) {
    Write-Error "Detta skript måste köras som administratör (höjd PowerShell). Avbryter."
    exit 1
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " KOLL AV PAPPERSKORGAR FÖR ANVÄNDARKONTON  " -ForegroundColor Cyan
Write-Host " (alla användarprofiler under C:\Users\...) " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$allUserBins = Get-UserRecycleBinInfo

if (-not $allUserBins -or $allUserBins.Count -eq 0) {
    Write-Host "Inga papperskorgsmappar hittades för användarprofiler." -ForegroundColor Yellow
    exit 0
}

# Visa första översikten
$displayList = Show-UserRecycleBinSummary -UserBins $allUserBins

$answerIndexList = Read-Host "Vill du lista alla konton och dess index? (J/N)"
if ($answerIndexList -in @('J','j','Ja','ja','Y','y')) {
    Show-IndexList -DisplayList $displayList
}

# ===================== VAL: LISTA FILER =====================

$answerList = Read-Host "Vill du lista filer i papperskorgen för någon användare? (J/N)"
if ($answerList -in @('J','j','Ja','ja','Y','y')) {
    Write-Host ""
    Write-Host "Ange index för de användare du vill lista filer för." -ForegroundColor Cyan
    Write-Host "Du kan ange t.ex. '1', '1,3,5' eller skriva 'alla' för alla." -ForegroundColor Cyan
    $selectionList = Read-Host "Val (lista)"

    $selectedForList = @()

    if ($selectionList -match '^(alla|ALLA|Alla)$') {
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
                else {
                    Write-Warning "Index $i hittades inte i listan och hoppas över."
                }
            }
        }
        else {
            Write-Host "Inga giltiga index angavs för listning." -ForegroundColor Yellow
        }
    }

    foreach ($user in $selectedForList) {
        Show-UserRecycleBinFiles -UserBin $user
        if ($selectedForList.Count -gt 1) {
            Read-Host "Tryck Enter för att gå vidare till nästa användare..."
        }
    }

    Write-Host ""
    Read-Host "Listning klar. Tryck Enter för att fortsätta till ev. tömning..."
}

# ===================== VAL: TÖMMA PAPPERSKORG =====================

$answer = Read-Host "Vill du tömma papperskorgen för någon användare? (J/N)"
if ($answer -notin @('J','j','Ja','ja','Y','y')) {
    Write-Host "Ingen papperskorg tömdes." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Aktuell sammanställning (använd Index-kolumnen vid val för tömning):" -ForegroundColor Cyan
$displayList = Show-UserRecycleBinSummary -UserBins $allUserBins

$answerIndexList2 = Read-Host "Vill du lista alla konton och dess index igen? (J/N)"
if ($answerIndexList2 -in @('J','j','Ja','ja','Y','y')) {
    Show-IndexList -DisplayList $displayList
}

Write-Host "Ange index för de användare du vill tömma papperskorgen för." -ForegroundColor Cyan
Write-Host "Du kan ange t.ex. '1', '1,3,5' eller skriva 'alla' för alla." -ForegroundColor Cyan
$selection = Read-Host "Val (töm)"

$selectedUsers = @()

if ($selection -match '^(alla|ALLA|Alla)$') {
    $selectedUsers = $allUserBins
}
else {
    $indexes = @(
        $selection -split '[,; ]+' |
        Where-Object { $_ -match '^\d+$' } |
        ForEach-Object { [int]$_ }
    )

    if ($indexes.Count -eq 0) {
        Write-Host "Inga giltiga index angavs. Ingen papperskorg töms." -ForegroundColor Yellow
        #exit 0
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
        else {
            Write-Warning "Index $i hittades inte i listan och hoppas över."
        }
    }

    if ($selectedUsers.Count -eq 0) {
        Write-Host "Ingen giltig användare hittades baserat på index. Ingen papperskorg töms." -ForegroundColor Yellow
        #exit 0
    }
}

Write-Host ""
Write-Host "VARNING: Detta kommer att tömma papperskorgen permanent" -ForegroundColor Red
Write-Host "för valda användare (alla diskar). Detta kan inte ångras." -ForegroundColor Red
$final = Read-Host "Är du säker? (J/N)"

if ($final -notin @('J','j','Ja','ja','Y','y','jajjemen')) {
    Write-Host "Åtgärden avbröts. Inga papperskorgar tömdes." -ForegroundColor Yellow
    #exit 0
}

foreach ($user in $selectedUsers) {
    Clear-UserRecycleBin -UserBin $user
}

Write-Host ""
Write-Host "Färdigt. Du kan köra skriptet igen för att se uppdaterad storlek." -ForegroundColor Green
#exit 0
