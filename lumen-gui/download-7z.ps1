# Download full 7-Zip for bundling with Lumen
# Must support RAR extraction — 7za.exe (standalone) does NOT.
# Priority: local install → full NuGet package → placeholder

$targetDir = Join-Path $PSScriptRoot "resources"
New-Item -ItemType Directory -Force $targetDir | Out-Null
$target = Join-Path $targetDir "7z.exe"

if (Test-Path $target) {
    Write-Host "7z.exe already exists at $target"
    exit 0
}

# Test if a 7z binary supports RAR format
function Test-RarSupport($path) {
    if (-not (Test-Path $path)) { return $false }
    try {
        # Check if --help mentions RAR (full version does, 7za does not)
        $help = & $path --help 2>&1 | Out-String
        if ($help -match '\brar\b' -or $help -match '\bRAR\b') {
            Write-Host "  -> RAR support confirmed in help text"
            return $true
        }
        # Some versions don't list formats in help. Fallback: run 'i' (info)
        $info = & $path i 2>&1 | Out-String
        if ($info -match '\brar\b') {
            Write-Host "  -> RAR support confirmed"
            return $true
        }
        Write-Host "  -> No RAR support detected (standalone 7za variant)"
        return $false
    } catch { return $false }
}

# 1. Copy from existing 7-Zip installation (guaranteed full version)
Write-Host "Checking existing 7-Zip installations..."
$paths = @(
    "${env:ProgramFiles}\7-Zip\7z.exe",
    "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
)
foreach ($p in $paths) {
    if ((Test-Path $p) -and (Test-RarSupport $p)) {
        $dll = [System.IO.Path]::ChangeExtension($p, "dll")
        Copy-Item $p $target
        if (Test-Path $dll) {
            Copy-Item $dll (Join-Path $targetDir "7z.dll")
        }
        Write-Host "Copied full 7z.exe from $p"
        exit 0
    }
}

# 2. Try NuGet package with full 7z (not 7za standalone)
Write-Host "Trying NuGet packages..."
$nugetPkgs = @("7-Zip.x64", "7-Zip", "7-Zip.CommandLine")
$foundFull = $false
foreach ($pkg in $nugetPkgs) {
    Write-Host "  Trying NuGet package: $pkg"
    try {
        # Use nuget.exe if available, otherwise try dotnet
        if (Get-Command nuget.exe -ErrorAction SilentlyContinue) {
            $outDir = "$env:TEMP\$pkg"
            & nuget install $pkg -OutputDirectory "$env:TEMP" -ExcludeVersion -NonInteractive *>$null 2>&1
            # Check for full 7z.exe first, then 7za.exe
            foreach ($exe in @("$env:TEMP\$pkg\tools\7z.exe", "$env:TEMP\$pkg\7z.exe",
                               "$env:TEMP\$pkg\tools\7za.exe", "$env:TEMP\$pkg\7za.exe")) {
                if (Test-Path $exe) {
                    $dll = [System.IO.Path]::ChangeExtension($exe, "dll")
                    if (Test-RarSupport $exe) {
                        Copy-Item $exe $target
                        if (Test-Path $dll) { Copy-Item $dll (Join-Path $targetDir "7z.dll") }
                        Write-Host "Copied full 7z from NuGet package $pkg"
                        $foundFull = $true
                        break
                    }
                }
            }
        } elseif (Get-Command dotnet.exe -ErrorAction SilentlyContinue) {
            & dotnet new tool-manifest --force *>$null 2>&1
            & dotnet tool install $pkg --tool-path "$env:TEMP\$pkg" *>$null 2>&1
            $dotnetExe = "$env:TEMP\$pkg\7z.exe"
            if ((Test-Path $dotnetExe) -and (Test-RarSupport $dotnetExe)) {
                Copy-Item $dotnetExe $target
                $dll = "$env:TEMP\$pkg\7z.dll"
                if (Test-Path $dll) { Copy-Item $dll (Join-Path $targetDir "7z.dll") }
                Write-Host "Copied full 7z from dotnet tool $pkg"
                $foundFull = $true
                break
            }
        }
    } catch { Write-Host "    Failed: $_"; continue }
    if ($foundFull) { break }
}

if ($foundFull) { exit 0 }

# 3. Download extra package and extract full 7z.exe
Write-Host "Trying extra package download..."
try {
    $extraUrl = "https://www.7-zip.org/a/7z2601-extra.7z"
    $pkg = "$env:TEMP\7z-extra.7z"
    Invoke-WebRequest -Uri $extraUrl -OutFile $pkg

    $extractors = @(
        "${env:ProgramFiles}\7-Zip\7z.exe",
        "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
    )
    foreach ($exe in $extractors) {
        $dest = "$env:TEMP\7z-extracted"
        try {
            & $exe x $pkg -o"$dest" -y *>$null 2>&1
            $fullExe = Join-Path $dest "x64\7z.exe"
            $fullDll = Join-Path $dest "x64\7z.dll"
            if ((Test-Path $fullExe) -and (Test-RarSupport $fullExe)) {
                Copy-Item $fullExe $target
                if (Test-Path $fullDll) { Copy-Item $fullDll (Join-Path $targetDir "7z.dll") }
                Write-Host "Extracted full 7z from extra package"
                Remove-Item -Recurse -Force $dest -ErrorAction SilentlyContinue
                exit 0
            }
        } catch { continue }
    }
} catch { Write-Host "Extra package failed: $_" }

# 4. Placeholder
Set-Content -Path $target -Value "PLACEHOLDER"
Write-Host "============================================"
Write-Host "WARNING: Could not obtain full 7z.exe with RAR support."
Write-Host "RAR/CAB/ISO extraction will use probe fallback."
Write-Host "Place 7z.exe + 7z.dll in: $targetDir"
Write-Host "Install 7-Zip from: https://www.7-zip.org/"
Write-Host "============================================"
