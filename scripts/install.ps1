# Installs ogl (og-local) on Windows.
# Usage: irm https://raw.githubusercontent.com/outgate-ai/og-local/main/scripts/install.ps1 | iex
#
# Env overrides:
#   OGL_VERSION       tag to install (default: latest)
#   OGL_DOWNLOAD_URL  base URL for archives (default: GitHub releases)
#   OGL_INSTALL_DIR   where to install (default: %LOCALAPPDATA%\Programs\ogl)
#   OGL_CACHE_DIR     cache dir for the bundled runtime lib (matches the binary)

function Install-Ogl {
    $ErrorActionPreference = 'Stop'
    $Repo = 'outgate-ai/og-local'
    $BaseUrl = if ($env:OGL_DOWNLOAD_URL) { $env:OGL_DOWNLOAD_URL } else { "https://github.com/$Repo/releases" }

    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($arch -ne 'AMD64') {
        throw "Unsupported architecture: $arch. Only windows/amd64 is supported."
    }

    $Version = if ($env:OGL_VERSION) { $env:OGL_VERSION } else { 'latest' }
    if ($Version -eq 'latest') {
        $Version = (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest").tag_name
        if (-not $Version) { throw 'Could not resolve the latest release tag.' }
    }
    $Num = $Version.TrimStart('v')
    $Archive = "ogl_${Num}_windows_amd64.zip"
    $Url = if ($env:OGL_DOWNLOAD_URL) { "$BaseUrl/$Archive" } else { "$BaseUrl/download/$Version/$Archive" }

    $Temp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $Temp | Out-Null
    try {
        Write-Host ">>> Downloading ogl $Version for windows/amd64..."
        $Zip = Join-Path $Temp $Archive
        Invoke-WebRequest -Uri $Url -OutFile $Zip

        $InstallDir = if ($env:OGL_INSTALL_DIR) { $env:OGL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\ogl' }
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        Expand-Archive -Path $Zip -DestinationPath $InstallDir -Force

        # Place the bundled ONNX Runtime where ogl looks for it. Mirrors the
        # binary's cache precedence: OGL_CACHE_DIR > XDG_CACHE_HOME\og-local >
        # ~\.cache\og-local.
        $Cache = if ($env:OGL_CACHE_DIR) { $env:OGL_CACHE_DIR }
        elseif ($env:XDG_CACHE_HOME) { Join-Path $env:XDG_CACHE_HOME 'og-local' }
        else { Join-Path $env:USERPROFILE '.cache\og-local' }
        $RtDir = Join-Path $Cache 'runtime\windows-amd64'
        New-Item -ItemType Directory -Force -Path $RtDir | Out-Null
        Copy-Item (Join-Path $InstallDir 'lib\onnxruntime.dll') (Join-Path $RtDir 'onnxruntime.dll') -Force
        Write-Host ">>> Placed ONNX Runtime at $RtDir\onnxruntime.dll"

        # Alias binaries: ogl dispatches on its invoked name, so ogl-claude.exe /
        # ogl-codex.exe run that agent through the proxy — handy for IDE settings
        # that take a single executable path. Hardlink when the volume allows it,
        # else copy.
        foreach ($Alias in 'ogl-claude.exe', 'ogl-codex.exe') {
            $AliasPath = Join-Path $InstallDir $Alias
            Remove-Item $AliasPath -Force -ErrorAction SilentlyContinue
            try {
                New-Item -ItemType HardLink -Path $AliasPath -Target (Join-Path $InstallDir 'ogl.exe') | Out-Null
            } catch {
                Copy-Item (Join-Path $InstallDir 'ogl.exe') $AliasPath -Force
            }
        }

        # Add the install dir to the user PATH if it isn't there yet.
        $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (($UserPath -split ';') -notcontains $InstallDir) {
            [Environment]::SetEnvironmentVariable('Path', "$UserPath;$InstallDir", 'User')
            Write-Host ">>> Added $InstallDir to your user PATH (restart the terminal to pick it up)."
        }

        & (Join-Path $InstallDir 'ogl.exe') version
        Write-Host ''
        Write-Host 'ogl installed!'
        Write-Host ''
        Write-Host 'Next:'
        Write-Host '  ogl model pull          Download the detection model (~800MB, one-time)'
        Write-Host '  ogl claude "..."        Run Claude through the local privacy proxy'
        Write-Host '  ogl codex "..."         Run Codex through the local privacy proxy'
    }
    finally {
        Remove-Item -Recurse -Force $Temp -ErrorAction SilentlyContinue
    }
}

Install-Ogl
