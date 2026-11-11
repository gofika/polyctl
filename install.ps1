# polyctl installer for Windows.
#
#   irm https://raw.githubusercontent.com/gofika/polyctl/main/install.ps1 | iex
#
# Environment:
#   POLYCTL_VERSION      version to install (e.g. 0.3.0 or v0.3.0); default: latest release
#   POLYCTL_INSTALL_DIR  directory for polyctl.exe; default: %LOCALAPPDATA%\polyctl\bin

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'gofika/polyctl'
    $baseUrl = if ($env:POLYCTL_BASE_URL) { $env:POLYCTL_BASE_URL } else { "https://github.com/$repo" }

    # The machine-level value is the real architecture even when this process is
    # emulated (x64 PowerShell on ARM64 Windows reports AMD64 in its environment).
    $procArch = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -ErrorAction SilentlyContinue).PROCESSOR_ARCHITECTURE
    if (-not $procArch) {
        $procArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    }
    switch ($procArch) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw "Unsupported architecture: $procArch" }
    }

    $tag = $env:POLYCTL_VERSION
    if (-not $tag) {
        # Follow the /releases/latest redirect instead of the rate-limited API.
        $request = [Net.HttpWebRequest]::Create("$baseUrl/releases/latest")
        $request.Method = 'HEAD'
        $request.AllowAutoRedirect = $true
        $request.UserAgent = 'polyctl-install'
        $response = $request.GetResponse()
        try { $finalUrl = $response.ResponseUri.AbsoluteUri } finally { $response.Close() }
        if ($finalUrl -notmatch '/releases/tag/([^/]+)$') {
            throw "Could not determine the latest release (is one published at $baseUrl/releases?)"
        }
        $tag = $Matches[1]
    }
    if (-not $tag.StartsWith('v')) { $tag = "v$tag" }
    $version = $tag.Substring(1)

    $installDir = if ($env:POLYCTL_INSTALL_DIR) { $env:POLYCTL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'polyctl\bin' }
    $archive = "polyctl_${version}_windows_${arch}.zip"
    $url = "$baseUrl/releases/download/$tag"

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("polyctl-install-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "Downloading polyctl $version (windows/$arch)..."
        Invoke-WebRequest -UseBasicParsing -Uri "$url/$archive" -OutFile (Join-Path $tmp $archive)
        Invoke-WebRequest -UseBasicParsing -Uri "$url/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt')

        $want = $null
        foreach ($line in Get-Content (Join-Path $tmp 'checksums.txt')) {
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $archive) { $want = $parts[0].ToLowerInvariant() }
        }
        if (-not $want) { throw "$archive is not listed in checksums.txt" }
        $got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $archive)).Hash.ToLowerInvariant()
        if ($want -ne $got) { throw "Checksum mismatch for $archive (expected $want, got $got)" }

        Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath (Join-Path $tmp 'out') -Force
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        $target = Join-Path $installDir 'polyctl.exe'
        # A running polyctl.exe cannot be overwritten, but it can be renamed.
        if (Test-Path $target) {
            $old = "$target.old"
            Remove-Item $old -Force -ErrorAction SilentlyContinue
            Move-Item $target $old -Force
        }
        Copy-Item (Join-Path $tmp 'out\polyctl.exe') $target -Force
        Remove-Item "$target.old" -Force -ErrorAction SilentlyContinue
    }
    finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "Installed $target"
    & $target --version

    # Read and write the registry value directly: the .NET environment API
    # expands %VAR% entries on read and would write them back expanded.
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
        $userPath = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind = if ($key.GetValueNames() -contains 'Path') { $key.GetValueKind('Path') } else { [Microsoft.Win32.RegistryValueKind]::ExpandString }
        # @() keeps a single entry an array, so the append below never turns
        # into string concatenation.
        $entries = @()
        if ($userPath) { $entries = @($userPath -split ';' | Where-Object { $_ }) }
        $known = @($entries | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') })
        if ($known -notcontains $installDir.TrimEnd('\')) {
            $key.SetValue('Path', (($entries + $installDir) -join ';'), $kind)
            # A registry write is not announced to running programs. Deleting a
            # variable that does not exist makes .NET broadcast WM_SETTINGCHANGE.
            [Environment]::SetEnvironmentVariable('POLYCTL_PATH_REFRESH', $null, 'User')
            $env:Path = "$env:Path;$installDir"
            Write-Host "Added $installDir to your user PATH. Open a new terminal to use polyctl everywhere."
        }
    }
    finally {
        $key.Close()
    }
}
