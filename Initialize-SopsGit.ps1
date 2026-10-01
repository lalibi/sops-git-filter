<#
.SYNOPSIS
    Sets up transparent SOPS + age encryption for Git repositories on Windows.

.DESCRIPTION
    This script implements a git-crypt-like workflow using:
      - SOPS for file encryption/decryption
      - age for key management
      - Git clean/smudge filters for transparent working-tree plaintext
      - a pre-commit validator that refuses plaintext protected blobs
      - a repository bootstrap script for fresh clones/worktrees

    Supported modes:
      Initialize       Configure a repository for the first time.
      Join             Prepare a fresh clone/new machine and decrypt the working tree.
      AddRecipient     Add one or more age public recipients and re-encrypt tracked protected blobs.
      MigrateGitCrypt  Replace git-crypt attributes with SOPS and stage the current plaintext files.

    The script is intentionally Windows-first. It requires PowerShell 7.4+ for the generated
    repository tooling. It can install/upgrade Git, age and SOPS when missing.

.EXAMPLE
    .\Initialize-SopsGit.ps1 -Mode Initialize -ProtectedPath @(
        'secrets',
        'appsettings.json',
        'src/Web/appsettings.Production.json'
    )

.EXAMPLE
    .\.githooks\Initialize-SopsGit.ps1 -Mode Join -AgeKeySource 'E:\secure\sops-age-keys.txt'

.EXAMPLE
    .\.githooks\Initialize-SopsGit.ps1 -Mode AddRecipient `
        -AdditionalAgeRecipient 'age1...'

.EXAMPLE
    .\Initialize-SopsGit.ps1 -Mode MigrateGitCrypt -ProtectedPath @(
        'secrets',
        'appsettings.json'
    )

.NOTES
    Private age keys are never written to the repository.
    Review all staged changes before committing.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Initialize', 'Join', 'AddRecipient', 'MigrateGitCrypt')]
    [string] $Mode = 'Initialize',

    [string] $RepoPath = '.',

    [string[]] $ProtectedPath = @('secrets/'),

    [string[]] $AdditionalAgeRecipient = @(),

    [string] $AgeKeySource,

    [bool] $InstallMissing = $true,

    [string] $SopsVersion = '3.13.3',

    [string] $AgeVersion = '1.3.2',

    [switch] $NoStage,

    [switch] $RemoveGitCryptMetadata,

    [switch] $Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$MinimumGitVersion = [version]'2.55.0'
$MinimumPowerShellVersion = [version]'7.4.0'
$ManagedSopsMarker = '# Managed by Initialize-SopsGit.ps1'
$AttributesBegin = '# BEGIN SOPS TRANSPARENT ENCRYPTION'
$AttributesEnd = '# END SOPS TRANSPARENT ENCRYPTION'

function Write-Info {
    param([string] $Message)
    Write-Host "[INFO] $Message"
}

function Write-Ok {
    param([string] $Message)
    Write-Host "[ OK ] $Message"
}

function Write-Warn {
    param([string] $Message)
    Write-Warning $Message
}

function Assert-Windows {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This bootstrap script is Windows-first and currently supports Windows only.'
    }
}

function Refresh-ProcessPath {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machinePath;$userPath"
}

function Add-UserPathEntry {
    param(
        [Parameter(Mandatory)]
        [string] $Directory
    )

    $full = [IO.Path]::GetFullPath($Directory)
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')

    if ([string]::IsNullOrWhiteSpace($current)) {
        [Environment]::SetEnvironmentVariable('Path', $full, 'User')
    }
    else {
        $entries = $current -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if (-not ($entries | Where-Object { [IO.Path]::GetFullPath($_) -eq $full })) {
            [Environment]::SetEnvironmentVariable(
                'Path',
                (($entries + $full) -join ';'),
                'User'
            )
        }
    }

    Refresh-ProcessPath
}

function Get-Application {
    param([Parameter(Mandatory)][string] $Name)

    Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

function Get-CommandVersion {
    param(
        [Parameter(Mandatory)]
        [string] $Command,

        [Parameter(Mandatory)]
        [string[]] $Arguments
    )

    $rawOutput = @(
        & $Command @Arguments 2>$null
    )

    $commandSucceeded = $?

    if (-not $commandSucceeded -or $rawOutput.Count -eq 0) {
        return $null
    }

    $output = [string](
        $rawOutput |
            Select-Object -First 1
    )

    if ([string]::IsNullOrWhiteSpace($output)) {
        return $null
    }

    $match = [regex]::Match(
        $output,
        '\d+(?:\.\d+){1,3}'
    )

    if (-not $match.Success) {
        return $null
    }

    try {
        return [version] $match.Value
    }
    catch {
        return $null
    }
}

function Get-Winget {
    Get-Application -Name 'winget'
}

function Invoke-WingetInstall {
    param(
        [Parameter(Mandatory)]
        [string] $Id,
        [switch] $Upgrade
    )

    $winget = Get-Winget
    if ($null -eq $winget) {
        return $false
    }

    $verb = if ($Upgrade) { 'upgrade' } else { 'install' }

    Write-Info "$verb $Id using winget"

    & $winget.Path `
        $verb `
        --id $Id `
        -e `
        --source winget `
        --accept-source-agreements `
        --accept-package-agreements `
        --silent

    if ($LASTEXITCODE -ne 0) {
        Write-Warn "winget $verb failed for '$Id'."
        return $false
    }

    Refresh-ProcessPath
    return $true
}

function Ensure-PowerShell {
    $current = $PSVersionTable.PSVersion

    if ($PSVersionTable.PSEdition -eq 'Core' -and $current -ge $MinimumPowerShellVersion) {
        Write-Ok "PowerShell $current"
        return
    }

    if (-not $InstallMissing) {
        throw "PowerShell $MinimumPowerShellVersion or newer is required."
    }

    Write-Warn "PowerShell $MinimumPowerShellVersion+ is required by the repository tooling."

    if (-not (Invoke-WingetInstall -Id 'Microsoft.PowerShell' -Upgrade)) {
        throw 'Could not install PowerShell 7 automatically. Install PowerShell 7.4+ and rerun this script with pwsh.'
    }

    $pwsh = Get-Application -Name 'pwsh'
    if ($null -eq $pwsh) {
        $fallback = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
        if (Test-Path $fallback) {
            $pwsh = Get-Item $fallback
        }
    }

    if ($null -eq $pwsh) {
        throw 'PowerShell 7 was installed but pwsh.exe could not be located. Open a new terminal and rerun the script.'
    }

    throw "PowerShell 7 was installed/upgraded. Rerun this script using: pwsh -File `"$PSCommandPath`" ..."
}

function Ensure-Git {
    $git = Get-Application -Name 'git'
    $version = $null

    if ($null -ne $git) {
        $version = Get-CommandVersion -Command $git.Path -Arguments @('--version')
    }

    if ($null -ne $version -and $version -ge $MinimumGitVersion) {
        Write-Ok "Git $version"
        return $git.Path
    }

    if (-not $InstallMissing) {
        throw "Git $MinimumGitVersion+ is required."
    }

    if ($null -eq $git) {
        Write-Info 'Git is missing.'
        if (-not (Invoke-WingetInstall -Id 'Git.Git')) {
            throw 'Could not install Git automatically.'
        }
    }
    else {
        Write-Info "Git $version is older than the required $MinimumGitVersion."
        if (-not (Invoke-WingetInstall -Id 'Git.Git' -Upgrade)) {
            throw 'Could not upgrade Git automatically.'
        }
    }

    $git = Get-Application -Name 'git'

    if ($null -eq $git) {
        $fallback = 'C:\Program Files\Git\cmd\git.exe'
        if (Test-Path $fallback) {
            return $fallback
        }

        throw 'git.exe could not be located after installation.'
    }

    $version = Get-CommandVersion -Command $git.Path -Arguments @('--version')
    if ($null -eq $version -or $version -lt $MinimumGitVersion) {
        throw "Git $MinimumGitVersion+ is required. Installed version: $version"
    }

    Write-Ok "Git $version"
    return $git.Path
}

function Get-NativeArchitectureName {
    $arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()

    switch ($arch) {
        'X64'   { return 'amd64' }
        'Arm64' { return 'arm64' }
        default { throw "Unsupported Windows architecture: $arch" }
    }
}

function Invoke-VerifiedGitHubAssetDownload {
    param(
        [Parameter(Mandatory)]
        [string] $Repository,
        [Parameter(Mandatory)]
        [string] $Tag,
        [Parameter(Mandatory)]
        [string] $AssetName,
        [Parameter(Mandatory)]
        [string] $Destination
    )

    $api = "https://api.github.com/repos/$Repository/releases/tags/$Tag"
    $headers = @{
        'User-Agent' = 'Initialize-SopsGit.ps1'
        'Accept' = 'application/vnd.github+json'
    }

    Write-Info "Reading release metadata: $Repository $Tag"
    $release = Invoke-RestMethod -Uri $api -Headers $headers

    $asset = $release.assets |
        Where-Object { $_.name -eq $AssetName } |
        Select-Object -First 1

    if ($null -eq $asset) {
        throw "Release asset '$AssetName' was not found in $Repository $Tag."
    }

    Invoke-WebRequest `
        -Uri $asset.browser_download_url `
        -Headers $headers `
        -OutFile $Destination

    if ($asset.PSObject.Properties.Name -contains 'digest' -and
        -not [string]::IsNullOrWhiteSpace($asset.digest) -and
        $asset.digest -match '^sha256:(?<hash>[0-9a-fA-F]{64})$') {

        $expected = $Matches.hash.ToLowerInvariant()
        $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()

        if ($expected -ne $actual) {
            Remove-Item $Destination -Force -ErrorAction SilentlyContinue
            throw "SHA256 verification failed for '$AssetName'."
        }

        Write-Ok "SHA256 verified: $AssetName"
    }
    else {
        Write-Warn "GitHub release metadata did not expose a SHA256 digest for '$AssetName'. HTTPS was used, but no local hash comparison was possible."
    }
}

function Install-AgeDirect {
    $arch = Get-NativeArchitectureName
    $tag = "v$AgeVersion"
    $assetName = "age-v$AgeVersion-windows-$arch.zip"

    $installDir = Join-Path $env:LOCALAPPDATA 'Programs\age'
    $tempDir = Join-Path ([IO.Path]::GetTempPath()) ("age-install-" + [guid]::NewGuid())
    $zip = Join-Path $tempDir $assetName

    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null

    try {
        Invoke-VerifiedGitHubAssetDownload `
            -Repository 'FiloSottile/age' `
            -Tag $tag `
            -AssetName $assetName `
            -Destination $zip

        Expand-Archive -LiteralPath $zip -DestinationPath $tempDir -Force

        $ageExe = Get-ChildItem $tempDir -Filter age.exe -File -Recurse |
            Select-Object -First 1
        $ageKeygenExe = Get-ChildItem $tempDir -Filter age-keygen.exe -File -Recurse |
            Select-Object -First 1

        if ($null -eq $ageExe -or $null -eq $ageKeygenExe) {
            throw 'Downloaded age archive did not contain age.exe and age-keygen.exe.'
        }

        Copy-Item $ageExe.FullName (Join-Path $installDir 'age.exe') -Force
        Copy-Item $ageKeygenExe.FullName (Join-Path $installDir 'age-keygen.exe') -Force

        Add-UserPathEntry -Directory $installDir
    }
    finally {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Ensure-Age {
    $age = Get-Application -Name 'age'
    $ageKeygen = Get-Application -Name 'age-keygen'

    if ($null -ne $age -and $null -ne $ageKeygen) {
        $version = Get-CommandVersion -Command $age.Path -Arguments @('--version')
        Write-Ok "age $version"
        return @{
            Age = $age.Path
            Keygen = $ageKeygen.Path
        }
    }

    if (-not $InstallMissing) {
        throw 'age and age-keygen are required.'
    }

    if (-not (Invoke-WingetInstall -Id 'FiloSottile.age')) {
        Write-Warn 'winget installation of age failed; falling back to the official GitHub release.'
        Install-AgeDirect
    }

    Refresh-ProcessPath
    $age = Get-Application -Name 'age'
    $ageKeygen = Get-Application -Name 'age-keygen'

    if ($null -eq $age -or $null -eq $ageKeygen) {
        throw 'age installation completed but age.exe / age-keygen.exe could not be located.'
    }

    $version = Get-CommandVersion -Command $age.Path -Arguments @('--version')
    Write-Ok "age $version"

    return @{
        Age = $age.Path
        Keygen = $ageKeygen.Path
    }
}

function Install-SopsDirect {
    $arch = Get-NativeArchitectureName
    $tag = "v$SopsVersion"
    $assetName = "sops-v$SopsVersion.$arch.exe"

    $installDir = Join-Path $env:LOCALAPPDATA 'Programs\SOPS'
    $destination = Join-Path $installDir 'sops.exe'

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null

    Invoke-VerifiedGitHubAssetDownload `
        -Repository 'getsops/sops' `
        -Tag $tag `
        -AssetName $assetName `
        -Destination $destination

    Add-UserPathEntry -Directory $installDir
}

function Ensure-Sops {
    $sops = Get-Application -Name 'sops'

    if ($null -eq $sops) {
        $fallback = Join-Path $env:LOCALAPPDATA 'Programs\SOPS\sops.exe'
        if (Test-Path $fallback) {
            $sops = Get-Item $fallback
        }
    }

    if ($null -eq $sops) {
        if (-not $InstallMissing) {
            throw 'sops.exe is required.'
        }

        Install-SopsDirect
        Refresh-ProcessPath
        $sops = Get-Application -Name 'sops'

        if ($null -eq $sops) {
            $fallback = Join-Path $env:LOCALAPPDATA 'Programs\SOPS\sops.exe'
            if (Test-Path $fallback) {
                $sops = Get-Item $fallback
            }
        }
    }

    if ($null -eq $sops) {
        throw 'sops.exe could not be located.'
    }

    $sopsPath = $null

    if ($sops.PSObject.Properties.Name -contains 'Path' -and
        -not [string]::IsNullOrWhiteSpace([string]$sops.Path)) {
        $sopsPath = [string]$sops.Path
    }
    elseif ($sops.PSObject.Properties.Name -contains 'FullName' -and
            -not [string]::IsNullOrWhiteSpace([string]$sops.FullName)) {
        $sopsPath = [string]$sops.FullName
    }

    if ([string]::IsNullOrWhiteSpace($sopsPath)) {
        throw 'sops.exe was found but its executable path could not be determined.'
    }

    $version = Get-CommandVersion -Command $sopsPath -Arguments @('--version')

    Write-Ok "SOPS $version"
    return $sopsPath
}

function Get-StandardAgeKeyFile {
    Join-Path $env:APPDATA 'sops\age\keys.txt'
}

function Protect-AgeKeyAcl {
    param([Parameter(Mandatory)][string] $Path)

    if (-not (Test-Path $Path)) {
        return
    }

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls.exe $Path '/inheritance:r' | Out-Null
        & icacls.exe $Path '/grant:r' "${identity}:(F)" | Out-Null
        Write-Ok 'Restricted ACL on the age private-key file.'
    }
    catch {
        Write-Warn "Could not restrict the age key ACL automatically: $($_.Exception.Message)"
    }
}

function Import-AgeIdentity {
    param(
        [Parameter(Mandatory)]
        [string] $Source,
        [Parameter(Mandatory)]
        [string] $Destination
    )

    $resolved = (Resolve-Path -LiteralPath $Source).Path
    $lines = Get-Content -LiteralPath $resolved

    $secretLines = @(
        $lines | Where-Object { $_ -match '^AGE-SECRET-KEY-' }
    )

    if ($secretLines.Count -eq 0) {
        throw "No AGE-SECRET-KEY identity was found in '$Source'."
    }

    $directory = Split-Path $Destination -Parent
    New-Item -ItemType Directory -Force -Path $directory | Out-Null

    $existing = @()
    if (Test-Path $Destination) {
        $existing = @(Get-Content -LiteralPath $Destination)
    }

    $merged = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $existing) {
        $merged.Add($line)
    }

    foreach ($line in $secretLines) {
        if ($existing -notcontains $line) {
            if ($merged.Count -gt 0 -and $merged[$merged.Count - 1] -ne '') {
                $merged.Add('')
            }
            $merged.Add($line)
        }
    }

    Set-Content -LiteralPath $Destination -Value $merged -Encoding utf8NoBOM
    Protect-AgeKeyAcl -Path $Destination
}

function Ensure-AgeIdentity {
    param(
        [Parameter(Mandatory)]
        [string] $AgeKeygen,
        [switch] $AllowGenerate
    )

    $keyFile = Get-StandardAgeKeyFile

    if (-not [string]::IsNullOrWhiteSpace($AgeKeySource)) {
        Write-Info "Importing age identity from '$AgeKeySource'."
        Import-AgeIdentity -Source $AgeKeySource -Destination $keyFile
    }

    if (-not (Test-Path $keyFile)) {
        if (-not $AllowGenerate) {
            return $null
        }

        $directory = Split-Path $keyFile -Parent
        New-Item -ItemType Directory -Force -Path $directory | Out-Null

        Write-Info "Generating an age identity at '$keyFile'."
        & $AgeKeygen -o $keyFile

        if ($LASTEXITCODE -ne 0) {
            throw 'age-keygen failed.'
        }

        Protect-AgeKeyAcl -Path $keyFile
    }

    $recipient = (& $AgeKeygen -y $keyFile | Select-Object -First 1).Trim()
    if ($LASTEXITCODE -ne 0 -or $recipient -notmatch '^age1') {
        throw 'Could not derive the age public recipient from the local identity.'
    }

    return @{
        KeyFile = $keyFile
        Recipient = $recipient
    }
}

function Resolve-Repository {
    param(
        [Parameter(Mandatory)][string] $GitExe,
        [Parameter(Mandatory)][string] $Path
    )

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $root = (& $GitExe -C $resolved rev-parse --show-toplevel 2>$null | Select-Object -First 1)

    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($root)) {
        throw "'$resolved' is not inside a Git working tree."
    }

    return $root.Trim()
}

function Assert-CleanTrackedWorkingTree {
    param(
        [Parameter(Mandatory)][string] $GitExe,
        [Parameter(Mandatory)][string] $Root
    )

    $dirty = @(& $GitExe -C $Root status --porcelain --untracked-files=no)

    if ($dirty.Count -gt 0) {
        throw 'Tracked files have uncommitted changes. Commit or stash them before running this operation.'
    }
}

function Normalize-RelativeProtectedPath {
    param([Parameter(Mandatory)][string] $Path)

    $p = $Path.Trim().Replace('\', '/')
    $p = $p.TrimStart('/').TrimEnd('/')

    if ([string]::IsNullOrWhiteSpace($p)) {
        throw "Invalid protected path '$Path'."
    }

    if ($p -match '(^|/)\.\.($|/)' -or $p -match '[*?\[]') {
        throw "ProtectedPath accepts exact file or directory paths only, not '..' or glob patterns: '$Path'."
    }

    return $p
}

function Convert-PathToRegex {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][bool] $IsDirectory
    )

    $segments = $Path -split '/'
    $escaped = @($segments | ForEach-Object { [regex]::Escape($_) })
    $joined = $escaped -join '[\\/]'

    if ($IsDirectory) {
        return "$joined[\\/].*"
    }

    return $joined
}

function Get-ProtectedSpecifications {
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string[]] $Paths
    )

    $result = [System.Collections.Generic.List[object]]::new()

    foreach ($raw in $Paths) {
        $relative = Normalize-RelativeProtectedPath -Path $raw
        $absolute = Join-Path $Root ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))

        $isDirectory = $false

        if (Test-Path -LiteralPath $absolute -PathType Container) {
            $isDirectory = $true
        }
        elseif ($raw.EndsWith('/') -or $raw.EndsWith('\')) {
            $isDirectory = $true
        }

        $attributePattern = if ($isDirectory) {
            "/$relative/**"
        }
        else {
            "/$relative"
        }

        $result.Add([pscustomobject]@{
            RelativePath = $relative
            IsDirectory = $isDirectory
            AttributePattern = $attributePattern
            RegexPart = Convert-PathToRegex -Path $relative -IsDirectory $isDirectory
        })
    }

    return $result
}

function Update-ManagedGitAttributes {
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][object[]] $Specifications,
        [switch] $MigrateGitCryptRules
    )

    $path = Join-Path $Root '.gitattributes'
    $lines = @()

    if (Test-Path $path) {
        $lines = @(Get-Content -LiteralPath $path)
    }

    if ($MigrateGitCryptRules) {
        $rewritten = [System.Collections.Generic.List[string]]::new()

        foreach ($line in $lines) {
            if ($line -match 'filter=git-crypt(?:-[^\s]+)?') {
                $newLine = $line
                $newLine = [regex]::Replace($newLine, 'filter=git-crypt(?:-[^\s]+)?', 'filter=sops')
                $newLine = [regex]::Replace($newLine, '\s+diff=git-crypt(?:-[^\s]+)?', '')
                if ($newLine -notmatch '(^|\s)-text(\s|$)') {
                    $newLine += ' -text'
                }
                $rewritten.Add($newLine)
            }
            else {
                $rewritten.Add($line)
            }
        }

        $lines = @($rewritten)
    }

    $beginIndex = [Array]::IndexOf($lines, $AttributesBegin)
    $endIndex = [Array]::IndexOf($lines, $AttributesEnd)

    if (($beginIndex -ge 0) -xor ($endIndex -ge 0)) {
        throw 'The managed .gitattributes block is malformed.'
    }

    if ($beginIndex -ge 0 -and $endIndex -lt $beginIndex) {
        throw 'The managed .gitattributes block is malformed.'
    }

    $managed = [System.Collections.Generic.List[string]]::new()
    $managed.Add($AttributesBegin)

    # Repository tooling is generated with LF line endings.
    # Make this explicit so Git does not apply core.autocrlf to the scripts.
    $managed.Add('/.githooks/*.ps1 text eol=lf')
    $managed.Add('')

    foreach ($spec in $Specifications) {
        $managed.Add("$($spec.AttributePattern) filter=sops -text")
    }

    $managed.Add($AttributesEnd)

    $output = [System.Collections.Generic.List[string]]::new()

    if ($beginIndex -ge 0) {
        for ($i = 0; $i -lt $beginIndex; $i++) {
            $output.Add($lines[$i])
        }

        foreach ($line in $managed) {
            $output.Add($line)
        }

        for ($i = $endIndex + 1; $i -lt $lines.Count; $i++) {
            $output.Add($lines[$i])
        }
    }
    else {
        foreach ($line in $lines) {
            $output.Add($line)
        }

        if ($output.Count -gt 0 -and $output[$output.Count - 1] -ne '') {
            $output.Add('')
        }

        foreach ($line in $managed) {
            $output.Add($line)
        }
    }

    Set-Content -LiteralPath $path -Value $output -Encoding utf8NoBOM
}

function Get-ManagedSopsData {
    param([Parameter(Mandatory)][string] $Path)

    if (-not (Test-Path $Path)) {
        return $null
    }

    $lines = @(Get-Content -LiteralPath $Path)

    if ($lines.Count -eq 0 -or $lines[0] -ne $ManagedSopsMarker) {
        return $null
    }

    $protected = @(
        $lines |
            Where-Object { $_ -match '^# protected-path:\s*(.+)$' } |
            ForEach-Object {
                if ($_ -match '^# protected-path:\s*(.+)$') {
                    $Matches[1].Trim()
                }
            }
    )

    $recipients = @(
        $lines |
            Where-Object { $_ -match '^\s*-\s+(age1[0-9a-z]+)\s*$' } |
            ForEach-Object {
                if ($_ -match '^\s*-\s+(age1[0-9a-z]+)\s*$') {
                    $Matches[1]
                }
            }
    )

    return @{
        ProtectedPath = $protected
        Recipients = $recipients
    }
}

function Write-ManagedSopsConfig {
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][object[]] $Specifications,
        [Parameter(Mandatory)][string[]] $Recipients
    )

    $path = Join-Path $Root '.sops.yaml'

    if (Test-Path $path) {
        $existing = @(Get-Content -LiteralPath $path)
        $isManaged = $existing.Count -gt 0 -and $existing[0] -eq $ManagedSopsMarker

        if (-not $isManaged -and -not $Force) {
            throw ".sops.yaml already exists and was not generated by this script. Refusing to overwrite it. Merge the creation_rules manually or rerun with -Force after taking a backup."
        }

        if (-not $isManaged -and $Force) {
            $backup = "$path.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
            Copy-Item -LiteralPath $path -Destination $backup
            Write-Warn "Backed up the existing .sops.yaml to '$backup'."
        }
    }

    $regexParts = @($Specifications | ForEach-Object { $_.RegexPart })
    $combinedRegex = '^(?:' + ($regexParts -join '|') + ')$'

    $content = [System.Collections.Generic.List[string]]::new()
    $content.Add($ManagedSopsMarker)

    foreach ($spec in $Specifications) {
        $content.Add("# protected-path: $($spec.RelativePath)")
    }

    $content.Add('creation_rules:')
    $content.Add("  - path_regex: '$combinedRegex'")
    $content.Add('    age:')

    foreach ($recipient in ($Recipients | Sort-Object -Unique)) {
        $content.Add("      - $recipient")
    }

    Set-Content -LiteralPath $path -Value $content -Encoding utf8NoBOM
}

function Get-FilterScriptContent {
@'
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('clean', 'smudge')]
    [string] $Mode,

    [Parameter(Mandatory, Position = 1)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Read-StdInBytes {
    $inputStream = [Console]::OpenStandardInput()
    $memory = [IO.MemoryStream]::new()

    try {
        $inputStream.CopyTo($memory)
        return ,$memory.ToArray()
    }
    finally {
        $memory.Dispose()
    }
}

function Write-StdOutBytes {
    param([Parameter(Mandatory)][byte[]] $Bytes)

    $outputStream = [Console]::OpenStandardOutput()
    $outputStream.Write($Bytes, 0, $Bytes.Length)
    $outputStream.Flush()
}

function Invoke-ByteProcess {
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter(Mandatory)]
        [string[]] $Arguments,

        [byte[]] $InputBytes = [byte[]]::new(0)
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    foreach ($argument in $Arguments) {
        [void] $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo

    $stdout = [System.IO.MemoryStream]::new()

    [int] $exitCode = -1
    [byte[]] $stdoutBytes = [byte[]]::new(0)
    [string] $stderr = ''

    try {
        [bool] $started = $process.Start()

        if (-not $started) {
            throw "Could not start '$FilePath'."
        }

        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.ReadToEndAsync()

        if ($InputBytes.Length -gt 0) {
            [void] $process.StandardInput.BaseStream.Write(
                $InputBytes,
                0,
                $InputBytes.Length
            )
        }

        [void] $process.StandardInput.Close()
        [void] $process.WaitForExit()

        [void] $stdoutTask.GetAwaiter().GetResult()

        $stderr = [string] $stderrTask.GetAwaiter().GetResult()

        $exitCode = [int] $process.ExitCode
        $stdoutBytes = [byte[]] $stdout.ToArray()
    }
    finally {
        [void] $stdout.Dispose()
        [void] $process.Dispose()
    }

    return [pscustomobject] @{
        ExitCode = $exitCode
        StdOut   = $stdoutBytes
        StdErr   = $stderr
    }
}

function Test-ByteArrayEqual {
    param(
        [Parameter(Mandatory)][byte[]] $Left,
        [Parameter(Mandatory)][byte[]] $Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }

    $leftHash = [Security.Cryptography.SHA256]::HashData($Left)
    $rightHash = [Security.Cryptography.SHA256]::HashData($Right)

    return [Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
        $leftHash,
        $rightHash
    )
}

function Resolve-SopsExecutable {
    $command = Get-Command sops -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($null -ne $command) {
        return [string]$command.Path
    }

    $fallback = Join-Path $env:LOCALAPPDATA 'Programs\SOPS\sops.exe'

    if (Test-Path $fallback) {
        return [string]$fallback
    }

    throw 'sops.exe was not found.'
}

function Resolve-GitExecutable {
    $command = Get-Command git -CommandType Application -ErrorAction Stop |
        Select-Object -First 1

    return [string]$command.Path
}

function Get-SopsTypes {
    param([Parameter(Mandatory)][string] $Path)

    switch ([IO.Path]::GetExtension($Path).ToLowerInvariant()) {
        '.json' { return @{ Plain = 'json';   Encrypted = 'json' } }
        '.yaml' { return @{ Plain = 'yaml';   Encrypted = 'yaml' } }
        '.yml'  { return @{ Plain = 'yaml';   Encrypted = 'yaml' } }
        '.env'  { return @{ Plain = 'dotenv'; Encrypted = 'dotenv' } }
        '.ini'  { return @{ Plain = 'ini';    Encrypted = 'ini' } }
        default { return @{ Plain = 'binary'; Encrypted = 'json' } }
    }
}

try {
    $inputBytes = [byte[]](Read-StdInBytes)

    [string]$sops = Resolve-SopsExecutable
    [string]$git = Resolve-GitExecutable
    $types = Get-SopsTypes -Path $Path

    switch ($Mode) {
        'smudge' {
            $result = Invoke-ByteProcess `
                -FilePath $sops `
                -Arguments @(
                    'decrypt',
                    '--filename-override', $Path,
                    '--input-type', $types.Encrypted,
                    '--output-type', $types.Plain
                ) `
                -InputBytes $inputBytes

            if ($result.ExitCode -ne 0) {
                throw "SOPS decrypt failed for '$Path': $($result.StdErr)"
            }

            Write-StdOutBytes -Bytes $result.StdOut
            exit 0
        }

        'clean' {
            $indexResult = Invoke-ByteProcess `
                -FilePath $git `
                -Arguments @(
                    'cat-file',
                    'blob',
                    ":$Path"
                )

            if ($indexResult.ExitCode -eq 0) {
                # First determine whether the current index blob is actually
                # valid SOPS ciphertext.
                #
                # This distinction is important during first-time initialization:
                # before the file has ever been encrypted, both the working tree
                # and the current Git index may contain the same plaintext bytes.
                $decryptResult = Invoke-ByteProcess `
                    -FilePath $sops `
                    -Arguments @(
                        'decrypt',
                        '--filename-override', $Path,
                        '--input-type', $types.Encrypted,
                        '--output-type', $types.Plain
                    ) `
                    -InputBytes $indexResult.StdOut

                if ($decryptResult.ExitCode -eq 0) {
                    # The existing index blob is confirmed SOPS ciphertext.

                    # Case 1:
                    # Git is feeding the exact ciphertext back through clean.
                    # Preserve it verbatim instead of encrypting it again.
                    if (
                        Test-ByteArrayEqual `
                            -Left $inputBytes `
                            -Right $indexResult.StdOut
                    ) {
                        Write-StdOutBytes -Bytes $indexResult.StdOut
                        exit 0
                    }

                    # Case 2:
                    # The working plaintext has not changed.
                    #
                    # SOPS encryption is randomized, so generating fresh
                    # ciphertext here would make Git report a change on every
                    # git add. Reuse the existing ciphertext instead.
                    if (
                        Test-ByteArrayEqual `
                            -Left $inputBytes `
                            -Right $decryptResult.StdOut
                    ) {
                        Write-StdOutBytes -Bytes $indexResult.StdOut
                        exit 0
                    }
                }

                # If decrypt failed, the existing index blob is not SOPS
                # ciphertext. This is normal during first-time initialization.
                # Fall through and encrypt the incoming plaintext.
            }

            $encryptResult = Invoke-ByteProcess `
                -FilePath $sops `
                -Arguments @(
                    'encrypt',
                    '--filename-override', $Path,
                    '--input-type', $types.Plain,
                    '--output-type', $types.Encrypted
                ) `
                -InputBytes $inputBytes

            if ($encryptResult.ExitCode -ne 0) {
                throw "SOPS encrypt failed for '$Path': $($encryptResult.StdErr)"
            }

            Write-StdOutBytes -Bytes $encryptResult.StdOut
            exit 0
        }
    }
}
catch {
    [Console]::Error.WriteLine(
        "git-sops-filter: {0}" -f $_.Exception.Message
    )

    exit 1
}
'@
}

function Get-ValidatorScriptContent {
@'
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Resolve-SopsExecutable {
    $command = Get-Command sops `
        -CommandType Application `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($null -ne $command) {
        return [string] $command.Path
    }

    $fallback = Join-Path `
        $env:LOCALAPPDATA `
        'Programs\SOPS\sops.exe'

    if (Test-Path -LiteralPath $fallback) {
        return [string] $fallback
    }

    throw 'sops.exe was not found.'
}

function Resolve-GitExecutable {
    $command = Get-Command git `
        -CommandType Application `
        -ErrorAction Stop |
        Select-Object -First 1

    return [string] $command.Path
}

function Get-EncryptedSopsType {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    switch ([IO.Path]::GetExtension($Path).ToLowerInvariant()) {
        '.json' { return 'json' }
        '.yaml' { return 'yaml' }
        '.yml'  { return 'yaml' }
        '.env'  { return 'dotenv' }
        '.ini'  { return 'ini' }

        # Arbitrary/binary plaintext is stored by SOPS using
        # its JSON binary envelope.
        default { return 'json' }
    }
}

try {
    [string] $sops = Resolve-SopsExecutable
    [string] $git = Resolve-GitExecutable

    # Enumerate tracked files and evaluate the filter attribute from the
    # INDEX, not merely from the working tree. This protects against a
    # staged .gitattributes change that would otherwise weaken validation.
    $files = @(
        & $git ls-files
    )

    if ($LASTEXITCODE -ne 0) {
        throw 'git ls-files failed.'
    }

    $failures = [Collections.Generic.List[string]]::new()

    foreach ($path in $files) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        $attribute = & $git check-attr `
            --cached `
            filter `
            -- `
            $path

        if ($LASTEXITCODE -ne 0) {
            throw "git check-attr failed for '$path'."
        }

        if ($attribute -notmatch ':\s*filter:\s*sops$') {
            continue
        }

        $extension = [IO.Path]::GetExtension($path)

        $tempFile = Join-Path `
            ([IO.Path]::GetTempPath()) `
            ("sops-index-" + [guid]::NewGuid() + $extension)

        try {
            # PowerShell 7.4+ preserves native stdout bytes when
            # redirecting directly to a file.
            & $git cat-file blob ":$path" > $tempFile

            if ($LASTEXITCODE -ne 0) {
                $failures.Add($path)
                continue
            }

            $type = Get-EncryptedSopsType -Path $path

            $statusJson = & $sops `
                filestatus `
                --input-type $type `
                $tempFile `
                2>$null

            if ($LASTEXITCODE -ne 0) {
                $failures.Add($path)
                continue
            }

            try {
                $status = $statusJson | ConvertFrom-Json
            }
            catch {
                $failures.Add($path)
                continue
            }

            if ($status.encrypted -ne $true) {
                $failures.Add($path)
            }
        }
        finally {
            Remove-Item `
                -LiteralPath $tempFile `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }

    if ($failures.Count -gt 0) {
        [Console]::Error.WriteLine('')
        [Console]::Error.WriteLine(
            'ERROR: plaintext or invalid SOPS data found in the Git index:'
        )

        foreach ($path in $failures) {
            [Console]::Error.WriteLine("  - $path")
        }

        [Console]::Error.WriteLine('')
        [Console]::Error.WriteLine(
            'Commit aborted to prevent plaintext secrets from being committed.'
        )

        exit 1
    }

    Write-Host 'SOPS index validation passed.'
    exit 0
}
catch {
    [Console]::Error.WriteLine(
        "SOPS index validation failed: $($_.Exception.Message)"
    )

    exit 1
}
'@
}

function Get-SetupScriptContent {
@'
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Get-ApplicationPath {
    param(
        [Parameter(Mandatory)][string] $Name,
        [string] $Fallback
    )

    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($null -ne $command) {
        return [string]$command.Path
    }

    if (
        -not [string]::IsNullOrWhiteSpace($Fallback) -and
        (Test-Path -LiteralPath $Fallback)
    ) {
        return [string]$Fallback
    }

    throw "'$Name' was not found."
}

function Invoke-Git {
    param(
        [Parameter(ValueFromRemainingArguments)]
        [string[]] $Arguments
    )

    $output = & git @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }

    return $output
}

function Get-SopsTypes {
    param([Parameter(Mandatory)][string] $Path)

    switch ([IO.Path]::GetExtension($Path).ToLowerInvariant()) {
        '.json' { return @{ Plain = 'json';   Encrypted = 'json' } }
        '.yaml' { return @{ Plain = 'yaml';   Encrypted = 'yaml' } }
        '.yml'  { return @{ Plain = 'yaml';   Encrypted = 'yaml' } }
        '.env'  { return @{ Plain = 'dotenv'; Encrypted = 'dotenv' } }
        '.ini'  { return @{ Plain = 'ini';    Encrypted = 'ini' } }
        default { return @{ Plain = 'binary'; Encrypted = 'json' } }
    }
}

try {
    [void](Get-ApplicationPath -Name 'git')
    [void](Get-ApplicationPath -Name 'pwsh')

    $sopsFallback = Join-Path $env:LOCALAPPDATA 'Programs\SOPS\sops.exe'
    $sops = Get-ApplicationPath -Name 'sops' -Fallback $sopsFallback

    $repoRoot = (Invoke-Git rev-parse --show-toplevel).Trim()

    if ([string]::IsNullOrWhiteSpace($repoRoot)) {
        throw 'Could not determine repository root.'
    }

    Push-Location $repoRoot

    try {
        $requiredFiles = @(
            '.gitattributes',
            '.sops.yaml',
            '.githooks/git-sops-filter.ps1',
            '.githooks/Test-SopsIndex.ps1'
        )

        foreach ($requiredFile in $requiredFiles) {
            if (-not (Test-Path -LiteralPath $requiredFile)) {
                throw "Required file '$requiredFile' was not found."
            }
        }

        Write-Host "Repository : $repoRoot"
        Write-Host "SOPS       : $sops"
        Write-Host ''

        $protectedFiles = @(
            Invoke-Git ls-files ':(attr:filter=sops)'
        )

        $filesToSmudge = [Collections.Generic.List[string]]::new()

        foreach ($path in $protectedFiles) {
            if ([string]::IsNullOrWhiteSpace($path)) {
                continue
            }

            if (-not (Test-Path -LiteralPath $path)) {
                $filesToSmudge.Add($path)
                continue
            }

            $indexBlob = (Invoke-Git rev-parse ":$path").Trim()
            $workingBlob = (Invoke-Git hash-object --no-filters -- $path).Trim()

            if ($workingBlob -eq $indexBlob) {
                $filesToSmudge.Add($path)
            }
        }

        $cleanCommand = @(
            'pwsh'
            '-NoLogo'
            '-NoProfile'
            '-NonInteractive'
            '-ExecutionPolicy Bypass'
            '-File .githooks/git-sops-filter.ps1'
            'clean %f'
        ) -join ' '

        $smudgeCommand = @(
            'pwsh'
            '-NoLogo'
            '-NoProfile'
            '-NonInteractive'
            '-ExecutionPolicy Bypass'
            '-File .githooks/git-sops-filter.ps1'
            'smudge %f'
        ) -join ' '

        Invoke-Git config --local filter.sops.clean $cleanCommand | Out-Null
        Invoke-Git config --local filter.sops.smudge $smudgeCommand | Out-Null
        Invoke-Git config --local filter.sops.required true | Out-Null

        $hookCommand = @(
            'pwsh'
            '-NoLogo'
            '-NoProfile'
            '-NonInteractive'
            '-File .githooks/Test-SopsIndex.ps1'
        ) -join ' '

        Invoke-Git config --local hook.sops-index.command $hookCommand | Out-Null

        & git config --local --unset-all hook.sops-index.event 2>$null
        Invoke-Git config --local --add hook.sops-index.event pre-commit | Out-Null

        $hooks = @(& git hook list --show-scope pre-commit)

        if (
            $LASTEXITCODE -ne 0 -or
            -not ($hooks -match '\bsops-index$')
        ) {
            throw (
                'Git did not expose the configured named pre-commit hook. ' +
                'Git 2.55 or newer is required.'
            )
        }

        if ($filesToSmudge.Count -gt 0) {
            Write-Host 'Decrypting protected working-tree files...'

            foreach ($path in $filesToSmudge) {
                $extension = [IO.Path]::GetExtension($path)
                $encryptedTemp = Join-Path `
                    ([IO.Path]::GetTempPath()) `
                    ("sops-encrypted-" + [guid]::NewGuid() + $extension)
                $plainTemp = Join-Path `
                    ([IO.Path]::GetTempPath()) `
                    ("sops-plain-" + [guid]::NewGuid() + $extension)

                try {
                    # Use a native binary-safe export instead of a PowerShell
                    # text pipeline for the actual file contents.
                    $blobHash = (Invoke-Git rev-parse ":$path").Trim()
                    & git cat-file blob $blobHash > $encryptedTemp

                    if ($LASTEXITCODE -ne 0) {
                        throw "Could not read encrypted index blob for '$path'."
                    }

                    $types = Get-SopsTypes -Path $path

                    & $sops decrypt `
                        --filename-override $path `
                        --input-type $types.Encrypted `
                        --output-type $types.Plain `
                        --output $plainTemp `
                        $encryptedTemp

                    if ($LASTEXITCODE -ne 0) {
                        throw "Could not decrypt '$path'."
                    }

                    $targetPath = Join-Path $repoRoot $path
                    $targetDirectory = Split-Path $targetPath -Parent

                    if (-not (Test-Path -LiteralPath $targetDirectory)) {
                        New-Item `
                            -ItemType Directory `
                            -Force `
                            -Path $targetDirectory |
                            Out-Null
                    }

                    Move-Item `
                        -LiteralPath $plainTemp `
                        -Destination $targetPath `
                        -Force

                    Write-Host "  decrypted: $path"
                }
                finally {
                    Remove-Item -LiteralPath $encryptedTemp -Force -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath $plainTemp -Force -ErrorAction SilentlyContinue
                }
            }
        }

        if ($filesToSmudge.Count -gt 0) {
            foreach ($path in $filesToSmudge) {
                $blobBefore = (Invoke-Git rev-parse ":$path").Trim()

                & git add -- $path

                if ($LASTEXITCODE -ne 0) {
                    throw "Could not refresh '$path' through the clean filter."
                }

                $blobAfter = (Invoke-Git rev-parse ":$path").Trim()

                if ($blobAfter -ne $blobBefore) {
                    throw (
                        "Unexpected index change while refreshing '$path'. " +
                        'Bootstrap aborted.'
                    )
                }
            }
        }

        Write-Host ''
        Write-Host 'Validating SOPS-protected index...'

        & git hook run pre-commit

        if ($LASTEXITCODE -ne 0) {
            throw 'SOPS index validation failed.'
        }

        Write-Host ''
        Write-Host 'SOPS Git integration configured successfully.'
        Write-Host ''
        Write-Host 'Working tree : plaintext'
        Write-Host 'Git index    : SOPS ciphertext'
        Write-Host 'Pre-commit   : SOPS index validation enabled'
    }
    finally {
        Pop-Location
    }
}
catch {
    [Console]::Error.WriteLine('')
    [Console]::Error.WriteLine(
        "SOPS Git setup failed: $($_.Exception.Message)"
    )
    exit 1
}
'@
}

function Write-LfUtf8NoBomFile {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Content
    )

    $normalized = $Content `
        -replace "`r`n", "`n" `
        -replace "`r", "`n"

    $encoding = [System.Text.UTF8Encoding]::new($false)

    [IO.File]::WriteAllText(
        $Path,
        $normalized,
        $encoding
    )
}

function Write-RepositoryTooling {
    param(
        [Parameter(Mandatory)]
        [string] $Root
    )

    $hooksDir = Join-Path $Root '.githooks'

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $hooksDir |
        Out-Null

    Write-LfUtf8NoBomFile `
        -Path (Join-Path $hooksDir 'git-sops-filter.ps1') `
        -Content (Get-FilterScriptContent)

    Write-LfUtf8NoBomFile `
        -Path (Join-Path $hooksDir 'Test-SopsIndex.ps1') `
        -Content (Get-ValidatorScriptContent)

    Write-LfUtf8NoBomFile `
        -Path (Join-Path $hooksDir 'Setup-SopsGit.ps1') `
        -Content (Get-SetupScriptContent)

    if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
        $destination = Join-Path `
            $hooksDir `
            'Initialize-SopsGit.ps1'

        $sourceFull = [IO.Path]::GetFullPath($PSCommandPath)
        $destinationFull = [IO.Path]::GetFullPath($destination)

        if ($sourceFull -ne $destinationFull) {
            $initializerContent = [IO.File]::ReadAllText(
                $sourceFull
            )

            Write-LfUtf8NoBomFile `
                -Path $destinationFull `
                -Content $initializerContent
        }
    }
}

function Configure-LocalRepository {
    param(
        [Parameter(Mandatory)][string] $GitExe,
        [Parameter(Mandatory)][string] $Root
    )

    Push-Location $Root
    try {
        & pwsh -NoLogo -NoProfile -NonInteractive -File '.\.githooks\Setup-SopsGit.ps1'
        if ($LASTEXITCODE -ne 0) {
            throw 'Repository-local SOPS setup failed.'
        }
    }
    finally {
        Pop-Location
    }
}

function Get-ProtectedTrackedFiles {
    param(
        [Parameter(Mandatory)][string] $GitExe,
        [Parameter(Mandatory)][string] $Root
    )

    @(
        & $GitExe -C $Root ls-files ':(attr:filter=sops)' |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Get-SopsTypesForPath {
    param([Parameter(Mandatory)][string] $Path)

    switch ([IO.Path]::GetExtension($Path).ToLowerInvariant()) {
        '.json' { return @{ Plain = 'json';   Encrypted = 'json' } }
        '.yaml' { return @{ Plain = 'yaml';   Encrypted = 'yaml' } }
        '.yml'  { return @{ Plain = 'yaml';   Encrypted = 'yaml' } }
        '.env'  { return @{ Plain = 'dotenv'; Encrypted = 'dotenv' } }
        '.ini'  { return @{ Plain = 'ini';    Encrypted = 'ini' } }
        default { return @{ Plain = 'binary'; Encrypted = 'json' } }
    }
}

function Invoke-NativeByteProcess {
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter(Mandatory)]
        [string[]] $Arguments,

        [byte[]] $InputBytes = [byte[]]::new(0)
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    foreach ($argument in $Arguments) {
        [void] $startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo

    $stdout = [IO.MemoryStream]::new()

    [int] $exitCode = -1
    [byte[]] $stdoutBytes = [byte[]]::new(0)
    [string] $stderr = ''

    try {
        [bool] $started = $process.Start()

        if (-not $started) {
            throw "Could not start '$FilePath'."
        }

        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.ReadToEndAsync()

        if ($InputBytes.Length -gt 0) {
            [void] $process.StandardInput.BaseStream.Write(
                $InputBytes,
                0,
                $InputBytes.Length
            )
        }

        [void] $process.StandardInput.Close()
        [void] $process.WaitForExit()

        [void] $stdoutTask.GetAwaiter().GetResult()

        $stderr = [string] $stderrTask.GetAwaiter().GetResult()

        $exitCode = [int] $process.ExitCode
        $stdoutBytes = [byte[]] $stdout.ToArray()
    }
    finally {
        [void] $stdout.Dispose()
        [void] $process.Dispose()
    }

    return [pscustomobject] @{
        ExitCode = $exitCode
        StdOut   = $stdoutBytes
        StdErr   = $stderr
    }
}

function Add-RecipientsAndReencrypt {
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $GitExe,
        [Parameter(Mandatory)][string] $SopsExe,
        [Parameter(Mandatory)][string[]] $NewRecipients
    )

    $configPath = Join-Path $Root '.sops.yaml'
    $managed = Get-ManagedSopsData -Path $configPath

    if ($null -eq $managed) {
        throw 'AddRecipient currently requires a .sops.yaml generated by this script.'
    }

    $allRecipients = @(
        $managed.Recipients
        $NewRecipients
    ) |
        Where-Object { $_ -match '^age1[0-9a-z]+$' } |
        Sort-Object -Unique

    if ($allRecipients.Count -eq 0) {
        throw 'No valid age recipients were supplied.'
    }

    $specs = Get-ProtectedSpecifications -Root $Root -Paths $managed.ProtectedPath
    Write-ManagedSopsConfig `
        -Root $Root `
        -Specifications $specs `
        -Recipients $allRecipients

    Configure-LocalRepository -GitExe $GitExe -Root $Root

    $files = Get-ProtectedTrackedFiles -GitExe $GitExe -Root $Root

    foreach ($path in $files) {
        $workingPath = Join-Path $Root ($path.Replace('/', [IO.Path]::DirectorySeparatorChar))

        if (-not (Test-Path -LiteralPath $workingPath -PathType Leaf)) {
            throw "Protected file '$path' is missing from the working tree."
        }

        $plainBytes = [IO.File]::ReadAllBytes($workingPath)
        $types = Get-SopsTypesForPath -Path $path

        $encrypted = Invoke-NativeByteProcess `
            -FilePath $SopsExe `
            -Arguments @(
                'encrypt',
                '--filename-override', $path,
                '--input-type', $types.Plain,
                '--output-type', $types.Encrypted
            ) `
            -InputBytes $plainBytes

        if ($encrypted.ExitCode -ne 0) {
            throw "Failed to re-encrypt '$path': $($encrypted.StdErr)"
        }

        $temp = Join-Path ([IO.Path]::GetTempPath()) ("sops-rekey-" + [guid]::NewGuid())

        try {
            [IO.File]::WriteAllBytes($temp, $encrypted.StdOut)

            $blobHash = (& $GitExe -C $Root hash-object -w --no-filters $temp).Trim()
            if ($LASTEXITCODE -ne 0) {
                throw "git hash-object failed for '$path'."
            }

            $stageLine = & $GitExe -C $Root ls-files --stage -- $path |
                Select-Object -First 1

            if ($stageLine -notmatch '^(?<mode>\d+)\s+[0-9a-f]+\s+0\t') {
                throw "Could not determine index mode for '$path'."
            }

            $mode = $Matches.mode

            & $GitExe -C $Root update-index --cacheinfo "$mode,$blobHash,$path"
            if ($LASTEXITCODE -ne 0) {
                throw "git update-index failed for '$path'."
            }

            # Refresh stat metadata through the clean filter and confirm that
            # the newly generated ciphertext remains the canonical index blob.
            & $GitExe -C $Root add -- $path
            if ($LASTEXITCODE -ne 0) {
                throw "git add failed while refreshing '$path'."
            }

            $after = (& $GitExe -C $Root rev-parse ":$path").Trim()
            if ($after -ne $blobHash) {
                throw "Unexpected ciphertext change after rekeying '$path'."
            }

            Write-Ok "Re-encrypted for updated recipients: $path"
        }
        finally {
            Remove-Item $temp -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $NoStage) {
        & $GitExe -C $Root add -- '.sops.yaml'
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not stage .sops.yaml.'
        }
    }
}

function Test-IndexBlobIsSopsEncrypted {
    param(
        [Parameter(Mandatory)]
        [string] $GitExe,

        [Parameter(Mandatory)]
        [string] $SopsExe,

        [Parameter(Mandatory)]
        [string] $Root,

        [Parameter(Mandatory)]
        [string] $Path
    )

    $blob = Invoke-NativeByteProcess `
        -FilePath $GitExe `
        -Arguments @(
            '-C', $Root,
            'cat-file',
            'blob',
            ":$Path"
        )

    if ($blob.ExitCode -ne 0) {
        return $false
    }

    $extension = [IO.Path]::GetExtension($Path)

    $tempFile = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("sops-index-check-" + [guid]::NewGuid() + $extension)

    try {
        [IO.File]::WriteAllBytes(
            $tempFile,
            $blob.StdOut
        )

        $types = Get-SopsTypesForPath -Path $Path

        $statusOutput = @(
            & $SopsExe `
                filestatus `
                --input-type $types.Encrypted `
                $tempFile `
                2>$null
        )

        $succeeded = $?

        if (-not $succeeded -or $statusOutput.Count -eq 0) {
            return $false
        }

        try {
            $status = $statusOutput |
                ConvertFrom-Json
        }
        catch {
            return $false
        }

        return $status.encrypted -eq $true
    }
    finally {
        Remove-Item `
            -LiteralPath $tempFile `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

function Get-TrackedFilesForSpecification {
    param(
        [Parameter(Mandatory)]
        [string] $GitExe,

        [Parameter(Mandatory)]
        [string] $Root,

        [Parameter(Mandatory)]
        [object] $Specification
    )

    $pathSpec = if ($Specification.IsDirectory) {
        "$($Specification.RelativePath)/"
    }
    else {
        $Specification.RelativePath
    }

    $files = @(
        & $GitExe -C $Root `
            ls-files `
            -- `
            $pathSpec
    )

    if ($LASTEXITCODE -ne 0) {
        throw "git ls-files failed for '$pathSpec'."
    }

    return @(
        $files |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            }
    )
}

function Stage-RepositorySetup {
    param(
        [Parameter(Mandatory)][string] $GitExe,
        [Parameter(Mandatory)][string] $SopsExe,
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][object[]] $Specifications
    )

    if ($NoStage) {
        return
    }

    $setupPaths = @(
        '.gitattributes',
        '.sops.yaml',
        '.githooks'
    )

    & $GitExe -C $Root add -- @setupPaths
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not stage SOPS repository tooling.'
    }

    foreach ($spec in $Specifications) {
        $absolute = Join-Path `
            $Root `
            ($spec.RelativePath.Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar
            ))

        if (-not (Test-Path -LiteralPath $absolute)) {
            Write-Warn (
                "Protected path '$($spec.RelativePath)' does not exist yet; " +
                'the rule was configured but no file was staged.'
            )

            continue
        }

        $trackedFiles = @(
            Get-TrackedFilesForSpecification `
                -GitExe $GitExe `
                -Root $Root `
                -Specification $spec
        )

        $needsRenormalization = $false

        foreach ($trackedFile in $trackedFiles) {
            $encrypted = Test-IndexBlobIsSopsEncrypted `
                -GitExe $GitExe `
                -SopsExe $SopsExe `
                -Root $Root `
                -Path $trackedFile

            if (-not $encrypted) {
                $needsRenormalization = $true
                break
            }
        }

        if ($needsRenormalization) {
            Write-Info (
                "Renormalizing protected path through SOPS: " +
                $spec.RelativePath
            )

            & $GitExe -C $Root `
                add `
                --renormalize `
                -- `
                $spec.RelativePath

            if ($LASTEXITCODE -ne 0) {
                throw (
                    "Could not renormalize protected path " +
                    "'$($spec.RelativePath)'."
                )
            }
        }
        elseif ($trackedFiles.Count -gt 0) {
            Write-Info (
                "Protected path already uses SOPS ciphertext: " +
                $spec.RelativePath
            )
        }

        # Always run a normal add afterwards:
        #
        # - stages new/untracked protected files
        # - refreshes already tracked files
        # - leaves existing ciphertext stable through the clean filter
        & $GitExe -C $Root `
            add `
            -- `
            $spec.RelativePath

        if ($LASTEXITCODE -ne 0) {
            throw "Could not stage protected path '$($spec.RelativePath)'."
        }
    }
}

function Remove-GitCryptTrackedMetadataIfRequested {
    param(
        [Parameter(Mandatory)][string] $GitExe,
        [Parameter(Mandatory)][string] $Root
    )

    if (-not $RemoveGitCryptMetadata) {
        return
    }

    $tracked = @(& $GitExe -C $Root ls-files '.git-crypt')

    if ($tracked.Count -gt 0) {
        & $GitExe -C $Root rm -r -- '.git-crypt'
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not remove tracked .git-crypt metadata.'
        }
    }
}

Assert-Windows
Ensure-PowerShell

$gitExe = Ensure-Git
$ageTools = Ensure-Age
$sopsExe = Ensure-Sops
$root = Resolve-Repository -GitExe $gitExe -Path $RepoPath

Write-Info "Repository: $root"

switch ($Mode) {
    'Join' {
        $identity = Ensure-AgeIdentity `
            -AgeKeygen $ageTools.Keygen `
            -AllowGenerate:$false

        if ($null -eq $identity) {
            # Generate a new identity so a collaborator can send the public
            # recipient to a maintainer, but do not pretend it can decrypt
            # existing files yet.
            $identity = Ensure-AgeIdentity `
                -AgeKeygen $ageTools.Keygen `
                -AllowGenerate

            Write-Host ''
            Write-Warn 'A new age identity was generated, but this repository is not yet encrypted for it.'
            Write-Host "Public recipient: $($identity.Recipient)"
            Write-Host ''
            Write-Host 'Send this PUBLIC recipient to a maintainer. The maintainer should run:'
            Write-Host "  pwsh .\.githooks\Initialize-SopsGit.ps1 -Mode AddRecipient -AdditionalAgeRecipient '$($identity.Recipient)'"
            Write-Host 'After the maintainer commits/pushes the re-encryption, pull and rerun -Mode Join.'
            exit 2
        }

        Configure-LocalRepository -GitExe $gitExe -Root $root
        Write-Ok 'Fresh-clone/new-machine setup completed.'
    }

    'AddRecipient' {
        if ($AdditionalAgeRecipient.Count -eq 0) {
            throw 'AddRecipient requires -AdditionalAgeRecipient age1...'
        }

        Assert-CleanTrackedWorkingTree -GitExe $gitExe -Root $root

        Add-RecipientsAndReencrypt `
            -Root $root `
            -GitExe $gitExe `
            -SopsExe $sopsExe `
            -NewRecipients $AdditionalAgeRecipient

        & $gitExe -C $root hook run pre-commit
        if ($LASTEXITCODE -ne 0) {
            throw 'SOPS index validation failed after adding recipients.'
        }

        Write-Ok 'Recipients updated. Review and commit the staged ciphertext changes.'
    }

    'Initialize' {
        $identity = Ensure-AgeIdentity `
            -AgeKeygen $ageTools.Keygen `
            -AllowGenerate

        $specs = Get-ProtectedSpecifications `
            -Root $root `
            -Paths $ProtectedPath

        $existingManagedSops = Get-ManagedSopsData `
            -Path (Join-Path $root '.sops.yaml')

        $recipients = @(
            # The current user's identity must always remain authorized.
            $identity.Recipient

            # Preserve recipients already configured by previous AddRecipient
            # operations when Initialize is run again.
            if ($null -ne $existingManagedSops) {
                $existingManagedSops.Recipients
            }

            # Allow new recipients to be supplied during initialization as well.
            $AdditionalAgeRecipient
        ) |
            Where-Object { $_ -match '^age1[0-9a-z]+$' } |
            Sort-Object -Unique

        Update-ManagedGitAttributes `
            -Root $root `
            -Specifications $specs

        Write-ManagedSopsConfig `
            -Root $root `
            -Specifications $specs `
            -Recipients $recipients

        Write-RepositoryTooling -Root $root
        Configure-LocalRepository -GitExe $gitExe -Root $root
        Stage-RepositorySetup `
            -GitExe $gitExe `
            -SopsExe $sopsExe `
            -Root $root `
            -Specifications $specs

        & $gitExe -C $root hook run pre-commit
        if ($LASTEXITCODE -ne 0) {
            throw 'SOPS index validation failed.'
        }

        Write-Host ''
        Write-Ok 'Repository initialized for transparent SOPS encryption.'
        Write-Host "Age public recipient: $($identity.Recipient)"
        Write-Host 'Review `git status` and inspect protected index blobs before committing.'
    }

    'MigrateGitCrypt' {
        Assert-CleanTrackedWorkingTree -GitExe $gitExe -Root $root

        $gitCrypt = Get-Application -Name 'git-crypt'
        if ($null -eq $gitCrypt) {
            throw 'git-crypt must be installed and the repository must be unlocked before migration.'
        }

        Write-Info 'Current git-crypt encrypted-file inventory:'

        Push-Location $root
        try {
            & $gitCrypt.Path status -e

            if ($LASTEXITCODE -ne 0) {
                throw 'git-crypt status failed. Ensure the repository is unlocked and healthy before migration.'
            }
        }
        finally {
            Pop-Location
        }

        $identity = Ensure-AgeIdentity `
            -AgeKeygen $ageTools.Keygen `
            -AllowGenerate

        $specs = Get-ProtectedSpecifications -Root $root -Paths $ProtectedPath

        $recipients = @(
            $identity.Recipient
            $AdditionalAgeRecipient
        ) |
            Where-Object { $_ -match '^age1[0-9a-z]+$' } |
            Sort-Object -Unique

        Update-ManagedGitAttributes `
            -Root $root `
            -Specifications $specs `
            -MigrateGitCryptRules

        Write-ManagedSopsConfig `
            -Root $root `
            -Specifications $specs `
            -Recipients $recipients

        Write-RepositoryTooling -Root $root
        Configure-LocalRepository -GitExe $gitExe -Root $root

        Remove-GitCryptTrackedMetadataIfRequested -GitExe $gitExe -Root $root
        Stage-RepositorySetup `
            -GitExe $gitExe `
            -SopsExe $sopsExe `
            -Root $root `
            -Specifications $specs

        & $gitExe -C $root hook run pre-commit
        if ($LASTEXITCODE -ne 0) {
            throw 'SOPS index validation failed after git-crypt migration.'
        }

        Write-Host ''
        Write-Ok 'git-crypt -> SOPS migration has been staged.'
        Write-Host 'Do NOT delete your old git-crypt keys yet: historical commits remain git-crypt encrypted.'
        Write-Host 'Review the staged blobs and commit only after verification.'
    }
}
