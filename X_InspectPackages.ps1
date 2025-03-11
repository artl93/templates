# InspectPackages.ps1

[CmdletBinding()]
param()

Write-Verbose "Starting inspection of packages..."

function Check-Vulnerability {
    param(
        [string]$PackageManager,
        [string]$PackageName,
        [string]$Version
    )
    Write-Verbose "Checking vulnerability for $PackageManager package: $PackageName version: $Version"
    # Simulate a vulnerability check:
    # For demo purposes, mark package as vulnerable if the version's last digit is odd.
    $lastChar = $Version[-1]
    if ($lastChar -match '\d' -and [int]$lastChar % 2 -eq 1) {
        Write-Verbose "Package '$PackageName' (v$Version) determined as vulnerable (simulated)."
        return @{
            Vulnerable = $true;
            Details    = "Simulated vulnerability detected for $PackageName v$Version"
        }
    }
    else {
        Write-Verbose "Package '$PackageName' (v$Version) determined as not vulnerable (simulated)."
        return @{
            Vulnerable = $false;
            Details    = "No vulnerability detected"
        }
    }
}

$results = @()

Write-Verbose "Scanning for packages.config files (NuGet legacy)..."
Get-ChildItem -Recurse -Filter "packages.config" -File | ForEach-Object {
    $filePath = $_.FullName
    Write-Verbose "Processing file: $filePath"
    try {
        [xml]$xml = Get-Content $_.FullName
        foreach ($pkg in $xml.packages.package) {
            $packageName = $pkg.id
            $version = $pkg.version
            Write-Verbose "Found NuGet package (packages.config): $packageName, version: $version in $filePath"
            $vulnInfo = Check-Vulnerability -PackageManager "NuGet(packages.config)" -PackageName $packageName -Version $version
            $results += [PSCustomObject]@{
                FilePath       = $filePath
                PackageManager = "NuGet(packages.config)"
                PackageName    = $packageName
                Version        = $version
                Vulnerable     = $vulnInfo.Vulnerable
                Details        = $vulnInfo.Details
            }
        }
    }
    catch {
        Write-Warning "Error processing file $filePath : $_"
    }
}

Write-Verbose "Scanning for *.csproj files for NuGet PackageReference entries..."
Get-ChildItem -Recurse -Filter "*.csproj" -File | ForEach-Object {
    $filePath = $_.FullName
    Write-Verbose "Processing file: $filePath"
    try {
        [xml]$xml = Get-Content $_.FullName
        Write-Verbose "Attempting to locate PackageReference entries in $filePath"
        $packageRefs = $xml.SelectNodes("//PackageReference")
        if ($packageRefs -ne $null) {
            foreach ($pkg in $packageRefs) {
                $packageName = $pkg.GetAttribute("Include")
                $version = $pkg.GetAttribute("Version")
                if (-not $version) {
                    $versionNode = $pkg.SelectSingleNode("Version")
                    if ($versionNode) {
                        $version = $versionNode.InnerText
                    }
                }
                if ($packageName -and $version) {
                    Write-Verbose "Found NuGet package (csproj): $packageName, version: $version in $filePath"
                    $vulnInfo = Check-Vulnerability -PackageManager "NuGet(csproj)" -PackageName $packageName -Version $version
                    $results += [PSCustomObject]@{
                        FilePath       = $filePath
                        PackageManager = "NuGet(csproj)"
                        PackageName    = $packageName
                        Version        = $version
                        Vulnerable     = $vulnInfo.Vulnerable
                        Details        = $vulnInfo.Details
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error processing file $filePath : $_"
    }
}

Write-Verbose "Scanning for package.json files for npm dependencies..."
# Inspect package.json files for npm dependencies.
Get-ChildItem -Recurse -Filter "package.json" -File | ForEach-Object {
    $filePath = $_.FullName
    Write-Verbose "Processing file: $filePath"
    try {
        $jsonContent = Get-Content $_.FullName -Raw | ConvertFrom-Json
        $sections = @("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
        foreach ($section in $sections) {
            if ($jsonContent.$section) {
                foreach ($pkg in $jsonContent.$section.psobject.Properties) {
                    $packageName = $pkg.Name
                    # Remove common modifier characters like '^' or '~'
                    $version = $pkg.Value -replace "^[\^~]", ""
                    Write-Verbose "Found npm package: $packageName, version: $version in $filePath (section: $section)"
                    $vulnInfo = Check-Vulnerability -PackageManager "npm" -PackageName $packageName -Version $version
                    $results += [PSCustomObject]@{
                        FilePath       = $filePath
                        PackageManager = "npm"
                        PackageName    = $packageName
                        Version        = $version
                        Vulnerable     = $vulnInfo.Vulnerable
                        Details        = $vulnInfo.Details
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error processing file $filePath : $_"
    }
}

Write-Verbose "Scanning complete. Writing detailed JSON output..."
# Write full results to a JSON file.
$jsonFile = Join-Path -Path (Get-Location) -ChildPath "PackageScanResults.json"
$results | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonFile -Encoding utf8
Write-Verbose "JSON output written to $jsonFile"

Write-Verbose "Creating CSV summary..."
# Create a CSV summary.
$csvFile = Join-Path -Path (Get-Location) -ChildPath "PackageScanSummary.csv"
$results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding utf8
Write-Verbose "CSV summary written to $csvFile"

Write-Host "Inspection complete. JSON and CSV files have been generated."