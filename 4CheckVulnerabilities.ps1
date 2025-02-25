# CheckVulnerabilities.ps1

[CmdletBinding()]
param(
    [string]$DirectoryFilter = ""
)

# Global results array.
$global:results = @()
$global:scanCount = 0

Write-Verbose "Starting inspection of packages..."

function Check-Vulnerability {
    param(
        [string]$PackageManager,
        [string]$PackageName,
        [string]$Version,
        [string]$FilePath
    )
    Write-Verbose "Checking vulnerability for $PackageManager package: $PackageName version: $Version (source file: $FilePath)"
    
    if ($PackageManager -like "npm") {
        Write-Verbose "Using npm to check vulnerability for $PackageName@$Version"
        # Create a temporary folder for an isolated npm audit.
        $tempDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName()))
        try {
            $packageJsonContent = @{
                dependencies = @{$PackageName = $Version}
            } | ConvertTo-Json -Depth 3
            $packageJsonPath = Join-Path $tempDir "package.json"
            $packageJsonContent | Out-File -FilePath $packageJsonPath -Encoding utf8
            Write-Verbose "Created temporary package.json at $packageJsonPath"
            
            Push-Location $tempDir
            Write-Verbose "Running 'npm install' in $tempDir"
            npm install --silent | Out-Null
            Write-Verbose "Running 'npm audit --json' in $tempDir"
            $auditOutput = npm audit --json 2>$null | Out-String
            Pop-Location

            try {
                $auditJson = $auditOutput | ConvertFrom-Json
            }
            catch {
                Write-Verbose "Unable to parse npm audit output for $PackageName@$Version"
                $auditJson = $null
            }
            if ($auditJson -and $auditJson.metadata -and $auditJson.metadata.vulnerabilities) {
                $vulnData = $auditJson.metadata.vulnerabilities
                if (($vulnData.info -gt 0) -or ($vulnData.low -gt 0) -or ($vulnData.moderate -gt 0) -or ($vulnData.high -gt 0) -or ($vulnData.critical -gt 0)) {
                    Write-Verbose "npm audit reported vulnerabilities for $PackageName@$Version"
                    return @{ Vulnerable = $true; Details = "npm audit detected vulnerabilities for $PackageName@$Version" }
                }
                else {
                    Write-Verbose "npm audit reported no vulnerabilities for $PackageName@$Version"
                    return @{ Vulnerable = $false; Details = "No vulnerabilities reported by npm audit for $PackageName@$Version" }
                }
            }
            else {
                Write-Verbose "No audit information available for $PackageName@$Version"
                return @{ Vulnerable = $false; Details = "No audit information available for $PackageName@$Version" }
            }
        }
        finally {
            if (Test-Path $tempDir) {
                Remove-Item -Path $tempDir -Recurse -Force
                Write-Verbose "Removed temporary directory $tempDir for npm audit"
            }
        }
    }
    elseif ($PackageManager -like "NuGet*") {
        Write-Verbose "Using dotnet list package to check vulnerability for NuGet package: $PackageName@$Version"
        $projectFile = $null
        if ($FilePath -imatch "\.csproj$") {
            $projectFile = $FilePath
        }
        else {
            $dir = Split-Path $FilePath
            $project = Get-ChildItem -Path $dir -Filter "*.csproj" -File | Select-Object -First 1
            if ($project) { $projectFile = $project.FullName }
        }
        if (-not $projectFile) {
            Write-Verbose "No project file found for NuGet package $PackageName; skipping vulnerability check."
            return @{
                Vulnerable = $null; 
                Details = "No project file available for NuGet vulnerability check"; 
                MinimumPatchedVersion = $null;
                LatestVersion = $null
            }
        }
        Write-Verbose "Running 'dotnet list package --vulnerable' on $projectFile"
        $output = & dotnet list $projectFile package --vulnerable 2>$null | Out-String

        # Parse dotnet output (adjust regex as needed)
        $minPatchedVersion = $null
        $latestVersion = $null
        if ($output -match "$PackageName\s+([\d\.\-a-zA-Z]+)\s+([\d\.\-a-zA-Z]+)\s+([\d\.\-a-zA-Z]+)") {
            # Matches: Current, MinimumPatched, and Latest version numbers from the output
            $currentVersionFromOutput = $Matches[1]
            $minPatchedVersion = $Matches[2]
            $latestVersion = $Matches[3]
        }
        if ($output -match $PackageName) {
            Write-Verbose "dotnet list package indicates vulnerability for $PackageName@$Version"
            return @{
                Vulnerable = $true; 
                Details = "Vulnerability detected via dotnet list package for $PackageName@$Version";
                MinimumPatchedVersion = $minPatchedVersion;
                LatestVersion = $latestVersion
            }
        }
        else {
            Write-Verbose "dotnet list package indicates no vulnerability for $PackageName@$Version"
            return @{
                Vulnerable = $false; 
                Details = "No vulnerability detected via dotnet list package for $PackageName@$Version"; 
                MinimumPatchedVersion = $minPatchedVersion;
                LatestVersion = $latestVersion
            }
        }
    }
    else {
        Write-Verbose "Unsupported package manager: $PackageManager"
        return @{
            Vulnerable = $null; 
            Details = "Unsupported package manager: $PackageManager";
            MinimumPatchedVersion = $null;
            LatestVersion = $null
        }
    }
}

# Arrays for grouping discovered packages.
$nugetPackages = @()
$npmPackages   = @()

# --- SCAN PHASE ---

# Scan packages.config files (NuGet legacy)
$configFiles = Get-ChildItem -Recurse -Filter "packages.config" -File
if ($DirectoryFilter) {
    $configFiles = $configFiles | Where-Object { $_.DirectoryName -like "*$DirectoryFilter*" }
}
$totalConfigs = $configFiles.Count
$i = 0
foreach ($file in $configFiles) {
    $i++
    Write-Progress -Activity "Scanning packages.config files" -Status "Processing file $i of $totalConfigs" -PercentComplete (($i / $totalConfigs) * 100)
    $filePath = $file.FullName
    try {
        [xml]$xml = Get-Content $filePath
        foreach ($pkg in $xml.packages.package) {
            $packageName = $pkg.id
            $version     = $pkg.version
            Write-Verbose "Found NuGet package (packages.config): $packageName@$version in $filePath"
            $nugetPackages += [PSCustomObject]@{
                FilePath       = $filePath
                PackageManager = "NuGet"
                PackageName    = $packageName
                Version        = $version
            }
            $global:scanCount++
        }
    }
    catch {
        Write-Warning "Error processing file $filePath : $_"
    }
}

# Scan *.csproj files for PackageReference entries (NuGet)
$csprojFiles = Get-ChildItem -Recurse -Filter "*.csproj" -File
if ($DirectoryFilter) {
    $csprojFiles = $csprojFiles | Where-Object { $_.DirectoryName -like "*$DirectoryFilter*" }
}
$totalCsproj = $csprojFiles.Count
$i = 0
foreach ($file in $csprojFiles) {
    $i++
    Write-Progress -Activity "Scanning csproj files" -Status "Processing file $i of $totalCsproj" -PercentComplete (($i / $totalCsproj) * 100)
    $filePath = $file.FullName
    try {
        [xml]$xml = Get-Content $filePath
        $packageRefs = $xml.SelectNodes("//PackageReference")
        if ($packageRefs) {
            foreach ($pkg in $packageRefs) {
                $packageName = $pkg.GetAttribute("Include")
                $version     = $pkg.GetAttribute("Version")
                if (-not $version) {
                    $versionNode = $pkg.SelectSingleNode("Version")
                    if ($versionNode) { $version = $versionNode.InnerText }
                }
                if ($packageName -and $version) {
                    Write-Verbose "Found NuGet package (csproj): $packageName@$version in $filePath"
                    $nugetPackages += [PSCustomObject]@{
                        FilePath       = $filePath
                        PackageManager = "NuGet"
                        PackageName    = $packageName
                        Version        = $version
                    }
                    $global:scanCount++
                }
            }
        }
    }
    catch {
        Write-Warning "Error processing csproj file $filePath : $_"
    }
}

# Scan package.json files for npm dependencies.
$jsonFiles = Get-ChildItem -Recurse -Filter "package.json" -File
if ($DirectoryFilter) {
    $jsonFiles = $jsonFiles | Where-Object { $_.DirectoryName -like "*$DirectoryFilter*" }
}
$totalJson = $jsonFiles.Count
$i = 0
foreach ($file in $jsonFiles) {
    $i++
    Write-Progress -Activity "Scanning package.json files" -Status "Processing file $i of $totalJson" -PercentComplete (($i / $totalJson) * 100)
    $filePath = $file.FullName
    try {
        $jsonContent = Get-Content $filePath -Raw | ConvertFrom-Json
        $sections = @("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
        foreach ($section in $sections) {
            if ($jsonContent.$section) {
                foreach ($pkg in $jsonContent.$section.psobject.Properties) {
                    $packageName = $pkg.Name
                    # Remove common modifier characters like '^' or '~'
                    $version = $pkg.Value -replace "^[\^~]", ""
                    Write-Verbose "Found npm package: $packageName@$version in $filePath (section: $section)"
                    $npmPackages += [PSCustomObject]@{
                        FilePath       = $filePath
                        PackageManager = "npm"
                        PackageName    = $packageName
                        Version        = $version
                    }
                    $global:scanCount++
                }
            }
        }
    }
    catch {
        Write-Warning "Error processing package.json file $filePath : $_"
    }
}

# --- CONSOLIDATED SUMMARY BEFORE AUDIT ---
# Consolidate packages using PackageName and Version alone.
$npmUnique   = $npmPackages | Sort-Object PackageName, Version -Unique
$nugetUnique = $nugetPackages | Sort-Object PackageName, Version -Unique

$totalReferences = $npmUnique.Count + $nugetUnique.Count
Write-Host ""
Write-Host "Total package references found: $totalReferences"
Write-Host "Consolidated packages to audit (alphabetically): $totalReferences"

Write-Host "Consolidated npm packages: $($npmUnique.Count) found"
$npmUnique | Format-Table -AutoSize
Write-Host "Consolidated NuGet packages: $($nugetUnique.Count) found"
$nugetUnique | Format-Table -AutoSize

# --- AUDIT PHASE ---
# Process npm packages in one aggregated network call.
if ($npmUnique.Count -gt 0) {
    Write-Verbose "Aggregating npm packages for audit..."
    $tempDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName()))
    try {
        # Build dependency hash table using package name and version.
        $dependencies = @{} 
        foreach ($pkg in $npmUnique) {
            if (-not $dependencies.ContainsKey($pkg.PackageName)) {
                $dependencies[$pkg.PackageName] = $pkg.Version
            }
        }
        $packageJsonContent = @{ dependencies = $dependencies } | ConvertTo-Json -Depth 3
        $packageJsonPath = Join-Path $tempDir "package.json"
        $packageJsonContent | Out-File -FilePath $packageJsonPath -Encoding utf8
        Write-Verbose "Created aggregated package.json at $packageJsonPath for npm audit"
        
        Push-Location $tempDir
        Write-Verbose "Running 'npm install' in $tempDir"
        npm install --silent | Out-Null
        Write-Verbose "Running 'npm audit --json' in $tempDir"
        $auditOutput = npm audit --json 2>$null | Out-String
        Pop-Location
        
        $auditJson = $null
        try {
            $auditJson = $auditOutput | ConvertFrom-Json
        }
        catch {
            Write-Verbose "Unable to parse npm audit output from aggregated audit"
        }
        $npmTotal = $npmUnique.Count
        $npmCount = 0
        foreach ($pkg in $npmUnique) {
            $npmCount++
            Write-Progress -Activity "Auditing npm packages" -Status "Processing package ($npmCount of $npmTotal)" -PercentComplete (($npmCount / $npmTotal) * 100)

            # Placeholder for discovered minimum patched version (adjust parsing logic as needed)
            $minPatchedVersion = $null  
            $vulnStatus  = $false
            $vulnDetails = "No vulnerabilities reported by npm audit for $($pkg.PackageName)@$($pkg.Version)"
            if ($auditJson -and $auditJson.metadata -and $auditJson.metadata.vulnerabilities) {
                $vulnData = $auditJson.metadata.vulnerabilities
                if (($vulnData.info -gt 0) -or ($vulnData.low -gt 0) -or ($vulnData.moderate -gt 0) -or ($vulnData.high -gt 0) -or ($vulnData.critical -gt 0)) {
                    $vulnStatus  = $true
                    $vulnDetails = "npm audit detected vulnerabilities for $($pkg.PackageName)@$($pkg.Version)"
                }
            }
            # For npm we use placeholder values for LatestVersion and assume current version is in use.
            $latestVersion = "N/A"
            $status = "Current"
            
            $global:results += [PSCustomObject]@{
                FilePath             = $pkg.FilePath
                PackageManager       = "npm"
                PackageName          = $pkg.PackageName
                Version              = $pkg.Version
                Vulnerable           = $vulnStatus
                Details              = $vulnDetails
                MinimumPatchedVersion= $minPatchedVersion
                LatestVersion        = $latestVersion
                Status               = $status
            }

            if ($vulnStatus) {
                Write-Host "Vulnerability found for $($pkg.PackageName)@$($pkg.Version)" -ForegroundColor Red
            }
            Write-Verbose "npm package $($pkg.PackageName)@$($pkg.Version): Vulnerable=$vulnStatus"
        }
    }
    finally {
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
            Write-Verbose "Removed temporary directory $tempDir for npm audit"
        }
    }
}

# Process NuGet packages — audit one unique package (by PackageName and Version) at a time.
if ($nugetUnique.Count -gt 0) {
    $nugetTotal = $nugetUnique.Count
    $nugetCount = 0
    foreach ($pkg in $nugetUnique) {
        $nugetCount++
        Write-Progress -Activity "Auditing NuGet packages" -Status "Processing package ($nugetCount of $nugetTotal)" -PercentComplete (($nugetCount / $nugetTotal) * 100)
        $vulnResult = Check-Vulnerability -PackageManager "NuGet" -PackageName $pkg.PackageName -Version $pkg.Version -FilePath $pkg.FilePath

        if ($vulnResult.Vulnerable) {
            $minPatchedVersion = $vulnResult.MinimumPatchedVersion
            $latestVersion = $vulnResult.LatestVersion
            $status = ($pkg.Version -eq $latestVersion) ? "Current" : "Out of Date"
            $global:results += [PSCustomObject]@{
                FilePath             = $pkg.FilePath
                PackageManager       = "NuGet"
                PackageName          = $pkg.PackageName
                Version              = $pkg.Version
                Vulnerable           = $vulnResult.Vulnerable
                Details              = $vulnResult.Details
                MinimumPatchedVersion= $minPatchedVersion
                LatestVersion        = $latestVersion
                Status               = $status
            }
        }
        else {
            $latestVersion = $vulnResult.LatestVersion
            $status = ($pkg.Version -eq $latestVersion) ? "Current" : "Out of Date"
            $global:results += [PSCustomObject]@{
                FilePath             = $pkg.FilePath
                PackageManager       = "NuGet"
                PackageName          = $pkg.PackageName
                Version              = $pkg.Version
                Vulnerable           = $vulnResult.Vulnerable
                Details              = $vulnResult.Details
                MinimumPatchedVersion= $null
                LatestVersion        = $latestVersion
                Status               = $status
            }
        }

        if ($vulnResult.Vulnerable) {
            Write-Host "Vulnerability found for $($pkg.PackageName)@$($pkg.Version)" -ForegroundColor Red
        }
    }
}

# --- FINAL OUTPUT ---
Write-Verbose "Creating CSV summary..."
$csvFile = Join-Path -Path (Get-Location) -ChildPath "PackageScanSummary.csv"
$global:results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding utf8
Write-Verbose "CSV summary written to $csvFile"

# Output vulnerable packages to console as a table
$vulnerableResults = $global:results | Where-Object { $_.Vulnerable -eq $true }
if ($vulnerableResults) {
    Write-Host "`nVulnerable Packages Summary:" -ForegroundColor Yellow
    $vulnerableResults | Format-Table PackageManager, PackageName, Version, FilePath -AutoSize
}
else {
    Write-Host "`nNo vulnerabilities found in the scanned packages."
}

Write-Host "Inspection complete. CSV file has been generated."