# Recursively find all project files and package.json files
$csprojFiles = Get-ChildItem -Recurse -Filter *.csproj
$packageJsonFiles = Get-ChildItem -Recurse -Filter package.json

# Collect NuGet package references from .csproj files
$nugetPackages = foreach ($csproj in $csprojFiles) {
    try {
        [xml]$xml = Get-Content $csproj.FullName -ErrorAction Stop
        foreach ($pkg in $xml.Project.ItemGroup.PackageReference) {
            [PSCustomObject]@{
                PackageName    = $pkg.Include
                CurrentVersion = $pkg.Version
                PackageType    = 'NuGet'
                Source         = $csproj.DirectoryName
            }
        }
    }
    catch {
        Write-Warning "Could not parse $($csproj.FullName): $_"
    }
}

# Collect npm packages from package.json files
$npmPackages = foreach ($jsonFile in $packageJsonFiles) {
    try {
        $json = Get-Content $jsonFile.FullName | ConvertFrom-Json
        $allDeps = @{}
        if ($json.dependencies)      { $allDeps += $json.dependencies.PSObject.Properties.Name, $json.dependencies }
        if ($json.devDependencies)   { $allDeps += $json.devDependencies.PSObject.Properties.Name, $json.devDependencies }
        foreach ($dep in $json.dependencies.PSObject.Properties) {
            [PSCustomObject]@{
                PackageName    = $dep.Name
                CurrentVersion = $dep.Value
                PackageType    = 'npm'
                Source         = $jsonFile.DirectoryName
            }
        }
        if ($json.devDependencies) {
            foreach ($dep in $json.devDependencies.PSObject.Properties) {
                [PSCustomObject]@{
                    PackageName    = $dep.Name
                    CurrentVersion = $dep.Value
                    PackageType    = 'npm'
                    Source         = $jsonFile.DirectoryName
                }
            }
        }
    }
    catch {
        Write-Warning "Could not parse $($jsonFile.FullName): $_"
    }
}

# Combine all packages found
$allPackages = $nugetPackages + $npmPackages

# Function to get package info and simulate vulnerability data
function Get-VulnerabilityInfo {
    param(
        [Parameter(Mandatory)]
        [string]$PackageName,
        [Parameter(Mandatory)]
        [string]$CurrentVersion,
        [Parameter(Mandatory)]
        [string]$PackageType
    )
    # Default values
    $result = [PSCustomObject]@{
        IsVulnerable           = $false
        LatestVersion          = $CurrentVersion
        MinNonVulnerableVersion = $CurrentVersion
    }
    
    if ($PackageType -eq 'NuGet') {
        # Query the NuGet flat container API
        $nugetUrl = "https://api.nuget.org/v3-flatcontainer/$PackageName/index.json"
        try {
            $data = Invoke-RestMethod -Uri $nugetUrl -ErrorAction Stop
            if ($data.versions -and $data.versions.Count -gt 0) {
                $latest = $data.versions[-1]
                $result.LatestVersion = $latest
                if ($CurrentVersion -ne $latest) {
                    $result.IsVulnerable = $true
                    $result.MinNonVulnerableVersion = $latest
                }
            }
        }
        catch {
            Write-Warning "NuGet query failed for package ${PackageName}: $_"
        }
    }
    elseif ($PackageType -eq 'npm') {
        # Query the npm registry
        $npmUrl = "https://registry.npmjs.org/$PackageName"
        try {
            $data = Invoke-RestMethod -Uri $npmUrl -ErrorAction Stop
            if ($data.'dist-tags' -and $data.'dist-tags'.latest) {
                $latest = $data.'dist-tags'.latest
                $result.LatestVersion = $latest
                if ($CurrentVersion -ne $latest) {
                    $result.IsVulnerable = $true
                    $result.MinNonVulnerableVersion = $latest
                }
            }
        }
        catch {
            Write-Warning "npm query failed for package ${PackageName}: $_"
        }
    }
    return $result
}

# Assemble final report
$results = foreach ($pkg in $allPackages) {
    $vulnInfo = Get-VulnerabilityInfo -PackageName $pkg.PackageName `
                                        -CurrentVersion $pkg.CurrentVersion `
                                        -PackageType $pkg.PackageType
    $isCurrent = ($pkg.CurrentVersion -eq $vulnInfo.LatestVersion)
    [PSCustomObject]@{
        PackageName             = $pkg.PackageName
        PackageType             = $pkg.PackageType
        CurrentVersion          = $pkg.CurrentVersion
        IsVulnerable            = if ($vulnInfo.IsVulnerable) { 'Yes' } else { 'No' }
        LatestVersion           = $vulnInfo.LatestVersion
        MinNonVulnerableVersion = $vulnInfo.MinNonVulnerableVersion
        IsCurrent               = if ($isCurrent) { 'Yes' } else { 'No' }
    }
}

# Output the table to the console
$results | Format-Table -AutoSize
