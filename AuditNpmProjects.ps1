# Function to get projects with a top-level package.json
function Get-Projects {
    param (
        [string]$folder
    )
    $projects = @()
    if (Test-Path -Path (Join-Path -Path $folder -ChildPath 'package.json')) {
        $projects += $folder
        return $projects
    }
    $items = Get-ChildItem -Path $folder -Directory
    foreach ($item in $items) {
        if ($item.Name -ne 'node_modules' -and $item.Name -ne 'bin' -and $item.Name -ne 'obj') {
            $projects += Get-Projects -folder (Join-Path -Path $folder -ChildPath $item.Name)
        }
    }
    return $projects
}

# Function to build vulnerability map from npm audit output
function Build-VulnerabilityMap {
    param (
        [hashtable]$auditJson
    )
    $vulnMap = @{}
    if ($auditJson.advisories) {
        foreach ($advisory in $auditJson.advisories.Values) {
            $pkgName = $advisory.module_name
            if ($advisory.patched_versions -and -not $vulnMap.ContainsKey($pkgName)) {
                $vulnMap[$pkgName] = $advisory.patched_versions
            }
        }
    }
    if ($auditJson.actions) {
        foreach ($action in $auditJson.actions) {
            foreach ($resolve in $action.resolves) {
                $pkgName = $resolve.path.Split('>')[0]
                if ($resolve.range -and -not $vulnMap.ContainsKey($pkgName)) {
                    $vulnMap[$pkgName] = $resolve.range
                }
            }
        }
    }
    return $vulnMap
}

# Function to get outdated packages info via npm outdated --json
function Get-OutdatedInfo {
    param (
        [string]$projectDir
    )
    $outdated = @{}
    try {
        $stdout = & npm outdated --json -C $projectDir
        $outdated = $stdout | ConvertFrom-Json
    } catch {
        Write-Warning "npm outdated failed in $projectDir : $_"
        if ($_.Exception.Response) {
            try {
                $outdated = $_.Exception.Response | ConvertFrom-Json
            } catch {
                Write-Warning "Failed to parse npm outdated output: $_"
            }
        }
    }
    return $outdated
}

# Function to process each project folder to generate dependency audit details
function Process-Project {
    param (
        [string]$projectDir
    )
    Write-Output "Scanning project: $projectDir"
    $projectResults = @()
    $auditData = @{}
    try {
        $auditOutput = & npm audit --json -C $projectDir
        $auditData = $auditOutput | ConvertFrom-Json
    } catch {
        Write-Warning "npm audit failed for project $projectDir : $_"
    }
    $vulnMap = Build-VulnerabilityMap -auditJson $auditData
    $outdatedInfo = Get-OutdatedInfo -projectDir $projectDir
    $pkgPath = Join-Path -Path $projectDir -ChildPath 'package.json'
    try {
        $pkg = Get-Content -Path $pkgPath | ConvertFrom-Json
    } catch {
        Write-Error "Unable to read package.json in $projectDir"
        return $projectResults
    }
    $allDeps = @{}
    if ($pkg.dependencies) { $pkg.dependencies.GetEnumerator() | ForEach-Object { $allDeps.Add($_.Key, $_.Value) } }
    if ($pkg.devDependencies) { $pkg.devDependencies.GetEnumerator() | ForEach-Object { $allDeps.Add($_.Key, $_.Value) } }

    foreach ($dep in $allDeps.Keys) {
        $isVulnerable = $vulnMap.ContainsKey($dep)
        $minNonVulnerable = if ($isVulnerable) { $vulnMap[$dep] } else { 'N/A' }
        $currentVersion = 'N/A'
        $upToDate = 'N/A'
        if ($outdatedInfo.ContainsKey($dep)) {
            $info = $outdatedInfo[$dep]
            $currentVersion = $info.current
            $upToDate = if ($info.current -eq $info.latest) { 'Yes' } else { 'No' }
        } else {
            $currentVersion = $allDeps[$dep]
            $upToDate = 'Yes'
        }
        $projectResults += [pscustomobject]@{
            project = $projectDir
            package = $dep
            vulnerable = if ($isVulnerable) { 'Yes' } else { 'No' }
            minNonVulnerable = $minNonVulnerable
            currentVersion = $currentVersion
            upToDate = $upToDate
        }
    }
    return $projectResults
}

# Main execution: scan the base directory for projects and process each one
function Main {
    $baseDir = Get-Location
    Write-Output "Scanning base directory: $baseDir"
    $projects = Get-Projects -folder $baseDir
    Write-Output "Found projects: $($projects -join ', ')"
    $allResults = @()

    foreach ($projectDir in $projects) {
        $res = Process-Project -projectDir $projectDir
        $allResults += $res
    }

    $outFile = Join-Path -Path $baseDir -ChildPath 'audit-results.json'
    $allResults | ConvertTo-Json -Depth 3 | Set-Content -Path $outFile
    Write-Output "Results saved to $outFile"

    $allResults | Format-Table -Property project, package, vulnerable, minNonVulnerable, currentVersion, upToDate -AutoSize
}

Main