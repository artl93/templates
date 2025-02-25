# InspectNugetReferences.ps1

param(
    [string]$DirectoryFilter = ""
)

$results = @()

Write-Host "Scanning subdirectories for project files..."
$projectDirs = Get-ChildItem -Directory
if ($DirectoryFilter) {
    $projectDirs = $projectDirs | Where-Object { $_.Name -like "*$DirectoryFilter*" }
}

foreach ($dir in $projectDirs) {
    Write-Host "Inspecting project in directory: $($dir.Name)"
    
    # Find the first *.csproj file (assuming one project file per folder)
    $csprojFile = Get-ChildItem -Path $dir.FullName -Filter *.csproj -Recurse | Select-Object -First 1
    if ($csprojFile) {
        Write-Host "Found project file: $($csprojFile.Name)"
        try {
            [xml]$xmlContent = Get-Content $csprojFile.FullName -ErrorAction Stop
        }
        catch {
            Write-Host "Error reading $($csprojFile.FullName)" -ForegroundColor Red
            continue
        }
        
        # Find all PackageReference elements (this works if your project file uses the SDK style)
        $packageRefs = $xmlContent.Project.ItemGroup.PackageReference
        if ($packageRefs) {
            foreach ($pkg in $packageRefs) {
                $results += [pscustomobject]@{
                    Project = $dir.Name
                    Package = $pkg.Include
                    Version = $pkg.Version
                }
                Write-Host "Found NuGet package '$($pkg.Include)' version '$($pkg.Version)' in project $($dir.Name)"
            }
        }
        else {
            Write-Host "No PackageReference found in $($csprojFile.Name)"
        }
    }
    else {
        Write-Host "No project file found in $($dir.Name)" -ForegroundColor Yellow
    }
}

# Output the results to a JSON file.
$jsonOutput = "NugetReferences.json"
$results | ConvertTo-Json -Depth 3 | Out-File $jsonOutput
Write-Host "NuGet references have been written to $jsonOutput"
