# BuildProjects.ps1

param(
    [string]$DirectoryFilter = ""
)

Write-Host "Starting build for all projects..."

$projectDirs = Get-ChildItem -Directory
if ($DirectoryFilter) {
    $projectDirs = $projectDirs | Where-Object { $_.Name -like "*$DirectoryFilter*" }
}

foreach ($dir in $projectDirs) {
    Write-Host "----------------------------------------"
    Write-Host "Processing project in directory: $($dir.Name)"
    Push-Location $dir.FullName

    # Enumerate all solution files in subfolders.
    $slnFiles = Get-ChildItem -Path . -Recurse -Filter *.sln
    if ($slnFiles) {
        foreach ($sln in $slnFiles) {
            Write-Host "Building solution: $($sln.FullName)" -ForegroundColor Cyan
            dotnet build $sln.FullName --verbosity detailed
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Build FAILED for solution $($sln.FullName)" -ForegroundColor Red
            }
            else {
                Write-Host "Build succeeded for solution $($sln.FullName)"
            }
        }
    }
    else {
        # If no solution file is found, build individual csproj files.
        $csprojFiles = Get-ChildItem -Path . -Recurse -Filter *.csproj
        if ($csprojFiles) {
            foreach ($proj in $csprojFiles) {
                Write-Host "Building project file: $($proj.FullName)" -ForegroundColor Cyan
                dotnet build $proj.FullName --verbosity detailed
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "Build FAILED for project file $($proj.FullName)" -ForegroundColor Red
                }
                else {
                    Write-Host "Build succeeded for project file $($proj.FullName)"
                }
            }
        }
        else {
            Write-Host "No solution or project files found in $($dir.FullName)" -ForegroundColor Yellow
        }
    }
    
    Pop-Location
}

Write-Host "All projects have been processed."
