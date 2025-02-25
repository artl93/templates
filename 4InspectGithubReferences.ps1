# InspectGithubReferences.ps1

# Define a function to guess the GitHub URL based on the template (project) name.
function Get-GitHubUrl($projectName) {
    # Adjust this URL as needed for your organization.
    return "https://github.com/YourOrg/$projectName"
}

# Read the NuGet references JSON.
$jsonFile = "NugetReferences.json"
if (-not (Test-Path $jsonFile)) {
    Write-Host "JSON file $jsonFile not found. Please run InspectNugetReferences.ps1 first." -ForegroundColor Red
    exit
}
$nugetData = Get-Content $jsonFile | ConvertFrom-Json

$report = @()

# Group the data by project.
$projects = $nugetData | Group-Object -Property Project

foreach ($group in $projects) {
    $projectName = $group.Name
    $projectPath = Join-Path -Path (Get-Location) -ChildPath $projectName
    Write-Host "Processing GitHub info for project: $projectName"

    # Construct the GitHub repository URL.
    $githubUrl = Get-GitHubUrl $projectName

    # Search for the .csproj file in the project folder.
    $csprojFile = Get-ChildItem -Path $projectPath -Filter *.csproj -Recurse | Select-Object -First 1
    if (-not $csprojFile) {
        Write-Host "No project file found for $projectName" -ForegroundColor Yellow
        continue
    }

    # Check for the presence of a cgmanifest.json in the project folder (or its subfolders).
    $cgManifestExists = (Get-ChildItem -Path $projectPath -Filter "cgmanifest.json" -Recurse -ErrorAction SilentlyContinue) -ne $null

    # For each NuGet package in this project, locate the exact line.
    foreach ($entry in $group.Group) {
        $package = $entry.Package
        Write-Host "Searching for package reference '$package' in $($csprojFile.Name)..."
        $matches = Select-String -Path $csprojFile.FullName -Pattern $package
        $lineInfo = $null
        if ($matches) {
            # Take the first match.
            $match = $matches[0]
            $lineInfo = "File: $($csprojFile.Name), Line: $($match.LineNumber), Text: $($match.Line.Trim())"
        }
        else {
            $lineInfo = "No reference line found for package '$package'."
        }
        
        $report += [pscustomobject]@{
            Project       = $projectName
            GitHubUrl     = $githubUrl
            Package       = $package
            SourceLine    = $lineInfo
            HasCgManifest = $cgManifestExists
        }
    }
}

# Output the report. You can output to a file or simply print to the console.
$reportFile = "GitHubSourceReport.json"
$report | ConvertTo-Json -Depth 4 | Out-File $reportFile
Write-Host "GitHub source report generated: $reportFile"
