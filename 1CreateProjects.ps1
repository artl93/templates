param(
    [string[]]$Filter
)

# CreateProjects.ps1

# Run 'dotnet new list' and capture the output.
Write-Host "Running 'dotnet new list'..."
$output = dotnet new list

Write-Host "Parsing templates from dotnet new list output..."
$templates = @()

# Process each line to extract the Short Name.
foreach ($line in $output) {
    # Skip header lines and blank lines.
    if ($line -match "Template Name\s+Short Name\s+Language\s+Tags") { continue }
    if ($line -match "^-{2,}") { continue }
    if ($line.Trim() -eq "") { continue }
    
    # Split on two or more whitespace characters.
    $columns = $line -split "\s{2,}"
    if ($columns.Count -ge 2) {
        $shortNames = $columns[1].Trim() -split ","
        foreach ($shortName in $shortNames) {
            $shortName = $shortName.Trim()
            # Avoid duplicates if any.
            if ($templates -notcontains $shortName) {
                $templates += $shortName
            }
        }
    }
}

# Apply filter if provided using partial matches.
if ($Filter) {
    Write-Host "Filtering templates using partial matches for: $($Filter -join ', ')"
    $templates = $templates | Where-Object {
        $match = $false
        foreach ($f in $Filter) {
            if ($_ -like "*$f*") {
                $match = $true
                break
            }
        }
        $match
    }
}

Write-Host "Found $($templates.Count) templates. Creating projects..."

foreach ($template in $templates) {
    Write-Host "----------------------------------------"
    Write-Host "Processing template: $template"

    # Check if the directory already exists.
    if (Test-Path $template) {
        Write-Host "Directory '$template' already exists. Skipping..."
        continue
    }

    # Create a folder named after the template short name.
    Write-Host "Creating directory: $template"
    New-Item -ItemType Directory -Path $template | Out-Null
    
    # Create the project inside the folder.
    Push-Location $template
    Write-Host "Running: dotnet new $template --name $template"
    dotnet new $template --name $template
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: dotnet new failed for template $template" -ForegroundColor Red
    } else {
        Write-Host "Template $template created successfully."
    }
    Pop-Location
}

Write-Host "Project creation completed."