const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Returns list of directories that have a top-level package.json.
// This function looks in the current directory and its immediate subdirectories.
function getProjects(folder) {
    let projects = [];
    // If the folder contains a package.json, add it and do not scan deeper.
    if (fs.existsSync(path.join(folder, 'package.json'))) {
        projects.push(folder);
        return projects;
    }
    // Otherwise, scan its subdirectories.
    const items = fs.readdirSync(folder);
    for (const item of items) {
        const fullPath =  path.join(folder, item);
        if (fs.statSync(fullPath).isDirectory() && item !== 'node_modules') {
            projects = projects.concat(getProjects(fullPath));
        }
    }
    return projects;
}

// Parse npm audit output to record vulnerable packages
// Returns an object mapping package name to the minimum safe (non‑vulnerable) version
function buildVulnerabilityMap(auditJson) {
    let vulnMap = {};
    // In older versions of npm audit, vulnerabilities are found under "advisories"
    if (auditJson.advisories) {
        Object.values(auditJson.advisories).forEach(advisory => {
            const pkgName = advisory.module_name;
            // If multiple advisories exist for the same package, we take the first reported patched version.
            if (advisory.patched_versions) {
                // Note: patched_versions is a semver range (e.g. ">=2.3.1")
                if (!vulnMap[pkgName]) {
                    vulnMap[pkgName] = advisory.patched_versions;
                }
            }
        });
    }
    // In newer versions of npm audit (npm7+), the structure is different.
    // Check for the "actions" key and loop over the resolves.
    if (auditJson.actions) {
        auditJson.actions.forEach(action => {
            if (action.resolves) {
                action.resolves.forEach(resolve => {
                    const pkgName = resolve.path.split('>')[0]; // extract the top-level package
                    if (resolve.range) {
                        if (!vulnMap[pkgName]) {
                            vulnMap[pkgName] = resolve.range;
                        }
                    }
                });
            }
        });
    }
    return vulnMap;
}

// Get outdated packages info via npm outdated --json
// Returns an object mapping package name to their version info.
function getOutdatedInfo(projectDir) {
    let outdated = {};
    try {
        const stdout = execSync('npm outdated --json', { cwd: projectDir, encoding: 'utf-8' });
        outdated = JSON.parse(stdout);
    } catch (err) {
        // If npm outdated exits with non-zero status, it might be because nothing is outdated.
        // In that case, we try to parse the output.
        if (err.stdout) {
            try {
                outdated = JSON.parse(err.stdout);
            } catch (e) {
                // Unable to parse, leave outdated empty.
            }
        }
    }
    return outdated;
}

// Process each project folder to generate dependency audit details.
function processProject(projectDir) {
    console.log(`Scanning project: ${projectDir}`);
    let projectResults = [];
    let auditData = {};
    try {
        const auditOutput = execSync('npm audit --json', { cwd: projectDir, encoding: 'utf-8' });
        auditData = JSON.parse(auditOutput);
    } catch (err) {
        // If audit fails, log error and continue.
        console.warn(`npm audit failed for project ${projectDir}: ${err.message}`);
    }
    const vulnMap = buildVulnerabilityMap(auditData);
    const outdatedInfo = getOutdatedInfo(projectDir);
    const pkgPath = path.join(projectDir, 'package.json');
    let pkg;
    try {
        pkg = require(pkgPath);
    } catch (err) {
        console.error(`Unable to read package.json in ${projectDir}`);
        return projectResults;
    }
    // Merge dependencies and devDependencies.
    const allDeps = Object.assign({}, pkg.dependencies || {}, pkg.devDependencies || {});

    // For each dependency
    Object.keys(allDeps).forEach(dep => {
        // Determine vulnerable flag based on whether audit reported a patched version.
        const isVulnerable = vulnMap.hasOwnProperty(dep);
        // Minimum non-vulnerable version if applicable.
        const minNonVulnerable = isVulnerable ? vulnMap[dep] : 'N/A';

        // Get version info from npm outdated if available.
        let currentVersion = 'N/A';
        let upToDate = 'N/A';
        if (outdatedInfo.hasOwnProperty(dep)) {
            const info = outdatedInfo[dep];
            currentVersion = info.current;
            // Compare current version with latest.
            upToDate = (info.current === info.latest) ? 'Yes' : 'No';
        } else {
            // If not present in outdated, assume version is up-to-date.
            currentVersion = allDeps[dep];
            upToDate = 'Yes';
        }
        projectResults.push({
            project: projectDir,
            package: dep,
            vulnerable: isVulnerable ? 'Yes' : 'No',
            minNonVulnerable: minNonVulnerable,
            currentVersion: currentVersion,
            upToDate: upToDate
        });
    });
    return projectResults;
}

// Main execution: scan the base directory for projects and process each one.
function main() {
    // Change this to the root folder you want to scan.
    const baseDir = process.cwd();
    const projects = getProjects(baseDir);
    let allResults = [];

    projects.forEach(projectDir => {
        const res = processProject(projectDir);
        allResults = allResults.concat(res);
    });

    // Save results to a JSON file.
    const outFile = path.join(baseDir, 'audit-results.json');
    fs.writeFileSync(outFile, JSON.stringify(allResults, null, 2));
    console.log(`Results saved to ${outFile}`);

    // Present results as a table in the console.
    console.table(allResults, ['project', 'package', 'vulnerable', 'minNonVulnerable', 'currentVersion', 'upToDate']);
}

main();