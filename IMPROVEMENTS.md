# VCF9_deploy - Improvements and Optimizations

---

## CRITICAL: Bugs and Data Integrity

### 1. Confirmation prompt always exits (fleet deployment)

`vcf-automated-fleet-deployment.ps1:483`

```powershell
if($answer -ne "Y" -or $answer -ne "y") {
    exit
}
```

This condition is always true. If the user types "Y", then `$answer -ne "y"` is true
(case-sensitive), so the `-or` evaluates to true and the script exits. Fix:

```powershell
if($answer -ne "Y" -and $answer -ne "y") {
    exit
}
```

Or use case-insensitive comparison: `if($answer -inotmatch "^y$")`

### 2. Duplicate MGMT edge cluster config block

`SharedConfigs/VCFDeploymentConfig.ps1` lines 207-250 and 261-306 define the same
MGMT edge cluster variables twice. The second block silently overwrites the first.

First block (lines 238-250): Uses VLAN 106/107, IPs 10.2.106.x/10.2.107.x
Second block (lines 294-306): Uses VLAN 90/91, IPs 10.2.90.x/10.2.91.x

The second block also adds `$MGMTEdgeMgmtPrefix` and `$MGMTEdgeTEPPrefix` that the
first block is missing, which means the first block is an older version that was not
removed. Delete lines 207-250 (the first, incomplete block).

### 3. WLD network pool uses wrong subnets

`SharedConfigs/VCFDeploymentConfig.ps1` lines 187-198:

```powershell
$WLDvMotionCidr    = "10.10.201.0/24"
$WLDvMotionGateway = "10.10.201.1"
$WLDVsanCidr       = "10.10.203.0/24"
$WLDVsanGateway    = "10.10.203.1"
```

These use the `10.10.x.x` range, but everything else in the config uses `10.2.x.x`.
The WLD vMotion and vSAN networks defined elsewhere are:
- `$NestedWLDESXivMotionNetworkCidr = "10.2.201.0/24"` (line 108)
- `$NestedWLDESXivSANNetworkCidr = "10.2.202.0/24"` (line 109)

This mismatch means the WLD network pool created by `Get-OrCreate-WLDNetworkPool`
will be on a completely different subnet from the actual host networks. Fix:

```powershell
$WLDvMotionCidr    = "10.2.201.0/24"
$WLDvMotionGateway = "10.2.201.1"
$WLDvMotionStart   = "10.2.201.10"
$WLDvMotionEnd     = "10.2.201.50"
$WLDVsanCidr       = "10.2.202.0/24"
$WLDVsanGateway    = "10.2.202.1"
$WLDVsanStart      = "10.2.202.10"
$WLDVsanEnd        = "10.2.202.50"
```

### 4. VLAN ID mismatch between DNS script and deployment config

`CreateSharedVCF-VVF-DNS-Zones.ps1` lines 134-140 uses VLANs 2100-2160:
```powershell
$vcfMgmtVlanId = "2100"
$vcfVMotionVlanId = "2110"
```

`SharedConfigs/VCFDeploymentConfig.ps1` uses VLANs 100-105:
```powershell
$ESXMGMTVLAN = "100"
$VMMGMTVLAN = "101"
```

If the DNS script is for a different VLAN scheme (different physical environment), this
should be documented. If they target the same environment, align the VLAN IDs. The
DNS script also uses completely different IP ranges for some networks (192.168.168.x
for edge uplinks vs 10.2.90.x in the deployment config).

---

## CRITICAL: Security

### 5. All passwords hardcoded in plaintext

Every config file and JSON spec contains plaintext passwords committed to git:
- `VMware1!VMware1!` (SDDC Manager, vCenter, NSX, Operations)
- `VMwareVCF9!` (ESXi hosts, physical vCenter)
- `vcf123!` (offline depot)

These are in git history and cannot be removed by simply changing the files.

Recommendations:
- Move credentials to a separate `secrets.ps1` that is gitignored
- Have scripts prompt for passwords at runtime, or accept them as parameters
- Add a `.gitignore` (the repo has none)
- Consider rotating passwords after deployment

Example `.gitignore`:

```
secrets.ps1
*.log
*.tmp
```

### 6. Certificate validation disabled everywhere

All API calls use `-SkipCertificateCheck`. For a lab this is acceptable, but
it should be opt-in rather than unconditional. Consider a config variable:

```powershell
$SkipCertValidation = $true  # Set to $false for production
```

Then use `-SkipCertificateCheck:$SkipCertValidation` in API calls.

### 7. Empty BGP peer passwords

`vcf-edge-cluster-deployment.ps1` lines 242, 251, 265, 274:
```powershell
"bgpPeerPassword" = ""
```

BGP sessions without authentication are vulnerable to route injection. Add a
password variable to the config and use it in the edge cluster spec.

---

## HIGH: Code Quality

### 8. Duplicated functions across scripts

`My-Logger`, `Get-VCFSDDCmToken`, `Download-VCFBundle`, `Delete-VCFBundle`,
`Verify-VCFAPIEndpoint`, `Connect-VCFDepot`, `Sync-VCFDepot` are all
copy-pasted across `vcf-automated-fleet-deployment.ps1` and
`vcf-automated-wld-deployment.ps1`.

Extract shared functions into a common module file:

```
SharedConfigs/VCFCommonFunctions.ps1
```

Then dot-source it at the top of each script:
```powershell
. "$PSScriptRoot/SharedConfigs/VCFCommonFunctions.ps1"
```

### 9. Hardcoded VLAN IDs in JSON generation

`vcf-automated-fleet-deployment.ps1` lines 965-980 hardcode VLAN IDs in the
management domain JSON spec:

```powershell
"vlanId" = "101"   # VMOTION (line 965)
"vlanId" = "103"   # VSAN (line 980)
```

These should reference config variables (`$VMMGMTVLAN + 1` for vMotion, etc.)
or be defined as explicit variables in the config file.

### 10. Hardcoded Windows paths

`SharedConfigs/VCFDeploymentConfig.ps1` lines 31-32:
```powershell
$NestedESXiApplianceOVA = "c:\vcf_deploy\images\Nested_ESXi9.0.1_..."
$VCFInstallerOVA = "c:\vcf_deploy\images\VCF-SDDC-Manager-..."
```

`CreateSharedVCF-VVF-DNS-Zones.ps1` lines 10-19:
```powershell
$TemplateFile = "C:\vcf_deploy\DNSTemplate.csv"
$OutputFolder = "C:\vcf_deploy\SharedConfigs"
```

Use `$PSScriptRoot` for relative paths, or at least use variables that can
be overridden. Consider supporting both Windows and Linux paths.

### 11. No error recovery or rollback

If any step fails mid-deployment, the script exits (or breaks) leaving
partially deployed VMs and incomplete configurations. There is no cleanup
logic. At minimum, add a summary of what was deployed at exit:

```powershell
trap {
    My-Logger "DEPLOYMENT FAILED at step: $currentStep" "red"
    My-Logger "Deployed VMs so far: $deployedVMs" "yellow"
    My-Logger "Manual cleanup may be required" "yellow"
}
```

### 12. Magic timeout numbers

Various hardcoded sleep/timeout values with no explanation:
- `sleep 120` (lines 165, 540, 586 in fleet script) - 2 minute sleep
- `sleep 60` (line 273 in fleet script) - 1 minute sleep
- `sleep 120` after bundle download check labeled as "5min" (line 361)
- `TimeoutMinutes = 120` (edge cluster Wait-VCFTask)
- `TimeoutMinutes = 60` (supervisor Wait-SupervisorCluster)
- `TimeoutMinutes = 45` (supervisor actual call on line 659)

Define these as config variables:

```powershell
$APIReadyPollInterval = 120    # seconds between API readiness checks
$DepotSyncPollInterval = 60    # seconds between depot sync checks
$EdgeDeployTimeout = 120       # minutes for edge cluster deployment
$SupervisorDeployTimeout = 45  # minutes for supervisor deployment
```

### 13. Missing input validation

No validation that:
- IP addresses are valid
- CIDR ranges do not overlap
- VLAN IDs are within 1-4094
- Required config variables are set (non-empty)
- OVA files are accessible and valid
- Network pools match expected schema

Add a validation function at the start of each script:

```powershell
Function Validate-Config {
    $errors = @()
    if (-not $SddcManagerIP) { $errors += "SddcManagerIP is not set" }
    if (-not ($SddcManagerIP -match '^\d{1,3}(\.\d{1,3}){3}$')) {
        $errors += "SddcManagerIP '$SddcManagerIP' is not a valid IP"
    }
    # ... more checks
    if ($errors.Count -gt 0) {
        $errors | ForEach-Object { My-Logger $_ "red" }
        exit 1
    }
}
```

---

## MEDIUM: Maintainability

### 14. README is empty

`README.md` contains only `# vcf9`. It should document:
- What this project does
- Prerequisites (software, hardware, network)
- Execution order
- Example usage
- Known limitations

### 15. No .gitignore

The repository has no `.gitignore`. Add one to exclude:
- `*.log` (deployment logs)
- `secrets.ps1` (if credentials are extracted)
- `*.tmp`
- Generated JSON specs (they contain passwords)

### 16. Duplicate "DO NOT EDIT BEYOND HERE" comment

`vcf-edge-cluster-deployment.ps1` lines 33-35:
```powershell
#### DO NOT EDIT BEYOND HERE ####

#### DO NOT EDIT BEYOND HERE ####
```

Minor but indicates sloppy copy-paste.

### 17. Inconsistent log format timestamp

Fleet and WLD scripts use 12-hour format: `"MM-dd-yyyy_hh:mm:ss"`
Edge script uses 24-hour format: `"MM-dd-yyyy_HH:mm:ss"`

The 12-hour format is ambiguous (no AM/PM indicator). All scripts should
use 24-hour format (`HH`).

### 18. Token functions re-authenticate on every API call

`Get-VCFInstallerToken` and `Get-VCFSDDCmToken` are called inside most API
functions, meaning every single API call re-authenticates. Cache the token
with an expiry check:

```powershell
$script:cachedToken = $null
$script:tokenExpiry = [datetime]::MinValue

Function Get-VCFSDDCmToken {
    if ($script:cachedToken -and (Get-Date) -lt $script:tokenExpiry) {
        return $script:cachedToken
    }
    # ... authenticate ...
    $script:cachedToken = $headers
    $script:tokenExpiry = (Get-Date).AddMinutes(15)
    return $headers
}
```

---

## LOW: Performance Optimizations

### 19. Sequential ESXi VM deployment

Both MGMT and WLD ESXi VMs are deployed sequentially in a foreach loop.
Each deployment takes several minutes. Since they are independent,
deploy them in parallel using PowerShell jobs:

```powershell
$jobs = @()
$NestedESXiHostnameToIPsForManagementDomain.GetEnumerator() | ForEach-Object {
    $jobs += Start-Job -ScriptBlock {
        param($VMName, $VMIPAddress, ...)
        # Deploy VM logic here
    } -ArgumentList $_.Key, $_.Value, ...
}
$jobs | Wait-Job
$jobs | Receive-Job
```

This could cut deployment time roughly proportional to the number of hosts.

### 20. Excessive polling frequency for long operations

`Sync-VCFDepot` polls every 60 seconds. `Verify-VCFAPIEndpoint` polls every
120 seconds. These are reasonable, but `Download-VCFRelease` says "sleeping
for 5min" on line 360 but actually does `sleep 120` (2 minutes). The comment
is misleading and the interval could be longer for bundle downloads that take
30+ minutes.

### 21. Re-reading network pools after creation

`Get-OrCreate-WLDNetworkPool` (wld-deployment.ps1 line 176) re-reads all pools
via a second GET call after creating a new pool, instead of parsing the ID from
the creation response. The POST response likely contains the ID already -- use it
directly:

```powershell
$newPool = ($createResponse.Content | ConvertFrom-Json)
return $newPool.id
```

### 22. Redundant OVF configuration parsing

In the ESXi deployment loop (fleet-deployment.ps1 line 594), `Get-OvfConfiguration`
is called for every VM even though the configuration template is the same for all
VMs in a domain. Parse once, clone per VM.

---

## LOW: Nice-to-Have Enhancements

### 23. Add a cleanup/teardown script

No script exists to remove a deployment. A `vcf-teardown.ps1` that:
- Stops and removes VMs in the vApp
- Deletes the vApp and VM folder
- Optionally removes DNS records

### 24. Add progress tracking

For multi-hour deployments, a simple progress summary would help:

```powershell
My-Logger "=== Progress: Step 3/8 - Deploying ESXi VMs (2 of 4 complete) ==="
```

### 25. Support for variable number of hosts

Host lists are hardcoded hashtables. Consider accepting a count and a base IP:

```powershell
$MGMTHostCount = 4
$MGMTHostBaseIP = "10.2.100.10"
$MGMTHostPrefix = "esx"
```

### 26. Add dry-run mode

The supervisor script has `-ValidateOnly` which is good. Extend this pattern to
all scripts so users can verify configuration without deploying anything.

### 27. Structured logging

Current logging is text-only. Consider also writing a JSON log for
machine-parseable deployment records:

```json
{"timestamp": "...", "level": "INFO", "step": "deployESXi", "host": "esx01", "status": "success"}
```

---

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| Critical (bugs) | 4 | Confirmation logic bug, duplicate config, wrong subnets, VLAN mismatch |
| Critical (security) | 3 | Plaintext passwords, no cert validation, no BGP auth |
| High (code quality) | 6 | Duplicated functions, hardcoded values, no validation, no rollback |
| Medium (maintainability) | 5 | Missing README, no gitignore, inconsistent formatting, token caching |
| Low (performance) | 4 | Sequential deployment, polling intervals, redundant API calls |
| Low (enhancements) | 5 | Teardown script, progress tracking, dry-run, structured logs |

Start with the 4 critical bugs -- items 1, 2, 3, and the confirmation logic fix
are quick wins that prevent deployment failures. The security items (5, 6, 7)
should follow, especially adding `.gitignore` and extracting credentials. The
shared function extraction (item 8) will pay off immediately by reducing
maintenance burden across all scripts.
