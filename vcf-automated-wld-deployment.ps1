# Author: William Lam
# Website: https://williamlam.com
#
# MIGRATED TO VCF PowerCLI 9 (VMware.Sdk.Vcf.SddcManager)
# Original version using PowerVCF backed up to: vcf-automated-wld-deployment.ps1.powervcf.backup
# See MIGRATION_GUIDE.md for details on cmdlet mappings

param (
    [string]$EnvConfigFile
)

# Validate that the file exists
if ($EnvConfigFile -and (Test-Path $EnvConfigFile)) {
    . $EnvConfigFile  # Dot-sourcing the config file
} else {
    Write-Host -ForegroundColor Red "`nNo valid deployment configuration file was provided or file was not found.`n"
    exit
}

#### DO NOT EDIT BEYOND HERE ####

$confirmDeployment = 1
$updateSDDCMConfig = 1
$configureSDDCMConfig = 1
$generateWldHostCommissionJson = 1
$commissionHost = 1
$generateWLDDeploymentFile = 1
$startWLDDeployment = 1

$VCFManagementDomainVLCMImageName = "Management-Domain-ESXi-Personality"
$VCFWorkloadDomainUIJSONFile = "vcf-commission-host-ui.json"
$VCFWorkloadDomainAPIJSONFile = "vcf-commission-host-api.json"
$VCFWorkloadJSONFile = "vcf-$VCFWorkloadDomainName-deployment.json"
$verboseLogFile = "vcf-workload-domain-deployment.log"

$sddcManagerFQDN = "${SddcManagerHostname}.${VMDomain}"

"networkPoolName" = "$VCFWorkloadDomainPoolName";

$StartTime = Get-Date

Function My-Logger {
    param(
    [Parameter(Mandatory=$true)][String]$message,
    [Parameter(Mandatory=$false)][String]$color="green"
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_hh:mm:ss"

    Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
    Write-Host -ForegroundColor $color " $message"
    $logMessage = "[$timeStamp] $message"
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
}

Function Get-VCFSDDCmToken {
    $payload = @{
        "username" = "administrator@vsphere.local"
        "password" = $VCSASSOPassword
    }

    $body = $payload | ConvertTo-Json

    try {
        $requests = Invoke-WebRequest -Uri "https://${SddcManagerIP}/v1/tokens" -Method POST -SkipCertificateCheck -TimeoutSec 5 -Headers @{"Content-Type"="application/json";"Accept"="application/json"} -Body $body
        if($requests.StatusCode -eq 200) {
            $accessToken = ($requests.Content | ConvertFrom-Json).accessToken
        }
    } catch {
        My-Logger "Unable to retrieve SDDC Manager Token ..."
        exit
    }

    $headers = @{
        "Content-Type"="application/json"
        "Accept"="application/json"
        "Authorization"="Bearer ${accessToken}"
    }

    return $headers
}

Function Download-VCFBundle {
    param(
        [Parameter(Mandatory=$true)][String]$BundleId
    )

    $headers = Get-VCFSDDCmToken

    try {
        $payload = @{
            "bundleDownloadSpec" = @{
                "downloadNow" = $true
            }
        }

        $uri = "https://${SddcManagerIP}/v1/bundles/$bundleId"
        $method = "PATCH"
        $body = $payload | ConvertTo-Json

        if($Debug) {
            My-Logger "DEBUG: Method: $method"
            My-Logger "DEBUG: Uri: $uri"
            My-Logger "DEBUG: Body: $body"
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $headers -Body $body
    } catch {
        # Check if error is because bundle is already downloaded
        $errorMessage = $_.Exception.Message

        # Try to parse the error as JSON to check the error code
        try {
            $errorJson = $errorMessage | ConvertFrom-Json
            if($errorJson.errorCode -eq "BUNDLE_DOWNLOAD_ALREADY_DOWNLOADED") {
                My-Logger "Bundle ${bundleId} is already downloaded, skipping..." "yellow"
                return
            }
        } catch {
            # If JSON parsing fails, try simple string match
            if($errorMessage -match "BUNDLE_DOWNLOAD_ALREADY_DOWNLOADED") {
                My-Logger "Bundle ${bundleId} is already downloaded, skipping..." "yellow"
                return
            }
        }

        # Only log error if it's not already downloaded
        My-Logger "Failed to start VCF download for bundle ${bundleId}" "red"
        Write-Error "`n($errorMessage)`n"
        return
    }
}

Function Delete-VCFBundle {
    param(
        [Parameter(Mandatory=$true)][String]$BundleId
    )

    $headers = Get-VCFSDDCmToken

    try {
        $uri = "https://${SddcManagerIP}/v1/bundles/$bundleId"
        $method = "DELETE"
        $body = $null

        if($Debug) {
            My-Logger "DEBUG: Method: $method"
            My-Logger "DEBUG: Uri: $uri"
            My-Logger "DEBUG: Body: $body"
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $headers
    } catch {
        My-Logger "Failed to delete VCF bundle ${bundleId}" "red"
        Write-Error "`n($_.Exception.Message)`n"
        return
    }
}

Function Verify-VCFAPIEndpoint {
    param(
        [Parameter(Mandatory=$true)][String]$EndpointName,
        [Parameter(Mandatory=$true)][String]$EndpointIp
    )

    while(1) {
        try {
            $method = "GET"
            $uri = "https://${EndpointIp}/v1/system/appliance-info"
            $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5
            if($requests.StatusCode -eq 200) {
                My-Logger "`t${EndpointName} API is now ready!"
                break
            }
        } catch {
            My-Logger "${EndpointName} API is not ready yet, sleeping for 120 seconds ..."
            sleep 30
        }
    }
}

Function Connect-VCFDepot {
    param(
        [Parameter(Mandatory=$true)][String]$EndpointIp
    )

    $headers = Get-VCFSDDCmToken

    try {
        if($VCFInstallerSoftwareDepot -eq "offline") {
            $payload = @{
                "offlineAccount" = [Ordered]@{
                    "username" = $VCFInstallerDepotUsername
                    "password" = $VCFInstallerDepotPassword
                }
                "depotConfiguration" = @{
                    "isOfflineDepot" = $true
                    "hostname" = $VCFInstallerDepotHost
                    "port" = $VCFInstallerDepotPort
                }
            }
        } else {
            $payload = @{
                "vmwareAccount" = [Ordered]@{
                    "downloadToken" = $VCFInstallerDepotToken
                }
            }
        }

        $uri = "https://${EndpointIp}/v1/system/settings/depot"
        $method = "PUT"
        $body = $payload | ConvertTo-Json

        if($Debug) {
            My-Logger "DEBUG: Method: $method"
            My-Logger "DEBUG: Uri: $uri"
            My-Logger "DEBUG: Body: $body"
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $headers -Body $body
    } catch {
        My-Logger "Failed to connect to VCF Software Depot" "red"
        Write-Error "`n($_.Exception.Message)`n"
        return
    }

    if($requests.Statuscode -eq 202) {
        My-Logger "Successfully connected to VCF Software Depot ..."
    } else {
        My-Logger "Something went wrong updating connecting to VCF Software Depot" "yellow"
        $requests
        return
    }
}

Function Sync-VCFDepot {
    param(
        [Parameter(Mandatory=$true)][String]$EndpointIp
    )

    $headers = Get-VCFSDDCmToken

    try {
        $uri = "https://${EndpointIp}/v1/system/settings/depot/depot-sync-info"
        $method = "PATCH"
        $body = $null

        if($Debug) {
            My-Logger "DEBUG: Method: $method"
            My-Logger "DEBUG: Uri: $uri"
            My-Logger "DEBUG: Body: $body"
        }

        $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $headers
    } catch {
        My-Logger "Failed to sync VCF Software Depot" "red"
        Write-Error "`n($_.Exception.Message)`n"
        return
    }

    if($requests.Statuscode -eq 202) {
        My-Logger "Successfully started VCF Software Depot sync ..."
    } else {
        My-Logger "Something went wrong starting VCF Software Depot sync" "yellow"
        $requests
        return
    }

    while(1) {
        try {
            $uri = "https://${EndpointIp}/v1/system/settings/depot/depot-sync-info"
            $method = "GET"
            $body = $null

            if($Debug) {
                My-Logger "DEBUG: Method: $method"
                My-Logger "DEBUG: Uri: $uri"
                My-Logger "DEBUG: Body: $body"
            }

            $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $headers
            if($requests.StatusCode -eq 200) {
                if(($requests.Content | ConvertFrom-Json).syncStatus -ne "SYNCED") {
                    My-Logger "VCF Software Depot Sync not ready yet, sleeping for 60 seconds ..."
                    sleep 60
                } else {
                    My-Logger "Successfully synced VCF Software Depot ..."
                    break
                }
            }
        }
        catch {
            My-Logger "Failed to sync VCF Software Depot ..."
            $requests
            return
        }
    }
}

Function Download-VCFRelease {
    param(
        [Parameter(Mandatory=$true)][String]$EndpointIp
    )

    $headers = Get-VCFSDDCmToken

    try {
        $uri = "https://${EndpointIp}/v1/releases/${VCFInstallerProductSKU}/release-components?releaseVersion=${VCFInstallerProductVersion}&automatedInstall=true&imageType=INSTALL"
        $method = "GET"
        $body = $null

        if($Debug) {
            My-Logger "DEBUG: Method: $method"
            My-Logger "DEBUG: Uri: $uri"
            My-Logger "DEBUG: Body: $body"
        }

        $requests = Invoke-WebRequest -Uri $uri -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers $headers
    } catch {
        My-Logger "Failed to retrieve $VCFInstallerProductSKU release" "red"
        Write-Error "`n($_.Exception.Message)`n"
        return
    }

    if($requests.Statuscode -eq 200) {
        My-Logger "Successfully retrieved $VCFInstallerProductSKU release ..."
    } else {
        My-Logger "Something went wrong retreiving $VCFInstallerProductSKU release" "yellow"
        $requests
        return
    }

    # Retreive the components for a given SKU
    $bundle = @{}
    $components = (($requests.Content | ConvertFrom-Json).elements | where {$_.releaseVersion -eq $VCFInstallerProductVersion}).components
    foreach ($component in $components) {
        $bundle[$component.name]=$component.versions.artifacts.bundles.id
    }

    # Download Bundle
    $bundle.GetEnumerator() | ForEach-Object {
        My-Logger "Starting download for $($_.key) component ..."
        Download-VCFBundle -BundleId $_.value
    }

    while(1) {
        try {
            $uri = "https://${EndpointIp}/v1/bundles/download-status?releaseVersion=${VCFInstallerVersion}&imageType=INSTALL"
            $method = "GET"
            $body = $null

            if($Debug) {
                My-Logger "DEBUG: Method: $method"
                My-Logger "DEBUG: Uri: $uri"
                My-Logger "DEBUG: Body: $body"
            }

            $requests = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -TimeoutSec 5 -Headers $headers
            if($requests.StatusCode -eq 200) {
                $downloadStatus = ($requests.Content | ConvertFrom-Json).elements.downloadStatus

                if($downloadStatus-contains "INPROGRESS" -or $downloadStatus -contains "SCHEDULED" -or $downloadStatus -contains "VALIDATING" -or $downloadStatus-contains "FAILED") {
                    if($downloadStatus -contains "FAILED") {
                        $failedBundles = (($requests.Content | ConvertFrom-Json).elements | where {$_.downloadStatus -eq "FAILED"})

                        foreach ($failedBundle in $failedBundles) {
                            My-Logger "Re-attempting to download $(${failedBundle}.componentType) component"
                            Delete-VCFBundle -BundleId $(${failedBundle}.bundleId)
                            Download-VCFBundle -BundleId $(${failedBundle}.bundleId)
                        }
                    }
                    My-Logger "$VCFInstallerProductSKU bundle download has not completed or has not been validated yet, sleeping for 5min ..."
                    sleep 120
                } else {
                    My-Logger "Successfully downloaded $VCFInstallerProductSKU ${VCFInstallerProductVersion} bundle ..."
                    break
                }
            }
        }
        catch {
            My-Logger "Failed to wait for $VCFInstallerProductSKU bundle download ..."
            $requests
            return
        }
    }
}

if($confirmDeployment -eq 1) {
    Write-Host -ForegroundColor Magenta "`nPlease confirm the following configuration will be deployed:`n"

    Write-Host -ForegroundColor Yellow "---- VCF Automated Workload Domain Deployment Configuration ---- "
    Write-Host -NoNewline -ForegroundColor Green "Workload Domain Name: "
    Write-Host -ForegroundColor White $VCFWorkloadDomainName
    Write-Host -NoNewline -ForegroundColor Green "Workload Domain Org Name: "
    Write-Host -ForegroundColor White $VCFWorkloadDomainOrgName

    Write-Host -ForegroundColor Yellow "`n---- Target SDDC Manager Configuration ---- "
    Write-Host -NoNewline -ForegroundColor Green "SDDC Manager Hostname: "
    Write-Host -ForegroundColor White $sddcManagerFQDN

    Write-Host -ForegroundColor Yellow "`n---- Workload Domain vCenter Server Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "vCenter Server Hostname: "
    Write-Host -ForegroundColor White "${VCFWorkloadDomainVCSAHostname}.${VMDomain} (${VCFWorkloadDomainVCSAIP})"

    Write-Host -ForegroundColor Yellow "`n---- Workload Domain NSX Server Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "NSX Manager VIP Hostname: "
    Write-Host -ForegroundColor White $VCFWorkloadDomainNSXManagerVIPHostname"."$VMDomain
    Write-Host -NoNewline -ForegroundColor Green "Node 1: "
    Write-Host -ForegroundColor White "${VCFWorkloadDomainNSXManagerNode1Hostname}.${VMDomain}"

    Write-Host -ForegroundColor Magenta "`nWould you like to proceed with this deployment?`n"
    $answer = Read-Host -Prompt "Do you accept (Y or N)"
    if($answer -ne "Y" -or $answer -ne "y") {
        exit
    }
    Clear-Host
}

if($updateSDDCMConfig -eq 1) {
    My-Logger "Connecting to VCF Management vCenter Server $VCSAName ..."
    $viConnection = Connect-VIServer $VCSAIP -User "administrator@vsphere.local" -Password $VCSASSOPassword -WarningAction SilentlyContinue

    $sddcmVM = Get-VM -Server $viConnection $SddcManagerHostname

    $scriptName = "vcfSddcmScript.sh"
    $script = @"
#!/bin/bash
# Generated by William Lam's VCF 9 Automated Deployment Lab Script


"@

    if($VCFInstallerSoftwareDepot -eq "offline") {
        $vcfLcmConfigFile = "/opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties"
        if($VCFInstallerDepotPort -ne "") {
            $script += "sed -i -e `"s|lcm.depot.adapter.port=.*|lcm.depot.adapter.port=${VCFInstallerDepotPort}|`" ${vcfLcmConfigFile}`n"
        }

        if($VCFInstallerDepotHttps -eq $false) {
            $script += "sed -i -e `"/lcm.depot.adapter.port=.*/a lcm.depot.adapter.httpsEnabled=false`" ${vcfLcmConfigFile}`n"
        }
    }

    $script += "systemctl stop lcm`n"
	$script += "systemctl start lcm"
    $script | Set-Content -NoNewline -Encoding UTF8 $scriptName

    My-Logger "Transfering configuration shell script ($scriptName) to SDDC Manager VM ..."
    Copy-VMGuestFile -Server $viConnection -VM $sddcmVM -GuestUser "root" -GuestPassword $SddcManagerRootPassword -LocalToGuest -Source ${scriptName} -Destination /tmp/${scriptName} -Force | Out-Null
    My-Logger "Running configuration shell script on SDDC Manager VM ..."
    Invoke-VMScript -ScriptText "bash /tmp/${scriptName}" -VM $sddcmVM -GuestUser "root" -GuestPassword $SddcManagerRootPassword  | Out-Null

    Start-Sleep -Seconds 120

    My-Logger "Disconnecting from VCF Management vCenter Server $VCSAName ..."
    Disconnect-VIServer -Server $viConnection -Confirm:$false
}

if($configureSDDCMConfig -eq 1) {
    My-Logger "Updating SDDC Manager Software Depot ..."

    Verify-VCFAPIEndpoint -EndpointName "SDDC Manager" -EndpointIp $SddcManagerIP

    $connectDepot = 1
    $syncDepot = 1
    $downloadReleases = 1

    if($connectDepot -eq 1) {
        Connect-VCFDepot -EndpointIp $SddcManagerIP
    }

    if($syncDepot -eq 1) {
        Sync-VCFDepot -EndpointIp $SddcManagerIP
    }

    if($downloadReleases -eq 1) {
        Download-VCFRelease -EndpointIp $SddcManagerIP
    }
}

if($generateWldHostCommissionJson -eq 1 -or $startWLDDeployment -eq 1) {
    # Disconnect any existing sessions first
    try {
        Disconnect-VcfSddcManagerServer -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    } catch {
        # Ignore disconnect errors
    }

    My-Logger "Connecting to SDDC Manager at $SddcManagerIP ..."
    try {
        Connect-VcfSddcManagerServer -Server $SddcManagerIP -User "administrator@vsphere.local" -Password $VCSASSOPassword -ErrorAction Stop | Out-Null
        My-Logger "Successfully connected to SDDC Manager"
    } catch {
        My-Logger "Failed to connect to SDDC Manager at $SddcManagerIP" "red"
        Write-Error "`n($_.Exception.Message)`n"
        exit
    }
}

if($generateWldHostCommissionJson -eq 1) {
    My-Logger "Generating VCF Workload Domain Host Commission file $VCFWorkloadDomainUIJSONFile and $VCFWorkloadDomainAPIJSONFile for SDDC Manager UI and API"

    # Get network pool ID using REST API directly to avoid DNS issues
    $headers = Get-VCFSDDCmToken
    try {
        $networkPoolResponse = Invoke-WebRequest -Uri "https://${SddcManagerIP}/v1/network-pools" -Method GET -SkipCertificateCheck -Headers $headers
        $networkPools = ($networkPoolResponse.Content | ConvertFrom-Json).elements
        $mgmtPoolId = ($networkPools | where {$_.name -match $DeploymentId} | Select-Object -First 1).id
        My-Logger "Found network pool ID: $mgmtPoolId"
    } catch {
        My-Logger "Failed to retrieve network pools" "red"
        Write-Error "`n($_.Exception.Message)`n"
        exit
    }

    if($VCFWorkloadDomainEnableVSANESA) {
        $storageType = "VSAN_ESA"
    } else {
        $storageType = "VSAN"
    }

    $commissionHostsUI= @()
    $commissionHostsAPI= @()
    $NestedESXiHostnameToIPsForWorkloadDomain.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $hostFQDN = $_.Key + "." + $VMDomain

        $tmp1 = [ordered] @{
            "fqdn" = $hostFQDN;
            "username" = "root";
            "password" = $VMPassword;
            "networkPoolName" = "$VCFManagementDomainPoolName";
            "storageType" = $storageType;
        }
        $commissionHostsUI += $tmp1

        $tmp2 = [ordered] @{
            "fqdn" = $hostFQDN;
            "username" = "root";
            "password" = $VMPassword;
            "networkPoolId" = $mgmtPoolId;
            "storageType" = $storageType;
        }
        $commissionHostsAPI += $tmp2
    }

    $vcfCommissionHostConfigUI = @{
        "hosts" = $commissionHostsUI
    }

    $vcfCommissionHostConfigUI | ConvertTo-Json -Depth 2 | Out-File -LiteralPath $VCFWorkloadDomainUIJSONFile
    $commissionHostsAPI | ConvertTo-Json -Depth 2 | Out-File -LiteralPath $VCFWorkloadDomainAPIJSONFile
}

if($commissionHost -eq 1) {
    My-Logger "Commissioning ESXi hosts for Workload Domain deployment using $VCFWorkloadDomainAPIJSONFile ..."

    # Read the JSON file
    $commissionHostsJson = Get-Content -Raw $VCFWorkloadDomainAPIJSONFile

    # Get auth token
    $headers = Get-VCFSDDCmToken

    try {
        $uri = "https://${SddcManagerIP}/v1/hosts"
        $method = "POST"

        if($Debug) {
            My-Logger "DEBUG: Method: $method"
            My-Logger "DEBUG: Uri: $uri"
            My-Logger "DEBUG: Body: $commissionHostsJson"
        }

        $response = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -Headers $headers -Body $commissionHostsJson -ContentType "application/json"

        if($response.StatusCode -eq 202) {
            $taskId = (($response.Content | ConvertFrom-Json).id)
            My-Logger "Host commission task started with ID: $taskId"

            # Wait for commission to complete
            while(1) {
                try {
                    $taskResponse = Invoke-WebRequest -Uri "https://${SddcManagerIP}/v1/tasks/$taskId" -Method GET -SkipCertificateCheck -Headers $headers
                    $task = ($taskResponse.Content | ConvertFrom-Json)
                    $taskStatus = $task.status

                    if($taskStatus -eq "Successful") {
                        My-Logger "Host commission completed successfully"
                        break
                    } elseif($taskStatus -eq "Failed") {
                        My-Logger "Host commission failed!" "red"
                        if($task.errors) {
                            My-Logger "Error details: $($task.errors | ConvertTo-Json)" "red"
                        }
                        break
                    } else {
                        My-Logger "Host commission in progress (Status: $taskStatus), sleeping for 30 seconds ..."
                        Start-Sleep -Second 30
                    }
                } catch {
                    My-Logger "Error checking task status: $($_.Exception.Message)" "yellow"
                    Start-Sleep -Second 30
                }
            }
        } else {
            My-Logger "Unexpected response status: $($response.StatusCode)" "yellow"
        }
    } catch {
        My-Logger "Failed to commission hosts" "red"
        Write-Error "`n($_.Exception.Message)`n"
        return
    }
}

if($generateWLDDeploymentFile -eq 1) {
    My-Logger "Retreiving unassigned ESXi hosts from SDDC Manager and creating Workload Domain JSON deployment file $VCFWorkloadJSONFile"

    # Get unassigned hosts using REST API
    $headers = Get-VCFSDDCmToken
    try {
        $hostsResponse = Invoke-WebRequest -Uri "https://${SddcManagerIP}/v1/hosts?status=UNASSIGNED_USEABLE" -Method GET -SkipCertificateCheck -Headers $headers
        $hosts = ($hostsResponse.Content | ConvertFrom-Json).elements
        My-Logger "Found $($hosts.Count) unassigned useable hosts"
    } catch {
        My-Logger "Failed to retrieve unassigned hosts" "red"
        Write-Error "`n($_.Exception.Message)`n"
        exit
    }

    $hostSpecs = @()
    foreach ($id in $hosts.id) {
        if($VCFWorkloadDomainSeparateNSXSwitch) {
            $vmNics = @(
                @{
                    "id" = "vmnic0"
                    "vdsName" = "${VCFWorkloadDomainVCSAClusterName}-vds01"
                }
                @{
                    "id" = "vmnic1"
                    "vdsName" = "${VCFWorkloadDomainVCSAClusterName}-vds01"
                }
                @{
                    "id" = "vmnic2"
                    "vdsName" = "${VCFWorkloadDomainVCSAClusterName}-vds02"
                }
                @{
                    "id" = "vmnic3"
                    "vdsName" = "${VCFWorkloadDomainVCSAClusterName}-vds02"
                }
            )
        } else {
                $vmNics = @(
                @{
                    "id" = "vmnic0"
                    "vdsName" = "${VCFWorkloadDomainVCSAClusterName}-vds01"
                }
                @{
                    "id" = "vmnic1"
                    "vdsName" = "${VCFWorkloadDomainVCSAClusterName}-vds01"
                }
            )
        }

        $tmp = [ordered] @{
            "id" = $id
            "hostNetworkSpec" = @{
                "vmNics" = $vmNics
            }
        }
        $hostSpecs += $tmp
    }

    $payload = [ordered] @{
        "domainName" = $VCFWorkloadDomainName
        "orgName" = $VCFWorkloadDomainOrgName
        "deployWithoutLicenseKeys" = $true
        "vcenterSpec" = @{
            "name" = $VCFWorkloadDomainVCSAHostname
            "networkDetailsSpec" = @{
                "ipAddress" = $VCFWorkloadDomainVCSAIP
                "dnsName" = $VCFWorkloadDomainVCSAHostname + "." + $VMDomain
                "gateway" = VMWLDGateway
                "subnetMask" = $VMNetmask
            }
            "rootPassword" = $VCFWorkloadDomainVCSARootPassword
            "datacenterName" = $VCFWorkloadDomainVCSADatacenterName
        }
        "ssoDomainSpec" = [ordered]@{
            "ssoDomainName" = "vsphere.local"
            "ssoDomainPassword" = $VCFWorkloadDomainVCSASSOPassword
        }
        "computeSpec" = [ordered] @{
            "clusterSpecs" = @(
                [ordered] @{
                    "name" = ${VCFWorkloadDomainVCSAClusterName}
                    "hostSpecs" = $hostSpecs
                    "datastoreSpec" = @{
                        "vsanDatastoreSpec" = @{
                            "failuresToTolerate" = "1"
                            "datastoreName" = "${VCFWorkloadDomainVCSAClusterName}-vsan01"
                        }
                    }
                    "networkSpec" = @{
                        "vdsSpecs" = @(
                            [ordered] @{
                                "name" = "${VCFWorkloadDomainVCSAClusterName}-vds01"
                                "portGroupSpecs" = @(
                                    @{
                                        "name" = "${VCFWorkloadDomainVCSAClusterName}-vds01-management"
                                        "transportType" = "MANAGEMENT"
                                    }
                                    @{
                                        "name" = "${VCFWorkloadDomainVCSAClusterName}-vds01-vmotion"
                                        "transportType" = "VMOTION"
                                    }
                                    @{
                                        "name" = "${VCFWorkloadDomainVCSAClusterName}-vds01-vsan"
                                        "transportType" = "VSAN"
                                    }
                                )
                            }
                        )
                        "nsxClusterSpec" = [ordered] @{
                            "nsxTClusterSpec" = @{
                                "geneveVlanId" = 2005
                                "ipAddressPoolSpec" = @{
                                    "name" = "wld-pool"
                                    "subnets" = @(
                                        [ordered] @{
                                            "cidr" = "10.0.5.0/24"
                                            "gateway" = "10.0.5.253"
                                            "ipAddressPoolRanges" = @(
                                                [ordered] @{
                                                    "start" = "10.0.5.1"
                                                    "end" = "10.0.5.128"
                                                }
                                            )
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
            )
        }
        "nsxTSpec" = [ordered] @{
            "nsxManagerSpecs" = @(
                [ordered] @{
                    "name" = $VCFWorkloadDomainNSXManagerNode1Hostname
                    "networkDetailsSpec" = @{
                        "ipAddress" = $VCFWorkloadDomainNSXManagerNode1IP
                        "dnsName" = $VCFWorkloadDomainNSXManagerNode1Hostname + "." + $VMDomain
                        "gateway" = $VMWLDGateway
                        "subnetMask" = $VMNetmask
                    }
                }
            )
            "formFactor"= $NSXManagerSize
            "vipFqdn" = $VCFWorkloadDomainNSXManagerVIPHostname + "." + $VMDomain
            "nsxManagerAdminPassword" = $VCFWorkloadDomainNSXAdminPassword
        }
    }

    if($VCFWorkloadDomainSeparateNSXSwitch) {
        $payload.computeSpec.clusterSpecs.networkSpec.vdsSpecs+=@{"name"="${VCFWorkloadDomainVCSAClusterName}-vds02";"isUsedByNsxt"=$true}
    }

    if($VCFWorkloadDomainEnableVSANESA) {
        $esaEnable = [ordered]@{
            "enabled" = $true
        }
        $payload.computeSpec.clusterSpecs.datastoreSpec.vsanDatastoreSpec.Add("esaConfig",$esaEnable)

        $payload.computeSpec.clusterSpecs.datastoreSpec.vsanDatastoreSpec.Remove("failuresToTolerate")
    }

    if($VCFWorkloadDomainEnableVCLM) {
        # Get vLCM personality using REST API
        $headers = Get-VCFSDDCmToken
        try {
            $personalityResponse = Invoke-WebRequest -Uri "https://${SddcManagerIP}/v1/personalities" -Method GET -SkipCertificateCheck -Headers $headers
            $personalities = ($personalityResponse.Content | ConvertFrom-Json).elements
            $clusterImageId = ($personalities | where {$_.personalityName -eq $VCFManagementDomainVLCMImageName}).personalityId

            if($clusterImageId -eq $null) {
                Write-Host -ForegroundColor Red "`nUnable to find vLCM Image named $VCFManagementDomainVLCMImageName ...`n"
                exit
            }

            $payload.computeSpec.clusterSpecs[0].Add("clusterImageId",$clusterImageId)
        } catch {
            My-Logger "Failed to retrieve vLCM personalities" "red"
            Write-Error "`n($_.Exception.Message)`n"
            exit
        }
    }

    $payload | ConvertTo-Json -Depth 12 | Out-File $VCFWorkloadJSONFile
}

if($startWLDDeployment -eq 1) {
    My-Logger "Starting Workload Domain deployment using file $VCFWorkloadJSONFile"

    # Read JSON file
    $domainJson = Get-Content -Raw $VCFWorkloadJSONFile

    # Get auth token
    $headers = Get-VCFSDDCmToken

    try {
        $uri = "https://${SddcManagerIP}/v1/domains"
        $method = "POST"

        if($Debug) {
            My-Logger "DEBUG: Method: $method"
            My-Logger "DEBUG: Uri: $uri"
            My-Logger "DEBUG: Body: $domainJson"
        }

        $response = Invoke-WebRequest -Uri $uri -Method $method -SkipCertificateCheck -Headers $headers -Body $domainJson -ContentType "application/json"

        if($response.StatusCode -eq 202 -or $response.StatusCode -eq 200) {
            $taskId = (($response.Content | ConvertFrom-Json).id)
            My-Logger "Workload Domain deployment task started with ID: $taskId"
            My-Logger "Open a browser to VCF Operations or vCenter Server to monitor the deployment progress"
        } else {
            My-Logger "Unexpected response status: $($response.StatusCode)" "yellow"
        }
    } catch {
        My-Logger "Failed to start Workload Domain deployment" "red"
        Write-Error "`n($_.Exception.Message)`n"
        exit
    }
}

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes,2)

My-Logger "VCF Workload Domain Deployment Complete!"
My-Logger "StartTime: $StartTime"
My-Logger "EndTime: $EndTime"
My-Logger "Duration: $duration minutes to initiate Workload Domain deployment"
