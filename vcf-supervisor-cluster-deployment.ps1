# Author: Based on William Lam's VCF Lab Deployment Scripts
# Purpose: Deploy and Configure Supervisor Cluster (vSphere with Tanzu) in Workload Domain
# Compatible with VCF 9.x with NSX Networking
#
# All configuration variables must be defined in the config file passed via -EnvConfigFile
# Required variables: See VCFEdgeSupervisorConfig.ps1

param (
    [string]$EnvConfigFile,
    [switch]$ValidateOnly,
    [switch]$SkipPreChecks
)

# Validate that the file exists
if ($EnvConfigFile -and (Test-Path $EnvConfigFile)) {
    . $EnvConfigFile  # Dot-sourcing the config file
} else {
    Write-Host -ForegroundColor Red "`nNo valid deployment configuration file was provided or file was not found.`n"
    exit
}

#### DO NOT EDIT BEYOND HERE ####

$verboseLogFile = "vcf-supervisor-cluster-deployment.log"
$wldVCenterFQDN = "${VCFWorkloadDomainVCSAHostname}.${VMDomain}"

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

Function Get-vCenterToken {
    param(
        [Parameter(Mandatory=$true)][String]$vCenterServer,
        [Parameter(Mandatory=$true)][String]$Username,
        [Parameter(Mandatory=$true)][String]$Password
    )

    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))

    try {
        $response = Invoke-WebRequest -Uri "https://${vCenterServer}/api/session" -Method POST -SkipCertificateCheck -Headers @{"Authorization"="Basic $base64AuthInfo"}
        if ($response.StatusCode -eq 201) {
            $sessionToken = ($response.Content | ConvertFrom-Json)
            return $sessionToken
        }
    } catch {
        My-Logger "Failed to get vCenter session token: $($_.Exception.Message)" "red"
        return $null
    }
}

Function Get-WLDClusterMoRef {
    param(
        [Parameter(Mandatory=$true)][String]$vCenterServer,
        [Parameter(Mandatory=$true)][String]$SessionToken,
        [Parameter(Mandatory=$true)][String]$ClusterName
    )

    $headers = @{
        "vmware-api-session-id" = $SessionToken
    }

    try {
        $response = Invoke-WebRequest -Uri "https://${vCenterServer}/api/vcenter/cluster" -Method GET -SkipCertificateCheck -Headers $headers
        $clusters = ($response.Content | ConvertFrom-Json)
        $cluster = $clusters | Where-Object { $_.name -eq $ClusterName }
        
        if ($cluster) {
            return $cluster.cluster
        }
    } catch {
        My-Logger "Failed to get cluster MoRef: $($_.Exception.Message)" "red"
    }
    return $null
}

Function Get-StoragePolicy {
    param(
        [Parameter(Mandatory=$true)][String]$vCenterServer,
        [Parameter(Mandatory=$true)][String]$SessionToken,
        [Parameter(Mandatory=$true)][String]$PolicyName
    )

    $headers = @{
        "vmware-api-session-id" = $SessionToken
    }

    try {
        $response = Invoke-WebRequest -Uri "https://${vCenterServer}/api/vcenter/storage/policies" -Method GET -SkipCertificateCheck -Headers $headers
        $policies = ($response.Content | ConvertFrom-Json)
        $policy = $policies | Where-Object { $_.name -like "*$PolicyName*" }
        
        if ($policy) {
            return ($policy | Select-Object -First 1).policy
        }
    } catch {
        My-Logger "Failed to get storage policy: $($_.Exception.Message)" "red"
    }
    return $null
}

Function Get-NSXEdgeClusterId {
    param(
        [Parameter(Mandatory=$true)][String]$NSXManager,
        [Parameter(Mandatory=$true)][String]$NSXPassword,
        [Parameter(Mandatory=$true)][String]$EdgeClusterName
    )

    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:${NSXPassword}"))

    try {
        $headers = @{
            "Authorization" = "Basic $base64AuthInfo"
            "Content-Type" = "application/json"
        }
        
        $response = Invoke-WebRequest -Uri "https://${NSXManager}/api/v1/edge-clusters" -Method GET -SkipCertificateCheck -Headers $headers
        $edgeClusters = ($response.Content | ConvertFrom-Json).results
        $edgeCluster = $edgeClusters | Where-Object { $_.display_name -eq $EdgeClusterName }
        
        if ($edgeCluster) {
            return $edgeCluster.id
        }
    } catch {
        My-Logger "Failed to get NSX Edge Cluster ID: $($_.Exception.Message)" "red"
    }
    return $null
}

Function Get-NSXTier0Id {
    param(
        [Parameter(Mandatory=$true)][String]$NSXManager,
        [Parameter(Mandatory=$true)][String]$NSXPassword,
        [Parameter(Mandatory=$true)][String]$Tier0Name
    )

    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:${NSXPassword}"))

    try {
        $headers = @{
            "Authorization" = "Basic $base64AuthInfo"
            "Content-Type" = "application/json"
        }
        
        $response = Invoke-WebRequest -Uri "https://${NSXManager}/policy/api/v1/infra/tier-0s" -Method GET -SkipCertificateCheck -Headers $headers
        $tier0s = ($response.Content | ConvertFrom-Json).results
        $tier0 = $tier0s | Where-Object { $_.display_name -eq $Tier0Name }
        
        if ($tier0) {
            return $tier0.id
        }
    } catch {
        My-Logger "Failed to get NSX Tier-0 ID: $($_.Exception.Message)" "red"
    }
    return $null
}

Function Get-DVSwitchUUID {
    param(
        [Parameter(Mandatory=$true)][String]$vCenterServer,
        [Parameter(Mandatory=$true)][String]$SessionToken,
        [Parameter(Mandatory=$false)][String]$DVSName = ""
    )

    $headers = @{
        "vmware-api-session-id" = $SessionToken
    }

    try {
        $response = Invoke-WebRequest -Uri "https://${vCenterServer}/api/vcenter/namespace-management/networks/nsx/distributed-switches" -Method GET -SkipCertificateCheck -Headers $headers
        $switches = ($response.Content | ConvertFrom-Json)
        
        if ($DVSName -and $DVSName -ne "") {
            $dvs = $switches | Where-Object { $_.name -eq $DVSName }
        } else {
            # Auto-select first available DVS
            $dvs = $switches | Select-Object -First 1
            if ($dvs) {
                My-Logger "Auto-discovered DVS: $($dvs.name)"
            }
        }
        
        if ($dvs) {
            return @{
                "name" = $dvs.name
                "uuid" = $dvs.distributed_switch
            }
        }
    } catch {
        My-Logger "Failed to get DVS UUID: $($_.Exception.Message)" "red"
    }
    return $null
}

Function Create-ContentLibrary {
    param(
        [Parameter(Mandatory=$true)][String]$vCenterServer,
        [Parameter(Mandatory=$true)][String]$SessionToken,
        [Parameter(Mandatory=$true)][String]$LibraryName,
        [Parameter(Mandatory=$true)][String]$SubscriptionURL,
        [Parameter(Mandatory=$true)][String]$DatastoreName
    )

    $headers = @{
        "vmware-api-session-id" = $SessionToken
        "Content-Type" = "application/json"
    }

    # Get datastore ID
    try {
        $dsResponse = Invoke-WebRequest -Uri "https://${vCenterServer}/api/vcenter/datastore" -Method GET -SkipCertificateCheck -Headers $headers
        $datastores = ($dsResponse.Content | ConvertFrom-Json)
        $datastore = $datastores | Where-Object { $_.name -like "*$DatastoreName*" -or $_.name -like "*vsan*" } | Select-Object -First 1
        
        if (-not $datastore) {
            $datastore = $datastores | Select-Object -First 1
        }
        $datastoreId = $datastore.datastore
    } catch {
        My-Logger "Failed to get datastore: $($_.Exception.Message)" "red"
        return $null
    }

    # Check if library exists
    try {
        $libResponse = Invoke-WebRequest -Uri "https://${vCenterServer}/api/content/library" -Method GET -SkipCertificateCheck -Headers $headers
        $libraries = ($libResponse.Content | ConvertFrom-Json)
        
        foreach ($libId in $libraries) {
            $libDetailResponse = Invoke-WebRequest -Uri "https://${vCenterServer}/api/content/library/$libId" -Method GET -SkipCertificateCheck -Headers $headers
            $libDetail = ($libDetailResponse.Content | ConvertFrom-Json)
            if ($libDetail.name -eq $LibraryName) {
                My-Logger "Content Library '$LibraryName' already exists"
                return $libId
            }
        }
    } catch {
        My-Logger "Error checking existing libraries: $($_.Exception.Message)" "yellow"
    }

    # Try to create subscribed content library first
    $librarySpec = @{
        "name" = $LibraryName
        "description" = "TKG Content Library for Supervisor Cluster"
        "type" = "SUBSCRIBED"
        "subscription_info" = @{
            "subscription_url" = $SubscriptionURL
            "authentication_method" = "NONE"
            "automatic_sync_enabled" = $true
            "on_demand" = $true
        }
        "storage_backings" = @(
            @{
                "datastore_id" = $datastoreId
                "type" = "DATASTORE"
            }
        )
    }

    $body = $librarySpec | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-WebRequest -Uri "https://${vCenterServer}/api/content/subscribed-library" -Method POST -SkipCertificateCheck -Headers $headers -Body $body
        $libraryId = ($response.Content | ConvertFrom-Json)
        My-Logger "Created Subscribed Content Library '$LibraryName' with ID: $libraryId"
        return $libraryId
    } catch {
        My-Logger "Failed to create subscribed content library: $($_.Exception.Message)" "yellow"
        My-Logger "Attempting to create local content library instead..." "yellow"
        
        # Fall back to local library
        $localLibrarySpec = @{
            "name" = $LibraryName
            "description" = "TKG Content Library for Supervisor Cluster (Local)"
            "type" = "LOCAL"
            "storage_backings" = @(
                @{
                    "datastore_id" = $datastoreId
                    "type" = "DATASTORE"
                }
            )
        }
        
        $localBody = $localLibrarySpec | ConvertTo-Json -Depth 10
        
        try {
            $localResponse = Invoke-WebRequest -Uri "https://${vCenterServer}/api/content/local-library" -Method POST -SkipCertificateCheck -Headers $headers -Body $localBody
            $localLibraryId = ($localResponse.Content | ConvertFrom-Json)
            My-Logger "Created Local Content Library '$LibraryName' with ID: $localLibraryId"
            My-Logger "NOTE: You will need to manually add TKG images to this library later" "yellow"
            return $localLibraryId
        } catch {
            My-Logger "Failed to create local content library: $($_.Exception.Message)" "red"
            return $null
        }
    }
}

Function Enable-WorkloadManagement {
    param(
        [Parameter(Mandatory=$true)][String]$vCenterServer,
        [Parameter(Mandatory=$true)][String]$SessionToken,
        [Parameter(Mandatory=$true)][String]$ClusterMoRef,
        [Parameter(Mandatory=$true)][String]$StoragePolicyId,
        [Parameter(Mandatory=$true)][String]$ContentLibraryId,
        [Parameter(Mandatory=$true)][String]$EdgeClusterId,
        [Parameter(Mandatory=$true)][String]$Tier0GatewayPath,
        [Parameter(Mandatory=$true)][String]$DVSwitchUUID
    )

    $headers = @{
        "vmware-api-session-id" = $SessionToken
        "Content-Type" = "application/json"
    }

    # Build Workload Management spec using config variables
    $wmSpec = [ordered]@{
        "size_hint" = $SupervisorClusterSize
        "service_cidr" = @{
            "address" = ($SupervisorServicesCIDR -split "/")[0]
            "prefix" = [int]($SupervisorServicesCIDR -split "/")[1]
        }
        "network_provider" = "NSXT_CONTAINER_PLUGIN"
        "ncp_cluster_network_spec" = [ordered]@{
            "nsx_edge_cluster" = $EdgeClusterId
            "pod_cidrs" = @(
                @{
                    "address" = ($SupervisorPodCIDRs[0] -split "/")[0]
                    "prefix" = [int]($SupervisorPodCIDRs[0] -split "/")[1]
                }
            )
            "ingress_cidrs" = @(
                @{
                    "address" = ($SupervisorIngressCIDR -split "/")[0]
                    "prefix" = [int]($SupervisorIngressCIDR -split "/")[1]
                }
            )
            "egress_cidrs" = @(
                @{
                    "address" = ($SupervisorEgressCIDR -split "/")[0]
                    "prefix" = [int]($SupervisorEgressCIDR -split "/")[1]
                }
            )
            "cluster_distributed_switch" = $DVSwitchUUID
            "nsx_tier0_gateway" = $Tier0GatewayPath
            "namespace_subnet_prefix" = $SupervisorNamespaceNetworkPrefix
            "routed_mode" = $false
        }
        "master_management_network" = [ordered]@{
            "mode" = $SupervisorMgmtNetworkMode
            "address_range" = @{
                "starting_address" = $SupervisorMgmtNetworkStartIP
                "address_count" = $SupervisorMgmtNetworkAddressCount
                "gateway" = $SupervisorMgmtNetworkGateway
                "subnet_mask" = $SupervisorMgmtNetworkSubnetMask
            }
            "network" = $null
        }
        "master_storage_policy" = $StoragePolicyId
        "ephemeral_storage_policy" = $StoragePolicyId
        "master_DNS" = @($VMDNS)
        "worker_DNS" = @($VMDNS)
        "master_DNS_search_domains" = @($VMDomain)
        "master_NTP_servers" = @($VMNTP)
        "default_kubernetes_service_content_library" = $ContentLibraryId
        "image_storage" = @{
            "storage_policy" = $StoragePolicyId
        }
    }

    # Get management network
    try {
        $networkResponse = Invoke-WebRequest -Uri "https://${vCenterServer}/api/vcenter/network" -Method GET -SkipCertificateCheck -Headers $headers
        $networks = ($networkResponse.Content | ConvertFrom-Json)
        $mgmtNetwork = $networks | Where-Object { $_.name -eq "wld-cl01-vds01-management" } | Select-Object -First 1
        if (-not $mgmtNetwork) {
            $mgmtNetwork = $networks | Where-Object { $_.name -like "*-management" -and $_.name -notlike "*External*" -and $_.name -notlike "*edge*" } | Select-Object -First 1
        }
        
        if ($mgmtNetwork) {
            $wmSpec.master_management_network.network = $mgmtNetwork.network
            My-Logger "Using management network: $($mgmtNetwork.name)"
        } else {
            $wmSpec.master_management_network.network = $networks[0].network
            My-Logger "WARNING: Falling back to first network: $($networks[0].name)" "yellow"
        }
    } catch {
        My-Logger "Failed to get networks: $($_.Exception.Message)" "red"
    }

    $body = $wmSpec | ConvertTo-Json -Depth 10

    if ($Debug) {
        My-Logger "DEBUG: Workload Management Spec:" "cyan"
        $body | Out-File -LiteralPath "supervisor-cluster-spec.json"
        My-Logger "Spec saved to supervisor-cluster-spec.json" "cyan"
    }

    My-Logger "Enabling Workload Management on cluster $ClusterMoRef..."

    try {
        $uri = "https://${vCenterServer}/api/vcenter/namespace-management/clusters/${ClusterMoRef}?action=enable"
        $response = Invoke-WebRequest -Uri $uri -Method POST -SkipCertificateCheck -Headers $headers -Body $body
        
        if ($response.StatusCode -eq 204 -or $response.StatusCode -eq 200) {
            My-Logger "Workload Management enablement initiated successfully"
            return $true
        }
    } catch {
        My-Logger "Failed to enable Workload Management: $($_.Exception.Message)" "red"
        
        try {
            $errorContent = $_.ErrorDetails.Message
            My-Logger "Error details: $errorContent" "red"
        } catch {}
        
        return $false
    }
}

Function Wait-SupervisorCluster {
    param(
        [Parameter(Mandatory=$true)][String]$vCenterServer,
        [Parameter(Mandatory=$true)][String]$SessionToken,
        [Parameter(Mandatory=$true)][String]$ClusterMoRef,
        [Parameter(Mandatory=$false)][Int]$TimeoutMinutes = 60
    )

    $headers = @{
        "vmware-api-session-id" = $SessionToken
    }

    $startTime = Get-Date
    $timeout = New-TimeSpan -Minutes $TimeoutMinutes

    while ((Get-Date) - $startTime -lt $timeout) {
        try {
            $uri = "https://${vCenterServer}/api/vcenter/namespace-management/clusters/${ClusterMoRef}"
            $response = Invoke-WebRequest -Uri $uri -Method GET -SkipCertificateCheck -Headers $headers
            $status = ($response.Content | ConvertFrom-Json)

            $configStatus = $status.config_status
            $kubernetesStatus = $status.kubernetes_status

            switch ($configStatus) {
                "RUNNING" {
                    My-Logger "Supervisor Cluster is now RUNNING!"
                    My-Logger "  Kubernetes Status: $kubernetesStatus"
                    My-Logger "  API Server Endpoint: $($status.api_server_cluster_endpoint)"
                    return $true
                }
                "ERROR" {
                    My-Logger "Supervisor Cluster configuration failed!" "red"
                    My-Logger "  Error Messages: $($status.messages | ConvertTo-Json)" "red"
                    return $false
                }
                default {
                    My-Logger "Supervisor Cluster status: $configStatus (Kubernetes: $kubernetesStatus). Waiting 60 seconds..."
                    Start-Sleep -Seconds 60
                }
            }
        } catch {
            My-Logger "Error checking Supervisor status: $($_.Exception.Message)" "yellow"
            Start-Sleep -Seconds 60
        }
    }

    My-Logger "Supervisor Cluster deployment timed out after $TimeoutMinutes minutes" "red"
    return $false
}

Function Create-Namespace {
    param(
        [Parameter(Mandatory=$true)][String]$vCenterServer,
        [Parameter(Mandatory=$true)][String]$SessionToken,
        [Parameter(Mandatory=$true)][String]$ClusterMoRef,
        [Parameter(Mandatory=$true)][String]$NamespaceName,
        [Parameter(Mandatory=$true)][String]$StoragePolicyId
    )

    $headers = @{
        "vmware-api-session-id" = $SessionToken
        "Content-Type" = "application/json"
    }

    $namespaceSpec = @{
        "namespace" = $NamespaceName
        "cluster" = $ClusterMoRef
        "description" = "Workload Domain Namespace"
        "storage_specs" = @(
            @{
                "policy" = $StoragePolicyId
            }
        )
    }

    $body = $namespaceSpec | ConvertTo-Json -Depth 5

    try {
        $uri = "https://${vCenterServer}/api/vcenter/namespaces/instances"
        $response = Invoke-WebRequest -Uri $uri -Method POST -SkipCertificateCheck -Headers $headers -Body $body
        
        if ($response.StatusCode -eq 204 -or $response.StatusCode -eq 201) {
            My-Logger "Namespace '$NamespaceName' created successfully"
            return $true
        }
    } catch {
        if ($_.Exception.Message -like "*already exists*") {
            My-Logger "Namespace '$NamespaceName' already exists" "yellow"
            return $true
        }
        My-Logger "Failed to create namespace: $($_.Exception.Message)" "red"
        return $false
    }
}

# Main Execution
Write-Host -ForegroundColor Cyan @"

╔═══════════════════════════════════════════════════════════════════╗
║     VCF 9 Supervisor Cluster Deployment Script                    ║
╠═══════════════════════════════════════════════════════════════════╣
║  Target vCenter: $wldVCenterFQDN
║  Target Cluster: $VCFWorkloadDomainVCSAClusterName
║  Supervisor Size: $SupervisorClusterSize
╚═══════════════════════════════════════════════════════════════════╝

"@

# Derive NSX Manager IP from config
$wldNSXManagerIP = $VCFWorkloadDomainNSXManagerNode1IP

if (-not $SkipPreChecks) {
    Write-Host -ForegroundColor Yellow "=== Pre-Deployment Checks ==="
    
    My-Logger "Checking WLD vCenter connectivity..."
    $sessionToken = Get-vCenterToken -vCenterServer $VCFWorkloadDomainVCSAIP -Username "administrator@vsphere.local" -Password $VCFWorkloadDomainVCSASSOPassword
    
    if (-not $sessionToken) {
        My-Logger "Failed to connect to WLD vCenter at $VCFWorkloadDomainVCSAIP" "red"
        exit 1
    }
    My-Logger "Successfully connected to WLD vCenter"
    
    $clusterMoRef = Get-WLDClusterMoRef -vCenterServer $VCFWorkloadDomainVCSAIP -SessionToken $sessionToken -ClusterName $VCFWorkloadDomainVCSAClusterName
    if (-not $clusterMoRef) {
        My-Logger "Failed to find cluster '$VCFWorkloadDomainVCSAClusterName'" "red"
        exit 1
    }
    My-Logger "Found cluster with MoRef: $clusterMoRef"
    
    $storagePolicyId = Get-StoragePolicy -vCenterServer $VCFWorkloadDomainVCSAIP -SessionToken $sessionToken -PolicyName $SupervisorStoragePolicy
    if (-not $storagePolicyId) {
        My-Logger "Storage policy '$SupervisorStoragePolicy' not found, trying 'vSAN'..." "yellow"
        $storagePolicyId = Get-StoragePolicy -vCenterServer $VCFWorkloadDomainVCSAIP -SessionToken $sessionToken -PolicyName "vSAN"
    }
    My-Logger "Using storage policy ID: $storagePolicyId"
    
    # Check DVS - auto-discover
    My-Logger "Looking up Distributed Virtual Switch..."
    $dvsInfo = Get-DVSwitchUUID -vCenterServer $VCFWorkloadDomainVCSAIP -SessionToken $sessionToken
    if (-not $dvsInfo) {
        My-Logger "Failed to find any DVS" "red"
        exit 1
    }
    My-Logger "Found DVS '$($dvsInfo.name)' with UUID: $($dvsInfo.uuid)"
    
    My-Logger "Checking NSX Manager connectivity at $wldNSXManagerIP..."
    
    $edgeClusterId = Get-NSXEdgeClusterId -NSXManager $wldNSXManagerIP -NSXPassword $VCFWorkloadDomainNSXAdminPassword -EdgeClusterName $SupervisorNSXEdgeCluster
    if (-not $edgeClusterId) {
        My-Logger "Failed to find NSX Edge Cluster '$SupervisorNSXEdgeCluster'" "red"
        My-Logger "Please ensure the Edge Cluster is deployed before running this script" "yellow"
        exit 1
    }
    My-Logger "Found NSX Edge Cluster with ID: $edgeClusterId"
    
    $tier0Id = Get-NSXTier0Id -NSXManager $wldNSXManagerIP -NSXPassword $VCFWorkloadDomainNSXAdminPassword -Tier0Name $SupervisorTier0Gateway
    if (-not $tier0Id) {
        My-Logger "Failed to find NSX Tier-0 Gateway '$SupervisorTier0Gateway'" "red"
        exit 1
    }
    My-Logger "Found NSX Tier-0 Gateway with ID: $tier0Id"
}

if ($ValidateOnly) {
    My-Logger "`nValidation completed successfully. Use -ValidateOnly:`$false to proceed with deployment."
    exit 0
}

Write-Host -ForegroundColor Yellow "`n=== Supervisor Cluster Deployment ==="

# Get fresh session token
$sessionToken = Get-vCenterToken -vCenterServer $VCFWorkloadDomainVCSAIP -Username "administrator@vsphere.local" -Password $VCFWorkloadDomainVCSASSOPassword

# Get required IDs
$clusterMoRef = Get-WLDClusterMoRef -vCenterServer $VCFWorkloadDomainVCSAIP -SessionToken $sessionToken -ClusterName $VCFWorkloadDomainVCSAClusterName
$storagePolicyId = Get-StoragePolicy -vCenterServer $VCFWorkloadDomainVCSAIP -SessionToken $sessionToken -PolicyName $SupervisorStoragePolicy
if (-not $storagePolicyId) {
    $storagePolicyId = Get-StoragePolicy -vCenterServer $VCFWorkloadDomainVCSAIP -SessionToken $sessionToken -PolicyName "vSAN"
}

# Get DVS UUID - auto-discover
$dvsInfo = Get-DVSwitchUUID -vCenterServer $VCFWorkloadDomainVCSAIP -SessionToken $sessionToken
if (-not $dvsInfo) {
    My-Logger "Failed to find any DVS" "red"
    exit 1
}
My-Logger "Using DVS '$($dvsInfo.name)' with UUID: $($dvsInfo.uuid)"

$edgeClusterId = Get-NSXEdgeClusterId -NSXManager $wldNSXManagerIP -NSXPassword $VCFWorkloadDomainNSXAdminPassword -EdgeClusterName $SupervisorNSXEdgeCluster
$tier0Id = Get-NSXTier0Id -NSXManager $wldNSXManagerIP -NSXPassword $VCFWorkloadDomainNSXAdminPassword -Tier0Name $SupervisorTier0Gateway
$tier0Path = $tier0Id

# Create Content Library
My-Logger "Creating TKG Content Library..."
$contentLibraryId = Create-ContentLibrary `
    -vCenterServer $VCFWorkloadDomainVCSAIP `
    -SessionToken $sessionToken `
    -LibraryName $SupervisorContentLibraryName `
    -SubscriptionURL $SupervisorContentLibraryURL `
    -DatastoreName "vsan"

if (-not $contentLibraryId) {
    My-Logger "Failed to create content library" "red"
    exit 1
}

# Enable Workload Management
$success = Enable-WorkloadManagement `
    -vCenterServer $VCFWorkloadDomainVCSAIP `
    -SessionToken $sessionToken `
    -ClusterMoRef $clusterMoRef `
    -StoragePolicyId $storagePolicyId `
    -ContentLibraryId $contentLibraryId `
    -EdgeClusterId $edgeClusterId `
    -Tier0GatewayPath $tier0Path `
    -DVSwitchUUID $dvsInfo.uuid

if ($success) {
    My-Logger "Waiting for Supervisor Cluster to become ready (this may take 20-30 minutes)..."
    
    $ready = Wait-SupervisorCluster `
        -vCenterServer $VCFWorkloadDomainVCSAIP `
        -SessionToken $sessionToken `
        -ClusterMoRef $clusterMoRef `
        -TimeoutMinutes 45

    if ($ready) {
        My-Logger "Creating initial namespace '$SupervisorNamespace'..."
        
        $sessionToken = Get-vCenterToken -vCenterServer $VCFWorkloadDomainVCSAIP -Username "administrator@vsphere.local" -Password $VCFWorkloadDomainVCSASSOPassword
        
        Create-Namespace `
            -vCenterServer $VCFWorkloadDomainVCSAIP `
            -SessionToken $sessionToken `
            -ClusterMoRef $clusterMoRef `
            -NamespaceName $SupervisorNamespace `
            -StoragePolicyId $storagePolicyId
    }
} else {
    My-Logger "Failed to enable Workload Management" "red"
}

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes,2)

Write-Host -ForegroundColor Cyan @"

╔═══════════════════════════════════════════════════════════════════╗
║               Deployment Summary                                  ║
╚═══════════════════════════════════════════════════════════════════╝
"@

My-Logger "Supervisor Cluster Deployment Complete!"
My-Logger "  StartTime: $StartTime"
My-Logger "  EndTime: $EndTime"
My-Logger "  Duration: $duration minutes"

if ($success -and $ready) {
    Write-Host -ForegroundColor Green @"

Next Steps:
1. Log into vCenter at https://$VCFWorkloadDomainVCSAIP
2. Navigate to Menu > Workload Management
3. Verify the Supervisor Cluster status is 'Running'
4. Download the Kubernetes CLI tools from the Supervisor Cluster
5. Use 'kubectl vsphere login' to authenticate to the Supervisor

Example login command:
kubectl vsphere login --server=$SupervisorMgmtNetworkStartIP -u administrator@vsphere.local --insecure-skip-tls-verify

"@
}