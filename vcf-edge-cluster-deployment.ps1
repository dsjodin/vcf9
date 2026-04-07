# Author: Based on William Lam's VCF Lab Deployment Scripts
# Purpose: Deploy NSX Edge Clusters for Management and Workload Domains
# Compatible with VCF 9.x
#
# All configuration variables must be defined in the config file passed via -EnvConfigFile
#   Example config file variables (must exist there, NOT here):
#   - SddcManagerIP
#   - VCSASSOPassword
#   - VMDomain
#   - VMMGMTGateway
#   - ESXWLDGateway
#   - MGMTEdge* variables (names, IPs, VLANs, ASN, etc.)
#   - WLDEdge* variables (names, IPs, VLANs, ASN, etc.)
#   - VCSAClusterName
#   - VCFWorkloadDomainVCSAClusterName
#   - NSXRootPassword, NSXAdminPassword, NSXAuditPassword
#   - Debug (optional)

param (
    [string]$EnvConfigFile,
    [ValidateSet("MGMT", "WLD", "BOTH")]
    [string]$DeploymentTarget = "BOTH"
)

# Validate that the config file exists and load it
if ($EnvConfigFile -and (Test-Path $EnvConfigFile)) {
    . $EnvConfigFile  # Dot-sourcing the config file (must define all env-specific variables)
} else {
    Write-Host -ForegroundColor Red "`nNo valid deployment configuration file was provided or file was not found.`n"
    exit
}

#### DO NOT EDIT BEYOND HERE ####

#### DO NOT EDIT BEYOND HERE ####

$verboseLogFile = "vcf-edge-cluster-deployment.log"
$StartTime      = Get-Date

Function My-Logger {
    param(
        [Parameter(Mandatory = $true)][String]$message,
        [Parameter(Mandatory = $false)][String]$color = "green"
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"

    Write-Host -NoNewline -ForegroundColor White "[$timeStamp]"
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
        $requests = Invoke-WebRequest -Uri "https://${SddcManagerIP}/v1/tokens" -Method POST -SkipCertificateCheck -TimeoutSec 5 -Headers @{
            "Content-Type" = "application/json"
            "Accept"       = "application/json"
        } -Body $body

        if ($requests.StatusCode -eq 200) {
            $accessToken = ($requests.Content | ConvertFrom-Json).accessToken
        } else {
            My-Logger ("Unexpected status code retrieving SDDC Manager token: {0}" -f $requests.StatusCode) "red"
            exit
        }
    } catch {
        My-Logger ("Unable to retrieve SDDC Manager Token: {0}" -f $_.Exception.Message) "red"
        exit
    }

    $headers = @{
        "Content-Type" = "application/json"
        "Accept"       = "application/json"
        "Authorization"= "Bearer ${accessToken}"
    }

    return $headers
}

Function Get-VCFClusterId {
    param(
        [Parameter(Mandatory = $true)][String]$ClusterName
    )

    $headers = Get-VCFSDDCmToken

    try {
        $response = Invoke-WebRequest -Uri "https://${SddcManagerIP}/v1/clusters" -Method GET -SkipCertificateCheck -Headers $headers
        $clusters = ($response.Content | ConvertFrom-Json).elements
        $cluster  = $clusters | Where-Object { $_.name -eq $ClusterName }

        if ($cluster) {
            return $cluster.id
        } else {
            My-Logger "Cluster '$ClusterName' not found" "red"
            return $null
        }
    } catch {
        My-Logger ("Failed to retrieve clusters: {0}" -f $_.Exception.Message) "red"
        return $null
    }
}

Function Get-VCFHostIds {
    param(
        [Parameter(Mandatory = $true)][String]$ClusterId,
        [Parameter(Mandatory = $true)][Int]$Count
    )

    $headers = Get-VCFSDDCmToken

    try {
        $response = Invoke-WebRequest -Uri "https://${SddcManagerIP}/v1/hosts" -Method GET -SkipCertificateCheck -Headers $headers
        $hosts    = ($response.Content | ConvertFrom-Json).elements
        $clusterHosts = $hosts | Where-Object { $_.cluster.id -eq $ClusterId } | Select-Object -First $Count

        return $clusterHosts.id
    } catch {
        My-Logger ("Failed to retrieve hosts: {0}" -f $_.Exception.Message) "red"
        return $null
    }
}

Function Wait-VCFTask {
    param(
        [Parameter(Mandatory = $true)][String]$TaskId,
        [Parameter(Mandatory = $false)][Int]$TimeoutMinutes = 120
    )

    $headers   = Get-VCFSDDCmToken
    $startTime = Get-Date
    $timeout   = New-TimeSpan -Minutes $TimeoutMinutes

    while ((Get-Date) - $startTime -lt $timeout) {
        try {
            $response = Invoke-WebRequest -Uri "https://${SddcManagerIP}/v1/tasks/$TaskId" -Method GET -SkipCertificateCheck -Headers $headers
            $task     = ($response.Content | ConvertFrom-Json)
            $status   = $task.status

            switch ($status.ToUpper()) {
                "SUCCESSFUL" {
                    My-Logger "Task $TaskId completed successfully"
                    return $true
                }
                "FAILED" {
                    My-Logger "Task $TaskId failed!" "red"
                    $task | ConvertTo-Json -Depth 10 | Out-File "failed-task-$TaskId.json"
                    if ($task.errorMessages) {
                        My-Logger ("Task error messages: {0}" -f ($task.errorMessages -join '; ')) "red"
                    }
                    return $false
                }
                "CANCELLED" {
                    My-Logger "Task $TaskId was cancelled" "yellow"
                    return $false
                }
                default {
                    $percentComplete = if ($task.completionPercentage) { $task.completionPercentage } else { 0 }
                    My-Logger "Task $TaskId in progress: $status ($percentComplete% complete). Waiting 60 seconds..." "yellow"
                    Start-Sleep -Seconds 60
                }
            }
        } catch {
            My-Logger ("Error checking task status for {0}: {1}" -f $TaskId, $_.Exception.Message) "yellow"
            Start-Sleep -Seconds 60
        }
    }

    My-Logger "Task $TaskId timed out after $TimeoutMinutes minutes" "red"
    return $false
}

Function Deploy-EdgeCluster {
    param(
        [Parameter(Mandatory = $true)][String]$DomainType,
        [Parameter(Mandatory = $true)][String]$ClusterName,
        [Parameter(Mandatory = $true)][String]$EdgeClusterName,
        [Parameter(Mandatory = $true)][String]$EdgeFormFactor,
        [Parameter(Mandatory = $true)][String]$EdgeNode1Name,
        [Parameter(Mandatory = $true)][String]$EdgeNode1MgmtIP,
        [Parameter(Mandatory = $true)][String]$EdgeNode1TEP1IP,
        [Parameter(Mandatory = $true)][String]$EdgeNode1TEP2IP,
        [Parameter(Mandatory = $true)][String]$EdgeNode2Name,
        [Parameter(Mandatory = $true)][String]$EdgeNode2MgmtIP,
        [Parameter(Mandatory = $true)][String]$EdgeNode2TEP1IP,
        [Parameter(Mandatory = $true)][String]$EdgeNode2TEP2IP,
        [Parameter(Mandatory = $true)][Int]$EdgeMgmtPrefix,
        [Parameter(Mandatory = $true)][Int]$EdgeTEPVLAN,
        [Parameter(Mandatory = $true)][String]$EdgeTEPGateway,
        [Parameter(Mandatory = $true)][Int]$EdgeTEPPrefix,
        [Parameter(Mandatory = $true)][String]$Tier0Name,
        [Parameter(Mandatory = $true)][Int]$Tier0ASN,
        [Parameter(Mandatory = $true)][Int]$BGPPeerASN,
        [Parameter(Mandatory = $true)][String]$ManagementGateway,
        # Uplink 1 (required)
        [Parameter(Mandatory = $true)][Int]$Uplink1VLAN,
        [Parameter(Mandatory = $true)][Int]$Uplink1Prefix,
        [Parameter(Mandatory = $true)][String]$Uplink1Gateway,
        [Parameter(Mandatory = $true)][String]$EdgeNode1Uplink1IP,
        [Parameter(Mandatory = $true)][String]$EdgeNode2Uplink1IP,
        # Uplink 2 (optional)
        [Parameter(Mandatory = $false)][Int]$Uplink2VLAN = 0,
        [Parameter(Mandatory = $false)][Int]$Uplink2Prefix = 24,
        [Parameter(Mandatory = $false)][String]$Uplink2Gateway = "",
        [Parameter(Mandatory = $false)][String]$EdgeNode1Uplink2IP = "",
        [Parameter(Mandatory = $false)][String]$EdgeNode2Uplink2IP = ""
    )

    My-Logger "Deploying Edge Cluster for $DomainType Domain..."

    $clusterId = Get-VCFClusterId -ClusterName $ClusterName
    if (-not $clusterId) {
        My-Logger "Failed to get cluster ID for $ClusterName" "red"
        return $false
    }
    My-Logger "[$DomainType] Using vSphere cluster '$ClusterName' with ID: $clusterId"

    $hostIds = Get-VCFHostIds -ClusterId $clusterId -Count 2
    if (-not $hostIds -or $hostIds.Count -lt 2) {
        My-Logger "Need at least 2 hosts in cluster '$ClusterName' for Edge deployment" "red"
        return $false
    }
    My-Logger "Found hosts for Edge placement in '$ClusterName': $($hostIds -join ', ')"

    $headers = Get-VCFSDDCmToken

    # Edge Node 1 uplinks
    $edgeNode1Uplinks = @(
        @{
            "uplinkVlan"        = $Uplink1VLAN
            "uplinkInterfaceIP" = "${EdgeNode1Uplink1IP}/${Uplink1Prefix}"
            "peerIP"            = "${Uplink1Gateway}/${Uplink1Prefix}"
            "asnPeer"           = $BGPPeerASN
            "bgpPeerPassword"   = ""
        }
    )
    if ($EdgeNode1Uplink2IP -ne "" -and $Uplink2VLAN -ne 0) {
        $edgeNode1Uplinks += @{
            "uplinkVlan"        = $Uplink2VLAN
            "uplinkInterfaceIP" = "${EdgeNode1Uplink2IP}/${Uplink2Prefix}"
            "peerIP"            = "${Uplink2Gateway}/${Uplink2Prefix}"
            "asnPeer"           = $BGPPeerASN
            "bgpPeerPassword"   = ""
        }
        My-Logger "Edge Node 1: Dual uplinks configured (VLAN $Uplink1VLAN + VLAN $Uplink2VLAN)"
    } else {
        My-Logger "Edge Node 1: Single uplink configured (VLAN $Uplink1VLAN)"
    }

    # Edge Node 2 uplinks
    $edgeNode2Uplinks = @(
        @{
            "uplinkVlan"        = $Uplink1VLAN
            "uplinkInterfaceIP" = "${EdgeNode2Uplink1IP}/${Uplink1Prefix}"
            "peerIP"            = "${Uplink1Gateway}/${Uplink1Prefix}"
            "asnPeer"           = $BGPPeerASN
            "bgpPeerPassword"   = ""
        }
    )
    if ($EdgeNode2Uplink2IP -ne "" -and $Uplink2VLAN -ne 0) {
        $edgeNode2Uplinks += @{
            "uplinkVlan"        = $Uplink2VLAN
            "uplinkInterfaceIP" = "${EdgeNode2Uplink2IP}/${Uplink2Prefix}"
            "peerIP"            = "${Uplink2Gateway}/${Uplink2Prefix}"
            "asnPeer"           = $BGPPeerASN
            "bgpPeerPassword"   = ""
        }
        My-Logger "Edge Node 2: Dual uplinks configured (VLAN $Uplink1VLAN + VLAN $Uplink2VLAN)"
    } else {
        My-Logger "Edge Node 2: Single uplink configured (VLAN $Uplink1VLAN)"
    }

    $edgeClusterSpec = [ordered]@{
        "edgeClusterName"               = $EdgeClusterName
        "edgeClusterProfileType"        = "DEFAULT"
        "edgeClusterType"               = "NSX-T"
        "edgeRootPassword"              = $NSXRootPassword
        "edgeAdminPassword"             = $NSXAdminPassword
        "edgeAuditPassword"             = $NSXAuditPassword
        "edgeFormFactor"                = $EdgeFormFactor
        "tier0ServicesHighAvailability" = "ACTIVE_ACTIVE"
        "mtu"                           = 8900
        "asn"                           = $Tier0ASN
        "edgeNodeSpecs"                 = @(
            [ordered]@{
                "edgeNodeName"     = "${EdgeNode1Name}.${VMDomain}"
                "managementIP"     = "${EdgeNode1MgmtIP}/${EdgeMgmtPrefix}"
                "managementGateway"= $ManagementGateway
                "edgeTepGateway"   = $EdgeTEPGateway
                "edgeTep1IP"       = "${EdgeNode1TEP1IP}/${EdgeTEPPrefix}"
                "edgeTep2IP"       = "${EdgeNode1TEP2IP}/${EdgeTEPPrefix}"
                "edgeTepVlan"      = $EdgeTEPVLAN
                "clusterId"        = $clusterId
                "interRackCluster" = $false
                "uplinkNetwork"    = $edgeNode1Uplinks
            }
            [ordered]@{
                "edgeNodeName"     = "${EdgeNode2Name}.${VMDomain}"
                "managementIP"     = "${EdgeNode2MgmtIP}/${EdgeMgmtPrefix}"
                "managementGateway"= $ManagementGateway
                "edgeTepGateway"   = $EdgeTEPGateway
                "edgeTep1IP"       = "${EdgeNode2TEP1IP}/${EdgeTEPPrefix}"
                "edgeTep2IP"       = "${EdgeNode2TEP2IP}/${EdgeTEPPrefix}"
                "edgeTepVlan"      = $EdgeTEPVLAN
                "clusterId"        = $clusterId
                "interRackCluster" = $false
                "uplinkNetwork"    = $edgeNode2Uplinks
            }
        )
        "tier0RoutingType"              = "EBGP"
        "tier0Name"                     = $Tier0Name
        "tier1Name"                     = "${EdgeClusterName}-t1-gw01"
        "tier1Unhosted"                 = $false
    }

    $body = $edgeClusterSpec | ConvertTo-Json -Depth 10

    if ($Debug) {
        My-Logger ("DEBUG: Edge Cluster Spec for {0}:" -f $DomainType) "cyan"
        My-Logger $body "cyan"
    }

    $specFile = "edge-cluster-spec-${DomainType}.json"
    $body | Out-File -LiteralPath $specFile
    My-Logger "Edge cluster spec for $DomainType saved to $specFile"

    try {
        $uri      = "https://${SddcManagerIP}/v1/edge-clusters"
        $response = Invoke-WebRequest -Uri $uri -Method POST -SkipCertificateCheck -Headers $headers -Body $body -ContentType "application/json"

        if ($response.StatusCode -eq 202 -or $response.StatusCode -eq 200) {
            $taskId = (($response.Content | ConvertFrom-Json).id)
            My-Logger "Edge cluster deployment for $DomainType started with task ID: $taskId"

            $success = Wait-VCFTask -TaskId $taskId -TimeoutMinutes 90
            return $success
        } else {
            My-Logger ("Unexpected response from Edge cluster deployment API: {0}" -f $response.StatusCode) "yellow"
            return $false
        }
    } catch {
        My-Logger ("Failed to deploy Edge cluster for {0}: {1}" -f $DomainType, $_.Exception.Message) "red"

        try {
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                My-Logger ("Error details: {0}" -f ($errorDetails | ConvertTo-Json -Depth 5)) "red"
            }
        } catch {
            My-Logger ("Raw error (could not parse JSON error details): {0}" -f $_.Exception.Message) "red"
        }
        return $false
    }
}

Write-Host -ForegroundColor Cyan @"

╔═══════════════════════════════════════════════════════════════════╗
║           VCF 9 NSX Edge Cluster Deployment Script                ║
╠═══════════════════════════════════════════════════════════════════╣
║  Deployment Target: $DeploymentTarget
║  SDDC Manager: $SddcManagerIP
╚═══════════════════════════════════════════════════════════════════╝

"@

if ($DeploymentTarget -eq "MGMT" -or $DeploymentTarget -eq "BOTH") {
    Write-Host -ForegroundColor Yellow "`n=== Management Domain Edge Cluster Deployment ==="
    Write-Host -ForegroundColor White "  Edge Cluster Name: $MGMTEdgeClusterName"
    Write-Host -ForegroundColor White "  Edge Nodes: $MGMTEdgeNode1Name, $MGMTEdgeNode2Name"
    Write-Host -ForegroundColor White "  Edge TEP VLAN: $MGMTEdgeTEPVLAN"
    Write-Host -ForegroundColor White "  Tier-0 Gateway: $MGMTEdgeTier0Name"

    $mgmtParams = @{
        DomainType         = "MGMT"
        ClusterName        = $VCSAClusterName
        EdgeClusterName    = $MGMTEdgeClusterName
        EdgeFormFactor     = $MGMTEdgeFormFactor
        EdgeNode1Name      = $MGMTEdgeNode1Name
        EdgeNode1MgmtIP    = $MGMTEdgeNode1MgmtIP
        EdgeNode1TEP1IP    = $MGMTEdgeNode1TEP1IP
        EdgeNode1TEP2IP    = $MGMTEdgeNode1TEP2IP
        EdgeNode2Name      = $MGMTEdgeNode2Name
        EdgeNode2MgmtIP    = $MGMTEdgeNode2MgmtIP
        EdgeNode2TEP1IP    = $MGMTEdgeNode2TEP1IP
        EdgeNode2TEP2IP    = $MGMTEdgeNode2TEP2IP
        EdgeMgmtPrefix     = $MGMTEdgeMgmtPrefix
        EdgeTEPVLAN        = $MGMTEdgeTEPVLAN
        EdgeTEPGateway     = $MGMTEdgeTEPGateway
        EdgeTEPPrefix      = $MGMTEdgeTEPPrefix
        Tier0Name          = $MGMTEdgeTier0Name
        Tier0ASN           = $MGMTEdgeTier0ASN
        BGPPeerASN         = $MGMTEdgeBGPPeerASN
        ManagementGateway  = $VMMGMTGateway
        Uplink1VLAN        = $MGMTEdgeUplink1VLAN
        Uplink1Prefix      = $MGMTEdgeUplink1Prefix
        Uplink1Gateway     = $MGMTEdgeUplink1Gateway
        EdgeNode1Uplink1IP = $MGMTEdgeNode1Uplink1IP
        EdgeNode2Uplink1IP = $MGMTEdgeNode2Uplink1IP
        Uplink2VLAN        = $MGMTEdgeUplink2VLAN
        Uplink2Prefix      = $MGMTEdgeUplink2Prefix
        Uplink2Gateway     = $MGMTEdgeUplink2Gateway
        EdgeNode1Uplink2IP = $MGMTEdgeNode1Uplink2IP
        EdgeNode2Uplink2IP = $MGMTEdgeNode2Uplink2IP
    }

    $mgmtSuccess = Deploy-EdgeCluster @mgmtParams

    if ($mgmtSuccess) {
        My-Logger "Management Domain Edge Cluster deployed successfully!"
    } else {
        My-Logger "Management Domain Edge Cluster deployment failed!" "red"
    }
}

if ($DeploymentTarget -eq "WLD" -or $DeploymentTarget -eq "BOTH") {
    Write-Host -ForegroundColor Yellow "`n=== Workload Domain Edge Cluster Deployment ==="
    Write-Host -ForegroundColor White "  Edge Cluster Name: $WLDEdgeClusterName"
    Write-Host -ForegroundColor White "  Edge Nodes: $WLDEdgeNode1Name, $WLDEdgeNode2Name"
    Write-Host -ForegroundColor White "  Edge TEP VLAN: $WLDEdgeTEPVLAN"
    Write-Host -ForegroundColor White "  Tier-0 Gateway: $WLDEdgeTier0Name"

    $wldParams = @{
        DomainType         = "WLD"
        ClusterName        = $VCFWorkloadDomainVCSAClusterName
        EdgeClusterName    = $WLDEdgeClusterName
        EdgeFormFactor     = $WLDEdgeFormFactor
        EdgeNode1Name      = $WLDEdgeNode1Name
        EdgeNode1MgmtIP    = $WLDEdgeNode1MgmtIP
        EdgeNode1TEP1IP    = $WLDEdgeNode1TEP1IP
        EdgeNode1TEP2IP    = $WLDEdgeNode1TEP2IP
        EdgeNode2Name      = $WLDEdgeNode2Name
        EdgeNode2MgmtIP    = $WLDEdgeNode2MgmtIP
        EdgeNode2TEP1IP    = $WLDEdgeNode2TEP1IP
        EdgeNode2TEP2IP    = $WLDEdgeNode2TEP2IP
        EdgeMgmtPrefix     = $WLDEdgeMgmtPrefix
        EdgeTEPVLAN        = $WLDEdgeTEPVLAN
        EdgeTEPGateway     = $WLDEdgeTEPGateway
        EdgeTEPPrefix      = $WLDEdgeTEPPrefix
        Tier0Name          = $WLDEdgeTier0Name
        Tier0ASN           = $WLDEdgeTier0ASN
        BGPPeerASN         = $WLDEdgeBGPPeerASN
        ManagementGateway  = $ESXWLDGateway   # <- WLD uses ESXWLDGateway as requested
        Uplink1VLAN        = $WLDEdgeUplink1VLAN
        Uplink1Prefix      = $WLDEdgeUplink1Prefix
        Uplink1Gateway     = $WLDEdgeUplink1Gateway
        EdgeNode1Uplink1IP = $WLDEdgeNode1Uplink1IP
        EdgeNode2Uplink1IP = $WLDEdgeNode2Uplink1IP
        Uplink2VLAN        = $WLDEdgeUplink2VLAN
        Uplink2Prefix      = $WLDEdgeUplink2Prefix
        Uplink2Gateway     = $WLDEdgeUplink2Gateway
        EdgeNode1Uplink2IP = $WLDEdgeNode1Uplink2IP
        EdgeNode2Uplink2IP = $WLDEdgeNode2Uplink2IP
    }

    $wldSuccess = Deploy-EdgeCluster @wldParams

    if ($wldSuccess) {
        My-Logger "Workload Domain Edge Cluster deployed successfully!"
    } else {
        My-Logger "Workload Domain Edge Cluster deployment failed!" "red"
    }
}

$EndTime  = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes, 2)

My-Logger "`nEdge Cluster Deployment Complete!"
My-Logger "  StartTime: $StartTime"
My-Logger "  EndTime:   $EndTime"
My-Logger "  Duration:  $duration minutes"
