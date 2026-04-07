# Create Shared VCF/VVF DNS Zones and Unified Deployment Configs
# Version 2.0 - Unified Configuration (Edge + BGP included)

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$TestMode,
    
    [Parameter(Mandatory=$false)]
    [string]$TemplateFile = "C:\vcf_deploy\DNSTemplate.csv",
    
    [Parameter(Mandatory=$false)]
    [string]$VCFTemplateFile = "C:\vcf_deploy\VCFDeploymentTemplate.ps1",
    
    [Parameter(Mandatory=$false)]
    [string]$VVFTemplateFile = "C:\vcf_deploy\VVFDeploymentTemplate.ps1",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFolder = "C:\vcf_deploy\SharedConfigs",
    
    [Parameter(Mandatory=$false)]
    [string]$VyOSInterface = "eth0",
    
    [Parameter(Mandatory=$false)]
    [string]$VCFMgmtNetwork = "10.2.100",
    
    [Parameter(Mandatory=$false)]
    [string]$VVFMgmtNetwork = "10.3.100",
    
    # vCenter Parameters for Port Group Creation
    [Parameter(Mandatory=$false)]
    [switch]$CreatePortGroups,
    
    [Parameter(Mandatory=$false)]
    [string]$VIServer = "labvcsa.lab.io",
    
    [Parameter(Mandatory=$false)]
    [string]$VIUsername = "administrator@vsphere.local",
    
    [Parameter(Mandatory=$false)]
    [string]$VIPassword = "VMwareVCF9!",
    
    [Parameter(Mandatory=$false)]
    [string]$vSwitchName = "internal",
    
    [Parameter(Mandatory=$false)]
    [string]$PortGroupPrefix = "PG-"
)

# Check if templates exist
if (!(Test-Path $TemplateFile)) {
    Write-Host "Error: DNS template file not found at $TemplateFile" -ForegroundColor Red
    exit 1
}

if (!(Test-Path $VCFTemplateFile)) {
    Write-Host "Error: VCF template file not found at $VCFTemplateFile" -ForegroundColor Red
    exit 1
}

if (!(Test-Path $VVFTemplateFile)) {
    Write-Host "Error: VVF template file not found at $VVFTemplateFile" -ForegroundColor Red
    exit 1
}

# Create output folder if it doesn't exist
if (!(Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

# Check DNS Server module
if (!$TestMode) {
    $dnsModule = Get-Module -ListAvailable -Name DnsServer
    if (!$dnsModule) {
        Write-Host ""
        Write-Host "WARNING: DNS Server module not found!" -ForegroundColor Yellow
        Write-Host "Use -TestMode to generate configs without creating DNS entries." -ForegroundColor Cyan
        exit 1
    }
}

# Show test mode warning
if ($TestMode) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "         TEST MODE - DNS SIMULATION     " -ForegroundColor Yellow
    Write-Host "   No actual DNS entries will be created" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
}

# Shared environment settings
$vcfZone = "vcf.lab.io"
$vvfZone = "vvf.lab.io"

# VCF Network configuration (using actual VLAN scheme)
$vcfVMotionNetwork = "10.2.110"
$vcfVsanNetwork = "10.2.120"
$vcfHostTepNetwork = "10.2.130"
$vcfEdgeTepNetwork = "10.2.140"
$vcfEdgeUplink1Network = "192.168.168"
$vcfEdgeUplink2Network = "192.168.68"

# VVF Network configuration (using actual VLAN scheme)
$vvfVMotionNetwork = "10.3.110"
$vvfVsanNetwork = "10.3.120"

# CIDR notations
$vcfMgmtNetworkCidr = "$VCFMgmtNetwork.0/24"
$vcfVMotionNetworkCidr = "$vcfVMotionNetwork.0/24"
$vcfVsanNetworkCidr = "$vcfVsanNetwork.0/24"
$vcfHostTepNetworkCidr = "$vcfHostTepNetwork.0/24"
$vcfEdgeTepNetworkCidr = "$vcfEdgeTepNetwork.0/24"
$vcfEdgeUplink1NetworkCidr = "$vcfEdgeUplink1Network.0/31"
$vcfEdgeUplink2NetworkCidr = "$vcfEdgeUplink2Network.0/31"

$vvfMgmtNetworkCidr = "$VVFMgmtNetwork.0/24"
$vvfVMotionNetworkCidr = "$vvfVMotionNetwork.0/24"
$vvfVsanNetworkCidr = "$vvfVsanNetwork.0/24"

# Gateways
$vcfMgmtGateway = "$VCFMgmtNetwork.1"
$vcfVMotionGateway = "$vcfVMotionNetwork.1"
$vcfVsanGateway = "$vcfVsanNetwork.1"
$vcfHostTepGateway = "$vcfHostTepNetwork.1"
$vcfEdgeTepGateway = "$vcfEdgeTepNetwork.1"
$vcfEdgeUplink1Gateway = "$vcfEdgeUplink1Network.0"
$vcfEdgeUplink2Gateway = "$vcfEdgeUplink2Network.0"

$vvfMgmtGateway = "$VVFMgmtNetwork.1"
$vvfVMotionGateway = "$vvfVMotionNetwork.1"
$vvfVsanGateway = "$vvfVsanNetwork.1"

# VLAN IDs (using actual VLAN scheme)
$vcfMgmtVlanId = "2100"
$vcfVMotionVlanId = "2110"
$vcfVsanVlanId = "2120"
$vcfHostTepVlanId = "2130"
$vcfEdgeTepVlanId = "2140"
$vcfEdgeUplink1VlanId = "2150"
$vcfEdgeUplink2VlanId = "2160"

$vvfMgmtVlanId = "3100"
$vvfVMotionVlanId = "3110"
$vvfVsanVlanId = "3120"

# Reverse zone names
$vcfMgmtReverseZone = "100.2.10.in-addr.arpa"
$vvfMgmtReverseZone = "100.3.10.in-addr.arpa"

Write-Host ""
Write-Host "=== Creating Shared VCF/VVF Environment ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "VCF Networks:" -ForegroundColor Cyan
Write-Host "  ESXi MGMT:     $vcfMgmtNetworkCidr - VLAN $vcfMgmtVlanId" -ForegroundColor Yellow
Write-Host "  vMotion:       $vcfVMotionNetworkCidr - VLAN $vcfVMotionVlanId" -ForegroundColor Yellow
Write-Host "  vSAN:          $vcfVsanNetworkCidr - VLAN $vcfVsanVlanId" -ForegroundColor Yellow
Write-Host "  HOST TEP:      $vcfHostTepNetworkCidr - VLAN $vcfHostTepVlanId" -ForegroundColor Yellow
Write-Host "  EDGE TEP:      $vcfEdgeTepNetworkCidr - VLAN $vcfEdgeTepVlanId" -ForegroundColor Yellow
Write-Host "  EDGE UPLINK 1: $vcfEdgeUplink1NetworkCidr - VLAN $vcfEdgeUplink1VlanId" -ForegroundColor Yellow
Write-Host "  EDGE UPLINK 2: $vcfEdgeUplink2NetworkCidr - VLAN $vcfEdgeUplink2VlanId" -ForegroundColor Yellow
Write-Host ""
Write-Host "VVF Networks:" -ForegroundColor Cyan
Write-Host "  ESXi MGMT: $vvfMgmtNetworkCidr - VLAN $vvfMgmtVlanId" -ForegroundColor Yellow
Write-Host "  vMotion:   $vvfVMotionNetworkCidr - VLAN $vvfVMotionVlanId" -ForegroundColor Yellow
Write-Host "  vSAN:      $vvfVsanNetworkCidr - VLAN $vvfVsanVlanId" -ForegroundColor Yellow

# Load DNS template
$dnsTemplate = Import-Csv $TemplateFile
$vcfRecords = $dnsTemplate | Where-Object { $_.Zone -eq "VCF" }
$vvfRecords = $dnsTemplate | Where-Object { $_.Zone -eq "VVF" }

# Function to create or reuse reverse zone
function Ensure-ReverseZone {
    param(
        [string]$ReverseZoneName,
        [bool]$IsTestMode
    )
    
    if ($IsTestMode) {
        Write-Host "  [TEST] Would ensure reverse zone exists: $ReverseZoneName" -ForegroundColor DarkYellow
        return $true
    }
    
    try {
        $zoneExists = Get-DnsServerZone -Name $ReverseZoneName -ErrorAction SilentlyContinue
        
        if ($zoneExists) {
            Write-Host "  Reverse zone already exists: $ReverseZoneName" -ForegroundColor Gray
            return $true
        } else {
            Add-DnsServerPrimaryZone -Name $ReverseZoneName -ZoneFile "$ReverseZoneName.dns"
            Write-Host "  Created reverse zone: $ReverseZoneName" -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Host "  Warning: Could not create/check reverse zone $ReverseZoneName - $_" -ForegroundColor Yellow
        return $false
    }
}

# Create VCF DNS Zone and Records
try {
    $existingZone = $null
    if (!$TestMode) {
        $existingZone = Get-DnsServerZone -Name $vcfZone -ErrorAction SilentlyContinue
    }
    
    if ($TestMode) {
        Write-Host ""
        Write-Host "[TEST MODE] Would create/update DNS zone: $vcfZone" -ForegroundColor Yellow
    } else {
        if ($existingZone) {
            Write-Host ""
            Write-Host "DNS zone already exists: $vcfZone (will add/update records)" -ForegroundColor Yellow
        } else {
            Add-DnsServerPrimaryZone -Name $vcfZone -ZoneFile "$vcfZone.dns"
            Write-Host ""
            Write-Host "Created DNS zone: $vcfZone" -ForegroundColor Green
        }
    }
    
    # Create VCF Management reverse zone
    Write-Host ""
    Write-Host "Creating VCF reverse zones..." -ForegroundColor Cyan
    $vcfMgmtReverseZoneCreated = Ensure-ReverseZone -ReverseZoneName $vcfMgmtReverseZone -IsTestMode $TestMode
    
    # Add forward and reverse records for VCF
    foreach ($record in $vcfRecords) {
        $hostName = $record.HostSuffix
        $ipAddress = "$VCFMgmtNetwork.$($record.IPOffset)"
        $fqdn = "$hostName.$vcfZone"
        
        # Add A record
        if ($TestMode) {
            Write-Host "  [TEST] Would add A record: $fqdn -> $ipAddress" -ForegroundColor DarkYellow
        } else {
            # Remove existing record if it exists
            $existingRecord = Get-DnsServerResourceRecord -Name $hostName -ZoneName $vcfZone -RRType A -ErrorAction SilentlyContinue
            if ($existingRecord) {
                Remove-DnsServerResourceRecord -Name $hostName -ZoneName $vcfZone -RRType A -Force
            }
            Add-DnsServerResourceRecordA -Name $hostName -ZoneName $vcfZone -IPv4Address $ipAddress
            Write-Host "  Added A record: $fqdn -> $ipAddress" -ForegroundColor Gray
        }
        
        # Add PTR record
        if ($vcfMgmtReverseZoneCreated) {
            $lastOctet = $record.IPOffset
            if ($TestMode) {
                Write-Host "  [TEST] Would add PTR record: $ipAddress -> $fqdn" -ForegroundColor DarkYellow
            } else {
                try {
                    # Remove existing PTR if it exists
                    $existingPtr = Get-DnsServerResourceRecord -Name $lastOctet -ZoneName $vcfMgmtReverseZone -RRType Ptr -ErrorAction SilentlyContinue
                    if ($existingPtr) {
                        Remove-DnsServerResourceRecord -Name $lastOctet -ZoneName $vcfMgmtReverseZone -RRType Ptr -Force
                    }
                    Add-DnsServerResourceRecordPtr -Name $lastOctet -ZoneName $vcfMgmtReverseZone -PtrDomainName $fqdn
                    Write-Host "  Added PTR record: $ipAddress -> $fqdn" -ForegroundColor Gray
                }
                catch {
                    Write-Host "  Warning: Could not add PTR record for $ipAddress - $_" -ForegroundColor Yellow
                }
            }
        }
    }
}
catch {
    Write-Host "Error creating VCF DNS zone: $_" -ForegroundColor Red
    Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Create VVF DNS Zone and Records
try {
    $existingZone = $null
    if (!$TestMode) {
        $existingZone = Get-DnsServerZone -Name $vvfZone -ErrorAction SilentlyContinue
    }
    
    if ($TestMode) {
        Write-Host ""
        Write-Host "[TEST MODE] Would create/update DNS zone: $vvfZone" -ForegroundColor Yellow
    } else {
        if ($existingZone) {
            Write-Host ""
            Write-Host "DNS zone already exists: $vvfZone (will add/update records)" -ForegroundColor Yellow
        } else {
            Add-DnsServerPrimaryZone -Name $vvfZone -ZoneFile "$vvfZone.dns"
            Write-Host ""
            Write-Host "Created DNS zone: $vvfZone" -ForegroundColor Green
        }
    }
    
    # Create VVF Management reverse zone
    Write-Host ""
    Write-Host "Creating VVF reverse zones..." -ForegroundColor Cyan
    $vvfMgmtReverseZoneCreated = Ensure-ReverseZone -ReverseZoneName $vvfMgmtReverseZone -IsTestMode $TestMode
    
    # Add forward and reverse records for VVF
    foreach ($record in $vvfRecords) {
        $hostName = $record.HostSuffix
        $ipAddress = "$VVFMgmtNetwork.$($record.IPOffset)"
        $fqdn = "$hostName.$vvfZone"
        
        # Add A record
        if ($TestMode) {
            Write-Host "  [TEST] Would add A record: $fqdn -> $ipAddress" -ForegroundColor DarkYellow
        } else {
            # Remove existing record if it exists
            $existingRecord = Get-DnsServerResourceRecord -Name $hostName -ZoneName $vvfZone -RRType A -ErrorAction SilentlyContinue
            if ($existingRecord) {
                Remove-DnsServerResourceRecord -Name $hostName -ZoneName $vvfZone -RRType A -Force
            }
            Add-DnsServerResourceRecordA -Name $hostName -ZoneName $vvfZone -IPv4Address $ipAddress
            Write-Host "  Added A record: $fqdn -> $ipAddress" -ForegroundColor Gray
        }
        
        # Add PTR record
        if ($vvfMgmtReverseZoneCreated) {
            $lastOctet = $record.IPOffset
            if ($TestMode) {
                Write-Host "  [TEST] Would add PTR record: $ipAddress -> $fqdn" -ForegroundColor DarkYellow
            } else {
                try {
                    # Remove existing PTR if it exists
                    $existingPtr = Get-DnsServerResourceRecord -Name $lastOctet -ZoneName $vvfMgmtReverseZone -RRType Ptr -ErrorAction SilentlyContinue
                    if ($existingPtr) {
                        Remove-DnsServerResourceRecord -Name $lastOctet -ZoneName $vvfMgmtReverseZone -RRType Ptr -Force
                    }
                    Add-DnsServerResourceRecordPtr -Name $lastOctet -ZoneName $vvfMgmtReverseZone -PtrDomainName $fqdn
                    Write-Host "  Added PTR record: $ipAddress -> $fqdn" -ForegroundColor Gray
                }
                catch {
                    Write-Host "  Warning: Could not add PTR record for $ipAddress - $_" -ForegroundColor Yellow
                }
            }
        }
    }
}
catch {
    Write-Host "Error creating VVF DNS zone: $_" -ForegroundColor Red
    Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Generate VCF Deployment Configuration with Edge and BGP
Write-Host ""
Write-Host "Generating VCF unified configuration (includes Edge + BGP)..." -ForegroundColor Cyan

$vcfConfigPath = Join-Path $OutputFolder "VCFDeploymentConfig.ps1"
$vcfTemplateContent = Get-Content $VCFTemplateFile -Raw

$vcfConfig = $vcfTemplateContent `
    -replace '\{\{FOLDER\}\}', 'VCF-Shared' `
    -replace '\{\{GATEWAY\}\}', $vcfMgmtGateway `
    -replace '\{\{VCF_NETWORK\}\}', $VCFMgmtNetwork `
    -replace '\{\{VCF_NETWORK_CIDR\}\}', $vcfMgmtNetworkCidr `
    -replace '\{\{VCF_VMOTION_CIDR\}\}', $vcfVMotionNetworkCidr `
    -replace '\{\{VCF_VMOTION_GATEWAY\}\}', $vcfVMotionGateway `
    -replace '\{\{VCF_VMOTION_NETWORK\}\}', $vcfVMotionNetwork `
    -replace '\{\{VCF_VSAN_CIDR\}\}', $vcfVsanNetworkCidr `
    -replace '\{\{VCF_VSAN_GATEWAY\}\}', $vcfVsanGateway `
    -replace '\{\{VCF_VSAN_NETWORK\}\}', $vcfVsanNetwork `
    -replace '\{\{VCF_NSXTEP_CIDR\}\}', $vcfHostTepNetworkCidr `
    -replace '\{\{VCF_NSXTEP_GATEWAY\}\}', $vcfHostTepGateway `
    -replace '\{\{VCF_NSXTEP_NETWORK\}\}', $vcfHostTepNetwork `
    -replace '\{\{VCF_EDGETEP_CIDR\}\}', $vcfEdgeTepNetworkCidr `
    -replace '\{\{VCF_EDGETEP_GATEWAY\}\}', $vcfEdgeTepGateway

$vcfConfig | Out-File -FilePath $vcfConfigPath -Encoding UTF8
Write-Host "VCF unified config saved to: $vcfConfigPath" -ForegroundColor Green
Write-Host "  Includes: Network config, Edge cluster specs, BGP settings" -ForegroundColor Gray

# Generate VVF Deployment Configuration  
Write-Host ""
Write-Host "Generating VVF configuration..." -ForegroundColor Cyan

$vvfConfigPath = Join-Path $OutputFolder "VVFDeploymentConfig.ps1"
$vvfTemplateContent = Get-Content $VVFTemplateFile -Raw

$vvfConfig = $vvfTemplateContent `
    -replace '\{\{FOLDER\}\}', 'VVF-Shared' `
    -replace '\{\{GATEWAY\}\}', $vvfMgmtGateway `
    -replace '\{\{VVF_NETWORK\}\}', $VVFMgmtNetwork `
    -replace '\{\{VVF_NETWORK_CIDR\}\}', $vvfMgmtNetworkCidr `
    -replace '\{\{VVF_VMOTION_CIDR\}\}', $vvfVMotionNetworkCidr `
    -replace '\{\{VVF_VSAN_CIDR\}\}', $vvfVsanNetworkCidr

$vvfConfig | Out-File -FilePath $vvfConfigPath -Encoding UTF8
Write-Host "VVF config saved to: $vvfConfigPath" -ForegroundColor Green

# Generate VyOS Configuration
$vyosConfigPath = Join-Path $OutputFolder "VyOSConfig.txt"
$vyosConfigLines = @(
    "# VyOS Configuration for Shared VCF/VVF Environment"
    "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    ""
    "# Copy and paste these commands into VyOS configuration mode"
    ""
    "configure"
    ""
    "# VCF Networks"
    "# ------------"
    ""
    "# VCF ESXi Management Network - VLAN $vcfMgmtVlanId"
    "set interfaces ethernet $VyOSInterface vif $vcfMgmtVlanId address '$vcfMgmtGateway/24'"
    "set interfaces ethernet $VyOSInterface vif $vcfMgmtVlanId description 'VCF ESXi MGMT ($vcfMgmtNetworkCidr)'"
    ""
    "# VCF vMotion Network - VLAN $vcfVMotionVlanId"
    "set interfaces ethernet $VyOSInterface vif $vcfVMotionVlanId address '$vcfVMotionGateway/24'"
    "set interfaces ethernet $VyOSInterface vif $vcfVMotionVlanId description 'VCF vMotion ($vcfVMotionNetworkCidr)'"
    ""
    "# VCF vSAN Network - VLAN $vcfVsanVlanId"
    "set interfaces ethernet $VyOSInterface vif $vcfVsanVlanId address '$vcfVsanGateway/24'"
    "set interfaces ethernet $VyOSInterface vif $vcfVsanVlanId description 'VCF vSAN ($vcfVsanNetworkCidr)'"
    ""
    "# VCF HOST TEP Network - VLAN $vcfHostTepVlanId"
    "set interfaces ethernet $VyOSInterface vif $vcfHostTepVlanId address '$vcfHostTepGateway/24'"
    "set interfaces ethernet $VyOSInterface vif $vcfHostTepVlanId description 'VCF HOST TEP ($vcfHostTepNetworkCidr)'"
    ""
    "# VCF EDGE TEP Network - VLAN $vcfEdgeTepVlanId"
    "set interfaces ethernet $VyOSInterface vif $vcfEdgeTepVlanId address '$vcfEdgeTepGateway/24'"
    "set interfaces ethernet $VyOSInterface vif $vcfEdgeTepVlanId description 'VCF EDGE TEP ($vcfEdgeTepNetworkCidr)'"
    ""
    "# VCF EDGE UPLINK 1 Network - VLAN $vcfEdgeUplink1VlanId"
    "set interfaces ethernet $VyOSInterface vif $vcfEdgeUplink1VlanId address '$vcfEdgeUplink1Gateway/31'"
    "set interfaces ethernet $VyOSInterface vif $vcfEdgeUplink1VlanId description 'VCF EDGE UPLINK 1 ($vcfEdgeUplink1NetworkCidr)'"
    ""
    "# VCF EDGE UPLINK 2 Network - VLAN $vcfEdgeUplink2VlanId"
    "set interfaces ethernet $VyOSInterface vif $vcfEdgeUplink2VlanId address '$vcfEdgeUplink2Gateway/31'"
    "set interfaces ethernet $VyOSInterface vif $vcfEdgeUplink2VlanId description 'VCF EDGE UPLINK 2 ($vcfEdgeUplink2NetworkCidr)'"
    ""
    "# BGP Configuration"
    "# -----------------"
    "set protocols bgp system-as 65000"
    "set protocols bgp neighbor 192.168.168.1 remote-as 65001"
    "set protocols bgp neighbor 192.168.168.1 password 'VMware1!'"
    "set protocols bgp neighbor 192.168.168.3 remote-as 65001"
    "set protocols bgp neighbor 192.168.168.3 password 'VMware1!'"
    "set protocols bgp neighbor 192.168.168.5 remote-as 65002"
    "set protocols bgp neighbor 192.168.168.5 password 'VMware1!'"
    "set protocols bgp neighbor 192.168.168.7 remote-as 65002"
    "set protocols bgp neighbor 192.168.168.7 password 'VMware1!'"
    "set protocols bgp neighbor 192.168.68.1 remote-as 65001"
    "set protocols bgp neighbor 192.168.68.1 password 'VMware1!'"
    "set protocols bgp neighbor 192.168.68.3 remote-as 65001"
    "set protocols bgp neighbor 192.168.68.3 password 'VMware1!'"
    "set protocols bgp neighbor 192.168.68.5 remote-as 65002"
    "set protocols bgp neighbor 192.168.68.5 password 'VMware1!'"
    "set protocols bgp neighbor 192.168.68.7 remote-as 65002"
    "set protocols bgp neighbor 192.168.68.7 password 'VMware1!'"
    ""
    "# VVF Networks"
    "# ------------"
    ""
    "# VVF ESXi Management Network - VLAN $vvfMgmtVlanId"
    "set interfaces ethernet $VyOSInterface vif $vvfMgmtVlanId address '$vvfMgmtGateway/24'"
    "set interfaces ethernet $VyOSInterface vif $vvfMgmtVlanId description 'VVF ESXi MGMT ($vvfMgmtNetworkCidr)'"
    ""
    "# VVF vMotion Network - VLAN $vvfVMotionVlanId"
    "set interfaces ethernet $VyOSInterface vif $vvfVMotionVlanId address '$vvfVMotionGateway/24'"
    "set interfaces ethernet $VyOSInterface vif $vvfVMotionVlanId description 'VVF vMotion ($vvfVMotionNetworkCidr)'"
    ""
    "# VVF vSAN Network - VLAN $vvfVsanVlanId"
    "set interfaces ethernet $VyOSInterface vif $vvfVsanVlanId address '$vvfVsanGateway/24'"
    "set interfaces ethernet $VyOSInterface vif $vvfVsanVlanId description 'VVF vSAN ($vvfVsanNetworkCidr)'"
    ""
    "# Save and commit"
    "# commit"
    "# save"
)

$vyosConfigLines | Out-File -FilePath $vyosConfigPath -Encoding UTF8
Write-Host "VyOS config saved to: $vyosConfigPath" -ForegroundColor Green

# Create a summary file
$summaryPath = Join-Path $OutputFolder "Summary.txt"
$summaryLines = @(
    "Shared VCF/VVF Environment Configuration Summary"
    "================================================"
    "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    ""
    "IMPORTANT: Edge and BGP configuration is now INTEGRATED"
    "into the VCFDeploymentConfig.ps1 file!"
    ""
    "================================"
    "DNS Zones Created"
    "================================"
    "VCF Zone: $vcfZone"
    "VVF Zone: $vvfZone"
    ""
    "VCF Reverse Zone: $vcfMgmtReverseZone"
    "VVF Reverse Zone: $vvfMgmtReverseZone"
    ""
    "================================"
    "VCF Hosts and IPs"
    "================================"
)

# Add VCF DNS records to summary
foreach ($record in $vcfRecords) {
    $hostName = $record.HostSuffix
    $ipAddress = "$VCFMgmtNetwork.$($record.IPOffset)"
    $fqdn = "$hostName.$vcfZone"
    $summaryLines += "$fqdn - $ipAddress"
}

$summaryLines += ""
$summaryLines += "================================"
$summaryLines += "VVF Hosts and IPs"
$summaryLines += "================================"

# Add VVF DNS records to summary
foreach ($record in $vvfRecords) {
    $hostName = $record.HostSuffix
    $ipAddress = "$VVFMgmtNetwork.$($record.IPOffset)"
    $fqdn = "$hostName.$vvfZone"
    $summaryLines += "$fqdn - $ipAddress"
}

$summaryLines += ""
$summaryLines += "================================"
$summaryLines += "VCF Network Details"
$summaryLines += "================================"
$summaryLines += "ESXi MGMT:     $vcfMgmtNetworkCidr (Gateway: $vcfMgmtGateway) - VLAN $vcfMgmtVlanId"
$summaryLines += "vMotion:       $vcfVMotionNetworkCidr (Gateway: $vcfVMotionGateway) - VLAN $vcfVMotionVlanId"
$summaryLines += "vSAN:          $vcfVsanNetworkCidr (Gateway: $vcfVsanGateway) - VLAN $vcfVsanVlanId"
$summaryLines += "HOST TEP:      $vcfHostTepNetworkCidr (Gateway: $vcfHostTepGateway) - VLAN $vcfHostTepVlanId"
$summaryLines += "EDGE TEP:      $vcfEdgeTepNetworkCidr (Gateway: $vcfEdgeTepGateway) - VLAN $vcfEdgeTepVlanId"
$summaryLines += "EDGE UPLINK 1: $vcfEdgeUplink1NetworkCidr (Gateway: $vcfEdgeUplink1Gateway) - VLAN $vcfEdgeUplink1VlanId"
$summaryLines += "EDGE UPLINK 2: $vcfEdgeUplink2NetworkCidr (Gateway: $vcfEdgeUplink2Gateway) - VLAN $vcfEdgeUplink2VlanId"
$summaryLines += ""
$summaryLines += "================================"
$summaryLines += "VCF Edge Cluster Configuration"
$summaryLines += "================================"
$summaryLines += "Management Edge Cluster:"
$summaryLines += "  - m01edge01.vcf.lab.io"
$summaryLines += "    Mgmt: $VCFMgmtNetwork.32"
$summaryLines += "    TEP:  10.2.140.32, 10.2.140.33"
$summaryLines += "    Uplink1: 192.168.168.1/31 <-> 192.168.168.0 (VyOS)"
$summaryLines += "    Uplink2: 192.168.68.1/31 <-> 192.168.68.0 (VyOS)"
$summaryLines += "  - m01edge02.vcf.lab.io"
$summaryLines += "    Mgmt: $VCFMgmtNetwork.33"
$summaryLines += "    TEP:  10.2.140.34, 10.2.140.35"
$summaryLines += "    Uplink1: 192.168.168.3/31 <-> 192.168.168.2 (VyOS)"
$summaryLines += "    Uplink2: 192.168.68.3/31 <-> 192.168.68.2 (VyOS)"
$summaryLines += ""
$summaryLines += "Workload Edge Cluster:"
$summaryLines += "  - wldedge01.vcf.lab.io"
$summaryLines += "    Mgmt: $VCFMgmtNetwork.43"
$summaryLines += "    TEP:  10.2.140.43, 10.2.140.44"
$summaryLines += "    Uplink1: 192.168.168.5/31 <-> 192.168.168.4 (VyOS)"
$summaryLines += "    Uplink2: 192.168.68.5/31 <-> 192.168.68.4 (VyOS)"
$summaryLines += "  - wldesge02.vcf.lab.io"
$summaryLines += "    Mgmt: $VCFMgmtNetwork.45"
$summaryLines += "    TEP:  10.2.140.45, 10.2.140.46"
$summaryLines += "    Uplink1: 192.168.168.7/31 <-> 192.168.168.6 (VyOS)"
$summaryLines += "    Uplink2: 192.168.68.7/31 <-> 192.168.68.6 (VyOS)"
$summaryLines += ""
$summaryLines += "================================"
$summaryLines += "BGP Configuration"
$summaryLines += "================================"
$summaryLines += "Router ASN:        65000 (VyOS)"
$summaryLines += "Mgmt Edge ASN:     65001"
$summaryLines += "Workload Edge ASN: 65002"
$summaryLines += "BGP Password:      VMware1!"
$summaryLines += ""
$summaryLines += "================================"
$summaryLines += "VVF Network Details"
$summaryLines += "================================"
$summaryLines += "ESXi MGMT: $vvfMgmtNetworkCidr (Gateway: $vvfMgmtGateway) - VLAN $vvfMgmtVlanId"
$summaryLines += "vMotion:   $vvfVMotionNetworkCidr (Gateway: $vvfVMotionGateway) - VLAN $vvfVMotionVlanId"
$summaryLines += "vSAN:      $vvfVsanNetworkCidr (Gateway: $vvfVsanGateway) - VLAN $vvfVsanVlanId"
$summaryLines += ""
$summaryLines += "================================"
$summaryLines += "Files Generated"
$summaryLines += "================================"
$summaryLines += "VCF Unified Config: $vcfConfigPath"
$summaryLines += "  (Includes: Network, Edge, BGP)"
$summaryLines += "VVF Config: $vvfConfigPath"
$summaryLines += "VyOS Configuration: $vyosConfigPath"
$summaryLines += "Summary: $summaryPath"

if ($TestMode) {
    $summaryLines += ""
    $summaryLines += "NOTE: This was generated in TEST MODE"
    $summaryLines += "DNS entries were NOT actually created"
}

$summaryLines | Out-File -FilePath $summaryPath -Encoding UTF8
Write-Host "Summary saved to: $summaryPath" -ForegroundColor Green

# ==========================================
# PORT GROUP CREATION (Optional)
# ==========================================

if ($CreatePortGroups) {
    Write-Host ""
    Write-Host "=== Creating Port Groups on vSwitch ===" -ForegroundColor Cyan
    
    # Check if vCenter parameters are provided
    if (-not $VIServer -or -not $VIUsername -or -not $VIPassword) {
        Write-Host "Error: -CreatePortGroups requires -VIServer, -VIUsername, and -VIPassword" -ForegroundColor Red
        Write-Host "Example: -CreatePortGroups -VIServer 'vcenter.lab.io' -VIUsername 'administrator@vsphere.local' -VIPassword 'password'" -ForegroundColor Yellow
        exit 1
    }
    
   
    Write-Host "Connecting to vCenter: $VIServer" -ForegroundColor Cyan
    
    try {
        $viConnection = Connect-VIServer -Server $VIServer -User $VIUsername -Password $VIPassword -ErrorAction Stop
        Write-Host "Connected to vCenter successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Error connecting to vCenter: $_" -ForegroundColor Red
        exit 1
    }
    
    # Function to create port group if it doesn't exist
    function Create-PortGroup {
        param(
            [string]$Name,
            [string]$VLanId,
            [string]$vSwitch,
            [string]$Description
        )
        
        try {
            # Check if port group already exists
            $existingPG = Get-VirtualPortGroup -Name $Name -Standard -ErrorAction SilentlyContinue
            
            if ($existingPG) {
                Write-Host "  Port Group already exists: $Name (VLAN $VLanId)" -ForegroundColor Gray
                return $true
            }
            
            # Get the vSwitch
            $vSwitchObj = Get-VirtualSwitch -Name $vSwitch -Standard -ErrorAction Stop
            
            # Create the port group
            $newPG = New-VirtualPortGroup -VirtualSwitch $vSwitchObj -Name $Name -VLanId $VLanId -ErrorAction Stop
            Write-Host "  Created Port Group: $Name (VLAN $VLanId)" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "  Error creating port group $Name : $_" -ForegroundColor Red
            return $false
        }
    }
    
    Write-Host ""
    Write-Host "Creating VCF Port Groups on vSwitch: $vSwitchName" -ForegroundColor Cyan
    Write-Host "  Port Group Prefix: $PortGroupPrefix" -ForegroundColor Gray
    Write-Host ""
    
    # VCF Port Groups
    $vcfPortGroups = @(
        @{Name="${PortGroupPrefix}VCF-MGMT"; VLAN=$vcfMgmtVlanId; Description="VCF Management Network"},
        @{Name="${PortGroupPrefix}VCF-vMotion"; VLAN=$vcfVMotionVlanId; Description="VCF vMotion Network"},
        @{Name="${PortGroupPrefix}VCF-vSAN"; VLAN=$vcfVsanVlanId; Description="VCF vSAN Network"},
        @{Name="${PortGroupPrefix}VCF-HostTEP"; VLAN=$vcfHostTepVlanId; Description="VCF Host Overlay Network"},
        @{Name="${PortGroupPrefix}VCF-EdgeTEP"; VLAN=$vcfEdgeTepVlanId; Description="VCF Edge Overlay Network"},
        @{Name="${PortGroupPrefix}VCF-Uplink1"; VLAN=$vcfEdgeUplink1VlanId; Description="VCF Edge Uplink 1"},
        @{Name="${PortGroupPrefix}VCF-Uplink2"; VLAN=$vcfEdgeUplink2VlanId; Description="VCF Edge Uplink 2"}
    )
    
    $vcfSuccess = 0
    $vcfFailed = 0
    
    foreach ($pg in $vcfPortGroups) {
        if (Create-PortGroup -Name $pg.Name -VLanId $pg.VLAN -vSwitch $vSwitchName -Description $pg.Description) {
            $vcfSuccess++
        } else {
            $vcfFailed++
        }
    }
    
    Write-Host ""
    Write-Host "Creating VVF Port Groups on vSwitch: $vSwitchName" -ForegroundColor Cyan
    Write-Host ""
    
    # VVF Port Groups
    $vvfPortGroups = @(
        @{Name="${PortGroupPrefix}VVF-MGMT"; VLAN=$vvfMgmtVlanId; Description="VVF Management Network"},
        @{Name="${PortGroupPrefix}VVF-vMotion"; VLAN=$vvfVMotionVlanId; Description="VVF vMotion Network"},
        @{Name="${PortGroupPrefix}VVF-vSAN"; VLAN=$vvfVsanVlanId; Description="VVF vSAN Network"}
    )
    
    $vvfSuccess = 0
    $vvfFailed = 0
    
    foreach ($pg in $vvfPortGroups) {
        if (Create-PortGroup -Name $pg.Name -VLanId $pg.VLAN -vSwitch $vSwitchName -Description $pg.Description) {
            $vvfSuccess++
        } else {
            $vvfFailed++
        }
    }
    
    Write-Host ""
    Write-Host "=== Port Group Creation Summary ===" -ForegroundColor Cyan
    Write-Host "VCF Port Groups: $vcfSuccess created, $vcfFailed failed" -ForegroundColor $(if($vcfFailed -eq 0){"Green"}else{"Yellow"})
    Write-Host "VVF Port Groups: $vvfSuccess created, $vvfFailed failed" -ForegroundColor $(if($vvfFailed -eq 0){"Green"}else{"Yellow"})
    Write-Host "Total: $(($vcfSuccess + $vvfSuccess)) port groups created" -ForegroundColor Green
    
    # Add port group info to summary file
    $portGroupSummary = @()
    $portGroupSummary += ""
    $portGroupSummary += "================================"
    $portGroupSummary += "Port Groups Created"
    $portGroupSummary += "================================"
    $portGroupSummary += "vSwitch: $vSwitchName"
    $portGroupSummary += ""
    $portGroupSummary += "VCF Port Groups:"
    foreach ($pg in $vcfPortGroups) {
        $portGroupSummary += "  - $($pg.Name) (VLAN $($pg.VLAN))"
    }
    $portGroupSummary += ""
    $portGroupSummary += "VVF Port Groups:"
    foreach ($pg in $vvfPortGroups) {
        $portGroupSummary += "  - $($pg.Name) (VLAN $($pg.VLAN))"
    }
    
    $portGroupSummary | Out-File -FilePath $summaryPath -Append -Encoding UTF8
    
    # Disconnect from vCenter
    Disconnect-VIServer -Server $viConnection -Confirm:$false
    Write-Host "Disconnected from vCenter" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== Complete! ===" -ForegroundColor Green
Write-Host "Configuration folder: $OutputFolder" -ForegroundColor Cyan
Write-Host ""
Write-Host "UNIFIED CONFIG: Edge and BGP settings are now in VCFDeploymentConfig.ps1!" -ForegroundColor Yellow
Write-Host "No separate CSV or conf files needed!" -ForegroundColor Yellow

if ($TestMode) {
    Write-Host ""
    Write-Host "Remember: This was TEST MODE - no DNS entries were created" -ForegroundColor Yellow
    Write-Host "Run without -TestMode on a DNS server to create actual entries" -ForegroundColor Yellow
}

if ($CreatePortGroups) {
    Write-Host ""
    Write-Host "Port groups have been created on vSwitch: $vSwitchName" -ForegroundColor Yellow
    Write-Host "Use these port groups when deploying VCF/VVF nested appliances" -ForegroundColor Yellow
}