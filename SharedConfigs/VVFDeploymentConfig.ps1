# Physical vCenter Server environment
$VIServer = "labvcsa.lab.io"
$VIUsername = "administrator@vsphere.local"
$VIPassword = "VMwareVCF9!"

# General Deployment Configuration
$VAppLabel = "VVF9"
$VMDatacenter = "Datacenter"
$VMCluster = "cluster"
$VMNetwork = "DSTEST"
$VMDatastore = "DS01"
$VMNetmask = "255.255.255.0"
$VMGateway = "10.3.100.1"
$VMDNS = "10.1.10.10"
$VMNTP = "10.1.10.1"
$VMPassword = "VMware1!"
$VMDomain = "vvf.lab.io"
$VMSyslog = ""
$VMFolder = "VVF-Shared"

# Enable Debugging
$Debug = $false

# Full Path to both the Nested ESXi & VCF Installer OVA
$NestedESXiApplianceOVA = "c:\vcf_deploy\images\Nested_ESXi9.0.1_Appliance_Template_v1.0.ova"
$VCFInstallerOVA = "c:\vcf_deploy\images\VCF-SDDC-Manager-Appliance-9.0.1.0.24962180.ova"

# VCF Version
$VCFInstallerProductVersion = "9.0.1.0"
$VCFInstallerProductSKU = "VVF"

# VCF Software Depot Configuration
$VCFInstallerSoftwareDepot = "offline" #online or offline
$VCFInstallerDepotToken = ""

# Offline Depot Configurations (optional)
$VCFInstallerDepotUsername = "depot"
$VCFInstallerDepotPassword = "VMwareVCF9!"
$VCFInstallerDepotHost = "10.1.10.20"
$VCFInstallerDepotPort = 80
$VCFInstallerDepotHttps = $false

# VCF Fleet Deployment Configuration
$DeploymentInstanceName = "VVF 9 Instance"
$DeploymentId = "vvf-m01"
$CEIPEnabled = $true
$FIPSEnabled = $true

# VCF Installer Configurations
$VCFInstallerVMName = "vvfinst"
$VCFInstallerFQDN = "vvfinst.vvf.lab.io"
$VCFInstallerIP = "10.3.100.10"
$VCFInstallerAdminUsername = "admin@local"
$VCFInstallerAdminPassword = "VMware1!VMware1!"
$VCFInstallerRootPassword = "VMware1!VMware1!"

# Nested ESXi VMs for Management Domain
$NestedESXiHostnameToIPsForManagementDomain = @{
    "esx01"   = "10.3.100.11"
    "esx02"   = "10.3.100.12"
    "esx03"   = "10.3.100.13"
}

# Nested ESXi VM Resources for Management Domain
$NestedESXiMGMTvCPU = "24"
$NestedESXiMGMTvMEM = "128" #GB
$NestedESXiMGMTCachingvDisk = "32" #GB
$NestedESXiMGMTCapacityvDisk = "500" #GB
$NestedESXiMGMTBootDisk = "64" #GB

# ESXi Network Configuration
$NestedESXiManagementNetworkCidr = "10.3.100.0/24"
$NestedESXivMotionNetworkCidr = "10.3.110.0/24"
$NestedESXivSANNetworkCidr = "10.3.120.0/24"
$NestedESXiNSXTepNetworkCidr = "10.1.34.0/24"

# vCenter Configuration
$VCSAName = "vc"
$VCSAIP = "10.3.100.14"
$VCSARootPassword = "VMware1!VMware1!"
$VCSASSOPassword = "VMware1!VMware1!"
$VCSASize = "small"
$VCSAEnableVCLM = $true
$VCSADatacenterName = "mgmt-dc"
$VCSAClusterName = "mgmt-cl01"

#vSAN Configuration
$VSANFTT = 0
$VSANDedupe = $false
$VSANESAEnabled = $false
$VSANDatastoreName = "vsanDatastore"

# VCF Operations Configuration
$VCFOperationsSize = "small"
$VCFOperationsHostname = "ops"
$VCFOperationsIP = "10.3.100.15"
$VCFOperationsRootPassword = "VMware1!VMware1!"
$VCFOperationsAdminPassword = "VMware1!VMware1!"

# ==========================================
# NSX EDGE & BGP CONFIGURATION
# ==========================================
# Note: VVF does not include NSX Edge or BGP configuration
# These sections are kept empty for consistency

$BGPConfig = @{
    RouterASN = $null
    MgmtEdgeASN = $null
    WldEdgeASN = $null
    Password = $null
}

$MgmtEdgeClusterConfig = @{
    ClusterName = $null
    FormFactor = $null
    HighAvailability = $null
    Nodes = @()
}

$WldEdgeClusterConfig = @{
    ClusterName = $null
    FormFactor = $null
    HighAvailability = $null
    Nodes = @()
}

$SupervisorConfig = @{
    Enabled = $false
}

