# Physical vCenter Server environment
$VIServer = "labvcsa.lab.io"
$VIUsername = "administrator@vsphere.local"
$VIPassword = "VMwareVCF9!"

# General Deployment Configuration
$VAppLabel = "TSLAB"
$VMDatacenter = "Datacenter"
$VMCluster = "labcluster"
$VMNetwork = "nested_trunk"
$VMDatastore = "DS01"
$ESXMGMTVLAN = "100"
$VMMGMTVLAN = "101"
$ESWLDVLAN = "200"
$VMVCFInstNetwork = "VLAN100"
$VMNetmask = "255.255.255.0"
$ESXMGMTGateway = "10.2.100.1"
$VMMGMTGateway = "10.2.101.1"
$VMWLDGateway = "10.2.200.1"
$VMDNS = "10.1.10.10"
$VMNTP = "10.1.10.1"
$VMPassword = "VMwareVCF9!"
$VMDomain = "vcf.lab.io"
$VMSyslog = ""
$VMFolder = "TSLAB"

# Enable Debugging
$Debug = $true

# Full Path to both the Nested ESXi & VCF Installer OVA
$NestedESXiApplianceOVA = "c:\vcf_deploy\images\Nested_ESXi9.0.1_Appliance_Template_v1.0.ova"
$VCFInstallerOVA = "c:\vcf_deploy\images\VCF-SDDC-Manager-Appliance-9.0.1.0.24962180.ova"


# VCF Version
$VCFInstallerProductVersion = "9.0.1.0"
$VCFInstallerProductSKU = "VCF"

# VCF Software Depot Configuration
$VCFInstallerSoftwareDepot = "offline" #online or offline
$VCFInstallerDepotToken = ""

# Offline Depot Configurations (optional)
$VCFInstallerDepotUsername = "vcf"
$VCFInstallerDepotPassword = "vcf123!"
$VCFInstallerDepotHost = "10.1.10.11"
$VCFInstallerDepotPort = 80
$VCFInstallerDepotHttps = $false

# VCF Fleet Deployment Configuration
$DeploymentInstanceName = "VCF9 Lab Instance"
$DeploymentId = "m01"
$CEIPEnabled = $false
$FIPSEnabled = $false

# VCF Installer Configurations
$VCFInstallerVMName = "vcfinst"
$VCFInstallerFQDN = "vcfinst.vcf.lab.io"
$VCFInstallerIP = "10.2.100.9"
$VCFInstallerAdminUsername = "admin@local"
$VCFInstallerAdminPassword = "VMware1!VMware1!"
$VCFInstallerRootPassword = "VMware1!VMware1!"

# SDDC Manager Configuration
$SddcManagerHostname = "sddcm01"
$SddcManagerIP = "10.2.100.20"
$SddcManagerRootPassword = "VMware1!VMware1!"
$SddcManagerVcfPassword = "VMware1!VMware1!"
$SddcManagerSSHPassword = "VMware1!VMware1!"
$SddcManagerLocalPassword = "VMware1!VMware1!"

# Nested ESXi VMs for Management Domain
$NestedESXiHostnameToIPsForManagementDomain = @{
    "esx01"   = "10.2.100.10"
    "esx02"   = "10.2.100.11"
    "esx03"   = "10.2.100.12"
    "esx04"   = "10.2.100.13"
}

# Nested ESXi VMs for Workload Domain
$NestedESXiHostnameToIPsForWorkloadDomain = @{
    "esx05"   = "10.2.200.10"
    "esx06"   = "10.2.200.11"
    "esx07"   = "10.2.200.12"
}

# Nested ESXi VM Resources for Management Domain
$NestedESXiMGMTvCPU = "24"
$NestedESXiMGMTvMEM = "128" #GB
$NestedESXiMGMTCapacityvDisk = "500" #GB
$NestedESXiMGMTBootDisk = "64" #GB

# Nested ESXi VM Resources for Workload Domain
$NestedESXiWLDvCPU = "24"
$NestedESXiWLDvMEM = "128" #GB
$NestedESXiWLDCapacityvDisk = "500" #GB
$NestedESXiWLDBootDisk = "64" #GB

# ESXi Network Configuration
$NestedMGMTESXiManagementNetworkCidr = "10.2.100.0/24" # should match $VMNetwork configuration
$NestedMGMTESXivMotionNetworkCidr = "10.2.101.0/24"
$NestedMGMTESXivSANNetworkCidr = "10.2.102.0/24"
$NestedMGMTESXiNSXTepNetworkCidr = "10.2.103.0/24"
$NestedMGMTESXiEdgeTepNetworkCidr = "10.2.104.0/24"

$NestedWLDESXiManagementNetworkCidr = "10.2.200.0/24" # should match $VMNetwork configuration
$NestedWLDESXivMotionNetworkCidr = "10.2.201.0/24"
$NestedWLDESXivSANNetworkCidr = "10.2.202.0/24"
$NestedWLDESXiNSXTepNetworkCidr = "10.2.203.0/24"
$NestedWLDESXiEdgeTepNetworkCidr = "10.2.204.0/24"
$NestedWLDServiceNetworkCidr = "10.96.0.0/24"

# vCenter Configuration
$VCSAName = "mgmt-vc"
$VCSAIP = "10.2.100.21"
$VCSARootPassword = "VMware1!VMware1!"
$VCSASSOPassword = "VMware1!VMware1!"
$VCSASize = "small"
$VCSAEnableVCLM = $true
$VCSADatacenterName = "mgmt-dc"
$VCSAClusterName = "mgmt-cl01"

#vSAN Configuration
$VSANFTT = 0
$VSANDedupe = $false
$VSANESAEnabled = $true
$VSANDatastoreName = "vsanDatastore"

# VCF Operations Configuration
$VCFOperationsSize = "small"
$VCFOperationsHostname = "ops"
$VCFOperationsIP = "10.2.100.22"
$VCFOperationsRootPassword = "VMware1!VMware1!"
$VCFOperationsAdminPassword = "VMware1!VMware1!"

# NSX Configuration
$NSXManagerSize = "medium"
$NSXManagerVIPHostname = "nsx01"
$NSXManagerVIPIP = "10.2.100.23"
$NSXManagerNodeHostname = "nsx01a"
$NSXRootPassword = "VMware1!VMware1!"
$NSXAdminPassword = "VMware1!VMware1!"
$NSXAuditPassword = "VMware1!VMware1!"

# VCF Operations Collector
$VCFOperationsCollectorSize = "small"
$VCFOperationsCollectorHostname = "opsproxy01"
$VCFOperationsCollectorRootPassword = "VMware1!VMware1!"

# VCF Operations Fleet Manager
$VCFOperationsFleetManagerHostname = "opsfm01"
$VCFOperationsFleetManagerAdminPassword = "VMware1!VMware1!"
$VCFOperationsFleetManagerRootPassword = "VMware1!VMware1!"

# VCF Automation
$VCFAutomationHostname = "auto01"
$VCFAutomationAdminPassword = "VMware1!VMware1!"
$VCFAutomationIPPool = @("10.2.100.26","10.2.100.27")
$VCFAutomationNodePrefix = "auto01"
$VCFAutomationClusterCIDR = "198.18.0.0/15"

# VCF Workload Domain Configurations
$VCFWorkloadDomainName = "w01"
$VCFWorkloadDomainOrgName = "w01"
$VCFWorkloadDomainEnableVCLM = $true
$VCFWorkloadDomainEnableVSANESA = $true

# WLD vCenter Configuration
$VCFWorkloadDomainVCSAHostname = "wld-vc"
$VCFWorkloadDomainVCSAIP = "10.2.200.20"
$VCFWorkloadDomainVCSARootPassword = "VMware1!VMware1!"
$VCFWorkloadDomainVCSASSOPassword = "VMware1!VMware1!"
$VCFWorkloadDomainVCSADatacenterName = "wld-dc"
$VCFWorkloadDomainVCSAClusterName = "wld-cl01"

# WLD NSX Configuration
$VCFWorkloadDomainNSXManagerVIPHostname = "nsx02"
$VCFWorkloadDomainNSXManagerNode1Hostname = "nsx02a"
$VCFWorkloadDomainNSXManagerNode1IP = "10.2.200.21"
$VCFWorkloadDomainNSXAdminPassword = "VMware1!VMware1!"
$VCFWorkloadDomainSeparateNSXSwitch = $false
