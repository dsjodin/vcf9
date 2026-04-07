# Physical vCenter Server environment
$VIServer = "labvcsa.lab.io"
$VIUsername = "administrator@vsphere.local"
$VIPassword = "VMwareVCF9!"

# General Deployment Configuration
$VAppLabel = "VCF9"
$VMDatacenter = "Datacenter"
$VMCluster = "cluster"
$VMNetwork = "PG-VCF-MGMT"
$VMDatastore = "DS01"
$VMNetmask = "255.255.255.0"
$VMGateway = "{{GATEWAY}}"
$VMDNS = "10.1.10.10"
$VMNTP = "10.1.10.1"
$VMPassword = "VMware1!"
$VMDomain = "vcf.lab.io"
$VMSyslog = ""
$VMFolder = "{{FOLDER}}"

# Enable Debugging
$Debug = $false

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
$VCFInstallerDepotUsername = "depot"
$VCFInstallerDepotPassword = "VMwareVCF9!"
$VCFInstallerDepotHost = "10.1.10.20"
$VCFInstallerDepotPort = 80
$VCFInstallerDepotHttps = $false

# VCF Fleet Deployment Configuration
$DeploymentInstanceName = "VCF 9 Instance"
$DeploymentId = "m01"
$CEIPEnabled = $true
$FIPSEnabled = $true

# VCF Installer Configurations
$VCFInstallerVMName = "vcfinst"
$VCFInstallerFQDN = "vcfinst.vcf.lab.io"
$VCFInstallerIP = "{{VCF_NETWORK}}.10"
$VCFInstallerAdminUsername = "admin@local"
$VCFInstallerAdminPassword = "VMware1!VMware1!"
$VCFInstallerRootPassword = "VMware1!VMware1!"

# SDDC Manager Configuration
$SddcManagerHostname = "sddc"
$SddcManagerIP = "{{VCF_NETWORK}}.21"
$SddcManagerRootPassword = "VMware1!VMware1!"
$SddcManagerVcfPassword = "VMware1!VMware1!"
$SddcManagerSSHPassword = "VMware1!VMware1!"
$SddcManagerLocalPassword = "VMware1!VMware1!"

# Nested ESXi VMs for Management Domain
$NestedESXiHostnameToIPsForManagementDomain = @{
    "esx01"   = "{{VCF_NETWORK}}.11"
    "esx02"   = "{{VCF_NETWORK}}.12"
    "esx03"   = "{{VCF_NETWORK}}.13"
}

# Nested ESXi VMs for Workload Domain
$NestedESXiHostnameToIPsForWorkloadDomain = @{
    "esx04"   = "{{VCF_NETWORK}}.14"
    "esx05"   = "{{VCF_NETWORK}}.15"
    "esx06"   = "{{VCF_NETWORK}}.16"
}

# Nested ESXi VM Resources for Management Domain
$NestedESXiMGMTvCPU = "32"
$NestedESXiMGMTvMEM = "128" #GB
$NestedESXiMGMTCachingvDisk = "32" #GB
$NestedESXiMGMTCapacityvDisk = "500" #GB
$NestedESXiMGMTBootDisk = "64" #GB

# Nested ESXi VM Resources for Workload Domain
$NestedESXiWLDvCPU = "16"
$NestedESXiWLDvMEM = "96" #GB
$NestedESXiWLDCachingvDisk = "32" #GB
$NestedESXiWLDCapacityvDisk = "250" #GB
$NestedESXiWLDBootDisk = "64" #GB

# ESXi Network Configuration
$NestedESXiManagementNetworkCidr = "{{VCF_NETWORK_CIDR}}"
$NestedESXivMotionNetworkCidr = "{{VCF_VMOTION_CIDR}}"
$NestedESXivSANNetworkCidr = "{{VCF_VSAN_CIDR}}"
$NestedESXiNSXTepNetworkCidr = "{{VCF_NSXTEP_CIDR}}"

# vCenter Configuration
$VCSAName = "m01vc"
$VCSAIP = "{{VCF_NETWORK}}.23"
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
$VCFOperationsIP = "{{VCF_NETWORK}}.22"
$VCFOperationsRootPassword = "VMware1!VMware1!"
$VCFOperationsAdminPassword = "VMware1!VMware1!"

# NSX Configuration
$NSXManagerSize = "medium"
$NSXManagerVIPHostname = "nsx01"
$NSXManagerVIPIP = "{{VCF_NETWORK}}.24"
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
$VCFAutomationIPPool = @("{{VCF_NETWORK}}.34","{{VCF_NETWORK}}.37")
$VCFAutomationNodePrefix = "vcf-auto"
$VCFAutomationClusterCIDR = "198.18.0.0/15"

# ==========================================
# VCF WORKLOAD DOMAIN CONFIGURATION
# ==========================================

# Workload Domain General Configuration
$VCFWorkloadDomainConfig = @{
    Enabled = $true                          # Set to $false to skip workload domain
    DomainName = "w01"
    OrgName = "w01"
    EnableVCLM = $true
    EnableVSANESA = $false
    SSODomainType = "SharedSSO"              # SharedSSO or IsolatedSSO
}

# WLD vCenter Configuration
$VCFWorkloadDomainVCenter = @{
    Hostname = "w01vc"
    FQDN = "w01vc.vcf.lab.io"
    IP = "{{VCF_NETWORK}}.40"
    RootPassword = "VMware1!VMware1!"
    SSOPassword = "VMware1!VMware1!"
    Size = "small"
    Datacenter = "wld-dc"
    Cluster = "wld-cl01"
}

# WLD NSX Configuration
$VCFWorkloadDomainNSX = @{
    VIPHostname = "nsx02"
    VIPFQDN = "nsx02.vcf.lab.io"
    VIPIP = "{{VCF_NETWORK}}.41"
    ManagerNode1Hostname = "nsx02a"
    ManagerNode1FQDN = "nsx02a.vcf.lab.io"
    ManagerNode1IP = "{{VCF_NETWORK}}.42"
    Size = "medium"
    RootPassword = "VMware1!VMware1!"
    AdminPassword = "VMware1!VMware1!"
    AuditPassword = "VMware1!VMware1!"
    SeparateSwitch = $false
}

# WLD ESXi Hosts Configuration
$VCFWorkloadDomainHosts = @{
    "esx04" = "{{VCF_NETWORK}}.14"
    "esx05" = "{{VCF_NETWORK}}.15"
    "esx06" = "{{VCF_NETWORK}}.16"
}

# WLD Network Configuration
$VCFWorkloadDomainNetworks = @{
    Management = @{
        CIDR = "{{VCF_NETWORK_CIDR}}"
        Gateway = "{{GATEWAY}}"
        VLAN = "2100"
    }
    VMotion = @{
        CIDR = "{{VCF_VMOTION_CIDR}}"
        Gateway = "{{VCF_VMOTION_GATEWAY}}"
        VLAN = "2110"
        IPPoolStart = "{{VCF_VMOTION_NETWORK}}.201"
        IPPoolEnd = "{{VCF_VMOTION_NETWORK}}.218"
    }
    VSAN = @{
        CIDR = "{{VCF_VSAN_CIDR}}"
        Gateway = "{{VCF_VSAN_GATEWAY}}"
        VLAN = "2120"
        IPPoolStart = "{{VCF_VSAN_NETWORK}}.201"
        IPPoolEnd = "{{VCF_VSAN_NETWORK}}.218"
    }
    NSXTep = @{
        CIDR = "{{VCF_NSXTEP_CIDR}}"
        Gateway = "{{VCF_NSXTEP_GATEWAY}}"
        VLAN = "2130"
        IPPoolStart = "{{VCF_NSXTEP_NETWORK}}.201"
        IPPoolEnd = "{{VCF_NSXTEP_NETWORK}}.218"
    }
}

# ==========================================
# NSX EDGE & BGP CONFIGURATION
# ==========================================

# BGP Configuration
$BGPConfig = @{
    RouterASN = "65000"           # Physical Router (VyOS) ASN
    MgmtEdgeASN = "65001"         # Management Edge Cluster ASN
    WldEdgeASN = "65002"          # Workload Edge Cluster ASN
    Password = "VMware1!"         # BGP Authentication Password
}

# Edge TEP Network (Shared by both domains)
$EdgeTEPNetworkCidr = "{{VCF_EDGETEP_CIDR}}"
$EdgeTEPGateway = "{{VCF_EDGETEP_GATEWAY}}"
$EdgeTEPVLAN = "2140"

# Edge Uplink Networks
$EdgeUplink1NetworkCidr = "192.168.168.0/31"
$EdgeUplink1VLAN = "2150"
$EdgeUplink2NetworkCidr = "192.168.68.0/31"
$EdgeUplink2VLAN = "2160"

# Management Edge Cluster Configuration
$MgmtEdgeClusterConfig = @{
    ClusterName = "edge-cluster-mgmt"
    FormFactor = "MEDIUM"
    HighAvailability = "ACTIVE_ACTIVE"
    Nodes = @(
        @{
            Name = "m01edge01"
            FQDN = "m01edge01.vcf.lab.io"
            MgmtIP = "{{VCF_NETWORK}}.32"
            MgmtGateway = "{{GATEWAY}}"
            TEP1IP = "10.2.140.32"
            TEP2IP = "10.2.140.33"
            TEPGateway = "{{VCF_EDGETEP_GATEWAY}}"
            TEPVLAN = "2140"
            Uplinks = @(
                @{
                    Name = "Uplink-1"
                    VLAN = "2150"
                    IP = "192.168.168.1/31"
                    PeerIP = "192.168.168.0"
                },
                @{
                    Name = "Uplink-2"
                    VLAN = "2160"
                    IP = "192.168.68.1/31"
                    PeerIP = "192.168.68.0"
                }
            )
        },
        @{
            Name = "m01edge02"
            FQDN = "m01edge02.vcf.lab.io"
            MgmtIP = "{{VCF_NETWORK}}.33"
            MgmtGateway = "{{GATEWAY}}"
            TEP1IP = "10.2.140.34"
            TEP2IP = "10.2.140.35"
            TEPGateway = "{{VCF_EDGETEP_GATEWAY}}"
            TEPVLAN = "2140"
            Uplinks = @(
                @{
                    Name = "Uplink-1"
                    VLAN = "2150"
                    IP = "192.168.168.3/31"
                    PeerIP = "192.168.168.2"
                },
                @{
                    Name = "Uplink-2"
                    VLAN = "2160"
                    IP = "192.168.68.3/31"
                    PeerIP = "192.168.68.2"
                }
            )
        }
    )
}

# Workload Edge Cluster Configuration
$WldEdgeClusterConfig = @{
    ClusterName = "edge-cluster-wld"
    FormFactor = "MEDIUM"
    HighAvailability = "ACTIVE_ACTIVE"
    Nodes = @(
        @{
            Name = "wldedge01"
            FQDN = "wldedge01.vcf.lab.io"
            MgmtIP = "{{VCF_NETWORK}}.43"
            MgmtGateway = "{{GATEWAY}}"
            TEP1IP = "10.2.140.43"
            TEP2IP = "10.2.140.44"
            TEPGateway = "{{VCF_EDGETEP_GATEWAY}}"
            TEPVLAN = "2140"
            Uplinks = @(
                @{
                    Name = "Uplink-1"
                    VLAN = "2150"
                    IP = "192.168.168.5/31"
                    PeerIP = "192.168.168.4"
                },
                @{
                    Name = "Uplink-2"
                    VLAN = "2160"
                    IP = "192.168.68.5/31"
                    PeerIP = "192.168.68.4"
                }
            )
        },
        @{
            Name = "wldedge02"
            FQDN = "wldedge02.vcf.lab.io"
            MgmtIP = "{{VCF_NETWORK}}.45"
            MgmtGateway = "{{GATEWAY}}"
            TEP1IP = "10.2.140.45"
            TEP2IP = "10.2.140.46"
            TEPGateway = "{{VCF_EDGETEP_GATEWAY}}"
            TEPVLAN = "2140"
            Uplinks = @(
                @{
                    Name = "Uplink-1"
                    VLAN = "2150"
                    IP = "192.168.168.7/31"
                    PeerIP = "192.168.168.6"
                },
                @{
                    Name = "Uplink-2"
                    VLAN = "2160"
                    IP = "192.168.68.7/31"
                    PeerIP = "192.168.68.6"
                }
            )
        }
    )
}

# Supervisor Cluster Configuration (if deploying)
$SupervisorConfig = @{
    Enabled = $false  # Set to $true to enable
    Name = "supervisor"
    ServiceCIDR = "10.96.0.0/23"
    ZoneName = "z-wld"
    ControlPlane = @{
        StartIP = "{{VCF_NETWORK}}.50"
        EndIP = "{{VCF_NETWORK}}.52"
    }
    VPC = @{
        PrivateTransitCIDR = "100.96.0.0/16"
        PrivateCIDR = "172.26.0.0/16"
    }
}
