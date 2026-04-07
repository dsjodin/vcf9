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

$ErrorActionPreference = "Stop"

# -------------------------------------------------------------------
# Load config
# -------------------------------------------------------------------
if (!(Test-Path $EnvConfigFile)) {
    Write-Host -ForegroundColor Red "`nConfig file not found: $EnvConfigFile`n"
    exit 1
}

. $EnvConfigFile   # dot-source the same config you posted

# -------------------------------------------------------------------
# Helper + logging
# -------------------------------------------------------------------
$random_string = -join ((48..57) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
$verboseLogFile = "wld-esxi-deployment-$random_string.log"

Function My-Logger {
    param(
        [Parameter(Mandatory = $true)][string]$message,
        [Parameter(Mandatory = $false)][string]$color = "Green"
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"
    Write-Host -NoNewline -ForegroundColor White "[$timeStamp]"
    Write-Host -ForegroundColor $color " $message"
    "[$timeStamp] $message" | Out-File -Append -LiteralPath $verboseLogFile
}

# -------------------------------------------------------------------
# Pre-checks
# -------------------------------------------------------------------
if ($PSVersionTable.PSEdition -ne "Core") {
    Write-Host -ForegroundColor Yellow "Warning: Script is tested with PowerShell Core. You're running: $($PSVersionTable.PSEdition)"
}

if (!(Test-Path $NestedESXiApplianceOVA)) {
    Write-Host -ForegroundColor Red "`nUnable to find Nested ESXi OVA: $NestedESXiApplianceOVA`n"
    exit 1
}

if (-not (Get-Module -Name VMware.VimAutomation.Core -ListAvailable)) {
    Write-Host -ForegroundColor Red "VMware PowerCLI module not found. Install it first:"
    Write-Host -ForegroundColor Cyan "  Install-Module VMware.PowerCLI"
    exit 1
}

# -------------------------------------------------------------------
# Summary + confirmation
# -------------------------------------------------------------------
Write-Host -ForegroundColor Yellow "`n---- WLD Nested ESXi Deployment (VCF 9 Lab) ----"
Write-Host -NoNewline -ForegroundColor Green "Config file: "
Write-Host -ForegroundColor White $EnvConfigFile

Write-Host -ForegroundColor Yellow "`n---- vCenter Target ----"
Write-Host -NoNewline -ForegroundColor Green "vCenter: "
Write-Host -ForegroundColor White $VIServer
Write-Host -NoNewline -ForegroundColor Green "Cluster: "
Write-Host -ForegroundColor White $VMCluster
Write-Host -NoNewline -ForegroundColor Green "Datastore: "
Write-Host -ForegroundColor White $VMDatastore
Write-Host -NoNewline -ForegroundColor Green "Network (Portgroup): "
Write-Host -ForegroundColor White $VMNetwork

Write-Host -ForegroundColor Yellow "`n---- WLD vESXi Config ----"
Write-Host -NoNewline -ForegroundColor Green "# of WLD Nested ESXi VMs: "
Write-Host -ForegroundColor White $NestedESXiHostnameToIPsForWorkloadDomain.Count
Write-Host -NoNewline -ForegroundColor Green "IP Address(es): "
Write-Host -ForegroundColor White ($NestedESXiHostnameToIPsForWorkloadDomain.Values -join ", ")
Write-Host -NoNewline -ForegroundColor Green "vCPU: "
Write-Host -ForegroundColor White $NestedESXiWLDvCPU
Write-Host -NoNewline -ForegroundColor Green "vMEM: "
Write-Host -ForegroundColor White "$NestedESXiWLDvMEM GB"
Write-Host -NoNewline -ForegroundColor Green "Boot Disk: "
Write-Host -ForegroundColor White "$NestedESXiWLDBootDisk GB"
Write-Host -NoNewline -ForegroundColor Green "vSAN Capacity Disk: "
Write-Host -ForegroundColor White "$NestedESXiWLDCapacityvDisk GB"
Write-Host -NoNewline -ForegroundColor Green "vMotion/vSAN/TEP VLANs come from existing config"

Write-Host -ForegroundColor Magenta "`nThis script will ONLY deploy the WLD Nested ESXi VMs."
Write-Host -ForegroundColor Magenta "Management domain, SDDC Manager and Installer are NOT touched.`n"

$answer = Read-Host -Prompt "Proceed with WLD ESXi deployment? (Y/N)"
if ($answer -notin @("Y","y")) {
    Write-Host "Aborted."
    exit 0
}

# -------------------------------------------------------------------
# Connect to vCenter
# -------------------------------------------------------------------
My-Logger "Connecting to vCenter Server $VIServer ..."
try {
    $viConnection = Connect-VIServer -Server $VIServer -User $VIUsername -Password $VIPassword -WarningAction SilentlyContinue
} catch {
    Write-Host -ForegroundColor Red "Failed to connect to vCenter: $($_.Exception.Message)"
    exit 1
}

try {
    $datastore = Get-Datastore -Server $viConnection -Name $VMDatastore | Select-Object -First 1
    $cluster   = Get-Cluster  -Server $viConnection -Name $VMCluster
    $vmhost    = $cluster | Get-VMHost | Get-Random -Count 1
} catch {
    Write-Host -ForegroundColor Red "Failed to resolve cluster/datastore/host: $($_.Exception.Message)"
    Disconnect-VIServer -Server $viConnection -Confirm:$false
    exit 1
}

My-Logger "Using host '$($vmhost.Name)' and datastore '$($datastore.Name)'."

# -------------------------------------------------------------------
# Deploy WLD Nested ESXi VMs
# -------------------------------------------------------------------
$StartTime = Get-Date

$NestedESXiHostnameToIPsForWorkloadDomain.GetEnumerator() |
    Sort-Object -Property Value | ForEach-Object {

    $VMName     = $_.Key
    $VMIPAddress = $_.Value

    # Check if VM already exists (to avoid Import-VApp failure)
    $existing = Get-VM -Server $viConnection -Name $VMName -ErrorAction SilentlyContinue
    if ($existing) {
        My-Logger "VM '$VMName' already exists. Skipping deployment of this host." "Yellow"
        return
    }

    $ovfconfig = Get-OvfConfiguration $NestedESXiApplianceOVA
    $networkMapLabel = ($ovfconfig.ToHashTable().keys |
                        Where-Object { $_ -match "NetworkMapping" }).replace("NetworkMapping.","").replace("-","_").replace(" ","_")

    $ovfconfig.NetworkMapping.$networkMapLabel.value   = $VMNetwork
    $ovfconfig.common.guestinfo.hostname.value         = "${VMName}.${VMDomain}"
    $ovfconfig.common.guestinfo.ipaddress.value        = $VMIPAddress
    $ovfconfig.common.guestinfo.netmask.value          = $VMNetmask
    $ovfconfig.common.guestinfo.gateway.value          = $ESXWLDGateway
    $ovfconfig.common.guestinfo.vlan.value             = $ESXWLDVLAN
    $ovfconfig.common.guestinfo.dns.value              = $VMDNS
    $ovfconfig.common.guestinfo.domain.value           = $VMDomain
    $ovfconfig.common.guestinfo.ntp.value              = $VMNTP
    $ovfconfig.common.guestinfo.syslog.value           = $VMSyslog
    $ovfconfig.common.guestinfo.password.value         = $VMPassword
    $ovfconfig.common.guestinfo.ssh.value              = $true

    My-Logger "Deploying WLD Nested ESXi VM $VMName ..."
    try {
        Import-VApp -Server $viConnection `
                   -Source $NestedESXiApplianceOVA `
                   -OvfConfiguration $ovfconfig `
                   -Name $VMName `
                   -Location $VMCluster `
                   -VMHost $vmhost `
                   -Datastore $datastore `
                   -DiskStorageFormat Thin | Out-Null

        $vm = Get-VM -Server $viConnection -Name $VMName
    } catch {
        My-Logger "Failed to deploy $VMName : $($_.Exception.Message)" "Red"
        throw
    }

    # Compute resources
    My-Logger "Updating compute for $VMName (vCPU=$NestedESXiWLDvCPU vMEM=${NestedESXiWLDvMEM}GB) ..."
    Set-VM -Server $viConnection -VM $vm `
           -NumCpu $NestedESXiWLDvCPU `
           -CoresPerSocket $NestedESXiWLDvCPU `
           -MemoryGB $NestedESXiWLDvMEM `
           -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

    # Storage (ESA style, mirror original script)
    My-Logger "Updating storage for $VMName (Boot Disk=${NestedESXiWLDBootDisk}GB, vSAN Capacity=${NestedESXiWLDCapacityvDisk}GB) ..."
    Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 1" |
        Set-HardDisk -CapacityGB $NestedESXiWLDBootDisk -Confirm:$false |
        Out-File -Append -LiteralPath $verboseLogFile

    My-Logger "Removing cache disk (Hard disk 2) for vSAN ESA configuration on $VMName ..."
    Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" |
        Remove-HardDisk -Confirm:$false |
        Out-File -Append -LiteralPath $verboseLogFile

    # Resize capacity disk (which becomes Hard disk 2 after removal)
    Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" |
        Set-HardDisk -CapacityGB $NestedESXiWLDCapacityvDisk -Confirm:$false |
        Out-File -Append -LiteralPath $verboseLogFile

    # Networking: add vmnic2/vmnic3
    My-Logger "Adding extra NICs (vmnic2/vmnic3) for $VMName ..."
    $vmPortGroup = Get-VirtualNetwork -Name $VMNetwork -Location ($cluster | Get-Datacenter)

    if ($vmPortGroup.NetworkType -eq "Distributed") {
        $vmPortGroup = Get-VDPortgroup -Name $VMNetwork
        New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $vmPortGroup -StartConnected -Confirm:$false |
            Out-File -Append -LiteralPath $verboseLogFile
        New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $vmPortGroup -StartConnected -Confirm:$false |
            Out-File -Append -LiteralPath $verboseLogFile
    } else {
        New-NetworkAdapter -VM $vm -Type Vmxnet3 -NetworkName $vmPortGroup -StartConnected -Confirm:$false |
            Out-File -Append -LiteralPath $verboseLogFile
        New-NetworkAdapter -VM $vm -Type Vmxnet3 -NetworkName $vmPortGroup -StartConnected -Confirm:$false |
            Out-File -Append -LiteralPath $verboseLogFile
    }

    # dvfilter MAC learn settings
    $vm | New-AdvancedSetting -Name "ethernet2.filter4.name"      -Value "dvfilter-maclearn" -Confirm:$false -ErrorAction SilentlyContinue |
        Out-File -Append -LiteralPath $verboseLogFile
    $vm | New-AdvancedSetting -Name "ethernet2.filter4.onFailure" -Value "failOpen"          -Confirm:$false -ErrorAction SilentlyContinue |
        Out-File -Append -LiteralPath $verboseLogFile

    $vm | New-AdvancedSetting -Name "ethernet3.filter4.name"      -Value "dvfilter-maclearn" -Confirm:$false -ErrorAction SilentlyContinue |
        Out-File -Append -LiteralPath $verboseLogFile
    $vm | New-AdvancedSetting -Name "ethernet3.filter4.onFailure" -Value "failOpen"          -Confirm:$false -ErrorAction SilentlyContinue |
        Out-File -Append -LiteralPath $verboseLogFile

    # Power on
    My-Logger "Powering on $VMName ..."
    $vm | Start-VM -RunAsync | Out-Null
}

# -------------------------------------------------------------------
# Disconnect + summary
# -------------------------------------------------------------------
My-Logger "Disconnecting from vCenter Server $VIServer ..."
Disconnect-VIServer -Server $viConnection -Confirm:$false | Out-Null

$EndTime  = Get-Date
$Duration = [Math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes, 2)

My-Logger "WLD Nested ESXi Deployment Complete!"
My-Logger "`tStartTime : $StartTime" -color Cyan
My-Logger "`tEndTime   : $EndTime"   -color Cyan
My-Logger "`tDuration  : $Duration minutes to deploy WLD Nested ESXi VMs" -color Cyan
My-Logger "`tLog file  : $verboseLogFile" -color Cyan
