# Windows Container MSDTC PoC

## Introduction

This document describes the step to have a container app doing msdtc transactions on 2 different SQL Server VMs on Azure.
The PoC environment includes:
- Domain Controller VM
- SQL Server 1 VM (domain joined)
- SQL Server 2 VM (domain joined)
- Container Host VM (domain joined)
- Container running inside that VM (using gMSA)

The sample application I used is doing just this:

````c#
class Program
{
    static void Main(string[] args)
    {
        bool useTx = false;
        if (args.Length > 0)
            if (args[0] == "Y")
                useTx = true;

        string connstr1 = "Server=sql1;Database=test;Integrated Security=True;MultipleActiveResultSets=True;Connect Timeout=30";
        string connstr2 = "Server=sql2;Database=test;Integrated Security=True;MultipleActiveResultSets=True;Connect Timeout=30";

        if (useTx)
        {
            Console.WriteLine("Starting transaction scope...");
            using (TransactionScope scope = new TransactionScope())
            {
                _executeCommand(connstr1);
                _executeCommand(connstr2);
                scope.Complete();
            }
        }
        else
        {
            _executeCommand(connstr1);
            _executeCommand(connstr2);
        }
        Console.WriteLine("OK!");
    }

    private static void _executeCommand(string connstr)
    {
        Console.WriteLine("Connecting to database... ");
        using (SqlConnection connection1 = new SqlConnection(connstr))
        {
            // Opening the connection automatically enlists it in the 
            // TransactionScope as a lightweight transaction.
            connection1.Open();


            Console.WriteLine("Inserting items... ");
            SqlCommand cmd = new SqlCommand("INSERT INTO [Table] VALUES ('NewItem')", connection1);
            cmd.ExecuteNonQuery();

        }
    }
}
````

## Environment Setup

### Container Host VM

For the container Host VM I used [this](https://github.com/patobelardo/azure-container-networking/blob/master/scripts/New-ContainerHostVm.ps1) Azure ARM Template.

Some modifications:
- Changed the $WindowsImageSku to "2019-Datacenter-with-Containers"
- VnetName based on my needs

### Instructions to create the gMSA

Service account creation (at the domain controller)

````powershell
Import-module ActiveDirectory
Add-KdsRootKey –EffectiveTime ((get-date).addhours(-10));
New-ADServiceAccount -Name [account_name] -DNSHostName myapp.mydomain.local -PrincipalsAllowedToRetrieveManagedPassword "Domain Controllers", "Domain Admins", "CN=Container Hosts,CN=Builtin, DC=mydomain, DC=local" -KerberosEncryptionType RC4, AES128, AES256
````

Add Host to the "Container Hosts" group and verify with:

````powershell
Get-ADGroupMember -Identity "CN=Container Hosts,CN=Builtin, DC=mydomain, DC=local"
````

After restart the host, execute this (on each host):

````powershell
Enable-WindowsOptionalFeature -FeatureName ActiveDirectory-Powershell -online -all
Get-ADServiceAccount -Identity [account_name]
Install-ADServiceAccount -Identity [account_name]
Test-AdServiceAccount -Identity [account_name]
````

Create json to be used by containers

````powershell
Invoke-WebRequest "https://raw.githubusercontent.com/Microsoft/Virtualization-Documentation/live/windows-server-container-tools/ServiceAccounts/CredentialSpec.psm1" -UseBasicParsing -OutFile $env:TEMP\cred.psm1
import-module $env:temp\cred.psm1
New-CredentialSpec -Name Gmsa -AccountName [account_name]
#This will return location and name of JSON file
Get-CredentialSpec
````

Added credentials to SQLs

````sql
CREATE LOGIN [domain\account_name$] FROM WINDOWS

sp_addsrvRolemember "[domain\account_name$]", "sysadmin"
````

## Container Host Setup

### Install CNI driver

Follow [this](https://github.com/patobelardo/azure-container-networking/blob/master/docs/cni.md) instructions

### Configure docker-exec script

[Here](https://github.com/patobelardo/azure-container-networking/blob/master/scripts/docker-exec.ps1) is the original script.

I made changes for my environment, like the path of cni (different to the k folder for k8s). Here is mine after some changes:

````powershell
Param(
	[parameter(Mandatory=$true)]
	[string] $containerName,
	
	[parameter(Mandatory=$true)]
	[string] $namespace,
	
	[parameter(Mandatory=$true)]
	[string] $image,
	
	[parameter (Mandatory=$true)]
	[string] $command
)

$contid=''

if ( $command -eq 'ADD' ) {
	$contid=(docker run -d  --security-opt "credentialspec=file://gmsa.json" -h myapp --name $containerName --net=none $image cmd /c ping -t localhost )
	$env:CNI_CONTAINERID=$contid
	$env:CNI_COMMAND='ADD'
} 
else {
	$contid=(docker inspect -f '{{ .Id }}' $containerName)
	$env:CNI_CONTAINERID=$contid
	$env:CNI_COMMAND='DEL'
}

$env:CNI_NETNS='none'
$env:CNI_PATH='c:\cni\bin'
$env:PATH="$env:CNI_PATH;"+$env:PATH
$k8sargs='IgnoreUnknown=1;K8S_POD_NAMESPACE={0};K8S_POD_NAME={1};K8S_POD_INFRA_CONTAINER_ID={2}' -f $namespace, $containerName, $contid
$env:CNI_ARGS=$k8sargs
$env:CNI_IFNAME='eth0'

$config=(jq-win64 '.plugins[0]' c:\cni\netconf\10-azure.conflist)
$name=(jq-win64 -r '.name' c:\cni\netconf\10-azure.conflist)
$config=(echo $config | jq-win64 --arg name $name '. + {name: $name}')
$cniVersion=(jq-win64 -r '.cniVersion' c:\cni\netconf\10-azure.conflist)
$config=(echo $config | jq-win64 --arg cniVersion $cniVersion '. + {cniVersion: $cniVersion}')

#$config

$res=(echo $config | azure-vnet)

echo $res

#optional - change dns record on DC

$ip = (ConvertFrom-Json ($res -join '')).ips 
$addresscidr = ($ip | select address).address
$ipaddress = Split-Path -Path $addresscidr -Parent

Invoke-Command -ScriptBlock {

    $OldObj = Get-DnsServerResourceRecord -Name "myapp" -ZoneName "mydomain.local" -RRType "A"
    $newObj = $OldObj.Clone()
    $newobj.recorddata.ipv4address=[System.Net.IPAddress]::parse($args[0])
    $NewObj.TimeToLive = [System.TimeSpan]::FromMinutes(1)
    Set-DnsServerResourceRecord -NewInputObject $NewObj -OldInputObject $OldObj -ZoneName "mydomain.local" -PassThru

} -ArgumentList $ipaddress -ComputerName dc


````

### Changes at container level

Once you have connectivity, there are some changes I needed to do.

>This is changing WMI access to everyone and MSDTC to use No Authentication. This was intended for test purposes and needed to be fixed. 

#### DNS suffix

````powershell
Set-DnsClientGlobalSetting -SuffixSearchList @("mydomain.local")
````

#### DTC Settings

````powershell
Set-ItemProperty -Path HKLM:\Software\Microsoft\MSDTC\Security -Name "NetworkDtcAccess" -Value 1 ; `
Set-ItemProperty -Path HKLM:\Software\Microsoft\MSDTC\Security -Name "NetworkDtcAccessClients" -Value 1 ; `
Set-ItemProperty -Path HKLM:\Software\Microsoft\MSDTC\Security -Name "NetworkDtcAccessInbound" -Value 1 ; `
Set-ItemProperty -Path HKLM:\Software\Microsoft\MSDTC\Security -Name "NetworkDtcAccessOutbound" -Value 1 ; `
Set-ItemProperty -Path HKLM:\Software\Microsoft\MSDTC\Security -Name "NetworkDtcAccessTransactions" -Value 1 ; `
Set-ItemProperty -Path HKLM:\Software\Microsoft\MSDTC\Security -Name "NetworkDtcAccessTip" -Value 1 ; `
Set-ItemProperty -Path HKLM:\Software\Microsoft\MSDTC\Security -Name "LuTransactions" -Value 0 ; `
Set-ItemProperty -Path HKLM:\Software\Microsoft\MSDTC\Security -Name "XaTransactions" -Value 0 ; `
set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC -Name "AllowOnlySecureRpcCalls" -Value 0 ; `
set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC -Name "FallbackToUnsecureRPCIfNecessary" -Value 0 ; `
set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\MSDTC -Name "TurnOffRpcSecurity" -Value 1
````

> If you are doing it interactively, do a "restart-service msdtc"

#### COM Access settings

> I needed to do it in one specific environment, but not neccesary on others. Need to confirm.

````powershell
#Everyone
$sid = "S-1-1-0"
$SDDL = "A;;CCWP;;;$sid"
$DCOMSDDL = "A;;CCDCRP;;;$sid"
$Reg = [WMIClass]"\\localhost\root\default:StdRegProv"
$DCOM = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
$security = Get-WmiObject -Namespace root/cimv2 -Class __SystemSecurity
$converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
$binarySD = @($null)
$result = $security.PsBase.InvokeMethod("GetSD",$binarySD)
$outsddl = $converter.BinarySDToSDDL($binarySD[0])
$outDCOMSDDL = $converter.BinarySDToSDDL($DCOM)
$newSDDL = $outsddl.SDDL += "(" + $SDDL + ")"
$newDCOMSDDL = $outDCOMSDDL.SDDL += "(" + $DCOMSDDL + ")"
$WMIbinarySD = $converter.SDDLToBinarySD($newSDDL)
$WMIconvertedPermissions = ,$WMIbinarySD.BinarySD
$DCOMbinarySD = $converter.SDDLToBinarySD($newDCOMSDDL)
$DCOMconvertedPermissions = ,$DCOMbinarySD.BinarySD
$result = $security.PsBase.InvokeMethod("SetSD",$WMIconvertedPermissions)
$result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction", $DCOMbinarySD.binarySD)
````


### Checklist

- DNS is working well. I added code to update DNS automatically at the docker-exec.ps1
- Connectivity is working (NETBIOS and fqdn - ping and nslookup)
- Remote WMI is working (was the last piece of this PoC). Do a simple gwmi win32_operatingsystem -computer [containerID] and should work well (To be reviewed)



## Execution

````powershell
docker-exec.ps1 -containerName test -namespace default -image mcr.microsoft.com/windows/servercore:ltsc2019 -command ADD
````

> In this case, I copied the .exe file there and ran scripts mentioned before.

## Results

````powershell
PS C:\> .\sqltest_trusted.exe Y
Starting transaction scope...
Connecting to database...
Inserting items...
Connecting to database...
Inserting items...
OK!
PS C:\>
PS C:\> $env:computername
dockermsa
PS C:\>
````
