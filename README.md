# Instructions to create the gMSA

Create the service account

````powershell
Import-module ActiveDirectory
Add-KdsRootKey –EffectiveTime ((get-date).addhours(-10));
New-ADServiceAccount -Name container_host -DNSHostName myapp.careadvance.local -PrincipalsAllowedToRetrieveManagedPassword "Domain Controllers", "Domain Admins", "CN=Container Hosts,CN=Builtin, DC=careadvance, DC=local" -KerberosEncryptionType RC4, AES128, AES256
````

Add Host to the group and verify with:

````powershell
Get-ADGroupMember -Identity "CN=Container Hosts,CN=Builtin, DC=careadvance, DC=local"
````

After restart the host, execute this (on each host):

````powershell
Enable-WindowsOptionalFeature -FeatureName ActiveDirectory-Powershell -online -all
Get-ADServiceAccount -Identity container_host1
Install-ADServiceAccount -Identity container_host1
Test-AdServiceAccount -Identity container_host1
````

Create json to be used by containers

````powershell
Invoke-WebRequest "https://raw.githubusercontent.com/Microsoft/Virtualization-Documentation/live/windows-server-container-tools/ServiceAccounts/CredentialSpec.psm1" -UseBasicParsing -OutFile $env:TEMP\cred.psm1
import-module $env:temp\cred.psm1
New-CredentialSpec -Name Gmsa -AccountName container_host1
#This will return location and name of JSON file
Get-CredentialSpec
````

Added credentials to SQLs

````sql
CREATE LOGIN [careadvance\container_host$] FROM WINDOWS

sp_addsrvRolemember "careadvance\container_host$", "sysadmin"
````

Docker run

Registered myapp as well.



````cmd
docker run --security-opt "credentialspec=file://gmsa.json" -d -p 80:80 -h myapp.mydomain.local test

 docker run -d --network tlan --security-opt "credentialspec=file://gmsa.json" -h myapp patobelardo/testv3
````
Under the docker container

````
$adapter = (Get-NetAdapter).name
New-NetIPAddress -IPAddress 10.0.2.44 -PrefixLength 24 -DefaultGateway 10.0.2.4 -InterfaceAlias $adapter
Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses ("10.0.3.4")
Set-DnsClient -InterfaceAlias $adapter -ConnectionSpecificSuffix "careadvance.local"
Set-DnsClientGlobalSetting -SuffixSearchList ("careadvance.local")

Set-DtcNetworkSetting -InboundTransactionsEnabled $true -OutboundTransactionsEnabled $true -RemoteClientAccesEnabled $true -RemoteAdministrationAccessEnabled $true -AuthenticationLevel NoAuth

````c#
Server=sql2;Database=test;Integrated Security=True;MultipleActiveResultSets=True;Connect Timeout=30
````

Reference: https://github.com/artisticcheese/artisticcheesecontainer/wiki/Using-Group-Managed-Service-Account-(GMSA)-to-connect-to-AD-resources

https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/manage-serviceaccounts


## Swarm mode

docker service create --name registry --publish 5000:5000 registry:2

docker tag myimage localhost:5000/myimage
docker push localhost:5000/myimage

## Kubernetes cluster

https://github.com/Azure/aks-engine/blob/master/docs/topics/windows.md#mac

Changed the vnet cidr  to 11.x.x.x
````cli
az group create --location eastus --name careadvance-aks-win

az group deployment create --name deploy1 --resource-group careadvance-aks-win --template-file ./_output/careadvance-aks/azuredeploy.json --parameters ./_output/careadvance-aks/azuredeploy.parameters.json 
````

Created vnet peering

Join the node to the domain

Can't use gMSA - https://github.com/kubernetes/website/pull/12869 

https://github.com/kubernetes/kubernetes/issues/62038 

## Pendings

- Try with l2bridge vnet
- Swarm mode - I can't use the gMSA
- 




# NOTE

https://docs.microsoft.com/en-us/dotnet/standard/modernize-with-azure-and-containers/modernize-existing-apps-to-cloud-optimized/when-not-to-deploy-to-windows-containers






Backup


# Setup MSDTC with "No authentcation required"
RUN Set-ItemProperty -Path HKLM:\Software\Microsoft\MSDTC\Security -Name "NetworkDtcAccess" -Value 1 ; `
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



# Install my services and setup IIS webpage
COPY install/ C:/Install/
WORKDIR C:/Install
ARG sqlserver
RUN winrm quickconfig -q ; `
    Set-Item -Force wsman:\localhost\Client\TrustedHosts -value $env:sqlserver 
RUN cmd /c Installer.exe -silent ; `
    Set-Service MyService -StartupType Manual ; `
    Set-Service W3SVC -StartupType Manual
EXPOSE 3372
WORKDIR /
COPY start.ps1 C:/start.ps1



# Dev 2019-2

## Installed  from the Azure-CNI template VM

## Exec

docker rm $(docker ps -aq) --force; C:\users\pbelardo\azure-container-networking\scripts\\docker-exec.ps1 -containerName test -namespace default -image patobelardo/testapp2019 -command ADD

## Docker exec ps1

	$contid=(docker run -d -h myapp --security-opt "credentialspec=file://gmsa.json" --name $containerName --net=none $image  powershell Start-Sleep -m 1000000)


## At container level

````
Set-DnsClientGlobalSetting -SuffixSearchList @("careadvance.local")
Set-DtcNetworkSetting -InboundTransactionsEnabled $true -OutboundTransactionsEnabled $true -RemoteClientAccesEnabled $true -RemoteAdministrationAccessEnabled $true -AuthenticationLevel NoAuth
````

## Enable DCOM

-- Test wmi from outside.

```` Powershell
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
