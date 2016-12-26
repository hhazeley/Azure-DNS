   <#
  .SYNOPSIS
  Add and Verify an Office 365 domain using Azure DNS with just one line.
  
  .DESCRIPTION
  This script will added and verifiy a domain in Office 365 and the neccessary DNS records to Azure DNS 
  
  .EXAMPLE
  Add-O365DomainAzureDNS.ps1 -Domain testme.o365tech.us -SubscriptionId 1d6737e7-4f6c-4a9e-8cd4-996b6f003d0e -ResourceGroupName AzureT

  All paramaters are required for te script to complete successfully. 

  .PARAMETER Domain
  The domain that needs to be added to Office 365. Required

  .PARAMETER SubscriptionId
  The Azure Subscription ID for the subscription that the DNS zone should be on. Required
    
  .PARAMETER ResourceGroupName
  The Resource Group that the DNS Zone that the DNS zone should be on. Required

  .NOTES
  File Name  : Add-O365DomainAzureDNS.ps1
  Author     : Hannel Hazeley - hhazeley@outlook.com
  Version    : 2.0
  Requires   : Azure PowerShell 3.0 and higher and MSonline Module

  .LINK
  Demo: https://youtu.be/VU6WBS8-ZrE
  Repository: https://github.com/hhazeley/Azure-DNS
  #>

 Param(
    [Parameter(Mandatory=$true)]
    $Domain,
    [Parameter(Mandatory=$true)]
    $SubscriptionId,
    [Parameter(Mandatory=$true)]
    $ResourceGroupName 
   )

$ErrorActionPreference = "SilentlyContinue"
$timecode = Get-Date -Format yyyyMMddHHmm
Start-Transcript -Path .\$domain.$timecode.txt

#Function for error checks
Function ErrorCheck{
If ($errorck -ne $null)
{
Write-host
Write-host -ForegroundColor Red "ERROR: " -NoNewline
$errorck
Write-host
Stop-Transcript
Break
}
}

#Login to Azure and set suscription
Login-AzureRmAccount -ErrorVariable errorck | Out-Null
ErrorCheck
Select-AzureRmSubscription -SubscriptionId $SubscriptionId -ErrorVariable errorck
ErrorCheck

#Check for and/or created Azure Resource Group
$ResourceGroupNameValidation = Get-AzureRmResourceGroup -Name $ResourceGroupName 
if ($ResourceGroupNameValidation -eq $null)
{
$location = "West us"
New-AzureRmResourceGroup -Name $ResourceGroupName -location $location -Force -ErrorVariable errorck | Out-Null
ErrorCheck
}

#Create new Azure DNS Zone
New-AzureRmDnsZone -Name $Domain -ResourceGroupName $ResourceGroupName -ErrorAction Stop -ErrorVariable errorck | Out-Null
ErrorCheck

#Get NS record for new DNS Zone 
$NS = Get-AzureRmDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $Domain -RecordType NS
Write-Host -ForegroundColor Cyan "Please add NS records below to domain........"
$ns.Records.nsdname

#Function that process domain changes
Function ProcessDomain
{
Write-Host -ForegroundColor Green "NS Record Validated........"
Write-Host -ForegroundColor Yellow "Connecting to Office 365........"

#Connect to MSOL Environment 
$count = 0
Do
{
$cred = Get-Credential -Message "Please enter a Global Admin credential for your O365 Environment."
Connect-MsolService -Credential $cred
$MSOLValidation = (Get-MsolCompanyInformation).displayname
$count = $count + 1
}
Until ($MSOLValidation -ne $null -or $count -ge "5")

#Rollback if connection fails
If ($count -ge "5")
{
Write-Host -ForegroundColor Red "Invalid Office 365 Credential supplied........ Rolling Back"
RollBack
}

#If MSOL connection, create and Validate new MSOL Domain 
New-MsolDomain -Name $Domain -VerificationMethod DnsRecord -ErrorVariable errorck
If ($errorck -ne $null)
{
Write-host
Write-host -ForegroundColor Red "ERROR: " -NoNewline
$errorck
Write-host
RollBack
}
$txtVerification = (Get-MsolDomainVerificationDns -DomainName $Domain).label -replace ".$Domain",""

$TXTinfo = New-AzureRmDnsRecordConfig -Value "MS=$txtVerification"
New-AzureRmDnsRecordSet -Name "@" -RecordType TXT -ZoneName $Domain -Ttl 3600 -ResourceGroupName $ResourceGroupName -DnsRecords $TXTinfo | Out-Null

Write-Host -ForegroundColor cyan "Verifying domain $domain on Office 365......."
Start-Sleep -Seconds 60
Confirm-MsolDomain -DomainName $Domain
If ((Get-MsolDomain -DomainName $Domain).Status -ne "Verified")
{
Write-Host -ForegroundColor Yellow "Unable to verify domain, the script will continue adding adding records but you will have to verify domain from the Office 365 portal after the script is done."
}

#Creating required MSOL DNS records on Azure DNS 
$MXRecord = $Domain.replace(".","-")
$MXRecord = "$MXRecord.mail.protection.outlook.com"

$MXinfo = New-AzureRmDnsRecordConfig -Exchange $MXRecord -Preference 0 
New-AzureRmDnsRecordSet -Name "@" -RecordType MX -ZoneName $Domain -Ttl 3600 -ResourceGroupName $ResourceGroupName -DnsRecords $MXinfo | Out-Null

$TXTinfo = Get-AzureRmDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $Domain -Name "@" -RecordType TXT
Add-AzureRmDnsRecordConfig -Value "v=spf1 include:spf.protection.outlook.com -all" -RecordSet $TXTinfo | Out-Null
Set-AzureRmDnsRecordSet -RecordSet $TXTinfo -Overwrite | Out-Null

$SRVinfo = New-AzureRmDnsRecordConfig -Port 443 -Priority 100 -Target sipdir.online.lync.com  -Weight 1
New-AzureRmDnsRecordSet -Name "_sip._tls" -RecordType SRV -ZoneName $Domain -Ttl 3600 -ResourceGroupName $ResourceGroupName -DnsRecords $SRVinfo | Out-Null

$SRVinfo = New-AzureRmDnsRecordConfig -Port 5061 -Priority 100 -Target sipfed.online.lync.com  -Weight 1
New-AzureRmDnsRecordSet -Name "_sipfederationtls._tcp" -RecordType SRV -ZoneName $Domain -Ttl 3600 -ResourceGroupName $ResourceGroupName -DnsRecords $SRVinfo | Out-Null

$CNAMEinfo = New-AzureRmDnsRecordConfig -Cname autodiscover.outlook.com
New-AzureRmDnsRecordSet -Name autodiscover -RecordType CNAME -ZoneName $Domain -Ttl 3600 -ResourceGroupName $ResourceGroupName -DnsRecords $CNAMEinfo | Out-Null

$CNAMEinfo = New-AzureRmDnsRecordConfig -Cname 	sipdir.online.lync.com
New-AzureRmDnsRecordSet -Name sip -RecordType CNAME -ZoneName $Domain -Ttl 3600 -ResourceGroupName $ResourceGroupName -DnsRecords $CNAMEinfo | Out-Null

$CNAMEinfo = New-AzureRmDnsRecordConfig -Cname 	webdir.online.lync.com
New-AzureRmDnsRecordSet -Name lyncdiscover -RecordType CNAME -ZoneName $Domain -Ttl 3600 -ResourceGroupName $ResourceGroupName -DnsRecords $CNAMEinfo | Out-Null

$CNAMEinfo = New-AzureRmDnsRecordConfig -Cname enterpriseregistration.windows.net
New-AzureRmDnsRecordSet -Name enterpriseregistration -RecordType CNAME -ZoneName $Domain -Ttl 3600 -ResourceGroupName $ResourceGroupName -DnsRecords $CNAMEinfo | Out-Null

$CNAMEinfo = New-AzureRmDnsRecordConfig -Cname enterpriseenrollment.manage.microsoft.com
New-AzureRmDnsRecordSet -Name enterpriseenrollment -RecordType CNAME -ZoneName $Domain -Ttl 3600 -ResourceGroupName $ResourceGroupName -DnsRecords $CNAMEinfo | Out-Null

$CNAMEinfo = New-AzureRmDnsRecordConfig -Cname clientconfig.microsoftonline-p.net	
New-AzureRmDnsRecordSet -Name msoid -RecordType CNAME -ZoneName $Domain -Ttl 3600 -ResourceGroupName $ResourceGroupName -DnsRecords $CNAMEinfo | Out-Null

Write-Host -ForegroundColor Green "Process Comleted.... Domain added and verified on Office 365, DNS records for Office 365 added to Azure DNS"
Stop-Transcript
}

#Function that Rolls back Azure DNS changes 
Function RollBack
{
#Removing Azure DNS Zone
Write-Host -ForegroundColor Red "Removing DNS Zone..... $Domain"
Remove-AzureRmDnsZone -Name $Domain -ResourceGroupName $ResourceGroupName -Force
if ($ResourceGroupNameValidation -eq $null)
{
#Remove Azure Resource Group
Write-Host -ForegroundColor Red "Removing Azure Resource Group..... $ResourceGroupName "
Remove-AzureRmResourceGroup -Name $ResourceGroupName -Force
}
Stop-Transcript
Break
}

#Validate NS record has been seton Domain Registrar 
Write-Host -ForegroundColor Cyan "Waiting on NS record Validation........"
$count = 0
Do
{
$NSValidation = (Resolve-DnsName -Name $Domain -Type SOA).nameadministrator
Start-Sleep -Seconds 300
$count = $count + 1
}
Until ($NSValidation -eq "azuredns-hostmaster.microsoft.com" -or $count -ge "9")

#Rollback if Unable to validate NS record 
If ($count -ge "9")
{
Write-Host -ForegroundColor Red "NS Record Validation Failed Try again later........Rolling Back"
RollBack
}

#Process fuction if NS record is validated
ProcessDomain