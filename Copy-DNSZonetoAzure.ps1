   <#
  .SYNOPSIS
  Copies DNS Zone records from a Windows DNS Server to an Azure DNS.
  
  .DESCRIPTION
  This script will copy supported DNS records (MX,A,AAAA,SRV,TXT,CNAME & PTR) from a Windows DNS Server to an Azure DNS. 
  
  .EXAMPLE
  Copy-DNSZonetoAzure.ps1 -DNSZone dvideo.com -SubscriptionId 5ab198c5-3475-56f18-8f0e-c0c6267dad58 -ResourceGroupName DNSZones

  All paramaters are required for te script to complete successfully. 

  .PARAMETER DNSZone
  The name of the DNS Zone that needs to be copied to Azure DNS. Required

  .PARAMETER SubscriptionId
  Subscription ID for the subscription that the DNS Zone should be copied into. Required
    
  .PARAMETER ResourceGroupName
  The Resource Group that the DNS Zone should be copied into. Required
  

  .NOTES
  File Name  : Copy-DNSZonetoAzure.ps1
  Author     : Hannel Hazeley - hhazeley@outlook.com
  Version    : 1.0
  Requires   : Azure PowerShell 3.0 and higher, Windows PowerShell 4.0 or higher 

  .LINK
  Demo: https://youtu.be/yXuiAiQN82U
  Repository: https://github.com/hhazeley/Azure-DNS
  #>

 Param(
    [Parameter(Mandatory=$true)]
    $DNSZone,
    [Parameter(Mandatory=$true)]
    $SubscriptionId,
    [Parameter(Mandatory=$true)]
    $ResourceGroupName
   )

$ErrorActionPreference = "SilentlyContinue"

#Function for error checks
Function ErrorCheck{
If ($errorck -ne $null)
{
Write-host
Write-host -ForegroundColor Red "ERROR: " -NoNewline
$errorck
Write-host
Break
}
}

#Get zone records from Windows DNS Server 
$dnsr = Get-DnsServerResourceRecord $DNSZone -ErrorVariable errorck | ? {$_.recordtype -eq "MX" -or $_.recordtype -eq "A" -or $_.recordtype -eq "AAAA" -or $_.recordtype -eq "SRV" -or $_.recordtype -eq "TXT" -or $_.recordtype -eq "CNAME" -or $_.recordtype -eq "PTR"}
ErrorCheck

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
New-AzureRmDnsZone -Name $DNSZone -ResourceGroupName $ResourceGroupName -ErrorAction Stop -ErrorVariable errorck | Out-Null
ErrorCheck

#Get NS record for new DNS Zone 
$NS = Get-AzureRmDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $DNSZone -RecordType NS

#Set each record from Windows DNS Server to Azure DNS Zone
Foreach ($r in $dnsr)
{
if ($r.RecordType -eq "MX")
{
$MXinfo = Get-AzureRmDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $DNSZone -Name $r.Hostname -RecordType $r.RecordType
if ($MXinfo -eq $null)
{
$MXinfo = New-AzureRmDnsRecordConfig -Exchange $r.RecordData.MailExchange -Preference $r.RecordData.Preference 
New-AzureRmDnsRecordSet -Name $r.Hostname -RecordType $r.RecordType -ZoneName $DNSZone -Ttl $r.TimeToLive.TotalSeconds -ResourceGroupName $ResourceGroupName -DnsRecords $MXinfo | Out-Null
}
Else
{
Add-AzureRmDnsRecordConfig -Exchange $r.RecordData.MailExchange -Preference $r.RecordData.Preference -RecordSet $MXinfo | Out-Null
Set-AzureRmDnsRecordSet -RecordSet $MXinfo -Overwrite | Out-Null
}
}
if ($r.RecordType -eq "A")
{
$Ainfo = Get-AzureRmDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $DNSZone -Name $r.Hostname -RecordType $r.RecordType
if ($Ainfo -eq $null)
{
$Ainfo = New-AzureRmDnsRecordConfig -Ipv4Address $r.RecordData.IPv4Address.IPAddressToString
New-AzureRmDnsRecordSet -Name $r.Hostname -RecordType $r.RecordType -ZoneName $DNSZone -Ttl $r.TimeToLive.TotalSeconds -ResourceGroupName $ResourceGroupName -DnsRecords $Ainfo | Out-Null
}
Else
{
Add-AzureRmDnsRecordConfig -Ipv4Address $r.RecordData.IPv4Address.IPAddressToString -RecordSet $Ainfo | Out-Null
Set-AzureRmDnsRecordSet -RecordSet $Ainfo -Overwrite  | Out-Null
}
}
if ($r.RecordType -eq "AAAA")
{
$AAAAinfo = Get-AzureRmDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $DNSZone -Name $r.Hostname -RecordType $r.RecordType
if ($AAAAinfo -eq $null)
{
$AAAAinfo = New-AzureRmDnsRecordConfig -Ipv6Address $r.RecordData.IPv6Address.IPAddressToString
New-AzureRmDnsRecordSet -Name $r.Hostname -RecordType $r.RecordType -ZoneName $DNSZone -Ttl $r.TimeToLive.TotalSeconds -ResourceGroupName $ResourceGroupName -DnsRecords $AAAAinfo | Out-Null
}
Else
{
Add-AzureRmDnsRecordConfig -Ipv6Address $r.RecordData.IPv6Address.IPAddressToString -RecordSet $AAAAinfo | Out-Null
Set-AzureRmDnsRecordSet -RecordSet $AAAAinfo -Overwrite | Out-Null
}
}
if ($r.RecordType -eq "SRV")
{
$SRVinfo = Get-AzureRmDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $DNSZone -Name $r.Hostname -RecordType $r.RecordType
if ($SRVinfo -eq $null)
{
$SRVinfo = New-AzureRmDnsRecordConfig -Port $r.RecordData.Port -Priority $r.RecordData.Priority -Target $r.RecordData.DomainName -Weight $r.RecordData.Weight
New-AzureRmDnsRecordSet -Name $r.Hostname -RecordType $r.RecordType -ZoneName $DNSZone -Ttl $r.TimeToLive.TotalSeconds -ResourceGroupName $ResourceGroupName -DnsRecords $SRVinfo | Out-Null
}
Else
{
Add-AzureRmDnsRecordConfig -Port $r.RecordData.Port -Priority $r.RecordData.Priority -Target $r.RecordData.DomainName -Weight $r.RecordData.Weight -RecordSet $SRVinfo | Out-Null
Set-AzureRmDnsRecordSet -RecordSet $SRVinfo -Overwrite | Out-Null
}
}
if ($r.RecordType -eq "TXT")
{
$TXTinfo = Get-AzureRmDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $DNSZone -Name $r.Hostname -RecordType $r.RecordType
if ($TXTinfo -eq $null)
{
$TXTinfo = New-AzureRmDnsRecordConfig -Value $r.RecordData.DescriptiveText
New-AzureRmDnsRecordSet -Name $r.Hostname -RecordType $r.RecordType -ZoneName $DNSZone -Ttl $r.TimeToLive.TotalSeconds -ResourceGroupName $ResourceGroupName -DnsRecords $TXTinfo | Out-Null
}
Else
{
Add-AzureRmDnsRecordConfig -Value $r.RecordData.DescriptiveText -RecordSet $TXTinfo | Out-Null
Set-AzureRmDnsRecordSet -RecordSet $TXTinfo -Overwrite | Out-Null
}
}
if ($r.RecordType -eq "CNAME")
{
$CNAMEinfo = New-AzureRmDnsRecordConfig -Cname $r.RecordData.HostNameAlias
New-AzureRmDnsRecordSet -Name $r.Hostname -RecordType $r.RecordType -ZoneName $DNSZone -Ttl $r.TimeToLive.TotalSeconds -ResourceGroupName $ResourceGroupName -DnsRecords $CNAMEinfo | Out-Null
}
if ($r.RecordType -eq "PTR")
{
$PTRinfo = Get-AzureRmDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $DNSZone -Name $r.Hostname -RecordType $r.RecordType
if ($PTRinfo -eq $null)
{
$PTRinfo = New-AzureRmDnsRecordConfig -Ptrdname $r.RecordData.PtrDomainName
New-AzureRmDnsRecordSet -Name $r.Hostname -RecordType $r.RecordType -ZoneName $DNSZone -Ttl $r.TimeToLive.TotalSeconds -ResourceGroupName $ResourceGroupName -DnsRecords $PTRinfo | Out-Null
}
Else
{
Add-AzureRmDnsRecordConfig -Ptrdname $r.RecordData.PtrDomainName -RecordSet $PTRinfo | Out-Null
Set-AzureRmDnsRecordSet -RecordSet $PTRinfo -Overwrite | Out-Null
}
}
}
Write-Host
Write-Host -ForegroundColor Cyan "Please add NS records below to domain Registrar to complete cut over........"
$ns.Records.nsdname