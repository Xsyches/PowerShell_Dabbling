﻿function Get-SecOpsIPX{
    [CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    $ip)
    (get-host).PrivateData.ErrorForegroundColor = "green" ;

$computername = [system.net.dns]::GetHostByAddress("$ip").hostname
$identity = (Get-WmiObject -Class win32_computersystem -ComputerName $computername).UserName ; $identity = $identity.substring( "6") ;

Get-Date | Out-File $env:userprofile\Desktop\$computername.txt;  

"ADUser:" | Out-File $env:userprofile\Desktop\$computername.txt -Append;  
Get-ADUser -Identity $Identity -Server SCLHS -Properties department,created,description,displayname,telephoneNumber,
distinguishedname,lastbadpasswordattempt,PasswordLastSet,mail,manager,memberof,modified,name,objectguid,objectsid,
office,streetaddress,title,whenchanged,primarygroup |
Format-List | Out-File $env:userprofile\Desktop\$computername.txt -Append;  

"ADComputer:" | Out-File $env:userprofile\Desktop\$computername.txt -Append;  
Get-ADComputer -Identity "$ComputerName" -Server "SCLHS" -Properties IPV4address,IPV6address,PasswordLastSet,canonicalname,
whenchanged,whencreated,primarygroup,objectguid,objectsid,operatingsystem,operatingsystemhotfix,operatingsystemservicepack |
Out-File $env:userprofile\Desktop\$computername.txt -Append;  

"Logged On Users:" | Out-File $env:userprofile\Desktop\$computername.txt -Append;  
$output = @{ 'ComputerName' = $computername }
$output.UserName = (Get-WmiObject -Class win32_computersystem -ComputerName $computername).UserName
 [PSCustomObject]$output |  Out-File $env:userprofile\Desktop\$computername.txt -Append;  

"MAC ADDRESS:" | Out-File $env:userprofile\Desktop\$computername.txt -Append;  
get-wmiobject -class "Win32_NetworkAdapterConfiguration" -computername $computername |
Where{$_.IpEnabled -Match "True"} |
select Description,MACAddress |
Out-File $env:userprofile\Desktop\$computername.txt -Append;    

"USB Device History:" | Out-File $env:userprofile\Desktop\$computername.txt -Append;  
Function Get-USBHistory
{
<#
.SYNOPSIS
	This fucntion will get the history for USB devices that have been plugged into a machine.

.DESCRIPTION
	 This funciton queries the "SYSTEM\CurrentControlSet\Enum\USBSTOR" key to get a list of all USB storage devices that have
	been connected to a machine.  The funciton can run against local or remote machines.

.PARAMETER  ComputerName
	Specifies the computer which you want to get the USB storage device history from.  The value can be a fully qualified domain
	name or an IP address.  This parameter can be piped to the function.  The local computer is the default.

.Parameter Ping
    Use Ping to verify a computer is online before connecting to it.
    
.EXAMPLE
	PS C:\>Get-USBHistory -ComputerName LAPTOP
		
	Computer                                                         USBDevice                                                              
	--------                                                         ---------                                                              
	LAPTOP                                                           A-DATA USB Flash Drive USB Device                                      
	LAPTOP                                                           CBM Flash Disk USB Device                                              
	LAPTOP                                                           WD 3200BEV External USB Device                                         

	Description
	-----------
	This command displays the history of USB storage device on the localhost.
		
.EXAMPLE
	PS C:\>$Servers = Get-Content ServerList.txt
		
	PS C:\>Get-USBHistory -ComputerName $Servers
		
		
	Description
	-----------
	This command first creates an array of server names from ServerList.txt then executes the Get-USBHistory script on the array of servers.
	
.EXAMPLE
	PS C:\>Get-USBHistory Server1 | Export-CSV -Path C:\Logs\USBHistory.csv -NoTypeInformation
    		
		
	Description
	-----------
	This command gets run the Get-USBHistory command on Server1 and pipes the output to a CSV file located in the C:\Logs directory.

	
.Notes
LastModified: 5/09/2012
Author:       Jason Walker

	
#>

 [CmdletBinding()]

Param
(
	[parameter(ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
	[alias("CN","Computer")]
	[String[]]$ComputerName=$Env:COMPUTERNAME,
    [Switch]$Ping	
)
       
 Begin
 {
          
     $USBDevices      = @()
     $TempErrorAction = $ErrorActionPreference
     $ErrorActionPreference = "Stop"
     $Hive   = "LocalMachine"
     $Key    = "SYSTEM\CurrentControlSet\Enum\USBSTOR"
     
  }

  Process
  {            
     $ComputerCounter = 0        
        
     ForEach($Computer in $ComputerName)
     {
        $ComputerCounter++        
    	$Computer = $Computer.Trim().ToUpper()
        Write-Progress -Activity "Collecting USB history" -Status "Retrieving USB history from $Computer" -PercentComplete (($ComputerCounter/($ComputerName.Count)*100))
        
                       	
        If($Ping)
        {
           If(-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet))
           {
              Write-Warning "Ping failed on $Computer"
              Continue
           }
        }#end if ping            			
    	   
    		    			
    	Try
    	{
           $SubKeys2        = @()
           $USBSTORSubKeys1 = @()
           $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive,$Computer)
    	   $USBSTORKey = $Reg.OpenSubKey($Key)
    	   $USBSTORSubKeys1  = $USBSTORKey.GetSubKeyNames()           
                  
    	   ForEach($SubKey1 in $USBSTORSubKeys1)
    	   {	
    	      $Key2 = "SYSTEM\CurrentControlSet\Enum\USBSTOR\$SubKey1"
    		  $RegSubKey2  = $Reg.OpenSubKey($Key2)
    		  $SubkeyName2 = $RegSubKey2.GetSubKeyNames()	
    	      $Subkeys2   += "$Key2\$SubKeyName2"
    		  $RegSubKey2.Close()		
    		}#end foreach SubKey1

    		ForEach($Subkey2 in $Subkeys2)
    		{	
    		   $USBKey      = $Reg.OpenSubKey($Subkey2)
    		   $USBDevice   = $USBKey.GetValue('FriendlyName')
               If($USBDevice)
               {	
    		      $USBDevices += New-Object -TypeName PSObject -Property @{
    		         USBDevice = $USBDevice
    			     Computer  = $Computer
    			       }
                }
                 $USBKey.Close()    		      						
    	     }#end foreach SubKey2
            
               $USBSTORKey.Close()
           }#end try
           Catch
           {
              Write-Warning "There was an error connecting to the registry on $Computer or USBSTOR key not found. Ensure the remote registry service is running on the remote machine."
           }#end catch
        
     }#end foreach computer 
              
  }#end process
    				    	
  End
  {
     #Display results		
     $USBDevices | Select Computer,USBDevice	
        
     #Set error action preference back to original setting		
     $ErrorActionPreference = $TempErrorAction 		
  }
           	
}#end function | 
Out-File $env:userprofile\Desktop\$computername.txt -Append;  

 "LogicalDisk:" | Out-File $env:userprofile\Desktop\$computername.txt -Append;   
Get-WmiObject -ComputerName $ComputerName -class win32_logicaldisk | 
Out-File $env:userprofile\Desktop\$computername.txt -Append;  

"Processes:" |  Out-File $env:userprofile\Desktop\$computername.txt -Append;    
Get-Process -ComputerName $ComputerName | sort status | Format-Table -AutoSize | 
Out-File $env:userprofile\Desktop\$computername.txt -Append;   

"Services:" | Out-File $env:userprofile\Desktop\$computername.txt -Append;   
Get-Service -ComputerName $ComputerName |  Sort-Object status |
    Where-Object {$_ -notmatch "Adobe"} |
    Where-Object {$_ -notmatch "AppSense"} |
    Where-Object {$_ -notmatch "BITS"} |
    Where-Object {$_ -notmatch "Fax"} |
    Where-Object {$_ -notmatch "Microsoft"} |
    Where-Object {$_ -notmatch "Synapse"} |
    Where-Object {$_ -notmatch "Win*"} | 
  Format-Table -AutoSize | Out-File $env:userprofile\Desktop\$computername.txt -Append;  

"Installed Software:"  | Out-File $env:userprofile\Desktop\$computername.txt -Append;  
Get-SecOpsInstalledSoftware -ComputerName $ComputerName| 
	Where-Object {$_ -notmatch "Microsoft"} |
	Where-Object {$_ -notmatch "Adobe"} |
	Where-Object {$_ -notmatch "AppSense"} | 
 	Where-Object {$_ -notmatch "Cisco"} |
 	Where-Object {$_ -notmatch "Citrix"} | 
 	Where-Object {$_ -notmatch "Hewlett-Packard"} | 
 	Where-Object {$_ -notmatch "Intel Corporation"} | 
 	Where-Object {$_ -notmatch "Java"} | 
	Where-Object {$_ -notmatch "Symantec"} | 
 	Where-Object {$_ -notmatch "VMware"} | 
    Where-Object {$_ -notmatch "SAP BusinessObjects"} |
    Where-Object {$_ -notmatch "Google"} |
    Where-Object {$_ -notmatch "HP"} |
Out-File $env:userprofile\Desktop\$computername.txt -Append;  

 "Network Statistics: " |  Out-File $env:userprofile\Desktop\$computername.txt -Append;   
 Get-SecOpsNetworkStatistics -ComputerName $computername | Format-Table -AutoSize |
Out-File $env:userprofile\Desktop\$computername.txt -Append;


 }
 
