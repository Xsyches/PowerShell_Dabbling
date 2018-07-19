function Get-Busy {
    [CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    $TargetIP,
    [Parameter(Mandatory=$true)]
    $AttackerIp)
$a = [system.net.dns]::GetHostByAddress("$TargetIP").hostname
$b = [system.net.dns]::GetHostAddresses("$AttackerIp").hostname
 
$AttackerIp
"ATTACKER NAME RESOLUTION: " ; Write-Host $b
 
"SCL DEVICE NAME: " ; (GWMI -ComputerName $a Win32_operatingsystem).CSName
"OPERATING SYSTEM: " ; (GWMI -ComputerName $a Win32_operatingsystem).Caption
"SERVICE PACK: " ; (Get-CimInstance -ComputerName $a Win32_operatingsytem).Version
(GWMI -ComputerName $a Win32_operatingsystem).OSArchitecture
 
 
"SYSTEM TYPE: " 
$producttype = (GWMI -ComputerName $a Win32_operatingsystem).ProductType
    if ($producttype -eq '1') {"Workstation"}
        elseif($producttype -eq '2') {"Domain Controller"}
        elseif($producttype -eq '3') {"Server"}
 
"USER NAME: "
$user =  (GWMI -ComputerName $a -Class win32_computersystem).UserName ; 
        $user = $user.substring("6") ; 
                $user ; Get-ADUser -Identity $user -Server SCLHS | Select-Object Name
                     Get-SecOpsSelfie -Identity $user;
 
mkdir $env.userprofile\desktop\$TargetIP.txt
 
}
 