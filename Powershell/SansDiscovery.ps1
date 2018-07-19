function Get-SansDiscovery{
    [CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    $ComputerName)



#Search for unusual/unexpected processes, and focus on processes with User Name "SYSTEM" or "Administrator"(or users in the Administrators' group).
"Tasklist:" | Out-File $env:userprofile\Desktop\$computername.txt -Append;
Invoke-Command -ComputerName $ComputerName -Command {tasklist /svc} -ErrorAction SilentlyContinue |
Out-File $env:userprofile\Desktop\$computername.txt -Append;

#Look for strange programs in startup registry keys in both HKLM & HKCU:
"HKLM:RUN" | Out-File $env:userprofile\Desktop\$computername.txt -Append;
Invoke-Command -ComputerName $ComputerName -Command {Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run} -ErrorAction SilentlyContinue |
Out-File $env:userprofile\Desktop\$computername.txt -Append;


"HKLM:RUNOnce" | Out-File $env:userprofile\Desktop\$computername.txt -Append;
Invoke-Command -ComputerName $ComputerName -Command {Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce} -ErrorAction SilentlyContinue|
Out-File $env:userprofile\Desktop\$computername.txt -Append;


"HKLM:RUNOnceEx" | Out-File $env:userprofile\Desktop\$computername.txt -Append;
Invoke-Command -ComputerName $ComputerName -Command {Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx} -ErrorAction SilentlyContinue |
Out-File $env:userprofile\Desktop\$computername.txt -Append;


"HKCU:RUN" | Out-File $env:userprofile\Desktop\$computername.txt -Append;
Invoke-Command -ComputerName $ComputerName -Command {Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run} -ErrorAction SilentlyContinue |
Out-File $env:userprofile\Desktop\$computername.txt -Append;


"HKCU:RUNOnce" | Out-File $env:userprofile\Desktop\$computername.txt -Append;
Invoke-Command -ComputerName $ComputerName -Command {Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce} -ErrorAction SilentlyContinue |
Out-File $env:userprofile\Desktop\$computername.txt -Append;


"HKCU:RUNOnceEx" | Out-File $env:userprofile\Desktop\$computername.txt -Append;
Invoke-Command -ComputerName $ComputerName -Command {Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx} -ErrorAction SilentlyContinue|
Out-File $env:userprofile\Desktop\$computername.txt -Append;

"Logged On Users:" | Out-File $env:userprofile\Desktop\$computername.txt -Append;  
$output = @{ 'ComputerName' = $computername }
$output.UserName = (Get-WmiObject -Class win32_computersystem -ComputerName $computername).UserName
 [PSCustomObject]$output |  Out-File $env:userprofile\Desktop\$computername.txt -Append;  


"NETSTAT" | Out-File $env:userprofile\Desktop\$computername.txt -Append;
Invoke-Command -ComputerName $ComputerName -Command {netstat -naob} -ErrorAction SilentlyContinue | 
Out-File $env:userprofile\Desktop\$computername.txt -Append;


#Check file space usage to look for sudden major decreases in free space, using the GUI:
"Directory C:" | Out-File $env:userprofile\desktop\$computername.txt -Append;
Invoke-Command -ComputerName $ComputerName -command {dir c:\} |
Out-File $env:userprofile\desktop\$ComputerName.txt -Append;

#Look at file shares, and make sure each has a defined business purpose:
"Net View:" | Out-File $env:userprofile\desktop\$ComputerName.txt -Append;
Invoke-Command -ComputerName $ComputerName -command {net view \\127.0.0.1} | 
Out-File $env:userprofile\desktop\$ComputerName.txt -Append;


#List the open SMB sessions with this machine:
"SMB Sessions:" | Out-File $env:userprofile\desktop\$ComputerName.txt -Append;
Invoke-Command -ComputerName $ComputerName -command {net use} |
Out-File $env:userprofile\desktop\$ComputerName.txt -Append


}