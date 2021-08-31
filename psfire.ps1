# Work in progress
# add proper function sections
# add output files

#region date, timezone and location
$date = "Date and time is $((Get-Date).ToString())"
$timezone = "Time Zone is (Get-TimeZone).Displayname"
$location = get-location
#endregion 
 
#region screenshot
[Reflection.Assembly]::LoadWithPartialName("System.Drawing")
$bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 1920, 1080)
#endregion screenshot

#verify AMSI detection
function Get-Screenshot([Drawing.Rectangle]$bounds, $path) {
    [CmdletBinding()]
    $bmp = New-Object Drawing.Bitmap $bounds.width, $bounds.height
    $graphics = [Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)
    $bmp.Save($path)
    $graphics.Dispose()
    $bmp.Dispose()
}

function Get-SysInfo {
    [CmdletBinding()]
    $computer = Get-WmiObject -Class Win32_ComputerSystem
    $computername = $env:COMPUTERNAME
    $domain = $env:USERDOMAIN
    $bios = Get-CimInstance Win32_bios     
    $drive = Get-PSDrive

    $computer
    $computergetname
    $domain
    $bios
    $drive
}

function Get-UsersGroups {
    #users and groups
    [CmdletBinding()]
    $localusers = Get-Ciminstance win32_useraccount
    $localgroups = Get-Wmiobject win32_group
    $currentuser =  $env:UserName

    $localusers
    $localgroups
    $currentuser
}

function Get-LastLogon {
    #last local logons
    [CmdletBinding()]
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME" 
    $adsi.Children | where {$_.SchemaClassName -eq 'user'} | ft name,lastlogin
}

function Get-Software {
    #software
    [CmdletBinding()]
    $installedsoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    foreach($sw in $installedsoftware){$sw.GetValue('DisplayName')}
}
  
function Get-NetworkInfo {
    [CmdletBinding()]
    $ipconfig = Get-NetIPConfiguration
    $ipint = Get-NetIPAddress | Sort InterfaceIndex | FT InterfaceIndex, InterfaceAlias, AddressFamily, IPAddress, PrefixLength -Autosize
    $ipv4 = Get-NetIPAddress | ? AddressFamily -eq IPv4 | FT –AutoSize
    #Get-NetAdapter "Wireless" | Get-NetIPAddress | FT -AutoSize
    $dns = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | select pscomputername, IPAddress, DNSServerSearchOrder
    $netcon = Get-NetTCPConnection
    $netcon_listen = Get-NetTCPConnection -state Listen
    $routes = Get-NetRoute
    $arp_table = Get-NetNeighbor
    $proxies = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer 
    
    if ($proxies) { 
        if ($proxies -ilike "*=*") 
            { $proxies -replace "=","://" -split(';') | Select-Object -First 1 } 
        else { "http://" + $proxies } 
          } 

    $ipconfig
    $ipint
    $ipv4
    $dns
    $netcon
    $netcon_listen
    $routes
    $arp_table
    $proxies
}

function Get-Usb {
    [CmdletBinding()]
    $usb = Get-PnpDevice -Class USB
    $usb_composite_detail = Get-PnpDevice -FriendlyName 'USB Composite Device' | select *

    $usb
    $usb_composite_detail
   }


function Get-AllProcesses {
    [CmdletBinding()]
    $processes = Get-Process -verbose

    # process tree
    # $psscriptpath = ""
    # https://p0w3rsh3ll.wordpress.com/2012/10/12/show-processtree/
    # Invoke-Expression "PowerShell.exe -ExecutionPolicy Bypass -File .\process-tree.ps1"
    # Invoke-Expression "& `"$scriptPath`" $argumentList"

    # process-mini-dump
    # $pid = 
    # Invoke-Expression "Powershell.exe -c rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid dump.bin full"
    # Get-WmiObject Win32_Process | Where {$_.Name -eq 'explorer.exe'} | Select ParentProcessId,@{N='ParentProcessName';E={(Get-Process -Id $_.ParentProcessId).Name}}

    #Listening processes
    $netprocesses = (Get-NetTCPConnection | ? {($_.State -eq "Listen") -and ($_.RemoteAddress -eq "0.0.0.0")}).OwningProcess 
    Write-Output "Listening processes:"
    foreach ($process in $netprocesses) {Get-Process -PID $process | select ID,ProcessName} 

    Write-Output "Processes:"
    $processes 
}

#Scheduled tasks
$sctasks = Get-ScheduledTask
#Gpresult
$gpresult = gpresult /Z
#Get-GPResultantSetOfPolicy -ReportType xml

#Services
$services = Get-Service

#Processes with running services
function Get-RunSvc {
    [CmdletBinding()]
    $svcid = Get-WmiObject -Class Win32_Service -Filter "State LIKE 'Running'" | Select-Object -ExpandProperty ProcessId $process
    Get-Process -Id $svcid
    }

#Group Member
$admins = Get-LocalGroupMember -Group "Administrators"

# Memory capture with Memoryze
$drive = $location.Drive.Root
# $memory = ".\memoryze\MemoryDD.bat -output $drive\images"
# & $cmd

# ROT-13 function reference - http://eddiejackson.net/wp/?p=319
function Get-Rot13 {
    [CmdletBinding()]
    param ($rot13string) 
    $rot13string.ToCharArray() | ForEach-Object {
      if((([int] $_ -ge 97) -and ([int] $_ -le 109)) -or (([int] $_ -ge 65) -and ([int] $_ -le 77))) {
        $string += [char] ([int] $_ + 13);
       }
      elseif((([int] $_ -ge 110) -and ([int] $_ -le 122)) -or (([int] $_ -ge 78) -and ([int] $_ -le 90))) {
        $string += [char] ([int] $_ - 13);
       }
      else {
        $string += $_
       }        
    } 
 $string
}

function Get-ProgramExecution {
    [CmdletBinding()]

    # Userassist
    $userassist = Get-ChildItem -Path HKCU:\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\ | Select -ExpandProperty Name
    $ua = $userassist.replace('HKEY_CURRENT_USER','HKCU:')
    $ua_complete = foreach ($uakey in $ua) {Get-ChildItem -Path "$uakey" | select -ExpandProperty Property}
    foreach ($encstr in $ua_complete) {Get-Rot13 "$encstr"}

    # Windows 10 Timeline
    $firstuser = Get-ChildItem  -Path C:\Users | Select-Object -ExpandProperty Name | Select-Object -First 1
    $timeline_folder = Get-ChildItem -Directory C:\Users\$firstuser\AppData\Local\ConnectedDevicesPlatform | Select-Object -ExpandProperty Name | Select-Object -First 1
    $timeline_file = "C:\Users\$firstuser\AppData\Local\ConnectedDevicesPlatform\$timeline_folder\ActivitiesCache.db"
    $timeline = Get-Content $timeline_file -Encoding UTF8

    # ShimCache
    $shimcache = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\" -Name "AppCompatCache"
    $shimecache_unicode = [System.Text.Encoding]::Unicode.GetString($shimcache.AppCompatCache)

    # BAM/DAM
    # SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}
    # Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $bam = Get-ChildItem -Path "HKLM:SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" | Select-Object -ExpandProperty Name
    foreach($b in $bam){Get-ItemProperty -Path $b.replace('HKEY_LOCAL_MACHINE','HKLM:')}

    # SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}

    # AmCache.hve

    # SRUM (System Resource Usage Monitor)
    # Jump Lists
    # Last Visited MRU
    # Jump Lists
    # Last Visited MRU
    # Prefetch
}


#region ideas and tests

# MFT sequence number and date big difference
# Bad passwords count:
# Bookmark hkeylocalmachine site
# Verify netclient

# Autorun is PS

# enable RD
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 
# enable RDP in firewall::
# Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
# disable RD
# Invoke-Command –Computername $computername –ScriptBlock {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1}

#endregion ideas and tests
 

# function Get-FileDownload {
# [CmdletBinding()]
# Open Save MRU
# Email Attachments
# Skype History
# Browser Artifacts
# Downloads
# ADS Zone Identifier
# }  

function Get-Fire {
    [CmdletBinding()]
    # function tests
    $date
    $timezone 
    $location
    #Get-Screenshot $bounds ".\screenshot.png"
    Get-SysInfo
    Get-UsersGroups
    Get-LastLogon
    Get-Software
    Get-NetworkInfo
    Get-Usb
    Get-AllProcesses
    $sctasks
    Get-RunningSvc
    $gpresult
    Get-ProgramExecution

}