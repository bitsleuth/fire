<#
 .Synopsis
  Volatile Information Extractor [Windows]
  Dynamic
 .DESCRIPTION
  This script gathers volatile dynamic information from a windows host.
  Triage with 3rd party tools or triage with PowerShell cmdlets
  Work in progress
#>

#region date, timezone and location
$date = "Date and time is $((Get-Date).ToString())"
$timezone = "Time Zone is (Get-TimeZone).Displayname"
$location = get-location
$drive = Get-CimInstance -Class Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
#endregion 

#region screenshot
[Reflection.Assembly]::LoadWithPartialName("System.Drawing")
$bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 1920, 1080)
#endregion
#verify AMSI detection


function Get-Triage {
    [CmdletBinding()]
    $drive = $location.Drive.Root
    # Memory capture
    $memdump = Start-Process -FilePath "DumpIt.exe" -ArgumentList "/OUTPUT " -Wait
    # Verify disk encryption
    $vencrypt = Start-Process -FilePath "EDD.exe" -Wait
    # Acquire triage data with Kape
    $kape = Start-Process -FilePath "kape.exe" -ArgumentList "--tsource $drive --tdest E:\%d%m --target !SANS_Triage --zip %m" -Wait
    # Scan triage data with Yara
    $yara = Start-Process -FilePath "yara64.exe" -ArgumentList "/rules -r /output"
}


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
    $netconlisten = Get-NetTCPConnection -state Listen
    $routes = Get-NetRoute
    $arptable = Get-NetNeighbor
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
    $netconlisten
    $routes
    $arptable
    $proxies
}

function Get-Usb {
    [CmdletBinding()]
    $usb = Get-PnpDevice -Class USB
    $usb_composite_detail = Get-PnpDevice -FriendlyName 'USB Composite Device' | select *
    # InstanceId, DeviceID, SystemName, ClassGuid, CompatibleID, HardwareID

    $usb
    $usb_composite_detail
   }

# https://p0w3rsh3ll.wordpress.com/2012/10/12/show-processtree/
Function Show-ProcessTree  {            
[CmdletBinding()]            
Param()            
    Begin {            
        # Identify top level processes            
        # They have either an identified processID that doesn't exist anymore            
        # Or they don't have a Parentprocess ID at all            
        $allprocess  = Get-WmiObject -Class Win32_process            
        $uniquetop  = ($allprocess).ParentProcessID | Sort-Object -Unique            
        $existingtop =  ($uniquetop | ForEach-Object -Process {$allprocess | Where ProcessId -EQ $_}).ProcessID            
        $nonexistent = (Compare-Object -ReferenceObject $uniquetop -DifferenceObject $existingtop).InPutObject            
        $topprocess = ($allprocess | ForEach-Object -Process {            
            if ($_.ProcessID -eq $_.ParentProcessID){            
                $_.ProcessID            
            }            
            if ($_.ParentProcessID -in $nonexistent) {            
                $_.ProcessID            
            }            
        })            
        # Sub functions            
        # Function that indents to a level i            
        function Indent {            
            Param([Int]$i)            
            $Global:Indent = $null            
            For ($x=1; $x -le $i; $x++)            
            {            
                $Global:Indent += [char]9            
            }            
        }            
        Function Get-ChildProcessesById {            
        Param($ID)            
            # use $allprocess variable instead of Get-WmiObject -Class Win32_process to speed up            
            $allprocess | Where { $_.ParentProcessID -eq $ID} | ForEach-Object {            
                Indent $i            
                '{0}{1} {2}' -f $Indent,$_.ProcessID,($_.Name -split "\.")[0]            
                $i++            
                # Recurse            
                Get-ChildProcessesById -ID $_.ProcessID            
                $i--            
            }            
        } # end of function            
    }            
    Process {            
        $topprocess | ForEach-Object {            
            '{0} {1}' -f $_,(Get-Process -Id $_).ProcessName            
            # Avoid processID 0 because parentProcessId = processID            
            if ($_ -ne 0 )            
            {            
                $i = 1            
                Get-ChildProcessesById -ID $_            
            }            
        }            
    }
                 
    End {}            
}


function Get-AllProcesses {
    [CmdletBinding()]
    $processes = Get-Process -verbose

    # invole epression sample
    # Invoke-Expression "& `"$scriptPath`" $argumentList"

    # process-mini-dump
    # $pid = 
    # Invoke-Expression "Powershell.exe -c rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid dump.bin full"
    # Get-WmiObject Win32_Process | Where {$_.Name -eq 'explorer.exe'} | Select ParentProcessId,@{N='ParentProcessName';E={(Get-Process -Id $_.ParentProcessId).Name}}

    Write-Output "Listening processes:"
    Get-NetTCPConnection | Where-Object { $_.State -eq "LISTEN" } | 
    select @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}},owningprocess, localaddress, localport, creationtime | Format-Table -AutoSize

    Write-Output "All Processes:"
    $processes 
    Write-Output "Process Tree:"
    Show-ProcessTree
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
    foreach ($encstr in $ua_complete) {
        Get-Rot13 ($encstr)
        }

    <# UserAssist2
      $userassist_path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
      $UserAssist2 = Get-ChildItem $userassist_path -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
      $UserAssist2 = Get-ChildItem $userassist_path -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property | '
      Where-Object {$_ -match "Count|Time"} | ForEach-Object {Get-ItemPropertyValue -Path $userassist_path -Name $_} | Select-Object -Property *
      #############
      foreach ($line in $UserAssist2) {
         Get-Rot13($line)
         }
    #>

    # Windows 10 Timeline
    $firstuser = Get-ChildItem  -Path C:\Users | Select-Object -ExpandProperty Name | Select-Object -First 1
    $timeline_folder = Get-ChildItem -Directory C:\Users\$firstuser\AppData\Local\ConnectedDevicesPlatform | Select-Object -ExpandProperty Name | Select-Object -First 1
    $timeline_file = "C:\Users\$firstuser\AppData\Local\ConnectedDevicesPlatform\$timeline_folder\ActivitiesCache.db"
    #$timeline - open sqlite3 file 

    
    # BAM/DAM
    # SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}
    # Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $bam = Get-ChildItem -Path "HKLM:SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" | Select-Object -ExpandProperty Name
    foreach($b in $bam) {
        Get-ItemProperty -Path $b.replace('HKEY_LOCAL_MACHINE','HKLM:')| Select-Object -Property * -ExcludeProperty Version,SequenceNumber,PSPath,PSParentPath,PSChildName
        }
    <#
      $dam = Get-ChildItem -Path "HKLM:SYSTEM\CurrentControlSet\Services\dam\State\UserSettings" | Select-Object -ExpandProperty Name
      foreach($d in $dam) {
          Get-ItemProperty -Path $d.replace('HKEY_LOCAL_MACHINE','HKLM:')
          }
     #>


    # Recycle Bin
    $shell = New-Object -com shell.application
    $recycle_bin = $shell.Namespace(10)
    $rb_item = $recycle_bin.Items() | Select-Object Name,Path,ModifyDate,Size
    

    # SRUM 
    #$srum_path = "HKLM:\SYSTEM\CurrentControlSet\Services\SRU\Parameters"
    $srum_file_path = "C:\Windows\System32\sru\SRUDB.dat"
    $srum_reg_path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions\"
    $srum_app_res_reg_path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions\{d10ca2fe-6fcf-4f6d-848e-b2e99266fa86}"

    # $SRUM = Get-ChildItem $srum_reg_path -ErrorAction SilentlyContinue | Select-Object -Property *

    
    # Retrieve Jump Lists artifacts
    $jump_list_path = "$env:LOCALAPPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
    $JumpLists = Get-ChildItem $jump_list_path -File -ErrorAction SilentlyContinue | Select-Object -Property FullName, Length, LastWriteTime

    # Last Visited MRU
    $mru_path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
    $mru = Get-Item $mru_path -ErrorAction SilentlyContinue

    # Path to the Remote Desktop cache directory
    $rdp_cache_path = "$env:LOCALAPPDATA\Microsoft\Terminal Server Client\Cache"
    # Retrieve the Remote Desktop cache files
    $RDPFiles = Get-ChildItem $rdp_cache_path -File -ErrorAction SilentlyContinue | Select-Object -Property FullName, Length, LastWriteTime

    
    ##############
}


#region R&D
# Ideas and tests
#######################################################
# Locked files example
# AmCache.hve example
# alernate noisy lolbin way to copy locked files
# $shadowcopy = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\\", "ClientAccessible")
# $shadowcopyid = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }
# $shadowcopyobject  = $shadowcopyid.DeviceObject + "\\"
# $scfolder = "C:\Temp\shadowcopy"

## command line way: cmd /c mklink /d $scfolder "$shadowcopyobject"
# New-Item -ItemType SymbolicLink -Path $scfolder -Target $shadowcopyobject

#sample copy
# copy C:\shadowcopy\Windows\appcompat\Programs\Amcache.hve C:\Temp\.

# (Get-Item $scfolder).Delete()
# $shadowcopyid.Delete()
######################################################

# Use Tscopy to copy locked files
#
# Retrieve $MFT and $J files
# $mft_path = "\\$env:computername\C:"
# $j_path = "\\$env:computername\C:$Extend\$UsnJrnl"
# $MFT = Get-Content $mft_path -Raw -ErrorAction Stop
# $J = Get-Content $j_path -Raw -ErrorAction Stop


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

#endregion
 

  function Get-FileDownload {
    # [CmdletBinding()]
    # Open Save MRU
    # Email Attachments
    # Browser Artifacts
    # MFT
    # ADS Zone Identifier
 }  


function Get-View {
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
    $gpresult
    Get-RunningSvc
    Get-ProgramExecution

}
