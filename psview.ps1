<#
 .Synopsis
  Volatile Information Extractor [Windows]
  Dynamic
 .DESCRIPTION
  This script gathers volatile dynamic information from a windows host.
  Triage with 3rd party tools or triage with PowerShell cmdlets
  Work in progress
#>

# Work in progress

#region date, timezone and location
$Date = "Date and time is $((Get-Date).ToString())"
$Timezone = "Time Zone is (Get-TimeZone).Displayname"
$Location = get-location
#endregion 
 
#region screenshot
# [Reflection.Assembly]::LoadWithPartialName("System.Drawing")
# $bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 1920, 1080)
Add-Type -AssemblyName System.Drawing
$Bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
#endregion screenshot

function Get-Screenshot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Drawing.Rectangle]$Bounds,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $bmp = New-Object Drawing.Bitmap $Bounds.Width, $Bounds.Height
        $graphics = [Drawing.Graphics]::FromImage($bmp)
        $graphics.CopyFromScreen($Bounds.Location, [Drawing.Point]::Empty, $Bounds.Size)
        $bmp.Save($Path)
    }
    catch {
        Write-Error "Failed to capture or save screenshot: $_"
    }
    finally {
        if ($graphics) { $graphics.Dispose() }
        if ($bmp) { $bmp.Dispose() }
    }
}

function Get-SysInfo {
    [CmdletBinding()]
    $Computer = Get-WmiObject -Class Win32_ComputerSystem
    $Computername = $env:COMPUTERNAME
    $Domain = $env:USERDOMAIN
    $Bios = Get-CimInstance Win32_bios     
    $Drive = Get-PSDrive

    $Computer
    $Computergetname
    $Domain
    $Bios
    $Drive
}

function Get-UsersGroups {
    #users and groups
    [CmdletBinding()]
    $Localusers = Get-Ciminstance win32_useraccount
    $Localgroups = Get-Wmiobject win32_group
    $Currentuser =  $env:UserName

    $Localusers
    $Localgroups
    $Currentuser
}

function Get-LastLogon {
    #last local logons
    [CmdletBinding()]
    $Adsi = [ADSI]"WinNT://$env:COMPUTERNAME" 
    $Adsi.Children | Where-Object {$_.SchemaClassName -eq 'user'} | Format-Table name,lastlogin
}

function Get-Software {
    #software
    [CmdletBinding()]
    $Installedsoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    foreach($sw in $Installedsoftware){$sw.GetValue('DisplayName')}
}

function Get-NetworkInfo {
    [CmdletBinding()]
    $Ipconfig = Get-NetIPConfiguration
    $Ipint = Get-NetIPAddress | Sort-Object InterfaceIndex | Format-Table InterfaceIndex, InterfaceAlias, AddressFamily, IPAddress, PrefixLength -Autosize
    $Ipv4 = Get-NetIPAddress | Where-Object AddressFamily -eq IPv4 | Format-Table -AutoSize
    #Get-NetAdapter "Wireless" | Get-NetIPAddress | FT -AutoSize
    $Dns = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object pscomputername, IPAddress, DNSServerSearchOrder
    $Netcon = Get-NetTCPConnection
    $Netcon_listen = Get-NetTCPConnection -state Listen
    $Routes = Get-NetRoute
    $Arp_table = Get-NetNeighbor
    $Proxies = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer 
    
    if ($Proxies) { 
        if ($Proxies -ilike "*=*") 
            { $Proxies -replace "=","://" -split(';') | Select-Object -First 1 } 
        else { "http://" + $Proxies } 
          } 

    $Ipconfig
    $Ipint
    $Ipv4
    $Dns
    $Netcon
    $Netcon_listen
    $Routes
    $Arp_table
    $Proxies
}

function Get-Usb {
    [CmdletBinding()]
    $Usb = Get-PnpDevice -Class USB
    $Usb_composite_detail = Get-PnpDevice -FriendlyName 'USB Composite Device' | Select-Object *

    $Usb
    $Usb_composite_detail
   }

function Get-AllProcesses {
    [CmdletBinding()]
    $Processes = Get-Process -verbose
    $Netprocesses = (Get-NetTCPConnection | Where-Object {($_.State -eq "Listen") -and ($_.RemoteAddress -eq "0.0.0.0")}).OwningProcess 
    Write-Output "Listening processes:"
    foreach ($Process in $Netprocesses) {Get-Process -PID $Process | Select-Object ID,ProcessName} 

    Write-Output "Processes:"
    $Processes 
}

#Scheduled tasks
$Sctasks = Get-ScheduledTask
#Gpresult
$Gpresult = gpresult /Z
#Get-GPResultantSetOfPolicy -ReportType xml

#Services
$Services = Get-Service

#Processes with running services
function Get-RunSvc {
    [CmdletBinding()]
    $Svcid = Get-WmiObject -Class Win32_Service -Filter "State LIKE 'Running'" | Select-Object -ExpandProperty ProcessId $Process
    Get-Process -Id $Svcid
    }

#Group Member
$Admins = Get-LocalGroupMember -Group "Administrators"

# Memory capture with Memoryze
$Drive = $Location.Drive.Root

function Get-Fire {
    [CmdletBinding()]
    # function tests
    $Date
    $Timezone 
    $Location
    Get-Screenshot $Bounds ".\screenshot.png"
    Get-SysInfo
    Get-UsersGroups
    Get-LastLogon
    Get-Software
    Get-NetworkInfo
    Get-Usb
    Get-AllProcesses
    $Sctasks
    Get-RunningSvc
    $Gpresult
    $Services
    $Admins
}
