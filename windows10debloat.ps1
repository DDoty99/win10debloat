#Import nessary functions
function Takeown-Registry($key) {
    # TODO does not work for all root keys yet
    switch ($key.split('\')[0]) {
        "HKEY_CLASSES_ROOT" {
            $reg = [Microsoft.Win32.Registry]::ClassesRoot
            $key = $key.substring(18)
        }
        "HKEY_CURRENT_USER" {
            $reg = [Microsoft.Win32.Registry]::CurrentUser
            $key = $key.substring(18)
        }
        "HKEY_LOCAL_MACHINE" {
            $reg = [Microsoft.Win32.Registry]::LocalMachine
            $key = $key.substring(19)
        }
    }

    # get administraor group
    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $admins = $admins.Translate([System.Security.Principal.NTAccount])

    # set owner
    $key = $reg.OpenSubKey($key, "ReadWriteSubTree", "TakeOwnership")
    $acl = $key.GetAccessControl()
    $acl.SetOwner($admins)
    $key.SetAccessControl($acl)

    # set FullControl
    $acl = $key.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admins, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)
}

function Takeown-File($path) {
    takeown.exe /A /F $path
    $acl = Get-Acl $path

    # get administraor group
    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $admins = $admins.Translate([System.Security.Principal.NTAccount])

    # add NT Authority\SYSTEM
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admins, "FullControl", "None", "None", "Allow")
    $acl.AddAccessRule($rule)

    Set-Acl -Path $path -AclObject $acl
}

function Takeown-Folder($path) {
    Takeown-File $path
    foreach ($item in Get-ChildItem $path) {
        if (Test-Path $item -PathType Container) {
            Takeown-Folder $item.FullName
        } else {
            Takeown-File $item.FullName
        }
    }
}

function Elevate-Privileges {
    param($Privilege)
    $Definition = @"
    using System;
    using System.Runtime.InteropServices;

    public class AdjPriv {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct TokPriv1Luid {
                public int Count;
                public long Luid;
                public int Attr;
            }

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        public static bool EnablePrivilege(long processHandle, string privilege) {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }
"@
    $ProcessHandle = (Get-Process -id $pid).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege)
}
function force-mkdir($path) {
    if (!(Test-Path $path)) {
        #Write-Host "-- Creating full path to: " $path -ForegroundColor White -BackgroundColor DarkGreen
        New-Item -ItemType Directory -Force -Path $path
    }
}
#Remove Crapware Apps
Write-Host "Removing Win10 Crapware"
$apps = @(
    # default Windows 10 apps
    "Microsoft.3DBuilder"
    "Microsoft.Appconnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingWeather"
    #"Microsoft.FreshPaint"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    #"Microsoft.MicrosoftStickyNotes"
    "Microsoft.Office.OneNote"
    #"Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.SkypeApp"
    #"Microsoft.Windows.Photos"
    "Microsoft.WindowsAlarms"
    #"Microsoft.WindowsCalculator"
    "Microsoft.WindowsCamera"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    #"Microsoft.WindowsStore"
    "Microsoft.XboxApp"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "microsoft.windowscommunicationsapps"
    "Microsoft.MinecraftUWP"

    # Threshold 2 apps
    "Microsoft.CommsPhone"
    "Microsoft.ConnectivityStore"
    "Microsoft.Messaging"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.WindowsFeedbackHub"


    #Redstone apps
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingTravel"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.WindowsReadingList"

    # non-Microsoft
    "9E2F88E3.Twitter"
    "PandoraMediaInc.29680B314EFC2"
    "Flipboard.Flipboard"
    "ShazamEntertainmentLtd.Shazam"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"
    "king.com.*"
    "ClearChannelRadioDigital.iHeartRadio"
    "4DF9E0F8.Netflix"
    "6Wunderkinder.Wunderlist"
    "Drawboard.DrawboardPDF"
    "2FE3CB00.PicsArt-PhotoStudio"
    "D52A8D61.FarmVille2CountryEscape"
    "TuneIn.TuneInRadio"
    "GAMELOFTSA.Asphalt8Airborne"
    "TheNewYorkTimes.NYTCrossword"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials"
    "Facebook.Facebook"
    "flaregamesGmbH.RoyalRevolt2"
    "Playtika.CaesarsSlotsFreeCasino"
    "A278AB0D.MarchofEmpires"
    "KeeperSecurityInc.Keeper"
    "ThumbmunkeysLtd.PhototasticCollage"
    "XINGAG.XING"
    "89006A2E.AutodeskSketchBook"
    "9E2F88E3.Twitter"
    "king.com.CandyCrushSodaSaga"
    "4DF9E0F8.Netflix"
    "Drawboard.DrawboardPDF"
    "D52A8D61.FarmVille2CountryEscape"
    "GAMELOFTSA.Asphalt8Airborne"
    "flaregamesGmbH.RoyalRevolt2"
    "AdobeSystemsIncorporated.AdobePhotoshopExpress"
    "ActiproSoftwareLLC.562882FEEB491"
    "5EA27B7.Duolingo-LearnLanguagesforFree"
    "Facebook.Facebook"
    "46928bounde.EclipseManager"
    "A278AB0D.MarchofEmpires"
    "KeeperSecurityInc.Keeper"
    "king.com.BubbleWitch3Saga"
    "89006A2E.AutodeskSketchBook"
    "CAF9E577.Plex"
    # apps which cannot be removed using Remove-AppxPackage
    #"Microsoft.BioEnrollment"
    #"Microsoft.MicrosoftEdge"
    #"Microsoft.Windows.Cortana"
    #"Microsoft.WindowsFeedback"
    #"Microsoft.XboxGameCallableUI"
    #"Microsoft.XboxIdentityProvider"
    #"Windows.ContactSupport"
)

foreach ($app in $apps) {
    echo "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage

    Get-AppXProvisionedPackage -Online |
        where DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
}
#Security Settings
Write-Host "Setting Security Settings"
Function SecuitySettings{

sp "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseOpen" 0sp "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
force-mkdir "HKCU:\Printers\Defaults"
sp "HKCU:\Printers\Defaults" "NetID" "{00000000-0000-0000-0000-000000000000}"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
sp "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" 0
force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0
echo "Disable synchronisation of settings"
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" 0x3c
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "DeviceMetadataUploaded" 0
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "PriorLogons" 1
echo "Do not share wifi networks"
$user = New-Object System.Security.Principal.NTAccount($env:UserName)
$sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value
force-mkdir ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid)
sp ("HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid) "FeatureStates" 0x33c
sp "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseCredShared" 0
sp "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseOpen" 0
echo "Set privacy policy accepted state to 0"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
sp "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0

echo "Do not scan contact informations"
force-mkdir "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
sp "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0

echo "Inking and typing settings"
force-mkdir "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
sp "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
sp "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
echo "Microsoft Edge settings"
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
sp "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" "DoNotTrack" 1
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
sp "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" "ShowSearchSuggestionsGlobal" 0
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
sp "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" "FPEnabled" 0
force-mkdir "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
sp "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" "EnabledV9" 0
echo "Disable location sensor"
force-mkdir "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
sp "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0
echo "Disabling telemetry via Group Policies"
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
$services = @(
    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                                # Diagnostics Tracking Service
    "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
    "HomeGroupListener"                        # HomeGroup Listener
    "HomeGroupProvider"                        # HomeGroup Provider
    "lfsvc"                                    # Geolocation Service
    "MapsBroker"                               # Downloaded Maps Manager
    "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
    "RemoteAccess"                             # Routing and Remote Access
    "RemoteRegistry"                           # Remote Registry
    "SharedAccess"                             # Internet Connection Sharing (ICS)
    "TrkWks"                                   # Distributed Link Tracking Client
    "WbioSrvc"                                 # Windows Biometric Service
    #"WlanSvc"                                 # WLAN AutoConfig
    "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
    #"wscsvc"                                   # Windows Security Center Service
    #"WSearch"                                 # Windows Search
    "XblAuthManager"                           # Xbox Live Auth Manager
    "XblGameSave"                              # Xbox Live Game Save Service
    "XboxNetApiSvc"                            # Xbox Live Networking Service

    # Services which cannot be disabled
    #"WdNisSvc"
)
foreach ($service in $services) {
    echo "Trying to disable $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
}
Write-Host "Disabling Advertising ID..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
	Write-Host "Raising UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
	Write-Host "Disabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Write-Host "Setting current network profile to private..."
	Set-NetConnectionProfile -NetworkCategory Private
	Write-Host "Stopping and disabling Home Groups services..."
	Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Disabled
	Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Disabled
	Write-Host "Disabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
Write-Host "Setting Data Execution Prevention (DEP) policy to OptIn..."
	bcdedit /set `{current`} nx OptOut | Out-Null
}
SecuitySettings
Function QualityOflife{
echo "Defuse Windows search settings"
Set-WindowsSearchSetting -EnableWebResultsSetting $false
echo "Disable background access of default apps"
foreach ($key in (ls "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
    sp ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
}
echo "Disable Game DVR and Game Bar"
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowgameDVR" 0

echo "Disable easy access keyboard stuff"
sp "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506"
sp "HKCU:\Control Panel\Accessibility\Keyboard Response" "Flags" "122"
sp "HKCU:\Control Panel\Accessibility\ToggleKeys" "Flags" "58"
echo "Setting folder view options"
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideDrivesWithNoMedia" 0
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" 0

echo "Setting default explorer view to This PC"
sp "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" 1

echo "Removing user folders under This PC"
# Remove Desktop from This PC
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
rm "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
# Remove Documents from This PC
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
rm "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
rm "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
# Remove Downloads from This PC
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
rm "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
rm "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
# Remove Music from This PC
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
rm "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
rm "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
# Remove Pictures from This PC
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
rm "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
rm "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
# Remove Videos from This PC
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
rm "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
rm "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
rm "HKLM:\SOFTWARE\Wow6432ode\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"

echo "Disable seeding of updates to other computers via Group Policies"
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0

#echo "Disabling automatic driver update"
#sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0

echo "Disable 'Updates are available' message"
takeown /F "$env:WinDIR\System32\MusNotification.exe"
icacls "$env:WinDIR\System32\MusNotification.exe" /deny "Everyone:(X)"
takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "Everyone:(X)"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0	
Write-Host "Disabling automatic Maps updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
Write-Host "Disabling Feedback..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Write-Host "Disabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
Write-Host "Uninstalling Hyper-V..."
	If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
		Uninstall-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	} Else {
		Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}
	Write-Host "Uninstalling Work Folders Client..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
$Keys = @(
       
        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
       
        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
       
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
       
        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
       
        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
           
        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
   
    #This writes the output of each key it is removing and also removes the keys listed above.
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT 
    ForEach ($Key in $Keys) {
        Write-Output "Removing $Key from registry"
        Remove-Item $Key -Recurse -ErrorAction SilentlyContinue
    }
      Write-Output "Disabling scheduled tasks"
    Get-ScheduledTask -TaskName XblGameSaveTaskLogon | Disable-ScheduledTask
    Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask
    Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask
    Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask
    Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask
    Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask.
     Remove-PSDrive HKCR
       Write-Output "Disabling People icon on Taskbar"
    If (!(Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People')) {
        mkdir 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -ErrorAction SilentlyContinue
        $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
        New-ItemProperty $People -Name PeopleBand -Value 0 -Verbose
    }
     Write-Output "Stopping Edge from taking over as the default .PDF viewer" 
    #Stops edge from taking over as the default .PDF viewer
    If (!(Get-ItemProperty 'HKCR:\.pdf' -Name NoOpenWith)) {
        $NoOpen = 'HKCR:\.pdf'
        New-ItemProperty $NoOpen -Name NoOpenWith -Verbose -ErrorAction SilentlyContinue
    }
    
    If (!(Get-ItemProperty 'HKCR:\.pdf' -Name NoStaticDefaultVerb)) {
        $NoStatic = 'HKCR:\.pdf'
        New-ItemProperty $NoStatic -Name NoStaticDefaultVerb -Verbose -ErrorAction SilentlyContinue
    }
    
    If (!(Get-ItemProperty 'HKCR:\.pdf\OpenWithProgids' -Name NoOpenWith)) {
        $NoOpen = 'HKCR:\.pdf\OpenWithProgids'
        New-ItemProperty $NoOpen -Name NoOpenWith -Verbose -ErrorAction SilentlyContinue
    }
    
    If (!(Get-ItemProperty 'HKCR:\.pdf\OpenWithProgids' -Name NoStaticDefaultVerb)) {
        $NoStatic = 'HKCR:\.pdf\OpenWithProgids'
        New-ItemProperty $NoStatic -Name NoStaticDefaultVerb -Verbose -ErrorAction SilentlyContinue
    }
    
    If (!(Get-ItemProperty 'HKCR:\.pdf\OpenWithList' -Name NoOpenWith)) {
        $NoOpen = 'HKCR:\.pdf\OpenWithList'
        New-ItemProperty $NoOpen -Name NoOpenWith -Verbose -ErrorAction SilentlyContinue
    }
    
    If (!(Get-ItemProperty 'HKCR:\.pdf\OpenWithList' -Name NoStaticDefaultVerb)) {
        $NoStatic = 'HKCR:\.pdf\OpenWithList'
        New-ItemProperty $NoStatic -Name NoStaticDefaultVerb -Verbose -ErrorAction SilentlyContinue
    }
     #Stops the Windows Feedback Experience from sending anonymous data
    Write-Output "Stopping the Windows Feedback Experience program"
    If ('HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds') { 
        $Period1 = 'HKCU:\Software\Microsoft\Siuf'
        $Period2 = 'HKCU:\Software\Microsoft\Siuf\Rules'
        $Period3 = 'HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds'
        mkdir $Period1 -ErrorAction SilentlyContinue
        mkdir $Period2 -ErrorAction SilentlyContinue
        mkdir $Period3 -ErrorAction SilentlyContinue
        New-ItemProperty $Period3 -Name PeriodInNanoSeconds -Value 0 -Verbose -ErrorAction SilentlyContinue
    }
       
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable

schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable

schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /Disable


Get-AppxPackage -AllUsers | 
        Where-Object {$_.name -notlike "*Microsoft.Paint3D*"} | 
        Where-Object {$_.name -notlike "*Microsoft.WindowsCalculator*"} |
        Where-Object {$_.name -notlike "*Microsoft.WindowsStore*"} | 
        Where-Object {$_.name -notlike "*Microsoft.Windows.Photos*"} |
        Remove-AppxPackage -ErrorAction SilentlyContinue
            
    #Removes AppxProvisionedPackages
    Get-AppxProvisionedPackage -online |
        Where-Object {$_.packagename -notlike "*Microsoft.Paint3D*"} |
        Where-Object {$_.packagename -notlike "*Microsoft.WindowsCalculator*"} |
        Where-Object {$_.packagename -notlike "*Microsoft.WindowsStore*"} |
        Where-Object {$_.packagename -notlike "*Microsoft.Windows.Photos*"} |
Remove-AppxProvisionedPackage -online -ErrorAction SilentlyContinue
Get-AppxPackage -allusers Microsoft.WindowsCalculator | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppxPackage -allusers Microsoft.WindowsStore | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
Get-AppxPackage -allusers Microsoft.Windows.Photos | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
QualityOflife
Function RemoveOneDrive { 
echo "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

echo "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

echo "Removing OneDrive leftovers"
rm -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
rm -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
rm -Recurse -Force -ErrorAction SilentlyContinue "C:\OneDriveTemp"

echo "Disable OneDrive via Group Policies"
force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
sp "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

echo "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
sp "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
sp "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
echo "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg add "HKEY_USERS\Default\SOFTWARE\Microsoft\Internet Explorer\Safety\PrivacIE" /v FilteringMode /t REG_DWORD /d 0
reg add "HKEY_USERS\Default\SOFTWARE\Microsoft\Internet Explorer\Safety\PrivacIE\Lists\{7C998372-3B89-46E6-9546-1945C711CD0C}" /v Enabled /t REG_DWORD /d 1
reg add "HKEY_USERS\Default\SOFTWARE\Microsoft\Internet Explorer\Safety\PrivacIE\Lists\{7C998372-3B89-46E6-9546-1945C711CD0C}" /v Name /t REG_SZ /d EasyList
reg add "HKEY_USERS\Default\SOFTWARE\Microsoft\Internet Explorer\Safety\PrivacIE\Lists\{7C998372-3B89-46E6-9546-1945C711CD0C}" /v Path /t REG_SZ /d "%AppDataDir%\Local\Microsoft\Internet Explorer\Tracking Protection\{7C998372-3B89-46E6-9546-1945C711CD0C}.tpl"
reg add "HKEY_USERS\Default\SOFTWARE\Microsoft\Internet Explorer\Safety\PrivacIE\Lists\{7C998372-3B89-46E6-9546-1945C711CD0C}" /v Url /t REG_SZ /d "https://easylist-msie.adblockplus.org/easylist.tpl"
reg import .\UACMAX.reg
reg unload "hku\Default"

echo "Removing startmenu entry"
rm -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

echo "Restarting explorer"
start "explorer.exe"

echo "Waiting for explorer to complete loading"
sleep 10

echo "Removing additional OneDrive leftovers"
foreach ($item in (ls "$env:WinDir\WinSxS\*onedrive*")) {
    Takeown-Folder $item.FullName
    rm -Recurse -Force $item.FullName
}
}
RemoveOneDrive