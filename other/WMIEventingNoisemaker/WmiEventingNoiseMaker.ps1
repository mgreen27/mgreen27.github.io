<#
.SYNOPSIS
WmiEventingNoiseMaker.ps1 installs several WMI EventConsumers over configured Namespaces to test detection usecases.
    
    Name: WmiEventingNoiseMaker.ps1
    Version: 1.11
    Author: Matt Green (@mgreen27)
    
.DESCRIPTION
    WmiEventingNoiseMaker.ps1 Installs several WMI Eventing consumers to test detection.
    Event Filter on all Consumers is CMD.exe being opened.
    Default namespaces include: ROOT/Default, ROOT/Subscription, ROOT/ThinPrint
    Manually specify a namespace using -Namespace switch to install to that namespace only.

    Configure consumer types with:
        -AST for ActiveScript Text
        -ASF for ActiveScript File
        -CLT for CommandLine Template
        -CLE for CommandLineExecutablePath
    Default with no consumer type switches is all of the above added

    Remove all consumers with -Remove switch. Note: no consumer type confiuration enabled for remove.

    The scripts drops a vbs file to disk for testing ActiveScript ScriptFileName attribute for each namespace.
    The scripts also compiles and drops an exe file to disk for testing CommandLine ExecutablePath attribute for each namespace.
    .NET required to be installed on test machine or create binaries seperately. Binary simply writes a line to log.

    Disk items include:
        c:\WMIEventing.log - generated on trigger of event filter/
        C:\WMI<Namespace>.exe
        c:\WMI<Namespace>.vbs

    Tested PS2+
 
.EXAMPLE
    WmiEventingNoiseMaker.ps1

    Installing EventConsumers for ROOT/Default
	    Installing ActiveScriptText EventConsumer
	    Installing ActiveScriptFile EventConsumer
	    Installing CommandLineTemplate EventConsumer
	    Installing CommandLineExecutablePath EventConsumer

    Installing EventConsumers for ROOT/Subscription
	    Installing ActiveScriptText EventConsumer
	    Installing ActiveScriptFile EventConsumer
	    Installing CommandLineTemplate EventConsumer
	    Installing CommandLineExecutablePath EventConsumer


   NameSpace: ROOT\ThinPrint

    Name                                Methods              Properties                                                                                                                            
    ----                                -------              ----------                                                                                                                            
    NotActiveScript                     {}                   {CreatorSID, KillTimeout, MachineName, MaximumQueueSize...}                                                                           
    NotCommandLine                      {}                   {CommandLineTemplate, CreateNewConsole, CreateNewProcessGroup, CreateSeparateWowVdm...}

    Installing EventConsumers for ROOT/ThinPrint
	    Installing ActiveScriptText EventConsumer
	    Installing ActiveScriptFile EventConsumer
	    Installing CommandLineTemplate EventConsumer
	    Installing CommandLineExecutablePath EventConsumer


    Name                LastWriteTime      
    ----                -------------      
    WMIDefault.exe      9/7/2018 7:52:24 AM
    WMIDefault.vbs      9/7/2018 7:52:24 AM
    WMISubscription.exe 9/7/2018 7:52:24 AM
    WMISubscription.vbs 9/7/2018 7:52:24 AM
    WMIThinPrint.exe    9/7/2018 7:52:24 AM
    WMIThinPrint.vbs    9/7/2018 7:52:24 AM
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $False)][String]$Namespace=$Null,
    [Parameter(Mandatory = $False)][Switch]$Remove=$Null,
    [Parameter(Mandatory = $False)][Switch]$AST=$Null,
    [Parameter(Mandatory = $False)][Switch]$ASF=$Null,
    [Parameter(Mandatory = $False)][Switch]$CLT=$Null,
    [Parameter(Mandatory = $False)][Switch]$CLE=$Null

)
$ErrorActionPreference = 'SilentlyContinue'

# Set default Namespaces here
$Namespaces = @("Default","Subscription","ThinPrint")

function Remove-WmiEventingNoiseMaker($Namespaces) {

    Foreach ($Namespace in $Namespaces){
        Write-Host -ForegroundColor Yellow "Removing EventConsumers for ROOT/$Namespace"

        Get-WmiObject -Namespace "ROOT/$Namespace" -Class "__EventFilter" -ErrorAction silentlycontinue | where-object {$_.Name -Like "*Evil*"}  | Remove-WmiObject
        Get-WmiObject -Namespace "ROOT/$Namespace" -Class "__FilterToConsumerBinding" -ErrorAction silentlycontinue | where-object {$_.Path -Like "*Evil*"}  | Remove-WmiObject
        Get-WmiObject -Namespace "ROOT/$Namespace" -Class "__EventConsumer" -ErrorAction silentlycontinue | where-object {$_.Name -Like "*Evil*"}  | Remove-WmiObject

        If ("ROOT/$Namespace" -ne "ROOT/Default" -And "ROOT/$Namespace" -ne "ROOT/Subscription"){

            If (Get-WmiObject -Namespace "ROOT/$Namespace" -Class Meta_Class | Where-Object {$_.Name -eq "TrackingClass"}){
                Get-WmiObject -Namespace root -ClassName __Namespace | Where-Object {$_.Name -eq $Namespace} | Remove-WmiObject
            }
            Else{
                Get-WmiObject -Namespace "ROOT/$Namespace" -Class Meta_Class -Filter "__CLASS = 'NotActiveScript'" | Remove-WmiObject
                Get-WmiObject -Namespace "ROOT/$Namespace" -Class Meta_Class -Filter "__CLASS = 'NotCommandLine'" | Remove-WmiObject
            }
        }

        Remove-Item $("c:\WMI" + $Namespace + ".vbs") -Force
        Remove-Item $("c:\WMI" + $Namespace + ".exe") -Force
    }

    Remove-Item "C:\WMIEventing.log" -Force
    Get-childItem c:\ -Filter WMI* | Select-Object Name,LastWriteTime
    Write-Host -ForegroundColor Yellow "`nWmiEventingNoisemaker: Removal Complete"
}

function New-ActiveScriptEventConsumerClass {
<#
.SYNOPSIS

Creates an ActiveScriptEventConsumer WMI class in the namespace of your choosing.

.DESCRIPTION

New-ActiveScriptEventConsumerClass creates a clone of the ActiveScriptEventConsumer WMI event consumer class using the class name and namespace name of your choosing.

The purpose of New-ActiveScriptEventConsumerClass is to highlight the difficulty of developing robust WMI persistence detections. Previously, it was assumed that ActiveScriptEventConsumer classes could only exist in the root/subscription and root/default namespaces. New-ActiveScriptEventConsumerClass proves that this is indeed not the case.

As of this writing, New-ActiveScriptEventConsumerClass bypasses both Sysinternals Autoruns and Sysmon WMI persistence detections. This technique will still be caught with event ID 5861 in the Microsoft-Windows-WMI-Activity/Operational event log (Win 10+).

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER Namespace

Specifies the namespace within the root namespace where the class will live. If the namespace already exists, it will create the class within that namespace (with the exception of root/subscription and root/default).

.PARAMETER ClassName

Specifies the name of the ActiveScriptEventConsumer class to create. A class name of ActiveScriptEventConsumer will be used my default.

.PARAMETER Credential

Specifies a user account that has permission to perform this action. The default is the current user. Type a user name, such as User01, Domain01\User01, or User@Contoso.com. Or, enter a PSCredential object, such as an object that is returned by the Get-Credential cmdlet. When you type a user name, you are prompted for a password.

.PARAMETER ComputerName

Specifies the target computer for the management operation. Enter a fully qualified domain name (FQDN), a NetBIOS name, or an IP address. When the remote computer is in a different domain than the local computer, the fully qualified domain name is required.

.EXAMPLE

New-ActiveScriptEventConsumerClass -Namespace Foo -ClassName Blah

Description
-----------
An ActiveScriptEventConsumer class will be created as the 'Blah' class in the 'root/Foo' namespace. WMI persistence will now be possible in the 'root/Foo' namespace, evading Sysinternals.

.EXAMPLE

New-ActiveScriptEventConsumerClass -Namespace Foo -ClassName Blah -Credential TestUser -ComputerName 192.168.1.24

.EXAMPLE

$NewActiveScriptEventConsumer = Get-WmiObject -Namespace root/Foo -Class Meta_Class -Filter "__CLASS = 'Blah'"
$NewActiveScriptEventConsumer.Delete()

Get-CimInstance -Namespace root/Foo -ClassName __Win32Provider -Filter 'Name = "Blah"' | Remove-CimInstance
Get-CimInstance -Namespace root -ClassName __NAMESPACE -Filter 'Name = "Foo"' | Remove-CimInstance

Description
-----------
An example of cleaning up the class and namespace that was created in the previous example.

.OUTPUTS

System.Management.ManagementClass

Outputs the class definition of the new ActiveScriptEventConsumer class.
#>

    [OutputType([System.Management.ManagementClass])]
    [CmdletBinding(DefaultParameterSetName = 'NotRemote')]
    param (
        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $True, ParameterSetName = 'NotRemote')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Namespace,

        [Parameter(ParameterSetName = 'Remote')]
        [Parameter(ParameterSetName = 'NotRemote')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ClassName = 'CommandLineEventConsumer',

        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName
    )

    $HadError = $False

    if (($Namespace -eq 'subscription') -or ($Namespace -eq 'default')) {
        Write-Error "New-ActiveScriptEventConsumerClass does not work with the root/subscription and root/default namespaces."
        $HadError = $True
    }

    $ExistingClass = $null

    $OptionalWMIArgs = @{}

    if ($Credential -and $ComputerName) {
        $OptionalWMIArgs['Credential'] = $Credential
        $OptionalWMIArgs['ComputerName'] = $ComputerName
    }

    try {
        $ExistingClass = Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '$ClassName'" @OptionalWMIArgs -ErrorAction SilentlyContinue
    } catch { }

    if ($ExistingClass) {
        Write-Error "WMI class root\$($Namespace):$ClassName already exists."
        $HadError = $True
    }

    if (-not $HadError) {
        $ExistingNamespace = Get-WmiObject -Namespace ROOT -Class __NAMESPACE -Filter "Name = '$Namespace'" -ErrorAction SilentlyContinue @OptionalWMIArgs

        if (-not $ExistingNamespace) {
            # Create a new namespace using the namespace name supplied
            $NewNamespace = Set-WmiInstance -Namespace ROOT -Class __NAMESPACE -Arguments @{ Name = $Namespace } -ErrorAction Stop @OptionalWMIArgs

            # <mgreen27> Create a new tracking class
            $TrackingClass = New-Object System.Management.ManagementClass("ROOT\$Namespace", $null, $null)
            $TrackingClass.name = "TrackingClass"
            #$TrackingClass.Properties.Add("Name", [System.Management.CimType]::String, $false)
            #$TrackingClass.Properties["Name"].Qualifiers.Add("key", $true)
            $Null = $TrackingClass.put()
        }
        
        
        # Derive the ActiveScriptEventConsumer in the specified namespace
        $EventConsumerBase = Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '__EventConsumer'" @OptionalWMIArgs
        # Derive the new ActiveScriptEventConsumer class. Upon creating the class, it will inherit the following properties:
        #  * CreatorSID
        #  * MachineName
        #  * MaximumQueueSize
        $NewActiveScriptEventConsumer = $EventConsumerBase.Derive($ClassName)

        # Mirror all the properties and respective qualifiers for ActiveScriptEventConsumer
        # scrcons.mof for reference/comparison:
        <#
        class ActiveScriptEventConsumer : __EventConsumer
        {
          [key] string Name;
          [not_null, write] string ScriptingEngine;
          [write] string ScriptText;
          [write] string ScriptFilename;
          [write] uint32 KillTimeout = 0;
        };
        #>

        $NewActiveScriptEventConsumer.Properties.Add('Name', [Management.CimType]::String, $False)
        $NewActiveScriptEventConsumer.Properties['Name'].Qualifiers.Add('key', $True, $False, $True, $True, $False)

        $NewActiveScriptEventConsumer.Properties.Add('ScriptingEngine', [Management.CimType]::String, $False)
        $NewActiveScriptEventConsumer.Properties['ScriptingEngine'].Qualifiers.Add('not_null', $True, $False, $False, $False, $True)
        $NewActiveScriptEventConsumer.Properties['ScriptingEngine'].Qualifiers.Add('write', $True, $False, $False, $False, $True)

        $NewActiveScriptEventConsumer.Properties.Add('ScriptText', [Management.CimType]::String, $False)
        $NewActiveScriptEventConsumer.Properties['ScriptText'].Qualifiers.Add('write', $True, $False, $False, $False, $True)

        $NewActiveScriptEventConsumer.Properties.Add('ScriptFilename', [Management.CimType]::String, $False)
        $NewActiveScriptEventConsumer.Properties['ScriptFilename'].Qualifiers.Add('write', $True, $False, $False, $False, $True)

        $NewActiveScriptEventConsumer.Properties.Add('KillTimeout', [Management.CimType]::UInt32, $False)
        $NewActiveScriptEventConsumer.Properties['KillTimeout'].Qualifiers.Add('write', $True, $False, $False, $False, $True)

        # Bake in the new type
        $null = $NewActiveScriptEventConsumer.Put()

        # ActiveScriptEventConsumer now needs to be bound to its provider
        # scrcons.mof for reference/comparison:
        <#
        Instance of __Win32Provider as $SCRCONS_P
        {
          Name = "ActiveScriptEventConsumer";
          Clsid = "{266c72e7-62e8-11d1-ad89-00c04fd8fdff}";
          PerUserInitialization = TRUE;
          HostingModel = "SelfHost";

        };
        #>
        $NewActiveScriptEventConsumerProviderBinding = Set-WmiInstance -ErrorAction SilentlyContinue -Namespace "ROOT/$Namespace" -Class __Win32Provider -Arguments @{
            Name = $ClassName
            Clsid = '{266c72e7-62e8-11d1-ad89-00c04fd8fdff}'
            PerUserInitialization = $True
            HostingModel = 'SelfHost'
        } @OptionalWMIArgs

        # Perform the final event consumer consumer to provider binding
        # scrcons.mof for reference/comparison:
        <#
        Instance of __EventConsumerProviderRegistration
        {
          Provider = $SCRCONS_P;
          ConsumerClassNames = {"ActiveScriptEventConsumer"};
        };
        #>

        $EventConsumerProviderRegistration = Set-WmiInstance -Namespace "ROOT/$Namespace" -Class __EventConsumerProviderRegistration -Arguments @{
            provider = $NewActiveScriptEventConsumerProviderBinding
            ConsumerClassNames = @($ClassName)
        } @OptionalWMIArgs

        Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '$ClassName'" @OptionalWMIArgs
    }
}

function New-CommandLineEventConsumerClass {
<#
.SYNOPSIS

Creates a CommandLineEventConsumer WMI class in the namespace of your choosing.

.DESCRIPTION

New-CommandLineEventConsumerClass creates a clone of the CommandLineEventConsumer WMI event consumer class using the class name and namespace name of your choosing.

The purpose of New-CommandLineEventConsumerClass is to highlight the difficulty of developing robust WMI persistence detections. Previously, it was assumed that CommandLineEventConsumer classes could only exist in the root/subscription and root/default namespaces. New-CommandLineEventConsumerClass proves that this is indeed not the case.

As of this writing, New-CommandLineEventConsumerClass bypasses both Sysinternals Autoruns and Sysmon WMI persistence detections. This technique will still be caught with event ID 5861 in the Microsoft-Windows-WMI-Activity/Operational event log (Win 10+).

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER Namespace

Specifies the namespace within the root namespace where the class will live. If the namespace already exists, it will create the class within that namespace (with the exception of root/subscription and root/default).

.PARAMETER ClassName

Specifies the name of the CommandLineEventConsumer class to create. A class name of CommandLineEventConsumer will be used my default.

.PARAMETER Credential

Specifies a user account that has permission to perform this action. The default is the current user. Type a user name, such as User01, Domain01\User01, or User@Contoso.com. Or, enter a PSCredential object, such as an object that is returned by the Get-Credential cmdlet. When you type a user name, you are prompted for a password.

.PARAMETER ComputerName

Specifies the target computer for the management operation. Enter a fully qualified domain name (FQDN), a NetBIOS name, or an IP address. When the remote computer is in a different domain than the local computer, the fully qualified domain name is required.

.EXAMPLE

New-CommandLineEventConsumerClass -Namespace Foo -ClassName Blah

Description
-----------
A CommandLineEventConsumer class will be created as the 'Blah' class in the 'root/Foo' namespace. WMI persistence will now be possible in the 'root/Foo' namespace, evading Sysinternals.

.EXAMPLE

New-CommandLineEventConsumerClass -Namespace Foo -ClassName Blah -Credential TestUser -ComputerName 192.168.1.24

.EXAMPLE

$NewCommandLineEventConsumer = Get-WmiObject -Namespace root/Foo -Class Meta_Class -Filter "__CLASS = 'Blah'"
$NewCommandLineEventConsumer.Delete()

Get-CimInstance -Namespace root/Foo -ClassName __Win32Provider -Filter 'Name = "Blah"' | Remove-CimInstance
Get-CimInstance -Namespace root -ClassName __NAMESPACE -Filter 'Name = "Foo"' | Remove-CimInstance

Description
-----------
An example of cleaning up the class and namespace that was created in the previous example.

.OUTPUTS

System.Management.ManagementClass

Outputs the class definition of the new CommandLineEventConsumer class.
#>

    [OutputType([System.Management.ManagementClass])]
    [CmdletBinding(DefaultParameterSetName = 'NotRemote')]
    param (
        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $True, ParameterSetName = 'NotRemote')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Namespace,

        [Parameter(ParameterSetName = 'Remote')]
        [Parameter(ParameterSetName = 'NotRemote')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ClassName = 'CommandLineEventConsumer',

        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName
    )

    $HadError = $False

    if (($Namespace -eq 'subscription') -or ($Namespace -eq 'default')) {
        Write-Error "New-CommandLineEventConsumerClass does not work with the root/subscription and root/default namespaces."
        $HadError = $True
    }

    $ExistingClass = $null

    $OptionalWMIArgs = @{}

    if ($Credential -and $ComputerName) {
        $OptionalWMIArgs['Credential'] = $Credential
        $OptionalWMIArgs['ComputerName'] = $ComputerName
    }

    try {
        $ExistingClass = Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '$ClassName'" @OptionalWMIArgs -ErrorAction SilentlyContinue
    } catch { }

    if ($ExistingClass) {
        Write-Error "WMI class root\$($Namespace):$ClassName already exists."
        $HadError = $True
    }

    if (-not $HadError) {
        $ExistingNamespace = Get-WmiObject -Namespace ROOT -Class __NAMESPACE -Filter "Name = '$Namespace'" -ErrorAction SilentlyContinue @OptionalWMIArgs

        if (-not $ExistingNamespace) {
            # Create a new namespace using the namespace name supplied
            $NewNamespace = Set-WmiInstance -Namespace ROOT -Class __NAMESPACE -Arguments @{ Name = $Namespace } -ErrorAction Stop @OptionalWMIArgs

            # <mgreen27> Create a new tracking class
            $TrackingClass = New-Object System.Management.ManagementClass("ROOT\$Namespace", $null, $null)
            $TrackingClass.name = "TrackingClass"
            #$TrackingClass.Properties.Add("Name", [System.Management.CimType]::String, $false)
            #$TrackingClass.Properties["Name"].Qualifiers.Add("key", $true)
            $Null = $TrackingClass.put()
        }
        
        
        # Derive the CommandLineEventConsumer in the specified namespace
        $EventConsumerBase = Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '__EventConsumer'" @OptionalWMIArgs
        # Derive the new CommandLineEventConsumer class. Upon creating the class, it will inherit the following properties:
        #  * CreatorSID
        #  * MachineName
        #  * MaximumQueueSize
        $NewCommandLineEventConsumer = $EventConsumerBase.Derive($ClassName)

        # Mirror all the properties and respective qualifiers for CommandLineEventConsumer
        # WBEMCons.mof for reference/comparison:
        <#
        class CommandLineEventConsumer : __EventConsumer
        {
          [key] string Name;
          [write] string ExecutablePath;
          [Template, write] string CommandLineTemplate;
          [write] boolean UseDefaultErrorMode = FALSE;
          [DEPRECATED] boolean CreateNewConsole = FALSE;
          [write] boolean CreateNewProcessGroup = FALSE;
          [write] boolean CreateSeparateWowVdm = FALSE;
          [write] boolean CreateSharedWowVdm = FALSE;
          [write] sint32 Priority = 32;
          [write] string WorkingDirectory;
          [DEPRECATED] string DesktopName;
          [Template, write] string WindowTitle;
          [write] uint32 XCoordinate;
          [write] uint32 YCoordinate;
          [write] uint32 XSize;
          [write] uint32 YSize;
          [write] uint32 XNumCharacters;
          [write] uint32 YNumCharacters;
          [write] uint32 FillAttribute;
          [write] uint32 ShowWindowCommand;
          [write] boolean ForceOnFeedback = FALSE;
          [write] boolean ForceOffFeedback = FALSE;
          [write] boolean RunInteractively = FALSE;
          [write] uint32 KillTimeout = 0;
        };
        #>

        $NewCommandLineEventConsumer.Properties.Add('Name', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['Name'].Qualifiers.Add('key', $True, $False, $True, $True, $False)
        $NewCommandLineEventConsumer.Properties.Add('ExecutablePath', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['ExecutablePath'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('CommandLineTemplate', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['CommandLineTemplate'].Qualifiers.Add('Template', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties['CommandLineTemplate'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('UseDefaultErrorMode', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['UseDefaultErrorMode'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('CreateNewConsole', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['CreateNewConsole'].Qualifiers.Add('DEPRECATED', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('CreateNewProcessGroup', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['CreateNewProcessGroup'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('CreateSeparateWowVdm', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['CreateSeparateWowVdm'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('CreateSharedWowVdm', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['CreateSharedWowVdm'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('Priority', [Int32] 32, [Management.CimType]::SInt32)
        $NewCommandLineEventConsumer.Properties['Priority'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('WorkingDirectory', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['WorkingDirectory'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('DesktopName', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['DesktopName'].Qualifiers.Add('DEPRECATED', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('WindowTitle', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['WindowTitle'].Qualifiers.Add('Template', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties['WindowTitle'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('XCoordinate', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['XCoordinate'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('YCoordinate', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['YCoordinate'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('XSize', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['XSize'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('YSize', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['YSize'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('XNumCharacters', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['XNumCharacters'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('YNumCharacters', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['YNumCharacters'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('FillAttribute', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['FillAttribute'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('ShowWindowCommand', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['ShowWindowCommand'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('ForceOnFeedback', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['ForceOnFeedback'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('ForceOffFeedback', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['ForceOffFeedback'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('RunInteractively', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['RunInteractively'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('KillTimeout', [UInt32] 0, [Management.CimType]::UInt32)
        $NewCommandLineEventConsumer.Properties['KillTimeout'].Qualifiers.Add('write', $True, $False, $False, $False, $True)

        # Bake in the new type
        $null = $NewCommandLineEventConsumer.Put()

        # CommandLineEventConsumer now needs to be bound to its provider
        # WBEMCons.mof for reference/comparison:
        <#
        Instance of __Win32Provider as $P2
        {
          Name = "CommandLineEventConsumer";
          Clsid = "{266c72e5-62e8-11d1-ad89-00c04fd8fdff}";
          HostingModel = "LocalSystemHost";

        };
        #>
        $NewCommandLineEventConsumerProviderBinding = Set-WmiInstance -Namespace "ROOT/$Namespace" -Class __Win32Provider -Arguments @{
            Name = $ClassName
            Clsid = '{266c72e5-62e8-11d1-ad89-00c04fd8fdff}'
            HostingModel = 'LocalSystemHost'
        } @OptionalWMIArgs

        # Perform the final event consumer consumer to provider binding
        # WBEMCons.mof for reference/comparison:
        <#
        Instance of __EventConsumerProviderRegistration
        {
          Provider = $P2;
          ConsumerClassNames = {"CommandLineEventConsumer"};
        };
        #>

        $EventConsumerProviderRegistration = Set-WmiInstance -Namespace "ROOT/$Namespace" -Class __EventConsumerProviderRegistration -Arguments @{
            provider = $NewCommandLineEventConsumerProviderBinding
            ConsumerClassNames = @($ClassName)
        } @OptionalWMIArgs

        Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '$ClassName'" @OptionalWMIArgs
    }
}


# MAIN
if ($Namespace){
    $Namespaces = $Namespace
}

If ($Remove){
    Remove-WmiEventingNoiseMaker $Namespaces
    break
}

if (!($AST) -and !($ASF) -and !($CLT) -and !($CLE)){
    $AST=$True
    $ASF=$True
    $CLT=$True
    $CLE=$True
}

Foreach ($SplitNameSpace in $Namespaces){

    If ($SplitNameSpace -ne "Default" -And $SplitNameSpace -ne "Subscription"){
        # Creating a New namespace and 2 new classes
        New-ActiveScriptEventConsumerClass -Namespace $SplitNameSpace -ClassName NotActiveScript
        New-CommandLineEventConsumerClass -Namespace $SplitNameSpace -ClassName NotCommandLine
    }

    # Set Variables
    $NameSpace = "ROOT/" + $SplitNameSpace
    $Name = "Evil" + $SplitNameSPace
    $Query = 'SELECT ProcessName FROM Win32_ProcessStartTrace WHERE ProcessName = "cmd.exe"'


    Write-Host -ForegroundColor Yellow "`nInstalling EventConsumers for $Namespace"

    # Define the signature - i.e. __EventFilter
    $EventFilterArgs = @{
        EventNamespace = "root/cimv2"
        Name = $Name
        Query = $Query
        QueryLanguage = "WQL"
    }

    $InstanceArgs = @{
        Namespace = $NameSpace
        Class = "__EventFilter"
        Arguments = $EventFilterArgs
    }

    $Filter = Set-WmiInstance @InstanceArgs


    ################
    ##ActiveSctipt##
    ################
    # 0 
    if ($ASF){
        Write-Host -ForegroundColor DarkYellow "`tInstalling ActiveScriptText EventConsumer"

        If ($SplitNameSpace -eq "Default" -Or $SplitNameSpace -eq "Subscription"){$Class = "ActiveScriptEventConsumer"}
        Else{$Class = "NotActiveScript"}

        $script=@"
Dim Evil
Dim strDate,strTime,strWmiResultsPath
Dim objWmiResultsFile,objFSO,dateTime

Set dateTime = CreateObject("WbemScripting.SWbemDateTime")    
dateTime.SetVarDate (now())
strDate = YEAR(dateTime.GetVarDate (false)) & "-" & Right(String(2,"0") & Month(dateTime.GetVarDate (false)), 2) & "-" & Right(String(2, "0") & DAY(dateTime.GetVarDate (false)), 2)
strTime = FormatDateTime(dateTime.GetVarDate (false),vbShortTime)

strWmiResultsPath = "C:\WMIEventing.log"
Set objFSO = CreateObject("Scripting.Filesystemobject")

Set objWmiResultsFile = objFSO.OpenTextFile(strWmiResultsPath,8,True,0)
objWmiResultsFile.WriteLine strDate & "T" & strTime & "Z|WMI Eventing 
"@
        $script = $script + $NameSpace + " ActiveSctiptText test successful.`"`nobjWmiResultsFile.Close"


        # Define the Event Consumers - ACTION
        $ActiveScriptConsumerArgs = @{
            Name = $Name + "0"
            ScriptingEngine = "VBScript"
            ScriptText = $script
        }

        $InstanceArgs = @{
            Namespace = $NameSpace
            Class = $Class
            Arguments = $ActiveScriptConsumerArgs
        }

        $Consumer = Set-WmiInstance @InstanceArgs

        $FilterConsumerBingingArgs = @{
            Filter = $Filter
            Consumer = $Consumer
        }

        $InstanceArgs = @{
            Namespace = $NameSpace
            Class = "__FilterToConsumerBinding"
            Arguments = $FilterConsumerBingingArgs
        }
    }

        # Register the alert
        $Binding = Set-WmiInstance @InstanceArgs



    #####################
    ##ActiveSctipt File##
    #####################
    # 1
    if ($AST){
        Write-Host -ForegroundColor DarkYellow "`tInstalling ActiveScriptFile EventConsumer"

        If ($SplitNameSpace -eq "Default" -Or $SplitNameSpace -eq "Subscription"){$Class = "ActiveScriptEventConsumer"}
        Else{$Class = "NotActiveScript"}

        $ScriptPath = "C:\WMI" + $SplitNameSPace + ".vbs"
        Remove-Item $ScriptPath -Force -ErrorAction SilentlyContinue

        $script = @"
Dim Evil
Dim strDate,strTime,strWmiResultsPath
Dim objWmiResultsFile,objFSO,dateTime

Set dateTime = CreateObject("WbemScripting.SWbemDateTime")    
dateTime.SetVarDate (now())
strDate = YEAR(dateTime.GetVarDate (false)) & "-" & Right(String(2,"0") & Month(dateTime.GetVarDate (false)), 2) & "-" & Right(String(2, "0") & DAY(dateTime.GetVarDate (false)), 2)
strTime = FormatDateTime(dateTime.GetVarDate (false),vbShortTime)

strWmiResultsPath = "C:\WMIEventing.log"
Set objFSO = CreateObject("Scripting.Filesystemobject")

Set objWmiResultsFile = objFSO.OpenTextFile(strWmiResultsPath,8,True,0)
objWmiResultsFile.WriteLine strDate & "T" & strTime & "Z|WMI Eventing 
"@
        $script=$script + $NameSpace + " ActiveSctiptFile test successful.`"`nobjWmiResultsFile.Close"


        # Write script created above to location
        Set-Content -Path $ScriptPath -Value $script

        # Define the Event Consumers - ACTION
        $ActiveScriptConsumerArgs = @{
            Name = $Name + "1"
            ScriptingEngine = "VBScript"
            ScriptFileName = $ScriptPath
        }

        $InstanceArgs = @{
            Namespace = $NameSpace
            Class = $Class
            Arguments = $ActiveScriptConsumerArgs
        }

        $Consumer = Set-WmiInstance @InstanceArgs

        $FilterConsumerBingingArgs = @{
            Filter = $Filter
            Consumer = $Consumer
        }

        $InstanceArgs = @{
            Namespace = $NameSpace
            Class = "__FilterToConsumerBinding"
            Arguments = $FilterConsumerBingingArgs
        }

        # Register the alert
        $Binding = Set-WmiInstance @InstanceArgs
    }


    ########################
    ##CommandLineTemplate ##
    ########################
    # 2
    if ($CLT){
        Write-Host -ForegroundColor DarkYellow "`tInstalling CommandLineTemplate EventConsumer"
    
        If ($SplitNameSpace -eq "Default" -Or $SplitNameSpace -eq "Subscription"){$Class = "CommandLineEventConsumer"}
        Else{$Class = "NotCommandLine"}

        $Payload = '"$(Get-Date ([DateTime]::UtcNow) -format "yyyy-MM-ddTHH:mmZ")|WMI Eventing ' + $NameSpace + ' CommandLineTemplate test successful." | Out-File "C:\WMIEventing.log" -Append ascii'
        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Payload))
        $Command = "powershell -nop -noni -w hidden -enc $b64"

        # Define the Event Consumers - ACTION
        $CommandLineConsumerArgs = @{
            Name = $Name + "2"
            CommandLineTemplate = $Command
        }

        $InstanceArgs = @{
            Namespace = $NameSpace
            Class = $Class
            Arguments = $CommandLineConsumerArgs
        }

        $Consumer = Set-WmiInstance @InstanceArgs

        $FilterConsumerBingingArgs = @{
            Filter = $Filter
            Consumer = $Consumer
        }

        $InstanceArgs = @{
            Namespace = $NameSpace
            Class = "__FilterToConsumerBinding"
            Arguments = $FilterConsumerBingingArgs
        }

        # Register the alert
        $Binding = Set-WmiInstance @InstanceArgs
    }



    ##############################
    ##CommandLineExecutablePath ##
    ##############################
    # 3
    if ($CLE){
        Write-Host -ForegroundColor DarkYellow "`tInstalling CommandLineExecutablePath EventConsumer"

        If ($SplitNameSpace -eq "Default" -Or $SplitNameSpace -eq "Subscription"){$Class = "CommandLineEventConsumer"}
        Else{$Class = "NotCommandLine"}

        $exe = $Null
        $WMIDefault = "C:\WMI" + $SplitNameSPace + ".exe"

        $exe = @"
using System;

class rootdefault
{
    static void Main()
    {
        var dt = DateTime.UtcNow;
        string text = dt.ToString("yyyy-MM-ddTHH:mmZ") + "|WMI Eventing 
"@

    $exe = $exe + $NameSpace + @"
 CommandLineEXE test successful.\n";
        System.IO.File.AppendAllText(@"C:\WMIEventing.log", text);
    }
}
"@

        Add-Type -outputtype consoleapplication -outputassembly $WMIDefault $exe

        # Define the Event Consumers - ACTION
        $CommandLineConsumerArgs = @{
            Name = $Name + "3"
            ExecutablePath = $WMIDefault
        }

        $InstanceArgs = @{
            Namespace = $NameSpace
            Class = $Class
            Arguments = $CommandLineConsumerArgs
        }

        $Consumer = Set-WmiInstance @InstanceArgs

        $FilterConsumerBingingArgs = @{
            Filter = $Filter
            Consumer = $Consumer
        }

        $InstanceArgs = @{
            Namespace = $NameSpace
            Class = "__FilterToConsumerBinding"
            Arguments = $FilterConsumerBingingArgs
        }

        # Register the alert
        $Binding = Set-WmiInstance @InstanceArgs
    }

}

Get-childItem c:\ -Filter WMI* | Select-Object Name,LastWriteTime | Format-Table