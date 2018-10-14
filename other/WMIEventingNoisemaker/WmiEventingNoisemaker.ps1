<#
.SYNOPSIS
	WmiEventingNoiseMaker.ps1 installs several WMI EventConsumers over several Namespaces to test detection usecases.
    
    Name: WmiEventingNoiseMaker.ps1
    Version: 1.0
    Author: Matt Green (@mgreen27)
    
.DESCRIPTION
    WmiEventingNoiseMaker.ps1 Installs all scripts in a Namespace folder.
    Event Filter on all Consumers is CMD.exe being opened.
    Current supported namespaces include: ROOT/Default, ROOT/Subscription, ROOT/ThinPrint
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

$ErrorActionPreference = "SilentlyContinue"

$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$Scripts = Get-ChildItem ($PSScriptRoot + "\Namespaces") -Filter *.ps1

Foreach($script in $Scripts){
    . $script.fullname
}

Get-childItem c:\ -Filter WMI* | Select-Object Name,LastWriteTime | Format-Table
