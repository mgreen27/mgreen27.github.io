---
layout: post
title:  "Invoke-LiveResponse"
date:   2018-01-14
categories: posts
tags: [DFIR,Powershell]
image: 00PowerShell.png
showTags: true
readTime: true
summary: In this post, I am going to talk about a Powershell module I have authored as a simple implementation for live response and file collections over Powershell remoting. The initial use case was considered after an endpoint vendor appliance failed and capability for raw collections was limited. The module uses Powerforensics over WinRM, and after some interest, I think is worth sharing.
aliases: /posts/2018/01/14/Invoke-LiveResponse.html
---
![ ](00PowerShellthumb.png)

Some of the areas I will cover are:

- Background.
- Requirements and setup.
- Module switches and configuration.
- Performance tweaks.
- Forensic Footprint over WinRM.

The goal of this project was to promote Powershell as a blue team tool and improve my Powershell knowledge with research.

Github: [https://github.com/mgreen27/Powershell-IR](https://github.com/mgreen27/Powershell-IR)

### Background
The ability to collect live response data from a remote system is a fundamental requirement for modern incident response. Rouge processes, code injection, suspicious network activity or other disk and memory artefacts are some of data points an analyst may look for signs of evil. The ability to collect these data points quickly, enables informed decisions and reduces risk of loss from an incident. Some of the difficulties in accessing these artefacts include lack of endpoint visibility or capabilities for ad-lib collection, from either a technical or business limitation.

![](02powerforensics.png)

PowerForensics is a disk forensic framework for Powershell written in C# by Jared Atkinson. Typical use case is local analysis from a traditional collection enabling the analyst to perform detailed disk forensics similar to the more well known Sleuth Kit. Powerforensics can also be used for similar tasks over Powershell remoting.

In offensive security, one of the biggest enablers in Powershell is the capability to reflectively load PE files, shellcode and assembly into memory. That means security tools can be loaded from a Powershell script, in some cases never touching disk. The same techniques can be used by the Blue Team and quite a few practitioners are starting to use this feature for things like memory and volatile data forensics. Powerforensics enables the capability for remote raw disk analysis using Assembly.Load Method.

Invoke-LiveResponse is the result of converting some scripts for raw collection with redirected acquisition and live response into an easy to use tool. During use, I have tweaked some performance and learnt a lot in implementation about both Powershell and Powerforensics.

### Requirements
- Powershell 4.0 or above collector machine (3 should also be functional).
- Powershell 2.0 or above target machine/s.
- Powerforensics installed in running user Powershell Modules path (I have included automatic installation below).
- WinRM setup with Kerberos and/or Negotiation authentication.
- SMB Network share with write access (for file collections).

### Setup
On a Powershell 4+ collector machine, assuming you trust me, run the following proxy aware powershell commands to download then install. The install places Invoke-LiveResponse into the running users profile.

```powershell
# Proxy aware download install of Invoke-LiveResponse
Set-Executionpolicy -ExecutionPolicy bypass -force
$url="https://raw.githubusercontent.com/mgreen27/Powershell-IR/master/Get-Forensicating.ps1"
$WebClient=(New-Object System.Net.WebClient)
$WebClient.Proxy=[System.Net.WebRequest]::GetSystemWebProxy()
$WebClient.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials
Invoke-Expression $WebClient.DownloadString($url)

# Once installed run to load
Import-Module Invoke-LiveResponse

# View help
Get-Help Invoke-LiveResponse -detailed
```

### WinRM
I recommend setting WinRM up via Group policy for simplified deployment across all Powershell versions. Please see the resource section for some good resources and a detailed walkthrough, including a previous post of mine in setting up a lab.

For a quick and dirty install, Invoke-StartWinRM will turn on PSRemoting and configure appropriate credential configurations on Powershell 3 machines and above. Similarly, Invoke-StopWinRM may also be used to revert changes.

![](03invoke-startwinrm.png)

### Credential Risk
To minimise credential risk, CredSSP (and any basic) authentication over WinRM should always be disabled. This results in a network logon type 3 and protected credentials of the account running WinRM. The drawbacks here means our SMB share for copy use cases requires unauthenticated write access or credentials passed into the script at runtime. As share credentials will be pushed to the endpoint, best practice would be to create temporary account/access to our share for the duration of our redirected file acquisition.

### Memory
Powershell has a configuration option to restrict the amount of memory available in a shell. This value is called MaxMemoryPerShellMB, and depending on Powershell version may be set in both Shell and Plugin WSMan configurations. In Powershell 2.0, the default is 150MB, which will likely need to be increased or turned off. As later versions of Powershell have been released, the default values have risen appropriately for most WinRM use, for example in 3.0 MaxMemoryPerShellMB = 1024, which is multiples above required memory.

```powershell
# To view this setting locally
Get-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB
Get-Item WSMan:\localhost\Plugin\Microsoft.PowerShell\Quotas\MaxMemoryPerShellMB

# To edit this setting locally
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 1024 -Force
Set-Item WSMan:\localhost\Plugin\Microsoft.PowerShell\Quotas\MaxMemoryPerShellMB -Value 1024 -Force
```

The simplest approach is to deploy WinRM via Group policy and configure these settings via GPO or logon script. For manual intervention, Invoke-MaxMemory will connect via WinRM and turn off this setting (set to 0). Powershell 2.0 has restrictions in remotely changing WinRM settings, although not ideal from a forensic standpoint, the “–Legacy” switch uses scheduled tasks to force a local configuration change.

![](05Maxmemory.png)

## Invoke-LiveResponse
The current scope of Invoke-LiveResponse is a live response tool for targeted collection. There are two main modes of use in Invoke-LiveResponse and both are configured by a variety of command line switches.

### ForensicCopy
Configured by simple command line switches, Invoke-LiveResponse enables file collection from a remote machine over WinRM.
- Reflectively loads Powerforensics onto target machine to enable raw disk access.
- Leverages a scriptblock for each configured function of the script. 
- Common forensic artefacts and custom file collections.
- Depending on the selected switches, each selected capability is joined at run time to build the scriptblock pushed out to the target machine. 

```powershell
PS> Invoke-LiveResponse -ComputerName WinRMtester -Credential <Domain>\<user> 
-all -Map <Drive>: -UNC "\\<Server>\<folder> /user:<optional share credentials>"
```

Some of the available configuration options:
![](07parameters1.png)

Some of the switches available in ForensicCopy mode:
![](08parameters2.png)


### Live Response
- Inspired by the Kansa Framework, LiveResponse mode will execute any Powershell scripts placed inside a content folder.
- Results consist of the standard out from the executed content, redirected from the collection machine to a local Results folder as ScriptName.txt.
- The benefit of this method is the ability to operationalise new capability easily by dropping in new content with desired StdOut.

```powershell
# Command to run Powersell mode
Invoke-LiveResponse -ComputerName WinRMtester -Credential <domain>\<user> -LR  -Results <results> e.g C:\Cases>
```

![](09LiveResponse.png)

Some of the additional switches available in LiveResponse and shell mode:
![](10parameters3.png)


### Performance Tweaks
Testing for Invoke-LiveResponse has primarily been on Windows 7 and 8.1, with some minor testing on Windows 10 and Server Operating systems. I have also tested on Powershell 2.0 to 5.0 target machines. The decision was made to use Powerforensics to enable raw collection and bypass the need to drop or run binaries as much as possible

Powerforensics is the best Powershell based forensics framework available, but has not been primarily designed for remote raw collections. With that in mind, during testing I discovered an issue in Powerforensics Copy command-lets around memory utilisation and limitation of file size. The limitation is around 2.1GB (Int32 max bytes) and caused by the way Powerforensics builds a byte array for the complete file stream prior to copying. The limitation also means that memory consumption for my use cases (large system files) spiked up to at least the size of the file.

Normally this would be a game killer for using Powerforensics in this way. However, one of its best features is the ability to use an API and collect data at the appropriate level for your needs. In this case, I was able to leverage the Powerforensics API to collect files of interest in smaller chunks. The public method used is called ForensicDD and I am doing some traditional volume boot record calculations to enable a low memory footprint. File size limitations are also removed as the byte stream size has been significantly reduced.

![](11forensicdd.png)

Its also worthy to note, the capability to copy alternate data streams besides hard coded special files is not exposed to the user. The ForensicCopy function will simply copy resident bytes or the DATA stream for a normal Raw file copy.

Another performance tweak was with UsnJournal:$J to limit the collection to non-sparse data. This differs from most forensic collection tools that acquire all $J data and results in a bloated collection including redundant zeros. This method did hit a snag for an edgecase on a 2012R2 server where Powerforensics failed to parse the MFT entry as expected for the UsnJournal. This case is currently under review however I decided to implement a fall back collection via fsutil if required.

In any case I would recommend tool validation of this collection compared to current tools. In my testing I was able to validate file size and entries with another tool with a similar approach finding sample journal entries as expected.

Finally, for user experience, I also decided to implement CPU prioritisation to run my collection on idle CPU cycles only.

![](12idlecpu.png)


### Forensic Footprint
The most important factor for forensic footprint should be to know and validate your tools. To respect the order of volatility I have moved Live Response mode to run first to minimise impact by ForensicCopy mode. I would also recommend a naming scheme of Live Response content to further respect order of volatility.

There has been significant research to optimise target memory performance to be as low as possible. As primarily running in memory, the visible disk footprint of Powershell remoting is relatively small during a PSSession. With default logging, only expected authentication events and very basic WinRM and Powershell logs are generated. Wsmprovhost.exe is spawned on the target machine when running Invoke-LiveResponse and target disk activity is minimised with a remote share transfer. Depending on the collection, Net.exe and any other binaries called in script content may also be spawned from wsmprovhost.exe for their relevant functions.

![ ](13Process.png)

During the collection we see the expected authentication IDs 4624 and 4672 to access the target machine. When in ForensicCopy mode, if enabled we also see Event ID 4648 - explicit logon resulting from the collection copy to remote share.

![ ](14_4648.png)

In Powershell 5+ environments the capability to enable Powershell scriptblock logging highlights the benefit of visibility with Event ID 4104. Over multiple events we can see the Powerforensics functions being pushed to the target machine, decompressed and loaded to memory with the Add-PowerForensicsType function. We can also see the script block itself in the log. For a complete version, I have included a copy of the raw transaction logs [here](https://github.com/mgreen27/mgreen27.github.io/tree/master/static/Invoke-LiveResponse/Powershell%20Transcript) for review.

![ ](15_4104.png)

Finally Event ID 4103 – Module logging records pipeline execution details as seen in the example below. Module logging has been available since Powershell 3+ and although not as verbose as 4104, collected context about the commands run inside my script block. Below you can see datastream preparation for an $MFT raw copy. Host application as "wsmprovhost.exe -Embedding" indicates a PSSession generated event.

![ ](16_4103.png)


### Future development ideas
Invoke-LiveResponse has currently been limited scope. Some ideas for additional features are:

- Add memory collection capability to ForensicCopy mode for less reliance on LiveResponse scripts (and make appropriate order of volatility changes).
- Expand scope to enable more scale through Powershell Start-Job capabilities.
- Larger artefact coverage in ForensicCopy mode.
- Automate analysis tasks.

### Conclusion
In this post I have walked through Invoke-LiveResponse, a Powershell module that enables raw file collections and live response over WinRM. Work still needs to be done on scale optimisations, however it provides a viable option of raw collection when other tools fail.

This kind of capability highlights where I believe Microsoft focused shops will be heading in the future. Although a political nightmare to setup in large environments, the Microsoft mantra of constrained endpoints, just in time administration and transparency in Powershell logging really assists opening up capability whilst minimising risk of remote administration.

Overall it has been a great learning experience putting together, and optimising some of the Powershell features. Im hoping others can benefit from this post as much as I have enjoyed the research and writing it. Feel free to reach out if you have any questions, find any bugs or pull requests.





### References
1. Atkinson, Jared. [Invoke-IR / Powerforensics](http://www.invoke-ir.com/)

2. Australian Signals Directorate. [Securing PowerShell in the Enterprise](http://www.asd.gov.au/publications/protect/Securing_PowerShell.pdf), 2016

3. Dunwoody, Matthew. [Greater Visibility Through PowerShell Logging](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.htm)

4. Forensics wiki. [New Technology File Systems (general NTFS information)](http://www.forensicswiki.org/wiki/New_Technology_File_System_NTFS)

5. Green, Matthew. [Powershell Remoting and Incident Response (WinRM lab setup)](https://www.linkedin.com/pulse/powershell-remoting-incident-response-matthew-green/)

6. Invoke-LiveResponse [https://github.com/mgreen27/Powershell-IR](https://github.com/mgreen27/Powershell-IR)

7. Sayer, Matthew. [Contents in sparse mirror may be smaller than they appear](http://www.hecfblog.com/2017/05/contents-in-sparse-mirror-may-be.html)
