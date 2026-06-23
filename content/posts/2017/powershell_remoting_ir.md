---
layout: post
title:  "PowerShell Remoting and Incident Response"
date:   2017-01-12 12:00:00 +1000
categories: [powershell, DFIR]          # (custom) some categories, but makesure these categories already exists inside path of `category/`
tags: [powershell, DFIR]                      # (custom) tags only for meta `property="article:tag"`
image: 00PowerShell.png          # (custom) image only for meta `property="og:image"`, save your image inside path of `static/img/_posts`
thumbnail: 00PowerShellthumb.png
showTags: true
readTime: true
summary: PowerShell is quickly becoming a tool of choice for many IT Operations staff and Security Practitioners alike. This post is a quick overview of using Windows Remote Management and PowerShell for Incident Response. I will also provide some proof of concept setup instructions and general themes for those interested in further research on this topic.
aliases: /posts/2017/01/12/PowerShell_Remoting_IR.html
---
![ ](00PowerShellthumb.png)

### So what is Windows Remote Management?
PowerShell is a powerful scripting language for systems management due to its ability to run on remote systems, automation capability and ability to scale. The component enabling this capability is called the Windows Remote Management service (WinRM), which works over a standardised Simple Object Access Protocol (SOAP) based, firewall friendly protocol – WS Management. PowerShell is just one consumer of this service/protocol combo and with all Windows management communications heading down this path, this capability is only going to be further entrenched moving forward.

Windows Remote Management has been available since PowerShell 2.0 and Windows 7 through to the most recent incarnation in Windows Management Framework (WMF) 5.1. WinRM is enabled by default in Windows Server 2012 and 2016 but, as you’ll see below, simple to enable back to Windows 7 running PowerShell 2.0.

### Why do I care?
There are six primary reasons why you should care about PowerShell Remoting for Incident Response:

**Data available for Collection** - PowerShell has access to WMI, COM, .NET as well as to the Windows API. When combined with the capability to run some smart 3rd party or open source tools there really isn’t much you can’t do with PowerShell. Data collection is possible from: static disk, registry, log and configuration data; or any volatile process, network connection, or other in memory artefact. Historical data can be collected with timeline collection tools or pre-deployment of a process monitoring tool or Event Tracing for Windows.

**Analysis** - PowerShell is an object based language making analysis fairly simple once the dataset and methods of sorting / searching are understood. There is much integration readily available for common use cases like: live response, outlier analysis, baseline comparisons or building a timeline

**Performance** - PowerShell Remoting can significantly improve performance when scripting collections at scale. Execution of the command occurs in parallel on each target machine reporting the results, opposed to the source machine running through commands in an iterative scripted loop.

![ ](01performance.png)

**Strategic** - Windows Remote Management is Microsoft’s strategic direction for all Windows management communications moving forward. Many operations teams are already considering or currently using WinRM so it is worthwhile to understand points of leverage and weaknesses. Interestingly, PowerShell is also now open source with both OSX and Linux versions available.

**Agentless** - PowerShell remoting provides capability without needing to install “yet another agent”.

**Cost** – It is hard to argue with free, especially if there are skillsets in house already taking advantage of WinRM / PowerShell remoting.

### What is the catch?
The benefits of PowerShell remoting seem quite compelling but there are two main catches:

**Operational overhead** - Traditional open source issues of cost to build and maintain capability rather than going down a COTS path. Most organisations are not really mature enough to fully embrace building a complete solution in this space beyond simple collections (not everyone is a well resourced Fortune 500).

A great example here is process monitoring solutions - i.e. collection and analysis of historical data. While open source collection via Sysmon or other tools is available and better than the status quo in most organisations (i.e. nothing), a paid solution may provide much more capability at lower overall cost. When deciding to build, buy or outsource it is important not only understanding requirements, but also workflow underpinning those requirements, as well as technology and architecture.

**Security perceptions** - There are concerns around PowerShell security. Increased in-wild threats and popularity of offensive research in the past few years have driven this concern. Although most definitely not infallible, a properly configured PowerShell network will arguably lead to a much more secure environment than default - "properly configured" being the key word. With that in mind, similar to operational overhead, maturity may be the major driver for concerns about turning on WinRM.

It’s also worthy to note Microsoft has come a long way in recent editions of Windows and PowerShell from the original WinRM version included in Windows 7. Modern Windows 10 / PowerShell 5.0 versions feature comprehensive auditing capabilities for PowerShell and additional OS level security features. Features like Credential Guard, Device Guard, Applocker and AntiMalware ScanInterface (when used mainstream); combined with the Microsoft concept of "constrained endpoints" will really help reduce options for attackers.

# So how do I start?
There are a few ways to setup WinRM. Group Policy, you can use a command line tool (Winrm), or PowerShell cmdlets. I have pointed at some good resources including ideas to lock down Windows Remote Management and how to configure WinRM over HTTPS in the reference section below.

A useful method for Lab / Proof of Concept testing is via group policy; also consider turning on PowerShell script block logging and process monitoring to list a couple of other generic recommendations. In a nutshell for a basic WinRM configuration you are required to:

#### 1. Configure a WinRM listener
Note: Examples are referencing Windows 2012R2 Domain with client machines running PowerShell 2.0 (WinRM minimum requirement) through 5.0. Recommendations are to upgrade to WMF5.0 to take advantage of capabilities like PowerShell Script Block logging and additional built-in PowerShell cmdlets.

![ ](02config1.png)

Group Policy > Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management > WinRM Service > Allow Remote server management through WinRM > Here you are required to Enable WinRM and set service listening IP to * or IP of listening interface.

![ ](03config2.png)

#### 2. Configure the WinRM service to start automatically
Group Policy > Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Windows Remote Management (WS-Management) > set to automatic

Note: a client reboot is required to start Windows Remote Management Service automatically from Group Policy.

#### 3. Allow WinRM traffic through the firewall
Group Policy > Computer Configuration > Policies > Windows Settings > Security Settings > Windows Firewall... > Windows Firewall… > Inbound Rule > Create rule using predefined Windows Remote Management (HTTP-In)

#### 4. Ensure local admin privileges on the target machine.
Note: WinRM can be configured to NOT require local admin however some of the collections your going to want to run will likely require administrator privilege. Credential risk is minimised using the default WinRM Kerberos authentication.

Group Policy > Computer Configuration > Policies > Preferences > Control Panel Settings > Local Users and Groups > right click > All Tasks > Add > add User or Group to local administrators group.

Alternatively, for those looking for a PowerShell command line version: Running the command below to setup WinRM locally on your test hosts is fairly painless. Options like Enterprise Deployment Tool, Logon Script, PSEXEC or WMIC can be used for deployment as required. It is also worth noting that to configure a custom listener port you are required to use a CLI based configuration.

```powershell
# Setup: 
PS> Enable-PSRemoting -Force

# Confirm WinRM is setup and responsive:
PS> Test-WSMan <ComputerName> [Options]
PS> Test-WSMan <ComputerName> -Credential <Domain\User> -Authentication Kerberos 
```

![ ](04testnoauth.png)

![ ](05testwithauth.png)

# Authentication
When using PowerShell Remoting you have the capability to configure authentication methods. The default and recommended when joined to a domain is PowerShell’s non-delegated Kerberos network logons. These authentication attempts result in network type 3 logons and no credential exposure. Other available options are Basic, CredSSP, Default, Digest, Kerberos, and Negotiate; Negotiate being recommended for non domain machines.

Note: make a point not to use CredSSP as there are credential risks associated with delegating credentials.

When testing in a domain to use default Kerberos authentication you do not need to specify the authentication method. There are a couple of ways to initiate a session, the simplest being a singular: “Invoke-Command” with parameters included.

![ ](/06simpleexampleNEW.png)

Reusable sessions can also be configured using the “New-PSSession” cmdlet then calling the open session. As seen in my animation below I can invoke a session then run several commands through the open session.

![PS-Session](gif01.gif)

Finally the “Enter-PSSession” cmdlet can be used for SSH like connectivity on the remote machine. In the animated example below I show some basic queries and filtering then query Sysmon logs.

![PS-Session Sysmon](gif02.gif)

In my test environment I used a specifically allocated Active Directory service account for my PowerShell Remoting use, which I then allocated into a local administrator role via group policy. Similar actions could be taken with an appropriate group with local admin rights across all machines. This is much easier to control as well as audit in Security and Windows Remote Management Event logs.

# What’s next?
Some good areas to start to understand capabilities or implementation code reference are the following interesting frameworks and capabilities able to leverage WinRM:

**1) Kansa** - Written by Dave Hull, Kansa is a modular incident response framework that takes advantage of PowerShell remoting to enable surprisingly simple and scalable, current state data collections from Windows machines. Kansa can facilitate incident response, an environment baseline, intrusion hunting analysis, or even remediation across thousands of machines with ease. Kansa enables fairly easy way to write additional modules and a prebuilt framework to run 3rd party binaries inside its workflow.

Get-Kansa: [https://github.com/davehull/Kansa](https://github.com/davehull/Kansa "Get Kansa")

**2) PowerForensics** - Written by Jared Atkinson, PowerForensics is a comprehensive disk forensic framework proving raw access to disk from PowerShell. Working with PowerForensics a typical analysis would occur locally, for a local or mounted drive.

Jared has recently been working on a remoting solution that leverages the Assembly class' Load method to load the PowerForensics DLL in memory. The general idea is when running a command over WinRM the local machine checks if PowerForensics is loaded, if not, the appropriate PowerForensics assembly dll is loaded in memory for the duration of the WinRM session. This capability enables remote raw drive analysis and would significantly speed up analysis times removing the need for imaging or pushing an agent.

Get-PowerForensics: [https://github.com/Invoke-IR/PowerForensics](https://github.com/Invoke-IR/PowerForensics "Get Powerforensics")

![ ](07Powerforensics.png)

The Remoting capability via "Invoke-Command" is very new and still in development. Current requirement is to run "Add-PowerForensicsType" in your PS-Session although the goal is to eventually make this transparent to the user. In my testing limitations around versioning of PowerForensics appear to require ironing out so testing and tool validation are essential.

# Conclusion
With PowerShell Remoting over WinRM we have a flexible, yet powerful scripting language that can be used to query endpoints to collect relevant data points that an Incident Responder or Security team may require. Capable at scale, and over a communications framework included free in all modern Windows Operating systems. Although actually turning on WinRM may be difficult, it is worth some research to understand PowerShell remoting capabilities when considering future needs. A great strategy, but one used too infrequently is justifying a paid solution through showing benefits of open source capability, and comparing to relevant capability provided from a vendor.

The above should provide a some food for thought and point you in the right direction for further research. Feel free to reach out if you have any questions.



### References / Further reading
1. Atkinson, [Jared. Invoke-IR](http://www.invoke-ir.com)

2. Australian Signals Directorate. [Securing PowerShell in the Enterprise](http://www.asd.gov.au/publications/protect/Securing_PowerShell.pdf), 2016

3. Hofferle, Jason. [Hey Scripting Guy! An Introduction to PowerShell Remoting: Part One](https://blogs.technet.microsoft.com/heyscriptingguy/2012/07/23/an-introduction-to-powershell-remoting-part-one/), 2012

4. Hull, Dave. [PowerShell Magazine. Kansa overview ](http://www.powershellmagazine.com/2014/07/18/kansa-a-powershell-based-incident-response-framework/), 2014

5. Kazanciyan, Ryan. Hastings, Matt. [Investigating Powershell Attacks](https://www.blackhat.com/docs/us-14/materials/us-14-Kazanciyan-Investigating-Powershell-Attacks-WP.pdf), 2014

6. Metcalf, Sean. [PowerShell Security: Defending the Enterprise from the Latest Attack Platform](https://adsecurity.org/wp-content/uploads/2015/01/), 2016. 

7. MSDN. [PowerShell for the Blue Team](https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/), 2015

8. MSDN. [Windows Remote Management](https://msdn.microsoft.com/en-us/library/aa384426(v=vs.85).aspx)

9. Upguard. [WinRM Configuration: Enabling HTTPS WinRM](https://support.upguard.com/upguard/winrm-configuration.html#enabling-https-winrm)

